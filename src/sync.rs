//! Locks and the session-result channel, with or without `std`.
//!
//! With `std`, [`Mutex`] wraps the OS lock and [`Receiver::recv`] blocks on a
//! condition variable. Without it, both fall back to spin locks and only the
//! non-blocking [`Receiver::try_recv`] exists: a bare-metal driver polls for
//! the result after feeding each inbound message.

use alloc::collections::VecDeque;
use alloc::sync::Arc;

#[cfg(any(feature = "std", test))]
mod imp {
    pub(crate) type RawMutex<T> = std::sync::Mutex<T>;
    pub(crate) type Guard<'a, T> = std::sync::MutexGuard<'a, T>;

    pub(crate) fn lock<T>(m: &RawMutex<T>) -> Guard<'_, T> {
        m.lock()
            .expect("tsslib: lock poisoned by a panicking handler")
    }
}

#[cfg(not(any(feature = "std", test)))]
mod imp {
    pub(crate) type RawMutex<T> = spin::mutex::SpinMutex<T>;
    pub(crate) type Guard<'a, T> = spin::mutex::SpinMutexGuard<'a, T>;

    pub(crate) fn lock<T>(m: &RawMutex<T>) -> Guard<'_, T> {
        m.lock()
    }
}

/// A mutual-exclusion lock. Panics on a lock poisoned by a panicking holder
/// (as the `std` lock's `.lock().unwrap()` did).
pub(crate) struct Mutex<T>(imp::RawMutex<T>);

impl<T> Mutex<T> {
    pub(crate) const fn new(v: T) -> Self {
        Mutex(imp::RawMutex::new(v))
    }

    pub(crate) fn lock(&self) -> imp::Guard<'_, T> {
        imp::lock(&self.0)
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Mutex::new(T::default())
    }
}

/// Error from [`Receiver::try_recv`] / [`Receiver::recv`]: nothing queued
/// (and, for `recv`, the [`Sender`] is gone).
#[derive(Debug)]
pub(crate) struct RecvError;

struct Queue<T> {
    items: VecDeque<T>,
    disconnected: bool,
}

struct Inner<T> {
    queue: imp::RawMutex<Queue<T>>,
    #[cfg(any(feature = "std", test))]
    ready: std::sync::Condvar,
}

/// The sending half of a [`channel`]. Dropping it wakes a blocked
/// [`Receiver::recv`], which then reports [`RecvError`].
pub(crate) struct Sender<T>(Arc<Inner<T>>);

/// The receiving half of a [`channel`].
pub(crate) struct Receiver<T>(Arc<Inner<T>>);

/// A single-producer single-consumer channel: the subset of
/// `std::sync::mpsc` the session types use to hand back their result.
pub(crate) fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let inner = Arc::new(Inner {
        queue: imp::RawMutex::new(Queue {
            items: VecDeque::new(),
            disconnected: false,
        }),
        #[cfg(any(feature = "std", test))]
        ready: std::sync::Condvar::new(),
    });
    (Sender(Arc::clone(&inner)), Receiver(inner))
}

impl<T> Sender<T> {
    pub(crate) fn send(&self, v: T) {
        imp::lock(&self.0.queue).items.push_back(v);
        #[cfg(any(feature = "std", test))]
        self.0.ready.notify_all();
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        imp::lock(&self.0.queue).disconnected = true;
        #[cfg(any(feature = "std", test))]
        self.0.ready.notify_all();
    }
}

impl<T> Receiver<T> {
    /// Takes the next queued value without blocking.
    pub(crate) fn try_recv(&self) -> Result<T, RecvError> {
        imp::lock(&self.0.queue).items.pop_front().ok_or(RecvError)
    }

    /// Blocks until a value is queued, or fails once the [`Sender`] is gone
    /// and the queue is empty.
    #[cfg(any(feature = "std", test))]
    pub(crate) fn recv(&self) -> Result<T, RecvError> {
        let mut q = imp::lock(&self.0.queue);
        loop {
            if let Some(v) = q.items.pop_front() {
                return Ok(v);
            }
            if q.disconnected {
                return Err(RecvError);
            }
            q = self
                .0
                .ready
                .wait(q)
                .expect("tsslib: lock poisoned by a panicking handler");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivers_then_reports_disconnect() {
        let (tx, rx) = channel();
        assert!(rx.try_recv().is_err());
        tx.send(7u32);
        drop(tx);
        assert_eq!(rx.try_recv().unwrap(), 7);
        assert!(rx.recv().is_err());
    }

    #[test]
    fn recv_blocks_until_sent() {
        let (tx, rx) = channel();
        let h = std::thread::spawn(move || tx.send(42u32));
        assert_eq!(rx.recv().unwrap(), 42);
        h.join().unwrap();
    }
}
