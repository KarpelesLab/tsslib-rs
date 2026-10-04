//! Compact binary encoding for keys and protocol messages.
//!
//! A serde data format meant for embedded targets: it streams through the
//! small [`Read`] / [`Write`] traits below (no buffering of whole documents,
//! no `std::io`, no serde_json) and writes no field names. It is not
//! self-describing: reading needs the same type that was written.
//!
//! # Encoding
//!
//! | serde type                         | bytes                                         |
//! |------------------------------------|-----------------------------------------------|
//! | `bool`                             | `0x00` / `0x01`                               |
//! | `u8`, `i8`                         | 1 byte                                        |
//! | `u16`..`u128`                      | LEB128 varint (canonical: no trailing `0x00`) |
//! | `i16`..`i128`                      | zigzag, then varint                           |
//! | `f32`, `f64`                       | IEEE 754, little-endian                       |
//! | `char`                             | varint of the scalar value                    |
//! | `str`, bytes                       | varint length, then the bytes                 |
//! | `Option`                           | `0x00`, or `0x01` then the value              |
//! | unit, unit struct                  | nothing                                       |
//! | newtype struct                     | the inner value                               |
//! | sequence, map                      | varint count, then the elements / pairs       |
//! | tuple, tuple struct, struct        | the fields in order (no count, no names)      |
//! | enum                               | varint variant index, then its content        |
//!
//! Lengths and counts are capped at [`MAX_LEN`], and buffers grow as bytes
//! arrive rather than being sized from an untrusted length, so a corrupt or
//! hostile length cannot force a large allocation.
//!
//! The crate's byte-string and big-integer fields serialize as raw bytes here
//! (and as base64 / decimal in JSON); they check serde's `is_human_readable`.

use crate::prelude::*;
use serde::de::{self, DeserializeOwned, IntoDeserializer, Visitor};
use serde::ser::{self, Serialize};

/// Upper bound on any single length or element count.
pub const MAX_LEN: usize = 1 << 24;

/// Chunk size used while reading a length-prefixed value.
const READ_CHUNK: usize = 4096;

/// A byte source.
pub trait Read {
    /// Fills `buf` completely, or fails (with [`Error::UnexpectedEof`] when the
    /// source runs out).
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error>;
}

/// A byte sink.
pub trait Write {
    /// Writes all of `buf`, or fails.
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Error>;
}

impl Read for &[u8] {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        if self.len() < buf.len() {
            return Err(Error::UnexpectedEof);
        }
        let (head, tail) = self.split_at(buf.len());
        buf.copy_from_slice(head);
        *self = tail;
        Ok(())
    }
}

impl<R: Read + ?Sized> Read for &mut R {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        (**self).read_exact(buf)
    }
}

impl Write for Vec<u8> {
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.extend_from_slice(buf);
        Ok(())
    }
}

impl<W: Write + ?Sized> Write for &mut W {
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        (**self).write_all(buf)
    }
}

/// Adapts a `std::io::Read` into a [`Read`].
#[cfg(feature = "std")]
pub struct IoReader<R>(pub R);

#[cfg(feature = "std")]
impl<R: std::io::Read> Read for IoReader<R> {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.0.read_exact(buf).map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => Error::UnexpectedEof,
            _ => Error::Io(e.to_string()),
        })
    }
}

/// Adapts a `std::io::Write` into a [`Write`].
#[cfg(feature = "std")]
pub struct IoWriter<W>(pub W);

#[cfg(feature = "std")]
impl<W: std::io::Write> Write for IoWriter<W> {
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.0.write_all(buf).map_err(|e| Error::Io(e.to_string()))
    }
}

/// An encoding or decoding failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The input ended in the middle of a value.
    UnexpectedEof,
    /// The underlying reader or writer failed.
    Io(String),
    /// A length or count above [`MAX_LEN`].
    TooLong,
    /// Malformed input (bad varint, bool, UTF-8, enum index, …).
    Invalid(&'static str),
    /// [`from_slice`] decoded a value but bytes were left over.
    TrailingBytes,
    /// A message from a `Serialize` / `Deserialize` implementation.
    Message(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::UnexpectedEof => f.write_str("wire: unexpected end of input"),
            Error::Io(m) => write!(f, "wire: i/o error: {m}"),
            Error::TooLong => f.write_str("wire: length exceeds limit"),
            Error::Invalid(m) => write!(f, "wire: invalid input: {m}"),
            Error::TrailingBytes => f.write_str("wire: trailing bytes after value"),
            Error::Message(m) => write!(f, "wire: {m}"),
        }
    }
}

impl core::error::Error for Error {}

impl ser::Error for Error {
    fn custom<T: core::fmt::Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl de::Error for Error {
    fn custom<T: core::fmt::Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

/// Encodes `value` into `w`.
pub fn to_writer<T: Serialize + ?Sized, W: Write>(value: &T, w: &mut W) -> Result<(), Error> {
    value.serialize(&mut Serializer { w })
}

/// Encodes `value` into a new buffer.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    to_writer(value, &mut out)?;
    Ok(out)
}

/// Decodes one `T` from `r`, leaving `r` positioned just after it.
pub fn from_reader<T: DeserializeOwned, R: Read>(r: &mut R) -> Result<T, Error> {
    T::deserialize(&mut Deserializer { r })
}

/// Decodes a `T` that must span all of `bytes`.
pub fn from_slice<T: DeserializeOwned>(mut bytes: &[u8]) -> Result<T, Error> {
    let v = from_reader(&mut bytes)?;
    if bytes.is_empty() {
        Ok(v)
    } else {
        Err(Error::TrailingBytes)
    }
}

// --- primitives ---

fn write_varint<W: Write>(w: &mut W, mut v: u128) -> Result<(), Error> {
    let mut buf = [0u8; 19];
    let mut n = 0;
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            buf[n] = byte;
            n += 1;
            break;
        }
        buf[n] = byte | 0x80;
        n += 1;
    }
    w.write_all(&buf[..n])
}

/// Reads a canonical LEB128 varint no larger than `max`.
fn read_varint<R: Read>(r: &mut R, max: u128) -> Result<u128, Error> {
    let mut v: u128 = 0;
    let mut shift = 0u32;
    loop {
        let mut b = [0u8; 1];
        r.read_exact(&mut b)?;
        let byte = b[0];
        let part = (byte & 0x7f) as u128;
        if shift >= 128 || (shift > 0 && part.leading_zeros() < shift) {
            return Err(Error::Invalid("varint overflow"));
        }
        v |= part << shift;
        if byte & 0x80 == 0 {
            if byte == 0 && shift > 0 {
                return Err(Error::Invalid("non-canonical varint"));
            }
            break;
        }
        shift += 7;
    }
    if v > max {
        return Err(Error::Invalid("integer out of range"));
    }
    Ok(v)
}

fn zigzag(v: i128) -> u128 {
    ((v << 1) ^ (v >> 127)) as u128
}

fn unzigzag(v: u128) -> i128 {
    ((v >> 1) as i128) ^ -((v & 1) as i128)
}

fn read_len<R: Read>(r: &mut R) -> Result<usize, Error> {
    let n = read_varint(r, u64::MAX as u128)?;
    if n > MAX_LEN as u128 {
        return Err(Error::TooLong);
    }
    Ok(n as usize)
}

/// Reads `len` bytes, growing the buffer as data arrives.
fn read_bytes<R: Read>(r: &mut R, len: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(len.min(READ_CHUNK));
    while out.len() < len {
        let start = out.len();
        let n = (len - start).min(READ_CHUNK);
        out.resize(start + n, 0);
        r.read_exact(&mut out[start..])?;
    }
    Ok(out)
}

// --- serializer ---

/// The serializer behind [`to_writer`].
pub struct Serializer<'a, W: Write> {
    w: &'a mut W,
}

impl<W: Write> Serializer<'_, W> {
    fn len(&mut self, len: usize) -> Result<(), Error> {
        if len > MAX_LEN {
            return Err(Error::TooLong);
        }
        write_varint(self.w, len as u128)
    }
}

impl<W: Write> ser::Serializer for &mut Serializer<'_, W> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn serialize_bool(self, v: bool) -> Result<(), Error> {
        self.w.write_all(&[v as u8])
    }
    fn serialize_i8(self, v: i8) -> Result<(), Error> {
        self.w.write_all(&[v as u8])
    }
    fn serialize_i16(self, v: i16) -> Result<(), Error> {
        write_varint(self.w, zigzag(v as i128))
    }
    fn serialize_i32(self, v: i32) -> Result<(), Error> {
        write_varint(self.w, zigzag(v as i128))
    }
    fn serialize_i64(self, v: i64) -> Result<(), Error> {
        write_varint(self.w, zigzag(v as i128))
    }
    fn serialize_i128(self, v: i128) -> Result<(), Error> {
        write_varint(self.w, zigzag(v))
    }
    fn serialize_u8(self, v: u8) -> Result<(), Error> {
        self.w.write_all(&[v])
    }
    fn serialize_u16(self, v: u16) -> Result<(), Error> {
        write_varint(self.w, v as u128)
    }
    fn serialize_u32(self, v: u32) -> Result<(), Error> {
        write_varint(self.w, v as u128)
    }
    fn serialize_u64(self, v: u64) -> Result<(), Error> {
        write_varint(self.w, v as u128)
    }
    fn serialize_u128(self, v: u128) -> Result<(), Error> {
        write_varint(self.w, v)
    }
    fn serialize_f32(self, v: f32) -> Result<(), Error> {
        self.w.write_all(&v.to_le_bytes())
    }
    fn serialize_f64(self, v: f64) -> Result<(), Error> {
        self.w.write_all(&v.to_le_bytes())
    }
    fn serialize_char(self, v: char) -> Result<(), Error> {
        write_varint(self.w, v as u128)
    }
    fn serialize_str(self, v: &str) -> Result<(), Error> {
        self.serialize_bytes(v.as_bytes())
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<(), Error> {
        self.len(v.len())?;
        self.w.write_all(v)
    }
    fn serialize_none(self) -> Result<(), Error> {
        self.w.write_all(&[0])
    }
    fn serialize_some<T: Serialize + ?Sized>(self, v: &T) -> Result<(), Error> {
        self.w.write_all(&[1])?;
        v.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        idx: u32,
        _: &'static str,
    ) -> Result<(), Error> {
        write_varint(self.w, idx as u128)
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        v: &T,
    ) -> Result<(), Error> {
        v.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        idx: u32,
        _: &'static str,
        v: &T,
    ) -> Result<(), Error> {
        write_varint(self.w, idx as u128)?;
        v.serialize(self)
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Self, Error> {
        self.len(len.ok_or(Error::Invalid("sequence length must be known"))?)?;
        Ok(self)
    }
    fn serialize_tuple(self, _: usize) -> Result<Self, Error> {
        Ok(self)
    }
    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self, Error> {
        Ok(self)
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        idx: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self, Error> {
        write_varint(self.w, idx as u128)?;
        Ok(self)
    }
    fn serialize_map(self, len: Option<usize>) -> Result<Self, Error> {
        self.len(len.ok_or(Error::Invalid("map length must be known"))?)?;
        Ok(self)
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self, Error> {
        Ok(self)
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        idx: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self, Error> {
        write_varint(self.w, idx as u128)?;
        Ok(self)
    }
}

macro_rules! compound {
    ($($tr:ident :: $method:ident),*) => {$(
        impl<W: Write> ser::$tr for &mut Serializer<'_, W> {
            type Ok = ();
            type Error = Error;
            fn $method<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), Error> {
                v.serialize(&mut **self)
            }
            fn end(self) -> Result<(), Error> {
                Ok(())
            }
        }
    )*};
}
compound!(
    SerializeSeq::serialize_element,
    SerializeTuple::serialize_element,
    SerializeTupleStruct::serialize_field,
    SerializeTupleVariant::serialize_field
);

impl<W: Write> ser::SerializeMap for &mut Serializer<'_, W> {
    type Ok = ();
    type Error = Error;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, k: &T) -> Result<(), Error> {
        k.serialize(&mut **self)
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), Error> {
        v.serialize(&mut **self)
    }
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

impl<W: Write> ser::SerializeStruct for &mut Serializer<'_, W> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        _: &'static str,
        v: &T,
    ) -> Result<(), Error> {
        v.serialize(&mut **self)
    }
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

impl<W: Write> ser::SerializeStructVariant for &mut Serializer<'_, W> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        _: &'static str,
        v: &T,
    ) -> Result<(), Error> {
        v.serialize(&mut **self)
    }
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

// --- deserializer ---

/// The deserializer behind [`from_reader`].
pub struct Deserializer<R: Read> {
    r: R,
}

impl<R: Read> Deserializer<R> {
    fn byte(&mut self) -> Result<u8, Error> {
        let mut b = [0u8; 1];
        self.r.read_exact(&mut b)?;
        Ok(b[0])
    }

    fn uint(&mut self, max: u128) -> Result<u128, Error> {
        read_varint(&mut self.r, max)
    }

    fn int(&mut self, min: i128, max: i128) -> Result<i128, Error> {
        let v = unzigzag(read_varint(&mut self.r, u128::MAX)?);
        if v < min || v > max {
            return Err(Error::Invalid("integer out of range"));
        }
        Ok(v)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, Error> {
        let len = read_len(&mut self.r)?;
        read_bytes(&mut self.r, len)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut b = [0u8; N];
        self.r.read_exact(&mut b)?;
        Ok(b)
    }
}

impl<'de, R: Read> de::Deserializer<'de> for &mut Deserializer<R> {
    type Error = Error;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Error> {
        Err(Error::Invalid("the binary format is not self-describing"))
    }
    fn deserialize_ignored_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Error> {
        Err(Error::Invalid("the binary format is not self-describing"))
    }
    fn deserialize_bool<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        match self.byte()? {
            0 => v.visit_bool(false),
            1 => v.visit_bool(true),
            _ => Err(Error::Invalid("bool must be 0 or 1")),
        }
    }
    fn deserialize_i8<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_i8(self.byte()? as i8)
    }
    fn deserialize_i16<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_i16(self.int(i16::MIN as i128, i16::MAX as i128)? as i16)
    }
    fn deserialize_i32<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_i32(self.int(i32::MIN as i128, i32::MAX as i128)? as i32)
    }
    fn deserialize_i64<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_i64(self.int(i64::MIN as i128, i64::MAX as i128)? as i64)
    }
    fn deserialize_i128<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_i128(self.int(i128::MIN, i128::MAX)?)
    }
    fn deserialize_u8<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_u8(self.byte()?)
    }
    fn deserialize_u16<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_u16(self.uint(u16::MAX as u128)? as u16)
    }
    fn deserialize_u32<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_u32(self.uint(u32::MAX as u128)? as u32)
    }
    fn deserialize_u64<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_u64(self.uint(u64::MAX as u128)? as u64)
    }
    fn deserialize_u128<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_u128(self.uint(u128::MAX)?)
    }
    fn deserialize_f32<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_f32(f32::from_le_bytes(self.array()?))
    }
    fn deserialize_f64<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_f64(f64::from_le_bytes(self.array()?))
    }
    fn deserialize_char<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        let c = self.uint(u32::MAX as u128)? as u32;
        v.visit_char(char::from_u32(c).ok_or(Error::Invalid("invalid char"))?)
    }
    fn deserialize_str<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        self.deserialize_string(v)
    }
    fn deserialize_string<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        let s = String::from_utf8(self.bytes()?).map_err(|_| Error::Invalid("invalid UTF-8"))?;
        v.visit_string(s)
    }
    fn deserialize_bytes<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        self.deserialize_byte_buf(v)
    }
    fn deserialize_byte_buf<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_byte_buf(self.bytes()?)
    }
    fn deserialize_option<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        match self.byte()? {
            0 => v.visit_none(),
            1 => v.visit_some(self),
            _ => Err(Error::Invalid("option tag must be 0 or 1")),
        }
    }
    fn deserialize_unit<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_unit()
    }
    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        v: V,
    ) -> Result<V::Value, Error> {
        v.visit_unit()
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        v: V,
    ) -> Result<V::Value, Error> {
        v.visit_newtype_struct(self)
    }
    fn deserialize_seq<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        let len = read_len(&mut self.r)?;
        v.visit_seq(Counted {
            de: self,
            left: len,
        })
    }
    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, v: V) -> Result<V::Value, Error> {
        v.visit_seq(Counted {
            de: self,
            left: len,
        })
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        len: usize,
        v: V,
    ) -> Result<V::Value, Error> {
        v.visit_seq(Counted {
            de: self,
            left: len,
        })
    }
    fn deserialize_map<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        let len = read_len(&mut self.r)?;
        v.visit_map(Counted {
            de: self,
            left: len,
        })
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        fields: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, Error> {
        v.visit_seq(Counted {
            de: self,
            left: fields.len(),
        })
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, Error> {
        v.visit_enum(self)
    }
    fn deserialize_identifier<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_u32(self.uint(u32::MAX as u128)? as u32)
    }
}

/// A sequence, tuple, struct or map with a known number of entries left.
struct Counted<'a, R: Read> {
    de: &'a mut Deserializer<R>,
    left: usize,
}

impl<'de, R: Read> de::SeqAccess<'de> for Counted<'_, R> {
    type Error = Error;
    fn next_element_seed<T: de::DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        if self.left == 0 {
            return Ok(None);
        }
        self.left -= 1;
        seed.deserialize(&mut *self.de).map(Some)
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.left.min(READ_CHUNK))
    }
}

impl<'de, R: Read> de::MapAccess<'de> for Counted<'_, R> {
    type Error = Error;
    fn next_key_seed<K: de::DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        if self.left == 0 {
            return Ok(None);
        }
        self.left -= 1;
        seed.deserialize(&mut *self.de).map(Some)
    }
    fn next_value_seed<V: de::DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        seed.deserialize(&mut *self.de)
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.left.min(READ_CHUNK))
    }
}

impl<'de, R: Read> de::EnumAccess<'de> for &mut Deserializer<R> {
    type Error = Error;
    type Variant = Self;
    fn variant_seed<V: de::DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Self), Error> {
        let idx = self.uint(u32::MAX as u128)? as u32;
        let v = seed.deserialize(IntoDeserializer::<Error>::into_deserializer(idx))?;
        Ok((v, self))
    }
}

impl<'de, R: Read> de::VariantAccess<'de> for &mut Deserializer<R> {
    type Error = Error;
    fn unit_variant(self) -> Result<(), Error> {
        Ok(())
    }
    fn newtype_variant_seed<T: de::DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        seed.deserialize(self)
    }
    fn tuple_variant<V: Visitor<'de>>(self, len: usize, v: V) -> Result<V::Value, Error> {
        de::Deserializer::deserialize_tuple(self, len, v)
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, Error> {
        de::Deserializer::deserialize_tuple(self, fields.len(), v)
    }
}

/// Leading byte of every binary key encoding, so the layout can evolve.
pub(crate) const KEY_ENCODING_VERSION: u8 = 1;

/// Writes a key's wire struct, prefixed with [`KEY_ENCODING_VERSION`].
pub(crate) fn write_key<T: Serialize + ?Sized, W: Write>(
    value: &T,
    w: &mut W,
) -> Result<(), Error> {
    w.write_all(&[KEY_ENCODING_VERSION])?;
    to_writer(value, w)
}

/// Counts the bytes written to it, discarding them.
struct Counter(usize);

impl Write for Counter {
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.0 += buf.len();
        Ok(())
    }
}

/// [`write_key`] into a new buffer allocated at its exact final size. Keys
/// hold secrets, and a buffer grown by doubling would leave partial copies of
/// them in freed memory.
pub(crate) fn key_to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    let mut counter = Counter(0);
    write_key(value, &mut counter)?;
    let mut out = Vec::with_capacity(counter.0);
    write_key(value, &mut out)?;
    debug_assert_eq!(out.len(), counter.0);
    Ok(out)
}

/// Reads a key's wire struct written by [`write_key`].
pub(crate) fn read_key<T: DeserializeOwned, R: Read>(r: &mut R) -> Result<T, Error> {
    let mut v = [0u8; 1];
    r.read_exact(&mut v)?;
    if v[0] != KEY_ENCODING_VERSION {
        return Err(Error::Invalid("unsupported key encoding version"));
    }
    from_reader(r)
}

/// Gives a key type `write_to` / `read_from` / `to_bytes` / `from_bytes` in
/// the binary encoding, through the same wire struct its JSON form uses.
/// `to_wire` maps `&self` to a `Result` of something `Serialize`; `from_wire`
/// maps the decoded wire struct back to a `Result<Self, _>`.
// Unused only in a build with no protocol enabled.
#[allow(unused_macros)]
macro_rules! key_codec {
    ($key:ty, $err:ty, $wire:ty, to_wire: |$k:ident| $to:expr, from_wire: |$w:ident| $from:expr $(,)?) => {
        impl $key {
            /// Writes the key in the compact binary encoding
            /// ([`crate::wire`]). The output holds the secret share in the
            /// clear; protecting it at rest is the caller's job.
            pub fn write_to<W: crate::wire::Write>(&self, w: &mut W) -> Result<(), $err> {
                let $k = self;
                crate::wire::write_key(&$to?, w)?;
                Ok(())
            }

            /// Reads a key written by [`Self::write_to`], leaving `r` just
            /// after it.
            pub fn read_from<R: crate::wire::Read>(r: &mut R) -> Result<Self, $err> {
                let $w: $wire = crate::wire::read_key(r)?;
                $from
            }

            /// The key in the compact binary encoding (see
            /// [`Self::write_to`]).
            pub fn to_bytes(&self) -> Result<Vec<u8>, $err> {
                let $k = self;
                Ok(crate::wire::key_to_vec(&$to?)?)
            }

            /// Parses a binary-encoded key that spans all of `bytes`.
            pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, $err> {
                let key = Self::read_from(&mut bytes)?;
                if !bytes.is_empty() {
                    return Err(crate::wire::Error::TrailingBytes.into());
                }
                Ok(key)
            }
        }
    };
}
#[allow(unused_imports)]
pub(crate) use key_codec;

/// Visits a byte string written with `serialize_bytes` (the crate's byte-string
/// and big-integer types in this format).
pub(crate) struct ByteBufVisitor;

impl<'de> Visitor<'de> for ByteBufVisitor {
    type Value = Vec<u8>;
    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a byte string")
    }
    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
        Ok(v.to_vec())
    }
    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    enum Kind {
        A,
        B(u32),
        C { x: i64, y: String },
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Sample {
        flag: bool,
        small: u8,
        neg: i32,
        big: u64,
        huge: u128,
        name: String,
        maybe: Option<u16>,
        list: Vec<Kind>,
        arr: [u8; 4],
        pair: (u16, i8),
    }

    fn sample() -> Sample {
        Sample {
            flag: true,
            small: 200,
            neg: -300,
            big: u64::MAX,
            huge: u128::MAX - 5,
            name: "héllo".into(),
            maybe: Some(7),
            list: vec![
                Kind::A,
                Kind::B(1 << 20),
                Kind::C {
                    x: i64::MIN,
                    y: "z".into(),
                },
            ],
            arr: [1, 2, 3, 4],
            pair: (65535, -1),
        }
    }

    #[test]
    fn roundtrips_every_shape() {
        let bytes = to_vec(&sample()).unwrap();
        assert_eq!(from_slice::<Sample>(&bytes).unwrap(), sample());
    }

    #[test]
    fn varints_are_compact_and_canonical() {
        assert_eq!(to_vec(&0u32).unwrap(), [0]);
        assert_eq!(to_vec(&127u32).unwrap(), [0x7f]);
        assert_eq!(to_vec(&128u32).unwrap(), [0x80, 0x01]);
        assert_eq!(to_vec(&-1i32).unwrap(), [1]);
        assert_eq!(to_vec(&1i32).unwrap(), [2]);
        // Overlong encoding of 0.
        assert!(from_slice::<u32>(&[0x80, 0x00]).is_err());
        // Out of range for the target type.
        assert!(from_slice::<u16>(&[0x80, 0x80, 0x04]).is_err());
        // More than 128 bits.
        assert!(from_slice::<u128>(&[0xff; 20]).is_err());
    }

    #[test]
    fn rejects_truncation_trailing_bytes_and_huge_lengths() {
        let bytes = to_vec(&sample()).unwrap();
        for cut in 0..bytes.len() {
            assert!(from_slice::<Sample>(&bytes[..cut]).is_err(), "cut at {cut}");
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(from_slice::<Sample>(&extra), Err(Error::TrailingBytes));
        // A string claiming u64::MAX bytes.
        let mut huge = Vec::new();
        write_varint(&mut huge, u64::MAX as u128).unwrap();
        assert_eq!(from_slice::<String>(&huge), Err(Error::TooLong));
        // A length within the cap but with no data behind it fails without
        // allocating it up front.
        let mut big = Vec::new();
        write_varint(&mut big, (MAX_LEN - 1) as u128).unwrap();
        assert_eq!(from_slice::<Vec<u8>>(&big), Err(Error::UnexpectedEof));
    }

    #[test]
    fn streams_values_back_to_back() {
        let mut buf = Vec::new();
        to_writer(&1u32, &mut buf).unwrap();
        to_writer("two", &mut buf).unwrap();
        to_writer(&sample(), &mut buf).unwrap();
        let mut r = buf.as_slice();
        assert_eq!(from_reader::<u32, _>(&mut r).unwrap(), 1);
        assert_eq!(from_reader::<String, _>(&mut r).unwrap(), "two");
        assert_eq!(from_reader::<Sample, _>(&mut r).unwrap(), sample());
        assert!(r.is_empty());
    }
}
