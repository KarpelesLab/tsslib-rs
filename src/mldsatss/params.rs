//! Threshold ML-DSA-44 (t, n) parameter table and replicated-sharing patterns.
//! Ported verbatim from the reference implementation
//! (github.com/GuilhemN/threshold-ml-dsa-and-raccoon, via tss-lib mldsatss).

/// Upper bound on N in the supported (t, n) table.
pub const MAX_PARTIES: usize = 6;

/// Parameters for one (t, n) configuration of threshold ML-DSA-44.
/// See ePrint 2025/1166 for the meaning of `k`, `nu`, `r`, `rp`.
#[derive(Clone, Copy, Debug)]
pub struct ThresholdParams44 {
    /// Threshold: minimum signers required.
    pub t: u8,
    /// Total parties.
    pub n: u8,
    /// Parallel signing tries per attempt (fresh `w` per try).
    pub k: u16,
    /// ν: anisotropic scaling factor of the L-part in the hyperball.
    pub nu: f64,
    /// r: primary ν-scaled L2 radius (party rejection bound).
    pub r: f64,
    /// r′: secondary L2 radius used in the Combine-side correctness check.
    pub rp: f64,
}

/// Error returned by [`get_threshold_params44`] for an unsupported `(t, n)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetThresholdParams44Error(pub String);

impl std::fmt::Display for GetThresholdParams44Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mldsatss: {}", self.0)
    }
}
impl std::error::Error for GetThresholdParams44Error {}

/// Returns the parameters for `(t, n)` if supported (2 ≤ t ≤ n ≤ 6).
pub fn get_threshold_params44(
    t: usize,
    n: usize,
) -> Result<ThresholdParams44, GetThresholdParams44Error> {
    if t < 2 {
        return Err(GetThresholdParams44Error("threshold t must be ≥ 2".into()));
    }
    if n < t {
        return Err(GetThresholdParams44Error(
            "total parties n must be ≥ t".into(),
        ));
    }
    if n > MAX_PARTIES {
        return Err(GetThresholdParams44Error(format!(
            "n must be ≤ {MAX_PARTIES}"
        )));
    }
    let p = |t: u8, n: u8, k: u16, r: f64, rp: f64| ThresholdParams44 {
        t,
        n,
        k,
        nu: 3.0,
        r,
        rp,
    };
    let out = match (t, n) {
        (2, 2) => p(2, 2, 2, 252778.0, 252833.0),
        (2, 3) => p(2, 3, 3, 310060.0, 310138.0),
        (3, 3) => p(3, 3, 4, 246490.0, 246546.0),
        (2, 4) => p(2, 4, 3, 305919.0, 305997.0),
        (3, 4) => p(3, 4, 7, 279235.0, 279314.0),
        (4, 4) => p(4, 4, 8, 243463.0, 243519.0),
        (2, 5) => p(2, 5, 3, 285363.0, 285459.0),
        (3, 5) => p(3, 5, 14, 282800.0, 282912.0),
        (4, 5) => p(4, 5, 30, 259427.0, 259526.0),
        (5, 5) => p(5, 5, 16, 239924.0, 239981.0),
        (2, 6) => p(2, 6, 4, 300265.0, 300362.0),
        (3, 6) => p(3, 6, 19, 277014.0, 277139.0),
        (4, 6) => p(4, 6, 74, 268705.0, 268831.0),
        (5, 6) => p(5, 6, 100, 250590.0, 250686.0),
        (6, 6) => p(6, 6, 37, 219245.0, 219301.0),
        _ => {
            return Err(GetThresholdParams44Error(format!(
                "unsupported (t={t}, n={n})"
            )));
        }
    };
    Ok(out)
}

/// Per-party honest-signer mask lists for reconstructing the aggregated secret.
/// Entry `i` (for the i-th party in the sorted signing set) lists the masks to
/// XOR-combine. `None` for the trivial cases `t == 1` or `t == n`.
pub fn sharing_pattern(t: u8, n: u8) -> Option<&'static [&'static [u8]]> {
    if t == 1 || t == n {
        return None;
    }
    let pat: &'static [&'static [u8]] = match (t, n) {
        (2, 3) => &[&[3, 5], &[6]],
        (2, 4) => &[&[11, 13], &[7, 14]],
        (3, 4) => &[&[3, 9], &[6, 10], &[12, 5]],
        (2, 5) => &[&[27, 29, 23], &[30, 15]],
        (3, 5) => &[&[25, 11, 19, 13], &[7, 14, 22, 26], &[28, 21]],
        (4, 5) => &[&[3, 9, 17], &[6, 10, 18], &[12, 5, 20], &[24]],
        (2, 6) => &[&[61, 47, 55], &[62, 31, 59]],
        (3, 6) => &[
            &[27, 23, 43, 57, 39],
            &[51, 58, 46, 30, 54],
            &[45, 53, 29, 15, 60],
        ],
        (4, 6) => &[
            &[19, 13, 35, 7, 49],
            &[42, 26, 38, 50, 22],
            &[52, 21, 44, 28, 37],
            &[25, 11, 14, 56, 41],
        ],
        (5, 6) => &[
            &[3, 5, 33],
            &[6, 10, 34],
            &[12, 20, 36],
            &[9, 24, 40],
            &[48, 17, 18],
        ],
        _ => return None,
    };
    Some(pat)
}
