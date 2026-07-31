//! Content-based benign APK whitelist via MinHash / Jaccard similarity.
//!
//! At init time we load `benign_signatures.bin` from the asset directory.
//! At scan time we compute a 64-value MinHash signature from the APK's raw
//! token set, then look up the package name in the database.  If any stored
//! signature for that package has estimated Jaccard similarity ≥ THRESHOLD,
//! the APK is declared KNOWN_BENIGN and heavy scanning (ClamAV, ML, TLSH)
//! is skipped.
//!
//! MinHash permutation: h_i(token) = (token XOR i) * FNV_PRIME   (mod 2^64)
//! Jaccard estimate:    |{i : sig_a[i] == sig_b[i]}| / K
//!
//! Binary format (`benign_signatures.bin`):
//!   u32                     — package count
//!   For each package:
//!     u8                    — package name byte length
//!     N bytes               — package name (UTF-8)
//!     u32                   — signature count
//!     sig_count × (64×u64) — MinHash values

use std::collections::HashMap;
use std::io::{Cursor, Read};

/// Number of MinHash permutations.  Must match gen_benign_signatures.py.
pub const K: usize = 64;

/// Jaccard similarity threshold for KNOWN_BENIGN.
pub const THRESHOLD: f32 = 0.85;

const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// A single 64-value MinHash signature.
pub type Sig = [u64; K];

/// In-memory benign signature database.
pub struct BenignDb {
    /// package_name → list of known-benign MinHash signatures
    sigs: HashMap<String, Vec<Sig>>,
}

impl BenignDb {
    /// Parse `benign_signatures.bin`.  Returns `None` on any read error.
    pub fn load(data: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(data);
        let pkg_count = read_u32(&mut c)?;

        let mut sigs: HashMap<String, Vec<Sig>> = HashMap::with_capacity(pkg_count as usize);

        for _ in 0..pkg_count {
            // Package name
            let name_len = read_u8(&mut c)? as usize;
            let mut name_buf = vec![0u8; name_len];
            c.read_exact(&mut name_buf).ok()?;
            let pkg = String::from_utf8_lossy(&name_buf).into_owned();

            // Signatures
            let sig_count = read_u32(&mut c)?;
            let mut pkg_sigs: Vec<Sig> = Vec::with_capacity(sig_count as usize);
            for _ in 0..sig_count {
                let mut sig = [0u64; K];
                for v in sig.iter_mut() {
                    *v = read_u64(&mut c)?;
                }
                pkg_sigs.push(sig);
            }
            sigs.entry(pkg).or_default().extend(pkg_sigs);
        }

        Some(BenignDb { sigs })
    }

    /// Return `true` if `tokens` is a known-benign set for `package_name`.
    pub fn is_known_benign(&self, package_name: &str, tokens: &std::collections::HashSet<u64>) -> bool {
        let stored = match self.sigs.get(package_name) {
            Some(v) => v,
            None => return false,
        };
        let query = compute_sig(tokens);
        for s in stored {
            if jaccard(&query, s) >= THRESHOLD {
                return true;
            }
        }
        false
    }

    /// Highest estimated Jaccard similarity between `tokens` and any stored
    /// signature for `package_name` (0.0 if the package is unknown). Exposed
    /// so the ML engine can use benign-DB similarity as a numerical feature,
    /// not just the boolean `is_known_benign` gate.
    pub fn max_jaccard(
        &self,
        package_name: &str,
        tokens: &std::collections::HashSet<u64>,
    ) -> f32 {
        let stored = match self.sigs.get(package_name) {
            Some(v) => v,
            None => return 0.0,
        };
        let query = compute_sig(tokens);
        stored.iter().map(|s| jaccard(&query, s)).fold(0.0_f32, f32::max)
    }

    /// Number of packages in the database.
    pub fn package_count(&self) -> usize {
        self.sigs.len()
    }

    /// Total number of stored signatures across all packages.
    pub fn signature_count(&self) -> usize {
        self.sigs.values().map(|v| v.len()).sum()
    }
}

/// Compute the MinHash signature for a token set.
/// h_i(t) = (t XOR i) * FNV_PRIME  (mod 2^64)
pub fn compute_sig(tokens: &std::collections::HashSet<u64>) -> Sig {
    let mut sig = [u64::MAX; K];
    for &t in tokens {
        for i in 0..K {
            let h = (t ^ i as u64).wrapping_mul(FNV_PRIME);
            if h < sig[i] {
                sig[i] = h;
            }
        }
    }
    sig
}

/// Estimated Jaccard similarity between two MinHash signatures.
#[inline]
pub fn jaccard(a: &Sig, b: &Sig) -> f32 {
    let matches = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
    matches as f32 / K as f32
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn read_u8(c: &mut Cursor<&[u8]>) -> Option<u8> {
    let mut buf = [0u8; 1];
    c.read_exact(&mut buf).ok()?;
    Some(buf[0])
}

fn read_u32(c: &mut Cursor<&[u8]>) -> Option<u32> {
    let mut buf = [0u8; 4];
    c.read_exact(&mut buf).ok()?;
    Some(u32::from_le_bytes(buf))
}

fn read_u64(c: &mut Cursor<&[u8]>) -> Option<u64> {
    let mut buf = [0u8; 8];
    c.read_exact(&mut buf).ok()?;
    Some(u64::from_le_bytes(buf))
}
