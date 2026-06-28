//! MinHash signatures + LSH banding for near-duplicate / variant detection.
//!
//! This is the generalising counterpart to the per-file YARA set: instead of
//! requiring exact strings, it estimates the Jaccard similarity of an APK's
//! token set against every known-malware token set, so repacks and variants
//! that share most of their structure still match.

use std::collections::{HashMap, HashSet};

use crate::features::fnv1a;

/// Number of MinHash permutations. More = tighter Jaccard estimate, linear cost.
pub const NUM_HASHES: usize = 128;
/// LSH bands. `BANDS * ROWS == NUM_HASHES`. Fewer rows per band = more recall.
pub const BANDS: usize = 32;
pub const ROWS: usize = NUM_HASHES / BANDS;

/// Mersenne prime 2^61 - 1 for the universal hash family `(a*x + b) mod p`.
const MERSENNE: u64 = (1 << 61) - 1;

fn splitmix64(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Deterministic `(a, b)` coefficients for permutation `i`.
fn params(i: usize) -> (u64, u64) {
    let a = splitmix64(2 * i as u64) % (MERSENNE - 1) + 1;
    let b = splitmix64(2 * i as u64 + 1) % MERSENNE;
    (a, b)
}

/// Compute the MinHash signature of a token set.
pub fn signature(tokens: &HashSet<u64>) -> Vec<u64> {
    let mut sig = vec![u64::MAX; NUM_HASHES];
    for &t in tokens {
        let x = t % MERSENNE;
        for (i, slot) in sig.iter_mut().enumerate() {
            let (a, b) = params(i);
            let h = ((a as u128 * x as u128 + b as u128) % MERSENNE as u128) as u64;
            if h < *slot {
                *slot = h;
            }
        }
    }
    sig
}

/// Estimated Jaccard similarity in `[0, 1]` from two signatures.
pub fn jaccard(a: &[u64], b: &[u64]) -> f32 {
    let eq = a.iter().zip(b).filter(|(x, y)| x == y).count();
    eq as f32 / NUM_HASHES as f32
}

/// LSH index over a corpus of signatures: maps band buckets to sample ids.
#[derive(Default)]
pub struct LshIndex {
    buckets: HashMap<u64, Vec<u32>>,
}

fn band_key(band: usize, rows: &[u64]) -> u64 {
    let mut bytes = Vec::with_capacity(8 * (rows.len() + 1));
    bytes.extend_from_slice(&(band as u64).to_le_bytes());
    for r in rows {
        bytes.extend_from_slice(&r.to_le_bytes());
    }
    fnv1a(&bytes)
}

impl LshIndex {
    /// Build an index from all training signatures.
    pub fn build(sigs: &[Vec<u64>]) -> Self {
        let mut idx = LshIndex::default();
        for (id, sig) in sigs.iter().enumerate() {
            for band in 0..BANDS {
                let rows = &sig[band * ROWS..(band + 1) * ROWS];
                idx.buckets
                    .entry(band_key(band, rows))
                    .or_default()
                    .push(id as u32);
            }
        }
        idx
    }

    /// Candidate sample ids that share at least one band with `sig`.
    pub fn candidates(&self, sig: &[u64]) -> HashSet<u32> {
        let mut out = HashSet::new();
        for band in 0..BANDS {
            let rows = &sig[band * ROWS..(band + 1) * ROWS];
            if let Some(ids) = self.buckets.get(&band_key(band, rows)) {
                out.extend(ids.iter().copied());
            }
        }
        out
    }
}
