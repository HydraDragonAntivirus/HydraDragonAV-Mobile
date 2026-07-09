//! Shared Binary-Fuse (xor) filter container used by BOTH the offline builder
//! (`dev-tools/xorfilter_writer`) and the on-device native scanner
//! (`hydradragonandroid`). Keeping the key derivation, the filter-type selection
//! and the on-disk format in ONE crate guarantees a filter written on the x86
//! build host is queryable byte-for-byte on the arm64 device.
//!
//! Binary Fuse filters are smaller (~1.08 B/key for BF8, ~2.16 for BF16, ~4.3
//! for BF32) and faster to query than quotient or Bloom/Cuckoo filters; the
//! trade-off is that construction needs every key in memory at once (done once,
//! offline) and the filter keys on `u64`, so textual items are folded to a
//! `u64` with [`key`].
//!
//! NOTE on memory: the filter is decoded into an owned buffer at load time (its
//! fingerprint array lives on the native heap) rather than mmap'd zero-copy.
//! Binary-fuse encodings are small enough that resident RAM is typically low
//! overall even so, but it is dirty RSS rather than reclaimable page cache.

use std::fs::File;
use std::path::Path;

use jdb_xorf::{Bf16, Bf32, Bf8, Filter as JdbFilter};

/// File-format tags (first byte of every `.xf` file) identifying which
/// `BinaryFuseN` width follows. The width is chosen at build time from the
/// requested false-positive probability (see [`build_from_keys`]).
const TAG_BF8: u8 = 8;
const TAG_BF16: u8 = 16;
const TAG_BF32: u8 = 32;

/// Approximate false-positive probability of each width (n-bit fingerprint):
/// BF8 ≈ 1/2^8 ≈ 3.9e-3, BF16 ≈ 1/2^16 ≈ 1.5e-5, BF32 ≈ 1/2^32 ≈ 2.3e-10.
const BF16_FPP: f64 = 1.5e-5;
const BF8_FPP: f64 = 3.9e-3;

/// Folds a textual item (domain, full URL or hex hash) to the `u64` key the
/// filter is built and queried on.
///
/// FNV-1a 64 over the ASCII-lowercased bytes: deterministic, platform
/// independent and dependency free. Both build and query lowercase, so case can
/// never cause a miss (hostnames and hex digests are case-insensitive). The
/// filter re-mixes this key with its own internal seed, so a simple non-crypto
/// hash is sufficient — its sole job here is to map a string to a `u64`.
pub fn key(s: &str) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for b in s.bytes() {
        h ^= b.to_ascii_lowercase() as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// A loaded Binary-Fuse filter of one of the three supported widths.
pub enum XorFilter {
    Bf8(Bf8),
    Bf16(Bf16),
    Bf32(Bf32),
}

impl XorFilter {
    /// Membership test for a precomputed key.
    pub fn contains_key(&self, key: u64) -> bool {
        match self {
            XorFilter::Bf8(f) => f.has(&key),
            XorFilter::Bf16(f) => f.has(&key),
            XorFilter::Bf32(f) => f.has(&key),
        }
    }

    /// Membership test for a textual item (folds it via [`key`] first).
    pub fn contains(&self, s: &str) -> bool {
        self.contains_key(key(s))
    }

    /// Decode a filter from its tagged on-disk bytes. `None` on a bad tag or a
    /// malformed body.
    pub fn from_bytes(bytes: &[u8]) -> Option<XorFilter> {
        let (&tag, rest) = bytes.split_first()?;
        match tag {
            TAG_BF8 => bitcode::decode::<Bf8>(rest).ok().map(XorFilter::Bf8),
            TAG_BF16 => bitcode::decode::<Bf16>(rest).ok().map(XorFilter::Bf16),
            TAG_BF32 => bitcode::decode::<Bf32>(rest).ok().map(XorFilter::Bf32),
            _ => None,
        }
    }

    /// mmap `path` and decode the filter from it. The mapping only backs the
    /// decode (its pages come from the OS page cache); the returned filter owns
    /// its data, so the mapping is dropped on return. `None` if the file is
    /// absent or not a valid `.xf`.
    pub fn load(path: &Path) -> Option<XorFilter> {
        let file = File::open(path).ok()?;
        // SAFETY: the file is a read-only asset we ship and never mutate while
        // mapped.
        let mmap = unsafe { memmap2::Mmap::map(&file).ok()? };
        std::panic::catch_unwind(|| XorFilter::from_bytes(&mmap))
            .ok()
            .flatten()
    }
}

/// Build a tagged `.xf` blob from `keys` (raw `u64` keys, i.e. already passed
/// through [`key`]). The width is picked to honour `fpp` as closely as the
/// binary-fuse granularity allows:
///
///   * `fpp <= 1.5e-5`  -> BF32 (e.g. the website filters' 1e-6 target)
///   * `fpp <= 3.9e-3`  -> BF16 (e.g. the hash whitelist's 1e-4 target)
///   * otherwise        -> BF8
///
/// Duplicate keys are removed first: binary-fuse construction requires distinct
/// keys. Returns the bytes to write, or an error string if construction failed.
pub fn build_from_keys(mut keys: Vec<u64>, fpp: f64) -> Result<Vec<u8>, String> {
    keys.sort_unstable();
    keys.dedup();
    if keys.is_empty() {
        return Err("no keys to build a filter from".to_string());
    }
    // Bf8/Bf16/Bf32::from panics (rather than returning Result) in the
    // extremely unlikely event construction doesn't converge even after
    // dedup; catch that to preserve this function's Result contract.
    let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if fpp <= BF16_FPP {
            (TAG_BF32, bitcode::encode(&Bf32::from(&keys)))
        } else if fpp <= BF8_FPP {
            (TAG_BF16, bitcode::encode(&Bf16::from(&keys)))
        } else {
            (TAG_BF8, bitcode::encode(&Bf8::from(&keys)))
        }
    }))
    .map_err(|_| "binary fuse filter construction panicked".to_string())?;
    let (tag, body) = built;
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(tag);
    out.extend_from_slice(&body);
    Ok(out)
}
