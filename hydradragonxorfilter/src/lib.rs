//! Shared Binary-Fuse (xor) filter container used by BOTH the offline builder
//! (`dev-tools/xorfilter_writer`) and the on-device native scanner
//! (`hydradragonandroid`). Keeping the key derivation, the filter-type selection
//! and the on-disk format in ONE crate guarantees a filter written on the x86
//! build host is queryable byte-for-byte on the arm64 device.
//!
//! This replaces the previous `qfilter` (Rank-Select Quotient Filter) approach.
//! Binary Fuse filters are smaller (~1.08 B/key for BF8, ~2.16 for BF16, ~4.3
//! for BF32) and faster to query than quotient or Bloom/Cuckoo filters; the
//! trade-off is that construction needs every key in memory at once (done once,
//! offline) and the filter keys on `u64`, so textual items are folded to a
//! `u64` with [`key`].
//!
//! NOTE on memory: unlike the old mmap'd zero-copy `qfilter`, the binary-fuse
//! filter is decoded into an owned buffer at load time (its fingerprint array
//! lives on the native heap). Binary-fuse encodings are far smaller than the
//! equivalent quotient filter, so resident RAM is typically LOWER overall, but
//! it is now dirty RSS rather than reclaimable page cache.

use std::fs::File;
use std::path::Path;

use xorf::{BinaryFuse16, BinaryFuse32, BinaryFuse8, Filter};

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
    Bf8(BinaryFuse8),
    Bf16(BinaryFuse16),
    Bf32(BinaryFuse32),
}

impl XorFilter {
    /// Membership test for a precomputed key.
    pub fn contains_key(&self, key: u64) -> bool {
        match self {
            XorFilter::Bf8(f) => f.contains(&key),
            XorFilter::Bf16(f) => f.contains(&key),
            XorFilter::Bf32(f) => f.contains(&key),
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
        let cfg = bincode::config::standard();
        match tag {
            TAG_BF8 => bincode::serde::decode_from_slice::<BinaryFuse8, _>(rest, cfg)
                .ok()
                .map(|(f, _)| XorFilter::Bf8(f)),
            TAG_BF16 => bincode::serde::decode_from_slice::<BinaryFuse16, _>(rest, cfg)
                .ok()
                .map(|(f, _)| XorFilter::Bf16(f)),
            TAG_BF32 => bincode::serde::decode_from_slice::<BinaryFuse32, _>(rest, cfg)
                .ok()
                .map(|(f, _)| XorFilter::Bf32(f)),
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
    let cfg = bincode::config::standard();
    let (tag, body) = if fpp <= BF16_FPP {
        let f = BinaryFuse32::try_from(keys.as_slice()).map_err(|e| e.to_string())?;
        (TAG_BF32, bincode::serde::encode_to_vec(&f, cfg).map_err(|e| e.to_string())?)
    } else if fpp <= BF8_FPP {
        let f = BinaryFuse16::try_from(keys.as_slice()).map_err(|e| e.to_string())?;
        (TAG_BF16, bincode::serde::encode_to_vec(&f, cfg).map_err(|e| e.to_string())?)
    } else {
        let f = BinaryFuse8::try_from(keys.as_slice()).map_err(|e| e.to_string())?;
        (TAG_BF8, bincode::serde::encode_to_vec(&f, cfg).map_err(|e| e.to_string())?)
    };
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(tag);
    out.extend_from_slice(&body);
    Ok(out)
}
