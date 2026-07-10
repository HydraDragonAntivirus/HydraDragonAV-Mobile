//! Shared Binary-Fuse (xor) filter container used by BOTH the offline builder
//! (`dev-tools/xorfilter_writer`) and the on-device native scanner
//! (`hydradragonandroid`). Keeping the key derivation, the filter-type selection
//! and the on-disk format in ONE crate guarantees a filter written on the x86
//! build host is queryable byte-for-byte on the arm64 device.
//!
//! **Only BinaryFuse16 (`Bf16`) is used** — it gives ~2.16 bytes/key, which is
//! the best size/accuracy tradeoff for every filter in this project (URL/domain
//! lists, IP blocklists, MD5 whitelists). Using a single width means:
//!   * one file-format tag, no branching on read
//!   * predictable asset sizes before building
//!   * `jdb_xorf::Bf16::from(&keys)` handles construction directly
//!
//! NOTE on memory: the filter is decoded into an owned buffer at load time (its
//! fingerprint array lives on the native heap) rather than mmap'd zero-copy.
//! Binary-fuse encodings are small enough that resident RAM is typically low
//! overall even so, but it is dirty RSS rather than reclaimable page cache.

use std::fs::File;
use std::path::Path;

use jdb_xorf::{Bf16, Filter as JdbFilter};

/// File-format tag (first byte of every `.xf` file) — always BF16.
const TAG_BF16: u8 = 16;

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

/// Same FNV-1a fold as [`key`], but over raw bytes with no ASCII-lowercasing.
/// For callers whose keys are case-sensitive by nature (e.g. binary signature
/// atoms), unlike the hostnames/hashes [`key`] is for.
pub fn key_bytes(b: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for &byte in b {
        h ^= byte as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// A loaded BinaryFuse16 filter.
pub struct XorFilter(Bf16);

impl XorFilter {
    /// Membership test for a precomputed key.
    pub fn contains_key(&self, k: u64) -> bool {
        self.0.has(&k)
    }

    /// Membership test for a textual item (folds it via [`key`] first).
    pub fn contains(&self, s: &str) -> bool {
        self.contains_key(key(s))
    }

    /// Decode a filter from its tagged on-disk bytes. `None` on a bad tag or a
    /// malformed body.
    pub fn from_bytes(bytes: &[u8]) -> Option<XorFilter> {
        let (&tag, rest) = bytes.split_first()?;
        if tag != TAG_BF16 {
            return None;
        }
        bitcode::decode::<Bf16>(rest).ok().map(XorFilter)
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
/// through [`key`]). Always uses BinaryFuse16 (`Bf16`).
///
/// Duplicate keys are removed first: binary-fuse construction requires distinct
/// keys. Returns the bytes to write, or an error string if construction failed.
pub fn build_from_keys(mut keys: Vec<u64>) -> Result<Vec<u8>, String> {
    keys.sort_unstable();
    keys.dedup();
    if keys.is_empty() {
        return Err("no keys to build a filter from".to_string());
    }
    // Bf16::from panics (rather than returning Result) in the extremely
    // unlikely event construction doesn't converge even after dedup; catch
    // that to preserve this function's Result contract.
    let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        bitcode::encode(&Bf16::from(&keys))
    }))
    .map_err(|_| "BF16 filter construction panicked".to_string())?;
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(TAG_BF16);
    out.extend_from_slice(&body);
    Ok(out)
}
