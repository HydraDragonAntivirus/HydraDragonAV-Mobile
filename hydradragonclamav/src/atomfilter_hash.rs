//! Rolling polynomial hash over fixed-width byte windows.
//!
//! Used to derive atom keys for the Binary-Fuse16 atom filters, both at build
//! time (`atomfilter_build.rs`, hashing each signature's extracted atom) and
//! at scan time (`atomscan.rs`, sweeping every window of the scanned buffer).
//! Unlike `hydradragonxorfilter::key`/`key_bytes` (whole-buffer FNV-1a folds),
//! this hash is incrementally updatable per byte, so sweeping every window of
//! a given length across a buffer is O(n) rather than O(n * len) — the same
//! complexity class as the `daachorse` automaton it replaces.

/// Odd 64-bit multiplier for the rolling polynomial hash (mod 2^64 via
/// wrapping arithmetic). Reuses the FNV-1a prime — already known-good as an
/// odd, well-distributed multiplier.
pub(crate) const ROLL_BASE: u64 = 0x0000_0100_0000_01b3;

/// Canonical atom-key window lengths, spanning prefilter.rs's
/// `MIN_DEPTH..=MAX_ATOM` (2..=16) range with no gaps. An atom's bucket is the
/// largest entry here not exceeding the atom's (post-`short_atom`-clamp)
/// length; its key is the rolling hash of the atom's first `bucket_len` bytes.
pub const ATOM_LENGTHS: [usize; 5] = [2, 4, 8, 12, 16];

/// The bucket length to use for an atom of length `atom_len`: the largest
/// entry in [`ATOM_LENGTHS`] not exceeding it, or `None` if `atom_len` is
/// below the smallest bucket (shorter than `MIN_DEPTH`).
pub fn bucket_len(atom_len: usize) -> Option<usize> {
    ATOM_LENGTHS.iter().rev().copied().find(|&l| l <= atom_len)
}

/// Rolling hash of `data` computed from scratch (`data.len()` is the window
/// length). The seed for [`roll_windows`], and the exact hash it must agree
/// with for every window it emits.
pub fn hash_window(data: &[u8]) -> u64 {
    let mut h = 0u64;
    for &b in data {
        h = h.wrapping_mul(ROLL_BASE).wrapping_add(b as u64);
    }
    h
}

/// `ROLL_BASE^(len - 1) mod 2^64` — the coefficient of the byte about to
/// leave a length-`len` rolling window.
pub(crate) fn leading_coeff(len: usize) -> u64 {
    ROLL_BASE.wrapping_pow((len - 1) as u32)
}

/// Sweep every length-`len` window of `data`, calling `emit(start_offset,
/// hash)` for each in left-to-right order. `hash` always equals
/// `hash_window(&data[start..start + len])`, but is computed incrementally in
/// O(1) amortized per byte rather than recomputed per window. No-op if
/// `data.len() < len`.
pub fn roll_windows(data: &[u8], len: usize, mut emit: impl FnMut(usize, u64)) {
    if len == 0 || data.len() < len {
        return;
    }
    let coeff = leading_coeff(len);
    let mut h = hash_window(&data[..len]);
    emit(0, h);
    for s in 0..(data.len() - len) {
        let leaving = data[s] as u64;
        h = h.wrapping_sub(leaving.wrapping_mul(coeff));
        h = h.wrapping_mul(ROLL_BASE).wrapping_add(data[s + len] as u64);
        emit(s + 1, h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rolling_matches_naive_for_every_bucket_length() {
        let data: Vec<u8> = (0..97u32).map(|i| (i.wrapping_mul(37) % 251) as u8).collect();
        for &len in &ATOM_LENGTHS {
            let mut seen = Vec::new();
            roll_windows(&data, len, |s, h| seen.push((s, h)));
            assert_eq!(seen.len(), data.len() - len + 1, "len={len}");
            for (s, h) in &seen {
                assert_eq!(*h, hash_window(&data[*s..*s + len]), "len={len} s={s}");
            }
        }
    }

    #[test]
    fn roll_windows_noop_when_data_shorter_than_len() {
        let data = [1u8, 2, 3];
        let mut calls = 0;
        roll_windows(&data, 16, |_, _| calls += 1);
        assert_eq!(calls, 0);
    }

    #[test]
    fn bucket_len_picks_largest_fit() {
        assert_eq!(bucket_len(1), None);
        assert_eq!(bucket_len(2), Some(2));
        assert_eq!(bucket_len(3), Some(2));
        assert_eq!(bucket_len(4), Some(4));
        assert_eq!(bucket_len(7), Some(4));
        assert_eq!(bucket_len(8), Some(8));
        assert_eq!(bucket_len(15), Some(12));
        assert_eq!(bucket_len(16), Some(16));
        assert_eq!(bucket_len(1000), Some(16));
    }
}
