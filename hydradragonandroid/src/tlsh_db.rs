//! Flat, allocation-free TLSH digests.
//!
//! `tlsh_rs::TlshDigest` stores each digest's checksum and code in two heap
//! `Vec<u8>`s — ~278K digests (ELF+APK+DEX) means ~556K heap allocations.
//! This module keeps the same T1 data as a single `[u8; 35]` (checksum 1 +
//! lvalue 1 + q_ratios 1 + code 32), matching the exact layout the hex text
//! files produced by `gen_tlsh_db.py` encode. Diffing replicates
//! `TlshDigest::try_diff_with_options` byte-for-byte so results are identical.

/// RANGE_LVALUE / RANGE_QRATIO / LENGTH_MULTIPLIER from tlsh-rs internal
/// constants — duplicated here so we don't depend on tlsh-rs internals.
const RANGE_LVALUE: u16 = 256;
const RANGE_QRATIO: u16 = 16;
const LENGTH_MULTIPLIER: i32 = 12;

/// A standard T1 TLSH digest in flat form:
///   [0] checksum (1 byte)
///   [1] lvalue
///   [2] q_ratios (q1_ratio in high nibble, q2_ratio in low nibble)
///   [3..35] code (32 bytes, natural order)
pub struct TlshFlat([u8; 35]);

impl TlshFlat {
    /// Decode a TLSH hex string ("T1..." or bare 70 hex chars) into a flat
    /// digest. Mirrors `TlshDigest::from_encoded` / `from_raw_hex` byte
    /// layout, including the nibble-swap on checksum/lvalue and the reversed
    /// code order used by the on-disk hex encoding.
    pub fn parse(s: &str) -> Option<TlshFlat> {
        let s = s.strip_prefix("T1").unwrap_or(s);
        if s.len() != 70 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let b = s.as_bytes();
        let pair = |off: usize| (hex_value(b[off]) << 4) | hex_value(b[off + 1]);
        let mut flat = [0u8; 35];
        flat[0] = swap_byte(pair(0)); // checksum
        flat[1] = swap_byte(pair(2)); // lvalue
        flat[2] = pair(4);            // q_ratios (no nibble swap)
        // code: on-disk hex stores it reversed; code[idx] = pair(6 + (31 - idx) * 2)
        for idx in 0..32 {
            flat[3 + idx] = pair(6 + (31 - idx) * 2);
        }
        Some(TlshFlat(flat))
    }

    /// Build a flat digest from a freshly-hashed `tlsh_rs::TlshDigest`
    /// (scanned buffer side), using its public accessors.
    pub fn from_tlsh_rs(d: &tlsh_rs::TlshDigest) -> Option<TlshFlat> {
        let checksum = d.checksum();
        let code = d.code();
        if checksum.len() != 1 || code.len() != 32 {
            return None;
        }
        let mut flat = [0u8; 35];
        flat[0] = checksum[0];
        flat[1] = d.lvalue();
        flat[2] = (d.q1_ratio() << 4) | d.q2_ratio();
        flat[3..].copy_from_slice(code);
        Some(TlshFlat(flat))
    }

    /// TLSH distance to another flat digest. Replicates
    /// `TlshDigest::try_diff_with_options` (standard T1 profile assumed).
    pub fn diff(&self, other: &TlshFlat) -> i32 {
        let s = &self.0;
        let o = &other.0;

        let mut diff = 0;

        // Length (lvalue) contribution.
        let ldiff = mod_diff(s[1], o[1], RANGE_LVALUE);
        if ldiff == 1 {
            diff += 1;
        } else if ldiff > 1 {
            diff += ldiff * LENGTH_MULTIPLIER;
        }

        // q1 / q2 ratio contributions.
        let q1diff = mod_diff(s[2] >> 4, o[2] >> 4, RANGE_QRATIO);
        diff += if q1diff <= 1 { q1diff } else { (q1diff - 1) * 12 };
        let q2diff = mod_diff(s[2] & 0x0F, o[2] & 0x0F, RANGE_QRATIO);
        diff += if q2diff <= 1 { q2diff } else { (q2diff - 1) * 12 };

        // Checksum mismatch.
        if s[0] != o[0] {
            diff += 1;
        }

        diff + h_distance(&s[3..], &o[3..])
    }
}

fn hex_value(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'A'..=b'F' => b - b'A' + 10,
        b'a'..=b'f' => b - b'a' + 10,
        _ => 0,
    }
}

fn swap_byte(byte: u8) -> u8 {
    ((byte & 0xF0) >> 4) | ((byte & 0x0F) << 4)
}

fn mod_diff(x: u8, y: u8, range: u16) -> i32 {
    let (dl, dr) = if y > x {
        ((y - x) as i32, x as i32 + range as i32 - y as i32)
    } else {
        ((x - y) as i32, y as i32 + range as i32 - x as i32)
    };
    dl.min(dr)
}

fn h_distance(left: &[u8], right: &[u8]) -> i32 {
    left.iter()
        .zip(right.iter())
        .map(|(&l, &r)| byte_distance(l, r))
        .sum()
}

fn byte_distance(left: u8, right: u8) -> i32 {
    let mut x = left;
    let mut y = right;
    let mut diff = 0;
    for _ in 0..4 {
        diff += pair_distance(x & 0b11, y & 0b11);
        x >>= 2;
        y >>= 2;
    }
    diff
}

fn pair_distance(left: u8, right: u8) -> i32 {
    match left.abs_diff(right) {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 6,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH1: &str =
        "T1F8A0220C0F8C0023CB880800CA33E88B8F0C022AB302C2008A030300300E8A00C83AAC";
    const HASH2: &str =
        "T1C6A022A2E0008CC320C083A3E20AA888022A00000A0AB0088828022A0008A00022F22A";

    #[test]
    fn parse_and_diff_match_tlsh_rs() {
        let a = TlshFlat::parse(HASH1).unwrap();
        let b = TlshFlat::parse(HASH2).unwrap();
        let da = HASH1.parse::<tlsh_rs::TlshDigest>().unwrap();
        let db = HASH2.parse::<tlsh_rs::TlshDigest>().unwrap();
        assert_eq!(a.diff(&b), da.diff(&db));
        assert_eq!(a.diff(&a), 0);
        assert_eq!(b.diff(&b), 0);
    }

    #[test]
    fn from_tlsh_rs_roundtrip() {
        let da = HASH1.parse::<tlsh_rs::TlshDigest>().unwrap();
        let flat = TlshFlat::from_tlsh_rs(&da).unwrap();
        assert_eq!(flat.diff(&TlshFlat::parse(HASH1).unwrap()), 0);
    }

    #[test]
    fn reject_invalid() {
        assert!(TlshFlat::parse("T1ABC").is_none());
        assert!(TlshFlat::parse("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ").is_none());
    }
}
