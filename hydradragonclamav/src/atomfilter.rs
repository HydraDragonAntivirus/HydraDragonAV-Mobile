//! Data model for the Binary-Fuse16 atom/counter/threshold promotion scanner.
//!
//! Mirrors `prefilter.rs`'s atom-index concept, but built from Binary-Fuse16
//! set-membership filters (`jdb_xorf::Bf16`) instead of an exact Aho-Corasick
//! trie: a filter answers "does this window's rolling hash belong to some
//! atom?" in O(1) with a fixed, tiny memory footprint per key. `Bf16` (unlike
//! a `HashMap`) can't store which atom/signature a key belongs to, so each
//! bucket pairs its filter with an exact key -> slot-list map that resolves a
//! filter hit to the slot(s) sharing that key. No byte-level re-verification
//! of the matched atom, nor of the owning signature's pattern, ever happens —
//! reaching a slot's hit threshold promotes its signature directly.

use crate::atomfilter_hash::ATOM_LENGTHS;
use jdb_xorf::Bf16;

/// Index into [`AtomFilterDb::slots`]. One "thing" (a whole extended
/// signature, or one subsignature of a logical signature) with its own hit
/// counter at scan time.
pub type SlotId = u32;

/// What a slot promotes to once its counter reaches [`SlotDef::threshold`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotTarget {
    /// An extended (`.ndb`/`.db`) signature.
    Extended { sig_index: u32 },
    /// One subsignature of a logical (`.ldb`) signature — reaching threshold
    /// counts as that subsignature matching, feeding `LogicalExpr::eval`
    /// exactly like a real body match would.
    LogicalSubsig { sig_index: u32, subsig_index: u32 },
}

#[derive(Clone, Debug)]
pub struct SlotDef {
    pub target: SlotTarget,
    /// Hit count required before this slot counts as matched. Almost always
    /// 1 (a single atom occurrence is enough) — kept general so a signature
    /// requiring several distinct atoms can demand more than one.
    pub threshold: u32,
    /// ClamAV file-type target this slot's signature belongs to:
    ///   `0` = generic (any file type).
    /// Set during database build from the owning signature's target field.
    /// At scan time, only slots whose `file_type_target` matches (or is 0)
    /// are incremented, preventing unrelated signatures from contributing to
    /// a file type's hit counters (reduces both scan time and false-positive
    /// candidate noise).
    pub file_type_target: u32,
}

/// One length-bucket's Bf16 membership filter for the hot rolling-hash sweep.
/// The hot loop calls only `bf.has(&key)` — no slot resolution, no HashMap.
/// After the sweep, matched hashes are resolved against `AtomFilterDb::hash_slots`
/// outside the hot loop.
#[derive(Debug)]
pub struct AtomBucket {
    pub bf: Bf16,
}

/// How an extended signature's match state is determined at scan time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtSlot {
    /// Every pattern had a usable atom; they share one slot (extended sigs
    /// match on ANY pattern, so one "any hit" counter suffices).
    Atom(SlotId),
    /// At least one pattern had no usable atom (e.g. fully wildcarded) — with
    /// no exact fallback, treated as unconditionally matched.
    AutoMatch,
}

/// How one logical signature's subsignature contributes to `LogicalExpr::eval`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubsigSlot {
    /// Feeds a Bf16-backed slot counter; counts as matched once the slot's
    /// threshold is reached.
    Atom(SlotId),
    /// A `Body` subsignature with no usable atom in any variant — with no
    /// exact fallback, treated as unconditionally matched.
    AutoMatch,
    /// Non-`Body` subsig (`Pcre`/`ByteCompare`/`Fuzzy`/`Unsupported`) — never
    /// touched by the atom filter; left for the scanner's exact-evaluation
    /// carve-out.
    External,
}

/// The full atom-filter database: one [`AtomBucket`] per canonical atom
/// length in [`ATOM_LENGTHS`], the slot metadata every bucket's [`SlotId`]s
/// index into, and the per-signature slot assignments used to assemble
/// `LogicalExpr::eval`'s `counts` array (or an extended signature's single
/// match bit) from resolved atom hits.
#[derive(Debug)]
pub struct AtomFilterDb {
    /// Indexed identically to `ATOM_LENGTHS` (`buckets[i]` is for length
    /// `ATOM_LENGTHS[i]`) — `None` when that bucket has no atoms at all.
    /// Keyed on the atom's bytes as they appear in the signature.
    pub buckets: [Option<AtomBucket>; ATOM_LENGTHS.len()],
    /// Same shape as `buckets`, for `nocase` atoms — keyed on the
    /// case-folded (lowercased) atom bytes, and probed at scan time against a
    /// lowercased copy of the scanned window (mirrors `prefilter.rs`'s
    /// `ac`/`ac_nocase` split: a case-sensitive and a case-insensitive atom
    /// index are always kept separate, never merged into one).
    pub buckets_nocase: [Option<AtomBucket>; ATOM_LENGTHS.len()],
    /// Post-sweep resolution table: rolling hash → slot ID list.
    /// Populated during build from every registered (hash, slot_id) pair.
    /// The hot sweep loop never touches this — it only checks `bf.has(&hash)`.
    /// After the sweep, each matched hash is resolved here to determine which
    /// slots to increment.
    pub hash_slots: std::collections::HashMap<u64, Box<[SlotId]>>,
    pub slots: Vec<SlotDef>,
    /// Indexed by extended signature index.
    pub ext_slot: Vec<ExtSlot>,
    /// Indexed by logical signature index, then by subsignature index.
    pub log_subsig_slots: Vec<Box<[SubsigSlot]>>,
}

impl AtomFilterDb {
    pub fn empty() -> Self {
        AtomFilterDb {
            buckets: Default::default(),
            buckets_nocase: Default::default(),
            hash_slots: std::collections::HashMap::new(),
            slots: Vec::new(),
            ext_slot: Vec::new(),
            log_subsig_slots: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use jdb_xorf::{Bf16, Filter};

    use super::*;
    use crate::atomfilter_hash::hash_window;

    #[test]
    fn bf16_membership_works() {
        let atoms: &[&[u8]] = &[b"HydraDragon", b"malware.exe", b"evil_payload"];
        let keys: Vec<u64> = atoms.iter().map(|a| hash_window(a)).collect();
        let bf = Bf16::from(&keys);
        let bucket = AtomBucket { bf };

        for atom in atoms {
            let key = hash_window(atom);
            assert!(bucket.bf.has(&key), "real atom key must pass bf16");
        }

        let absent_key = hash_window(b"totally_unrelated");
        // Bf16 may false-positive; we can't assert !has() but we can at
        // least verify the call doesn't panic.
        let _ = bucket.bf.has(&absent_key);
    }
}
