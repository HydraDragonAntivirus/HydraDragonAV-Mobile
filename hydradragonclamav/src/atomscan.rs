//! Scan-time path for the Binary-Fuse16 atom/counter/threshold scheme — the
//! replacement for `prefilter.rs`'s daachorse-based candidate search.
//!
//! One sliding-window sweep per canonical atom length (`ATOM_LENGTHS`, both
//! case-sensitive and case-folded) resolves every window's rolling hash
//! against its bucket's Bf16 filter + exact key map, incrementing the hit
//! counter of every [`SlotId`] the window's atom belongs to. That is the
//! *entire* scan: unlike `AtomPrefilter`, there is no follow-up byte-level
//! verification step for `Body` subsignatures/patterns — a slot's counter
//! reaching its threshold *is* the match, promoted straight into
//! `LogicalExpr::eval`'s `counts` array (Avast-style; see `atomfilter.rs`).
//!
//! `Pcre`/`ByteCompare`/`Fuzzy` subsignatures have no atom representation at
//! all (`SubsigSlot::External`) and are unaffected by this tradeoff — the
//! caller (scanner.rs) still evaluates them exactly, exactly as it does
//! today, using this module's derived counts only to decide which body
//! subsigs are "present" for their triggers.

use crate::atomfilter::{AtomFilterDb, ExtSlot, SlotDef, SlotId, SubsigSlot};
use crate::atomfilter_hash::{roll_windows, ATOM_LENGTHS};

/// Per-slot hit counts (and last-seen window offset) for one buffer, indexed
/// by [`SlotId`]. The offset is captured incidentally while sweeping for
/// counts — not a separate verification pass — so `ByteCompare` subsigs (which
/// anchor on their trigger's match position, mirroring `scanner.rs`'s
/// `last_offsets`) have something to read from despite no pattern ever being
/// byte-verified.
pub struct SlotCounts {
    counts: Vec<u32>,
    last_offset: Vec<u32>,
}

impl SlotCounts {
    pub fn get(&self, slot: SlotId) -> u32 {
        self.counts[slot as usize]
    }

    /// Buffer offset of this slot's most recent (highest-offset) resolved
    /// window, if it was ever hit.
    pub fn last_offset(&self, slot: SlotId) -> Option<usize> {
        let o = self.last_offset[slot as usize];
        (o != u32::MAX).then_some(o as usize)
    }
}

pub struct AtomFilterScanner<'a> {
    db: &'a AtomFilterDb,
}

impl<'a> AtomFilterScanner<'a> {
    pub fn new(db: &'a AtomFilterDb) -> Self {
        AtomFilterScanner { db }
    }

    /// Sweep `data` once per bucket length (case-sensitive, then — only if
    /// any nocase atom exists — case-folded) and return the resulting
    /// per-slot hit counts.
    pub fn scan(&self, data: &[u8]) -> SlotCounts {
        let mut counts = SlotCounts {
            counts: vec![0u32; self.db.slots.len()],
            last_offset: vec![u32::MAX; self.db.slots.len()],
        };
        sweep_buckets(&self.db.buckets, data, &mut counts);

        // Mirrors `AtomPrefilter::candidates`'s nocase guard: nocase atoms
        // were case-folded at build time, so they only ever match a
        // lowercased copy of the buffer. Skip the O(n) allocation entirely
        // when there are no nocase atoms to match against.
        if self.db.buckets_nocase.iter().any(Option::is_some) {
            let lowered: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
            sweep_buckets(&self.db.buckets_nocase, &lowered, &mut counts);
        }

        counts
    }
}

fn sweep_buckets(
    buckets: &[Option<crate::atomfilter::AtomBucket>; ATOM_LENGTHS.len()],
    data: &[u8],
    counts: &mut SlotCounts,
) {
    for (i, bucket) in buckets.iter().enumerate() {
        let Some(bucket) = bucket else { continue };
        let len = ATOM_LENGTHS[i];
        roll_windows(data, len, |start, hash| {
            if let Some(slots) = bucket.resolve(hash) {
                for &s in slots {
                    let si = s as usize;
                    counts.counts[si] = counts.counts[si].saturating_add(1);
                    counts.last_offset[si] = start as u32;
                }
            }
        });
    }
}

/// Whether an extended signature's slot reached its threshold (or is an
/// unconditional `AutoMatch`, for signatures with no atom-indexable pattern).
pub fn ext_matched(ext_slot: ExtSlot, slots: &[SlotDef], counts: &SlotCounts) -> bool {
    match ext_slot {
        ExtSlot::AutoMatch => true,
        ExtSlot::Atom(id) => counts.get(id) >= slots[id as usize].threshold,
    }
}

/// The initial `counts` array to feed `LogicalExpr::eval` for one logical
/// signature's subsignatures: a `Body` subsig's slot counter (0 if under
/// threshold), `1` for an unconditional `AutoMatch` subsig, and `0` for an
/// `External` subsig (`Pcre`/`ByteCompare`/`Fuzzy`/`Unsupported`) — the
/// caller fills those in with an exact evaluation before the final
/// `expression.eval`, exactly as `scanner.rs`'s existing phase-2 does today.
pub fn logical_initial_counts(sub_slots: &[SubsigSlot], slots: &[SlotDef], counts: &SlotCounts) -> Vec<usize> {
    sub_slots
        .iter()
        .map(|s| match *s {
            SubsigSlot::Atom(id) => {
                let hits = counts.get(id);
                if hits >= slots[id as usize].threshold {
                    hits as usize
                } else {
                    0
                }
            }
            SubsigSlot::AutoMatch => 1,
            SubsigSlot::External => 0,
        })
        .collect()
}

/// Buffer offset to anchor a `ByteCompare` subsig's read at, given its
/// trigger subsig's slot assignment — mirrors `scanner.rs`'s `last_offsets`
/// (missing offset coerced to 0, matching ClamAV's `CLI_OFF_NONE` handling).
pub fn subsig_anchor_offset(trigger: SubsigSlot, counts: &SlotCounts) -> usize {
    match trigger {
        SubsigSlot::Atom(id) => counts.last_offset(id).unwrap_or(0),
        SubsigSlot::AutoMatch | SubsigSlot::External => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atomfilter_build::AtomFilterBuilder;
    use crate::database::Database;

    fn load_str(name: &str, contents: &str) -> Database {
        let mut files = std::collections::HashMap::new();
        files.insert(name.to_string(), contents.as_bytes().to_vec());
        Database::from_bytes_map(&files).0
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn extended_signature_promotes_on_atom_presence() {
        let hex = hex_of(b"HydraDragonTestAtom");
        let db = load_str("test.ndb", &format!("Test.Ndb.Sig:0:*:{hex}\n"));
        let afdb = AtomFilterBuilder::build(&db);
        let scanner = AtomFilterScanner::new(&afdb);

        let present = scanner.scan(b"junk...HydraDragonTestAtom...junk");
        assert!(ext_matched(afdb.ext_slot[0], &afdb.slots, &present));

        let absent = scanner.scan(b"nothing interesting here at all");
        assert!(!ext_matched(afdb.ext_slot[0], &afdb.slots, &absent));
    }

    #[test]
    fn logical_and_expression_needs_both_subsigs() {
        let hex_a = hex_of(b"AtomAlphaLiteral");
        let hex_b = hex_of(b"AtomBravoLiteral");
        let db = load_str(
            "test.ldb",
            &format!("Test.Ldb.Sig;Target:0;0&1;{hex_a};{hex_b}\n"),
        );
        let afdb = AtomFilterBuilder::build(&db);
        let scanner = AtomFilterScanner::new(&afdb);
        let sub_slots = &afdb.log_subsig_slots[0];
        let expr = &db.logical[0].expression;

        let both = scanner.scan(b"...AtomAlphaLiteral...AtomBravoLiteral...");
        let counts = logical_initial_counts(sub_slots, &afdb.slots, &both);
        assert!(expr.eval(&counts).matched);

        let only_a = scanner.scan(b"...AtomAlphaLiteral only...");
        let counts = logical_initial_counts(sub_slots, &afdb.slots, &only_a);
        assert!(!expr.eval(&counts).matched);

        let neither = scanner.scan(b"...nothing relevant...");
        let counts = logical_initial_counts(sub_slots, &afdb.slots, &neither);
        assert!(!expr.eval(&counts).matched);
    }

    #[test]
    fn nocase_atom_matches_regardless_of_case() {
        // `required_atom_nocase` only kicks in for patterns whose bytes are
        // marked nocase in the signature; a plain hex body signature is
        // always case-sensitive. This test simply documents that a
        // case-sensitive atom does NOT match a differently-cased buffer,
        // guarding against accidentally routing exact atoms through the
        // nocase bucket.
        let hex = hex_of(b"CaseSensitiveAtom");
        let db = load_str("test.ndb", &format!("Test.Ndb.Sig:0:*:{hex}\n"));
        let afdb = AtomFilterBuilder::build(&db);
        let scanner = AtomFilterScanner::new(&afdb);

        let wrong_case = scanner.scan(b"...casesensitiveatom...");
        assert!(!ext_matched(afdb.ext_slot[0], &afdb.slots, &wrong_case));
    }
}
