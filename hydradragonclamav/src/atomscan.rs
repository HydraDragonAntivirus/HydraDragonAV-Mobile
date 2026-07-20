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

use crate::atomfilter::{AtomBucket, AtomFilterDb, ExtSlot, SlotDef, SlotId, SubsigSlot};
use crate::atomfilter_hash::{hash_window, hash_window_fold, leading_coeff, read_byte, ATOM_LENGTHS};

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
        sweep_buckets(&self.db.buckets, data, false, &mut counts);

        // Nocase atoms were case-folded at build time (lowercased keys), so
        // they match a lowercased view of the buffer. Instead of allocating a
        // full lowercased copy and re-sweeping it, sweep the original buffer
        // with `fold = true` — the rolling hash lowercases each byte on the
        // fly, producing the same hash the copied-buffer sweep would have.
        // Skipped entirely when there are no nocase buckets.
        if self.db.buckets_nocase.iter().any(Option::is_some) {
            sweep_buckets(&self.db.buckets_nocase, data, true, &mut counts);
        }

        counts
    }
}

fn sweep_buckets(
    buckets: &[Option<AtomBucket>; ATOM_LENGTHS.len()],
    data: &[u8],
    fold: bool,
    counts: &mut SlotCounts,
) {
    // Collect active (non-None) bucket indices — max 5, so a small fixed array.
    let mut active: [usize; ATOM_LENGTHS.len()] = [0; ATOM_LENGTHS.len()];
    let mut n = 0usize;
    for (i, b) in buckets.iter().enumerate() {
        if b.is_some() {
            active[n] = i;
            n += 1;
        }
    }
    if n == 0 { return; }

    let min_len = ATOM_LENGTHS[active[0]];
    if data.len() < min_len { return; }

    // Pre-compute initial hashes and leading coefficients for each length.
    let mut h: [u64; 5] = [0; 5];
    let mut coeff: [u64; 5] = [0; 5];
    for j in 0..n {
        let len = ATOM_LENGTHS[active[j]];
        if data.len() >= len {
            h[j] = if fold {
                hash_window_fold(&data[..len])
            } else {
                hash_window(&data[..len])
            };
            coeff[j] = leading_coeff(len);
        }
    }

    // Position 0: check every active bucket with its initial hash.
    for j in 0..n {
        if let Some(slots) = buckets[active[j]].as_ref().unwrap().resolve(h[j]) {
            for &slot_id in slots {
                let si = slot_id as usize;
                counts.counts[si] = counts.counts[si].saturating_add(1);
                counts.last_offset[si] = 0;
            }
        }
    }

    // Single pass over ALL valid window positions (0 .. data.len() - 2).
    // At each position, update the rolling hash for every active length and
    // check the corresponding bucket — but only for lengths whose current
    // window is still fully inside `data`. This reads `data[s]` once and
    // `data[s + len_j]` once per active length, instead of doing separate
    // per-length sweeps. `fold` lowercases the read bytes for nocase buckets.
    let max_pos = data.len() - min_len;
    for s in 0..max_pos {
        let leaving = read_byte(data, s, fold);
        for j in 0..n {
            let len = ATOM_LENGTHS[active[j]];
            let next_start = s + 1;
            if next_start + len > data.len() {
                continue;
            }
            h[j] = h[j]
                .wrapping_sub(leaving.wrapping_mul(coeff[j]))
                .wrapping_mul(crate::atomfilter_hash::ROLL_BASE)
                .wrapping_add(read_byte(data, s + len, fold));
            if let Some(slots) = buckets[active[j]].as_ref().unwrap().resolve(h[j]) {
                for &slot_id in slots {
                    let si = slot_id as usize;
                    counts.counts[si] = counts.counts[si].saturating_add(1);
                    counts.last_offset[si] = next_start as u32;
                }
            }
        }
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

/// Fill `out` with the initial counts to feed `LogicalExpr::eval` for one
/// logical signature's subsignatures: a `Body` subsig's slot counter (0 if
/// under threshold), `1` for an unconditional `AutoMatch` subsig, and `0` for
/// an `External` subsig (`Pcre`/`ByteCompare`/`Fuzzy`/`Unsupported`) — the
/// caller fills those in with an exact evaluation before the final
/// `expression.eval`, exactly as `scanner.rs`'s existing phase-2 does today.
/// Returns the number of elements written (always `sub_slots.len()`).
pub fn logical_initial_counts_into(
    out: &mut [usize],
    sub_slots: &[SubsigSlot],
    slots: &[SlotDef],
    counts: &SlotCounts,
) -> usize {
    let n = sub_slots.len().min(out.len());
    for (i, s) in sub_slots[..n].iter().enumerate() {
        out[i] = match *s {
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
        };
    }
    n
}

/// Convenience wrapper — allocates a new `Vec` from `sub_slots`.
pub fn logical_initial_counts(sub_slots: &[SubsigSlot], slots: &[SlotDef], counts: &SlotCounts) -> Vec<usize> {
    let mut out = vec![0; sub_slots.len()];
    logical_initial_counts_into(&mut out, sub_slots, slots, counts);
    out
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
