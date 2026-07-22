//! Daachorse-based atom prefilter scanner.
//!
//! Replaces the per-length Bf16 rolling-hash sweeps with a single Aho-Corasick
//! pass per automaton (exact + nocase). One daachorse `find_overlapping_iter`
//! pass matches every atom simultaneously, avoiding the 5× multiplier from
//! the per-bucket-length rolling-hash sweeps.

use crate::atomfilter::{AtomFilterDb, SlotId, SubsigSlot};
use crate::atomfilter::{ExtSlot, SlotDef};

/// Per-slot hit counts (and last-seen match start offset) for one buffer.
pub struct SlotCounts {
    counts: Vec<u32>,
    last_offset: Vec<u32>,
}

impl SlotCounts {
    pub fn get(&self, slot: SlotId) -> u32 {
        self.counts[slot as usize]
    }

    pub fn last_offset(&self, slot: SlotId) -> Option<usize> {
        let o = self.last_offset[slot as usize];
        (o != u32::MAX).then_some(o as usize)
    }
}

pub struct AtomFilterScanner<'a> {
    db: &'a AtomFilterDb,
    lowered_buf: Vec<u8>,
    /// Per-value count of remaining (not-yet-saturated) slots.
    value_remaining: Vec<u32>,
    /// Saturated slot bitset: one bit per slot, 1 = already at threshold.
    saturated: Vec<u64>,
}

impl<'a> AtomFilterScanner<'a> {
    pub fn new(db: &'a AtomFilterDb) -> Self {
        let n_slots = db.slots.len();
        let n_values = db.atom_to_slots.len();
        let mut value_remaining = Vec::with_capacity(n_values);
        for slots in db.atom_to_slots.iter() {
            value_remaining.push(slots.len() as u32);
        }
        AtomFilterScanner {
            db,
            lowered_buf: Vec::new(),
            value_remaining,
            saturated: vec![0u64; (n_slots + 63) / 64],
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_automaton(
        atom_to_slots: &[Box<[SlotId]>],
        pattern_lens: &[usize],
        slots: &[SlotDef],
        slot_to_values: &[Box<[u32]>],
        saturated: &mut [u64],
        value_remaining: &mut [u32],
        pma: &daachorse::DoubleArrayAhoCorasick<u32>,
        hay: &[u8],
        file_type_target: u32,
        counts: &mut [u32],
        last_offset: &mut [u32],
    ) {

        for m in pma.find_overlapping_iter(hay) {
            let end = m.end();
            let vi = m.value() as usize;
            if vi >= atom_to_slots.len() {
                continue;
            }
            if value_remaining[vi] == 0 {
                continue;
            }
            let start = end - pattern_lens[vi];
            for &slot_id in atom_to_slots[vi].iter() {
                let st = slot_id as usize;
                if (saturated[st >> 6] >> (st & 63)) & 1 == 1 {
                    continue;
                }
                let ft = slots[st].file_type_target;
                if ft != 0 && ft != file_type_target {
                    continue;
                }
                if counts[st] >= slots[st].threshold {
                    saturated[st >> 6] |= 1 << (st & 63);
                    for &ref_vi in slot_to_values[st].iter() {
                        let rvi = ref_vi as usize;
                        if rvi < value_remaining.len() {
                            value_remaining[rvi] = value_remaining[rvi].saturating_sub(1);
                        }
                    }
                    continue;
                }
                counts[st] = counts[st].saturating_add(1);
                last_offset[st] = last_offset[st].max(start as u32);
            }
        }
    }

    pub fn scan(&mut self, data: &[u8], file_type_target: u32) -> SlotCounts {
        let n_slots = self.db.slots.len();
        let mut counts = SlotCounts {
            counts: vec![0u32; n_slots],
            last_offset: vec![u32::MAX; n_slots],
        };

        // Reset per-scanner state.
        for w in &mut self.saturated {
            *w = 0;
        }
        for (vi, slots) in self.db.atom_to_slots.iter().enumerate() {
            self.value_remaining[vi] = slots.len() as u32;
        }

        // ── Exact automaton pass ──────────────────────────────────────────
        if let Some(ref pma) = self.db.exact {
            Self::run_automaton(
                &self.db.atom_to_slots,
                &self.db.pattern_lens,
                &self.db.slots,
                &self.db.slot_to_values,
                &mut self.saturated,
                &mut self.value_remaining,
                pma,
                data,
                file_type_target,
                &mut counts.counts,
                &mut counts.last_offset,
            );
        }

        // ── Nocase automaton pass ─────────────────────────────────────────
        if let Some(ref pma) = self.db.nocase {
            // Separate lowered buffer to avoid &mut self conflict with saturated/value_remaining.
            let mut lowered = std::mem::take(&mut self.lowered_buf);
            if data.len() > lowered.len() {
                lowered.resize(data.len(), 0);
            }
            for (i, &b) in data.iter().enumerate() {
                lowered[i] = b.to_ascii_lowercase();
            }
            Self::run_automaton(
                &self.db.atom_to_slots,
                &self.db.pattern_lens,
                &self.db.slots,
                &self.db.slot_to_values,
                &mut self.saturated,
                &mut self.value_remaining,
                pma,
                &lowered[..data.len()],
                file_type_target,
                &mut counts.counts,
                &mut counts.last_offset,
            );
            self.lowered_buf = lowered;
        }

        counts
    }
}

pub fn ext_matched(ext_slot: ExtSlot, slots: &[SlotDef], counts: &SlotCounts) -> bool {
    match ext_slot {
        ExtSlot::AutoMatch => true,
        ExtSlot::Atom(id) => counts.get(id) >= slots[id as usize].threshold,
    }
}

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

pub fn logical_initial_counts(
    sub_slots: &[SubsigSlot],
    slots: &[SlotDef],
    counts: &SlotCounts,
) -> Vec<usize> {
    let mut out = vec![0; sub_slots.len()];
    logical_initial_counts_into(&mut out, sub_slots, slots, counts);
    out
}

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
        let mut scanner = AtomFilterScanner::new(&afdb);

        let present = scanner.scan(b"junk...HydraDragonTestAtom...junk", 0);
        assert!(ext_matched(afdb.ext_slot[0], &afdb.slots, &present));

        let absent = scanner.scan(b"nothing interesting here at all", 0);
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
        let mut scanner = AtomFilterScanner::new(&afdb);
        let sub_slots = &afdb.log_subsig_slots[0];
        let expr = &db.logical[0].expression;

        let both = scanner.scan(b"...AtomAlphaLiteral...AtomBravoLiteral...", 0);
        let counts = logical_initial_counts(sub_slots, &afdb.slots, &both);
        assert!(expr.eval(&counts).matched);

        let only_a = scanner.scan(b"...AtomAlphaLiteral only...", 0);
        let counts = logical_initial_counts(sub_slots, &afdb.slots, &only_a);
        assert!(!expr.eval(&counts).matched);

        let neither = scanner.scan(b"...nothing relevant...", 0);
        let counts = logical_initial_counts(sub_slots, &afdb.slots, &neither);
        assert!(!expr.eval(&counts).matched);
    }

    #[test]
    fn nocase_atom_matches_regardless_of_case() {
        let hex = hex_of(b"CaseSensitiveAtom");
        let db = load_str("test.ndb", &format!("Test.Ndb.Sig:0:*:{hex}\n"));
        let afdb = AtomFilterBuilder::build(&db);
        let mut scanner = AtomFilterScanner::new(&afdb);

        // The signature is exact (no ::i), so wrong case must NOT match.
        let wrong_case = scanner.scan(b"...casesensitiveatom...", 0);
        assert!(!ext_matched(afdb.ext_slot[0], &afdb.slots, &wrong_case));
    }
}
