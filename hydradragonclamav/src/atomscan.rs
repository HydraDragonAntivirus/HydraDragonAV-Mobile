//! Daachorse-based atom prefilter scanner.
//!
//! Replaces the per-length Bf16 rolling-hash sweeps with a single Aho-Corasick
//! pass per automaton (exact + nocase). One daachorse `find_overlapping_iter`
//! pass matches every atom simultaneously, avoiding the 5× multiplier from
//! the per-bucket-length rolling-hash sweeps.

use crate::atomfilter::{AtomFilterDb, SlotId, SubsigSlot};
use crate::atomfilter::{ExtSlot, SlotDef};

/// Per-slot hit counts (and last-seen match start offset) for one buffer.
/// Borrows from the scanner's pre-allocated vectors to avoid per-call allocation.
pub struct SlotCounts<'a> {
    counts: &'a [u32],
    last_offset: &'a [u32],
}

impl SlotCounts<'_> {
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
    value_remaining: Vec<u32>,
    saturated: Vec<u64>,
    /// Pre-allocated per-slot count vector (reused across scan() calls).
    /// Kept alive in the struct; scan() returns a borrowing SlotCounts.
    counts: Vec<u32>,
    /// Pre-allocated per-slot last-offset vector.
    last_offset: Vec<u32>,
}

#[derive(Default)]
struct AutomatonStats {
    daachorse_us: u64,
    daachorse_matches: u64,
    inner_iterations: u64,
    saturated_skip: u64,
    ft_skip: u64,
    saturated_count: u64,
    saturated_dec: u64,
    incremented: u64,
    inner_loop_us: u64,
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
            counts: vec![0u32; n_slots],
            last_offset: vec![u32::MAX; n_slots],
        }
    }

    /// ClamAV-style one-lookup-per-byte match over a dense transition table.
    /// `dense[state * 256 + byte]` = next state (failure links pre-resolved).
    #[allow(clippy::too_many_arguments)]
    fn run_dense_automaton(
        pma: &daachorse::DoubleArrayAhoCorasick<u32>,
        dense: &[u32],
        atom_to_slots: &[Box<[SlotId]>],
        _pattern_lens: &[usize],
        slots: &[SlotDef],
        slot_to_values: &[Box<[u32]>],
        saturated: &mut [u64],
        value_remaining: &mut [u32],
        hay: &[u8],
        file_type_target: u32,
        counts: &mut [u32],
        last_offset: &mut [u32],
        _name: &str,
        out_stats: &mut AutomatonStats,
    ) {
        let t0 = std::time::Instant::now();
        let mut inner_us: u64 = 0;

        let mut state: u32 = 0;
        for (pos, &byte) in hay.iter().enumerate() {
            state = unsafe {
                *dense.get_unchecked(state as usize * 256 + byte as usize)
            };

            // Walk output chain (overlapping patterns ending at same position).
            let mut opt = pma.state_output_pos(state);
            while let Some(op) = opt {
                let (len, value) = pma.output_at(op);
                out_stats.daachorse_matches += 1;
                let end = pos + 1;
                let vi = value as usize;
                if vi < atom_to_slots.len() && value_remaining[vi] != 0 {
                    let start = end - len as usize;
                    let t_inner = std::time::Instant::now();
                    for &slot_id in atom_to_slots[vi].iter() {
                        out_stats.inner_iterations += 1;
                        let st = slot_id as usize;
                        if (saturated[st >> 6] >> (st & 63)) & 1 == 1 {
                            out_stats.saturated_skip += 1;
                            continue;
                        }
                        let ft = slots[st].file_type_target;
                        if ft != 0 && ft != file_type_target {
                            out_stats.ft_skip += 1;
                            continue;
                        }
                        if counts[st] >= slots[st].threshold {
                            saturated[st >> 6] |= 1 << (st & 63);
                            out_stats.saturated_count += 1;
                            for &ref_vi in slot_to_values[st].iter() {
                                out_stats.saturated_dec += 1;
                                let rvi = ref_vi as usize;
                                if rvi < value_remaining.len() {
                                    value_remaining[rvi] = value_remaining[rvi].saturating_sub(1);
                                }
                            }
                            continue;
                        }
                        counts[st] = counts[st].saturating_add(1);
                        last_offset[st] = last_offset[st].max(start as u32);
                        out_stats.incremented += 1;
                    }
                    inner_us += t_inner.elapsed().as_micros() as u64;
                }
                opt = pma.output_parent(op);
            }
        }

        out_stats.daachorse_us = t0.elapsed().as_micros() as u64;
        out_stats.inner_loop_us = inner_us;
    }

    pub fn scan(&mut self, data: &[u8], file_type_target: u32) -> SlotCounts<'_> {
        let n_slots = self.db.slots.len();

        // Ensure pre-allocated vectors are the right size.
        if self.counts.len() != n_slots {
            self.counts.resize(n_slots, 0);
            self.last_offset.resize(n_slots, u32::MAX);
        }

        // Reset per-scanner state.
        for c in self.counts.iter_mut() {
            *c = 0;
        }
        for o in self.last_offset.iter_mut() {
            *o = u32::MAX;
        }
        for w in &mut self.saturated {
            *w = 0;
        }
        for (vi, slots) in self.db.atom_to_slots.iter().enumerate() {
            self.value_remaining[vi] = slots.len() as u32;
        }

        // ── Shift-OR prefilter ────────────────────────────────────────────
        // If the prefilter says no pattern can match, skip both dense passes.
        let Some(start) = self.db.prefilter.search(data) else {
            return SlotCounts { counts: &self.counts, last_offset: &self.last_offset };
        };
        if start >= data.len() {
            return SlotCounts { counts: &self.counts, last_offset: &self.last_offset };
        }
        let window = &data[start..];

        let mut exact_stats = AutomatonStats::default();
        let mut nocase_stats = AutomatonStats::default();

        // ── Exact automaton pass ──────────────────────────────────────────
        if let (Some(ref pma), Some(ref dense)) = (self.db.exact.as_ref(), Some(&self.db.exact_dense[..])) {
            Self::run_dense_automaton(
                pma,
                dense,
                &self.db.atom_to_slots,
                &self.db.pattern_lens,
                &self.db.slots,
                &self.db.slot_to_values,
                &mut self.saturated,
                &mut self.value_remaining,
                window,
                file_type_target,
                &mut self.counts,
                &mut self.last_offset,
                "exact",
                &mut exact_stats,
            );
        }

        // ── Nocase automaton pass ─────────────────────────────────────────
        if let (Some(ref pma), Some(ref dense)) = (self.db.nocase.as_ref(), Some(&self.db.nocase_dense[..])) {
            // Separate lowered buffer to avoid &mut self conflict with saturated/value_remaining.
            let mut lowered = std::mem::take(&mut self.lowered_buf);
            if window.len() > lowered.len() {
                lowered.resize(window.len(), 0);
            }
            for (i, &b) in window.iter().enumerate() {
                lowered[i] = b.to_ascii_lowercase();
            }
            Self::run_dense_automaton(
                pma,
                dense,
                &self.db.atom_to_slots,
                &self.db.pattern_lens,
                &self.db.slots,
                &self.db.slot_to_values,
                &mut self.saturated,
                &mut self.value_remaining,
                &lowered[..window.len()],
                file_type_target,
                &mut self.counts,
                &mut self.last_offset,
                "nocase",
                &mut nocase_stats,
            );
            self.lowered_buf = lowered;
        }

        // Add `start` back to last_offsets since the automaton ran offset-relative.
        for o in self.last_offset.iter_mut() {
            if *o != u32::MAX {
                *o += start as u32;
            }
        }

        // Emit detailed timing when slow.
        let total_us = exact_stats.daachorse_us + nocase_stats.daachorse_us;
        if total_us > 200_000 {
            let exact_info = if self.db.exact.is_some() {
                format!(
                    "exact(daach={}us inner={}us matches={} iit={} sat_sk={} ft_sk={} dec={} inc={})",
                    exact_stats.daachorse_us,
                    exact_stats.inner_loop_us,
                    exact_stats.daachorse_matches,
                    exact_stats.inner_iterations,
                    exact_stats.saturated_skip,
                    exact_stats.ft_skip,
                    exact_stats.saturated_dec,
                    exact_stats.incremented,
                )
            } else {
                String::from("exact(none)")
            };
            let nocase_info = if self.db.nocase.is_some() {
                format!(
                    "nocase(daach={}us inner={}us matches={} iit={} sat_sk={} ft_sk={} dec={} inc={})",
                    nocase_stats.daachorse_us,
                    nocase_stats.inner_loop_us,
                    nocase_stats.daachorse_matches,
                    nocase_stats.inner_iterations,
                    nocase_stats.saturated_skip,
                    nocase_stats.ft_skip,
                    nocase_stats.saturated_dec,
                    nocase_stats.incremented,
                )
            } else {
                String::from("nocase(none)")
            };
            eprintln!("[ATOMSCAN] {}KB {} {}  prefilter_start={}",
                data.len() / 1024, exact_info, nocase_info, start);
        }

        SlotCounts { counts: &self.counts, last_offset: &self.last_offset }
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
