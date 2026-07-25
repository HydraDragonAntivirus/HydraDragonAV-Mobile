use crate::atomfilter::{AtomFilterDb, PerTarget, SlotId, SubsigSlot};
use crate::atomfilter::{ExtSlot, SlotDef};

/// Per-slot hit counts (and last-seen match start offset) for one buffer.
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
    counts: Vec<u32>,
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
        AtomFilterScanner {
            db,
            lowered_buf: Vec::new(),
            value_remaining: Vec::new(),
            saturated: vec![0u64; (n_slots + 63) / 64],
            counts: vec![0u32; n_slots],
            last_offset: vec![u32::MAX; n_slots],
        }
    }

    fn select_target<'b>(per_target: &'b [PerTarget], file_type_target: u32) -> &'b PerTarget {
        if file_type_target == 0 {
            return &per_target[0];
        }
        per_target.iter()
            .find(|pt| pt.target == file_type_target)
            .unwrap_or(&per_target[0])
    }

    #[allow(clippy::too_many_arguments)]
    fn run_dense_automaton(
        pt: &PerTarget,
        exact: bool,
        slots: &[SlotDef],
        saturated: &mut [u64],
        value_remaining: &mut [u32],
        hay: &[u8],
        file_type_target: u32,
        counts: &mut [u32],
        last_offset: &mut [u32],
        out_stats: &mut AutomatonStats,
    ) {
        let (pma, dense) = if exact {
            match pt.exact.as_ref() {
                Some(pma) => {
                    let dense = pt.exact_dense.get_or_init(|| pma.build_dense_table());
                    (pma, dense.as_slice())
                }
                None => return,
            }
        } else {
            match pt.nocase.as_ref() {
                Some(pma) => {
                    let dense = pt.nocase_dense.get_or_init(|| pma.build_dense_table());
                    (pma, dense.as_slice())
                }
                None => return,
            }
        };

        let atom_to_slots = &pt.atom_to_slots;
        let slot_to_values = &pt.slot_to_values;

        let t0 = std::time::Instant::now();
        let mut inner_us: u64 = 0;

        let mut state: u32 = 0;
        for (pos, &byte) in hay.iter().enumerate() {
            state = unsafe {
                *dense.get_unchecked(state as usize * 256 + byte as usize)
            };

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

        if self.counts.len() != n_slots {
            self.counts.resize(n_slots, 0);
            self.last_offset.resize(n_slots, u32::MAX);
        }
        for c in self.counts.iter_mut() { *c = 0; }
        for o in self.last_offset.iter_mut() { *o = u32::MAX; }
        for w in &mut self.saturated { *w = 0; }

        // Select target automaton — borrows only self.db, not other fields.
        let pt = Self::select_target(&self.db.per_target, file_type_target);

        self.value_remaining.clear();
        for slots in pt.atom_to_slots.iter() {
            self.value_remaining.push(slots.len() as u32);
        }

        let mut exact_stats = AutomatonStats::default();
        let mut nocase_stats = AutomatonStats::default();

        // ── Shift-OR prefilter (exact-only hint) ──────────────────────
        let (exact_window, exact_offset) = match self.db.prefilter.search(data) {
            Some(start) if start < data.len() => (&data[start..], start),
            _ => (&data[0..0], 0),
        };

        // ── Exact automaton pass ──────────────────────────────────────
        if !exact_window.is_empty() {
            Self::run_dense_automaton(
                pt, true,
                &self.db.slots,
                &mut self.saturated, &mut self.value_remaining,
                exact_window, file_type_target,
                &mut self.counts, &mut self.last_offset,
                &mut exact_stats,
            );
            if exact_offset > 0 {
                for o in self.last_offset.iter_mut() {
                    if *o != u32::MAX { *o += exact_offset as u32; }
                }
            }
        }

        // ── Nocase automaton pass ────────────────────────────────────
        if pt.nocase.is_some() {
            let mut lowered = std::mem::take(&mut self.lowered_buf);
            if data.len() > lowered.len() { lowered.resize(data.len(), 0); }
            for (i, &b) in data.iter().enumerate() { lowered[i] = b.to_ascii_lowercase(); }
            Self::run_dense_automaton(
                pt, false,
                &self.db.slots,
                &mut self.saturated, &mut self.value_remaining,
                &lowered[..data.len()], file_type_target,
                &mut self.counts, &mut self.last_offset,
                &mut nocase_stats,
            );
            self.lowered_buf = lowered;
        }

        // ── Timing output (pt is still alive from self.db borrow) ─────
        let total_us = exact_stats.daachorse_us + nocase_stats.daachorse_us;
        if total_us > 200_000 {
            let target_label = if pt.target == 0 {
                "full".to_string()
            } else {
                format!("tgt={}", pt.target)
            };
            let exact_info = if pt.exact.is_some() {
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
            let nocase_info = if pt.nocase.is_some() {
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
            eprintln!("[ATOMSCAN] {} {}KB {} {}  exact_window={}",
                target_label, data.len() / 1024, exact_info, nocase_info, exact_window.len());
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

        let wrong_case = scanner.scan(b"...casesensitiveatom...", 0);
        assert!(!ext_matched(afdb.ext_slot[0], &afdb.slots, &wrong_case));
    }
}
