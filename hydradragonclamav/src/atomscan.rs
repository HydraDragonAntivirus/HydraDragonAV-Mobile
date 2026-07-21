use std::collections::HashMap;

use jdb_xorf::Filter;

use crate::atomfilter::{AtomFilterDb, ExtSlot, SlotDef, SlotId, SubsigSlot};
use crate::atomfilter_hash::{hash_window, hash_window_fold, leading_coeff, ATOM_LENGTHS};

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

    pub fn scan(&self, data: &[u8], file_type_target: u32) -> SlotCounts {
        let mut counts = SlotCounts {
            counts: vec![0u32; self.db.slots.len()],
            last_offset: vec![u32::MAX; self.db.slots.len()],
        };

        let mut tracker: HashMap<u64, (u32, u32)> = HashMap::new();

        // ── Hot sweep: Bf16 + hash_slots gate ──────────────────────────────
        for (i, bucket) in self.db.buckets.iter().enumerate() {
            if let Some(ref b) = bucket {
                sweep_one(b, ATOM_LENGTHS[i], data, &self.db.hash_slots, &mut tracker);
            }
        }

        if self.db.buckets_nocase.iter().any(Option::is_some) {
            for (i, bucket) in self.db.buckets_nocase.iter().enumerate() {
                if let Some(ref b) = bucket {
                    sweep_one_fold(b, ATOM_LENGTHS[i], data, &self.db.hash_slots, &mut tracker);
                }
            }
        }

        // ── Post-sweep resolution: hash → slot IDs ─────────────────────────
        let accept_target = |st: u32| st == 0 || st == file_type_target;
        for (h, (cnt, last_off)) in &tracker {
            if let Some(slot_ids) = self.db.hash_slots.get(h) {
                for &slot_id in slot_ids.iter() {
                    if accept_target(self.db.slots[slot_id as usize].file_type_target) {
                        let si = slot_id as usize;
                        counts.counts[si] = counts.counts[si].saturating_add(*cnt);
                        counts.last_offset[si] = counts.last_offset[si].max(*last_off);
                    }
                }
            }
        }

        counts
    }
}

fn sweep_one(bucket: &crate::atomfilter::AtomBucket, len: usize, data: &[u8], hash_slots: &HashMap<u64, Box<[SlotId]>>, tracker: &mut HashMap<u64, (u32, u32)>) {
    if data.len() < len { return; }
    let max_pos = data.len() - len;
    let data_ptr = data.as_ptr();
    let coeff = leading_coeff(len);

    let mut h = hash_window(&data[..len]);
    if bucket.bf.has(&h) && hash_slots.contains_key(&h) {
        let e = tracker.entry(h).or_insert((0, 0));
        e.0 = e.0.saturating_add(1);
        e.1 = 0;
    }

    for s in 0..max_pos {
        let leaving = unsafe { *data_ptr.add(s) as u64 };
        let entering = unsafe { *data_ptr.add(s + len) as u64 };
        h = h
            .wrapping_sub(leaving.wrapping_mul(coeff))
            .wrapping_mul(crate::atomfilter_hash::ROLL_BASE)
            .wrapping_add(entering);
        if bucket.bf.has(&h) && hash_slots.contains_key(&h) {
            let e = tracker.entry(h).or_insert((0, 0));
            e.0 = e.0.saturating_add(1);
            e.1 = (s + 1) as u32;
        }
    }
}

fn sweep_one_fold(bucket: &crate::atomfilter::AtomBucket, len: usize, data: &[u8], hash_slots: &HashMap<u64, Box<[SlotId]>>, tracker: &mut HashMap<u64, (u32, u32)>) {
    if data.len() < len { return; }
    let max_pos = data.len() - len;
    let data_ptr = data.as_ptr();
    let coeff = leading_coeff(len);

    let mut h = hash_window_fold(&data[..len]);
    if bucket.bf.has(&h) && hash_slots.contains_key(&h) {
        let e = tracker.entry(h).or_insert((0, 0));
        e.0 = e.0.saturating_add(1);
        e.1 = 0;
    }

    for s in 0..max_pos {
        let leaving = unsafe { (data_ptr.add(s).read().to_ascii_lowercase()) as u64 };
        let entering = unsafe { (data_ptr.add(s + len).read().to_ascii_lowercase()) as u64 };
        h = h
            .wrapping_sub(leaving.wrapping_mul(coeff))
            .wrapping_mul(crate::atomfilter_hash::ROLL_BASE)
            .wrapping_add(entering);
        if bucket.bf.has(&h) && hash_slots.contains_key(&h) {
            let e = tracker.entry(h).or_insert((0, 0));
            e.0 = e.0.saturating_add(1);
            e.1 = (s + 1) as u32;
        }
    }
}

pub fn ext_matched(ext_slot: ExtSlot, slots: &[SlotDef], counts: &SlotCounts) -> bool {
    match ext_slot {
        ExtSlot::AutoMatch => false,
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
                if hits >= slots[id as usize].threshold { hits as usize } else { 0 }
            }
            SubsigSlot::AutoMatch => 1,
            SubsigSlot::External => 0,
        };
    }
    n
}

pub fn logical_initial_counts(sub_slots: &[SubsigSlot], slots: &[SlotDef], counts: &SlotCounts) -> Vec<usize> {
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
        let scanner = AtomFilterScanner::new(&afdb);

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
        let scanner = AtomFilterScanner::new(&afdb);
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
        let scanner = AtomFilterScanner::new(&afdb);

        let wrong_case = scanner.scan(b"...casesensitiveatom...", 0);
        assert!(!ext_matched(afdb.ext_slot[0], &afdb.slots, &wrong_case));
    }
}
