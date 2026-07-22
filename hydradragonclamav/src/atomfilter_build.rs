//! Builds an [`AtomFilterDb`] from a loaded [`Database`] — a pair of
//! daachorse Aho-Corasick automata (exact + nocase) replace the old
//! per-length Bf16 filters and rolling-hash sweeps.

use daachorse::{DoubleArrayAhoCorasick, DoubleArrayAhoCorasickBuilder};

use crate::atomfilter::{
    AtomFilterDb, ExtSlot, SlotDef, SlotId, SubsigSlot,
};
use crate::database::Database;
use crate::logical::Subsignature;
use crate::pattern::Pattern;

/// Shortest literal usable as an atom.
/// 2-byte atoms occur too often in real-world buffers (e.g. every PE section
/// with padding bytes) and nearly always promote, wasting the prefilter.
/// Requiring ≥3 bytes keeps the automaton smaller and the candidate list thin.
const MIN_DEPTH: usize = 3;
/// Longest atom indexed per signature.
const MAX_ATOM: usize = 16;

#[inline]
fn usable(a: &[u8]) -> bool {
    a.len() >= MIN_DEPTH
}

#[inline]
fn short_atom(a: &[u8]) -> Vec<u8> {
    a[..a.len().min(MAX_ATOM)].to_vec()
}

/// Compute a per-atom promotion threshold.
///   3+ bytes  → threshold 1  (selective enough — ~5% match rate for 4-byte in 20 MB)
///   (2-byte atoms are excluded at MIN_DEPTH=3, so the repeated-byte rule is moot)
fn atom_threshold(a: &Atom) -> u32 {
    let _ = a;
    1
}

enum Atom {
    Exact(Vec<u8>),
    Nocase(Vec<u8>),
}

fn pattern_atom(p: &Pattern) -> Option<Atom> {
    if let Some(a) = p.required_atom() {
        if usable(&a) {
            return Some(Atom::Exact(short_atom(&a)));
        }
    }
    if let Some(a) = p.required_atom_nocase() {
        if usable(&a) {
            return Some(Atom::Nocase(short_atom(&a)));
        }
    }
    None
}

fn all_pattern_atoms(patterns: &[Pattern]) -> Option<Vec<Atom>> {
    if patterns.is_empty() {
        return None;
    }
    let mut atoms = Vec::with_capacity(patterns.len());
    for p in patterns {
        atoms.push(pattern_atom(p)?);
    }
    Some(atoms)
}

/// Collects unique (atom_bytes, slot_id) pairs for each atom type.
struct AtomReg {
    exact: Vec<(Vec<u8>, SlotId)>,
    nocase: Vec<(Vec<u8>, SlotId)>,
}

impl AtomReg {
    fn register(&mut self, atom: &Atom, slot: SlotId) {
        match atom {
            Atom::Exact(b) => self.exact.push((b.clone(), slot)),
            Atom::Nocase(b) => self.nocase.push((b.clone(), slot)),
        }
    }
}

/// Build a daachorse automaton + value→slot mapping from a list of
/// (pattern_bytes, slot_id) pairs. `value_offset` is added to each
/// daachorse value so that the automaton's values index into the *combined*
/// `AtomFilterDb::atom_to_slots` array at the correct position.
fn build_automaton(
    entries: Vec<(Vec<u8>, SlotId)>,
    value_offset: u32,
) -> (Option<DoubleArrayAhoCorasick<u32>>, Vec<Box<[SlotId]>>, Vec<usize>) {
    if entries.is_empty() {
        return (None, Vec::new(), Vec::new());
    }

    // Deduplicate by pattern bytes — same bytes → same value index.
    let mut pattern_to_slots: std::collections::HashMap<Vec<u8>, Vec<SlotId>> =
        std::collections::HashMap::new();
    for (bytes, slot) in entries {
        pattern_to_slots.entry(bytes).or_default().push(slot);
    }

    // Build patterns array and values array for daachorse.
    let mut patterns: Vec<Vec<u8>> = Vec::with_capacity(pattern_to_slots.len());
    let mut values: Vec<u32> = Vec::with_capacity(pattern_to_slots.len());
    let mut atom_to_slots: Vec<Box<[SlotId]>> = Vec::with_capacity(pattern_to_slots.len());
    let mut pattern_lens: Vec<usize> = Vec::with_capacity(pattern_to_slots.len());

    for (i, (bytes, slots)) in pattern_to_slots.into_iter().enumerate() {
        let value = value_offset + i as u32;
        patterns.push(bytes.clone());
        values.push(value);
        atom_to_slots.push(slots.into_boxed_slice());
        pattern_lens.push(bytes.len());
    }

    // Build the automaton.
    let pma = DoubleArrayAhoCorasickBuilder::new()
        .build_with_values(
            patterns.iter().map(|p| p.as_slice()).zip(values.iter().copied()),
        )
        .expect("daachorse automaton build should succeed");

    (Some(pma), atom_to_slots, pattern_lens)
}

pub struct AtomFilterBuilder;

impl AtomFilterBuilder {
    pub fn build(db: &Database) -> AtomFilterDb {
        let mut reg = AtomReg {
            exact: Vec::new(),
            nocase: Vec::new(),
        };
        let mut slots: Vec<SlotDef> = Vec::new();
        let mut ext_slot: Vec<ExtSlot> = Vec::with_capacity(db.extended.len());
        let mut log_subsig_slots: Vec<Box<[SubsigSlot]>> = Vec::with_capacity(db.logical.len());

        // --- Extended signatures ---
        for (si, sig) in db.extended.iter().enumerate() {
            match all_pattern_atoms(&sig.patterns) {
                Some(atoms) => {
                    let slot_id = slots.len() as SlotId;
                    let threshold = atoms.iter().map(atom_threshold).max().unwrap_or(1);
                    slots.push(SlotDef {
                        target: crate::atomfilter::SlotTarget::Extended { sig_index: si as u32 },
                        threshold,
                        file_type_target: sig.target.unwrap_or(0),
                    });
                    for a in &atoms {
                        reg.register(a, slot_id);
                    }
                    ext_slot.push(ExtSlot::Atom(slot_id));
                }
                None => ext_slot.push(ExtSlot::AutoMatch),
            }
        }

        // --- Logical signatures ---
        for sig in db.logical.iter() {
            let mut sub_slots: Vec<SubsigSlot> = Vec::with_capacity(sig.subsignatures.len());
            for subsig in sig.subsignatures.iter() {
                let Subsignature::Body { patterns, .. } = subsig else {
                    sub_slots.push(SubsigSlot::External);
                    continue;
                };
                match all_pattern_atoms(patterns) {
                    Some(atoms) => {
                        let slot_id = slots.len() as SlotId;
                        let sig_index = log_subsig_slots.len() as u32;
                        let subsig_index = sub_slots.len() as u32;
                        let threshold = atoms.iter().map(atom_threshold).max().unwrap_or(1);
                        slots.push(SlotDef {
                            target: crate::atomfilter::SlotTarget::LogicalSubsig {
                                sig_index,
                                subsig_index,
                            },
                            threshold,
                            file_type_target: sig.target.unwrap_or(0),
                        });
                        for a in &atoms {
                            reg.register(a, slot_id);
                        }
                        sub_slots.push(SubsigSlot::Atom(slot_id));
                    }
                    None => {
                        sub_slots.push(SubsigSlot::AutoMatch);
                    }
                }
            }
            log_subsig_slots.push(sub_slots.into_boxed_slice());
        }

        // Build exact automaton (values start at 0).
        let (exact, exact_atom_to_slots, exact_lens) = build_automaton(reg.exact, 0);

        // Build nocase automaton (values start after exact entries so they
        // index into the combined atom_to_slots/pattern_lens arrays below).
        let nocase_offset = exact_atom_to_slots.len() as u32;
        let (nocase, nocase_atom_to_slots, nocase_lens) = build_automaton(reg.nocase, nocase_offset);

        // Merge value→slot arrays into a single atom_to_slots table.
        // Exact values index into the first block, nocase values into the second.
        let mut atom_to_slots = Vec::new();
        let mut pattern_lens = Vec::new();
        atom_to_slots.extend(exact_atom_to_slots);
        pattern_lens.extend(exact_lens);
        atom_to_slots.extend(nocase_atom_to_slots);
        pattern_lens.extend(nocase_lens);

        // Build reverse mapping: for each SlotId, list of value indices that
        // reference it.  Used by the scanner to decrement per-value remaining
        // counters when a slot becomes saturated.
        let n_slots = slots.len();
        let mut slot_to_values: Vec<Vec<u32>> = vec![Vec::new(); n_slots];
        for (vi, slot_ids) in atom_to_slots.iter().enumerate() {
            for &sid in slot_ids.iter() {
                slot_to_values[sid as usize].push(vi as u32);
            }
        }

        // Build ClamAV-style dense transition tables (one lookup per byte).
        let exact_dense = exact.as_ref().map(|pma| pma.build_dense_table()).unwrap_or_default();
        let nocase_dense = nocase.as_ref().map(|pma| pma.build_dense_table()).unwrap_or_default();

        AtomFilterDb {
            exact,
            nocase,
            exact_dense,
            nocase_dense,
            atom_to_slots,
            slot_to_values: slot_to_values.into_iter().map(|v| v.into_boxed_slice()).collect(),
            pattern_lens,
            slots,
            ext_slot,
            log_subsig_slots,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;

    fn load_str(name: &str, contents: &str) -> Database {
        let mut files = std::collections::HashMap::new();
        files.insert(name.to_string(), contents.as_bytes().to_vec());
        let (db, _report) = Database::from_bytes_map(&files);
        db
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn extended_signature_gets_one_atom_slot() {
        let hex = hex_of(b"HydraDragonTestAtom");
        let line = format!("Test.Ndb.Sig:0:*:{hex}\n");
        let db = load_str("test.ndb", &line);
        assert_eq!(db.extended.len(), 1);

        let afdb = AtomFilterBuilder::build(&db);
        assert_eq!(afdb.ext_slot.len(), 1);
        let ExtSlot::Atom(slot_id) = afdb.ext_slot[0] else {
            panic!("expected an atom slot, got {:?}", afdb.ext_slot[0]);
        };
        assert_eq!(
            afdb.slots[slot_id as usize].target,
            crate::atomfilter::SlotTarget::Extended { sig_index: 0 }
        );

        // The automaton must have been built.
        assert!(afdb.exact.is_some(), "expected exact automaton");
    }

    #[test]
    fn logical_subsignature_gets_its_own_slot() {
        let hex_a = hex_of(b"AtomAlphaLiteral");
        let hex_b = hex_of(b"AtomBravoLiteral");
        let line = format!("Test.Ldb.Sig;Target:0;0&1;{hex_a};{hex_b}\n");
        let db = load_str("test.ldb", &line);
        assert_eq!(db.logical.len(), 1);
        assert_eq!(db.logical[0].subsignatures.len(), 2);

        let afdb = AtomFilterBuilder::build(&db);
        assert_eq!(afdb.log_subsig_slots.len(), 1);
        assert_eq!(afdb.log_subsig_slots[0].len(), 2);
        for (subsig_index, slot) in afdb.log_subsig_slots[0].iter().enumerate() {
            let SubsigSlot::Atom(slot_id) = *slot else {
                panic!("expected an atom slot for subsig {subsig_index}, got {slot:?}");
            };
            assert_eq!(
                afdb.slots[slot_id as usize].target,
                crate::atomfilter::SlotTarget::LogicalSubsig {
                    sig_index: 0,
                    subsig_index: subsig_index as u32
                }
            );
        }
    }
}
