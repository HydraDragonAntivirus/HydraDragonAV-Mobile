//! Builds an [`AtomFilterDb`] from a loaded [`Database`] — the Binary-Fuse16
//! replacement for `prefilter.rs`'s daachorse-based `AtomPrefilter::build`.
//!
//! Same atom-selection logic as the old prefilter (reuses
//! `Pattern::required_atom`/`required_atom_nocase`, the same `MIN_DEPTH..=
//! MAX_ATOM` window, the same case/nocase split), but every signature/
//! subsignature gets its own [`SlotId`] with a promotion counter instead of
//! being threaded through one shared Aho-Corasick automaton. There is no
//! gating/short-circuit search here (that only matters for choosing which
//! literal to scan for first) — every usable atom of every signature is
//! indexed, since the point of the Bf16 filter is that indexing more atoms
//! costs almost nothing.

use std::collections::HashMap;

use jdb_xorf::Bf16;

use crate::atomfilter::{
    AtomBucket, AtomFilterDb, ExtSlot, SlotDef, SlotId, SlotTarget, SubsigSlot,
};
use crate::atomfilter_hash::{bucket_len, hash_window, ATOM_LENGTHS};
use crate::database::Database;
use crate::logical::Subsignature;
use crate::pattern::Pattern;

/// Shortest literal usable as an atom (mirrors `prefilter.rs::MIN_DEPTH`).
const MIN_DEPTH: usize = 2;
/// Longest atom indexed per signature (mirrors `prefilter.rs::MAX_ATOM`) —
/// the top of `ATOM_LENGTHS`.
const MAX_ATOM: usize = 16;

#[inline]
fn usable(a: &[u8]) -> bool {
    a.len() >= MIN_DEPTH
}

#[inline]
fn short_atom(a: &[u8]) -> &[u8] {
    &a[..a.len().min(MAX_ATOM)]
}

enum Atom {
    Exact(Vec<u8>),
    Nocase(Vec<u8>),
}

fn pattern_atom(p: &Pattern) -> Option<Atom> {
    if let Some(a) = p.required_atom() {
        if usable(&a) {
            return Some(Atom::Exact(a));
        }
    }
    if let Some(a) = p.required_atom_nocase() {
        if usable(&a) {
            return Some(Atom::Nocase(a));
        }
    }
    None
}

/// Every pattern's atom, if all of them have one; `None` if any pattern
/// lacks a usable atom (the caller then has no way to gate that pattern set
/// on atoms at all).
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

/// Accumulates `(bucket_len, key) -> Vec<SlotId>` registrations before the
/// final per-bucket Bf16 filters are built, kept as flat vectors (bucketed by
/// `ATOM_LENGTHS` index) to match `AtomFilterDb::buckets`'s shape.
#[derive(Default)]
struct BucketAcc {
    exact: [Vec<(u64, SlotId)>; ATOM_LENGTHS.len()],
    nocase: [Vec<(u64, SlotId)>; ATOM_LENGTHS.len()],
}

impl BucketAcc {
    fn register(&mut self, atom: &Atom, slot: SlotId) {
        let (bytes, table): (&[u8], &mut [Vec<(u64, SlotId)>; ATOM_LENGTHS.len()]) = match atom {
            Atom::Exact(b) => (b, &mut self.exact),
            Atom::Nocase(b) => (b, &mut self.nocase),
        };
        let clamped = short_atom(bytes);
        let Some(blen) = bucket_len(clamped.len()) else {
            return;
        };
        let idx = ATOM_LENGTHS.iter().position(|&l| l == blen).unwrap();
        let key = hash_window(&clamped[..blen]);
        table[idx].push((key, slot));
    }
}

fn build_buckets(mut acc: [Vec<(u64, SlotId)>; ATOM_LENGTHS.len()]) -> [Option<AtomBucket>; ATOM_LENGTHS.len()] {
    std::array::from_fn(|i| {
        let entries = std::mem::take(&mut acc[i]);
        if entries.is_empty() {
            return None;
        }
        let mut slots: HashMap<u64, Vec<SlotId>> = HashMap::new();
        for (key, slot) in entries {
            slots.entry(key).or_default().push(slot);
        }
        for v in slots.values_mut() {
            v.sort_unstable();
            v.dedup();
        }
        let keys: Vec<u64> = slots.keys().copied().collect();
        let bf = Bf16::from(&keys);
        let slots = slots
            .into_iter()
            .map(|(k, v)| (k, v.into_boxed_slice()))
            .collect();
        Some(AtomBucket { bf, slots })
    })
}

pub struct AtomFilterBuilder;

impl AtomFilterBuilder {
    pub fn build(db: &Database) -> AtomFilterDb {
        let mut acc = BucketAcc::default();
        let mut slots: Vec<SlotDef> = Vec::new();
        let mut ext_slot: Vec<ExtSlot> = Vec::with_capacity(db.extended.len());
        let mut log_subsig_slots: Vec<Box<[SubsigSlot]>> = Vec::with_capacity(db.logical.len());

        // --- Extended signatures: one slot per signature (matches on ANY of
        // its patterns, so a single "some atom of mine hit" counter is
        // exactly equivalent to the old per-pattern OR semantics). ---
        for (si, sig) in db.extended.iter().enumerate() {
            match all_pattern_atoms(&sig.patterns) {
                Some(atoms) => {
                    let slot_id = slots.len() as SlotId;
                    slots.push(SlotDef {
                        target: SlotTarget::Extended { sig_index: si as u32 },
                        threshold: 1,
                        file_type_target: sig.target.unwrap_or(0),
                    });
                    for a in &atoms {
                        acc.register(a, slot_id);
                    }
                    ext_slot.push(ExtSlot::Atom(slot_id));
                }
                None => ext_slot.push(ExtSlot::AutoMatch),
            }
        }

        // --- Logical signatures: one slot per atom-indexable Body
        // subsignature. Non-Body subsigs (Pcre/ByteCompare/Fuzzy/Unsupported)
        // have no atom concept and are left `External` for the scanner's own
        // exact-evaluation path. A Body subsig with no usable atom in some
        // variant has no way to gate on atoms at all — per the accepted
        // no-verification design, it is simply always counted as matched. ---
        let mut log_always_scan: Vec<u32> = Vec::new();
        for (si, sig) in db.logical.iter().enumerate() {
            let mut sub_slots: Vec<SubsigSlot> = Vec::with_capacity(sig.subsignatures.len());
            let mut always = false;
            for subsig in sig.subsignatures.iter() {
                let Subsignature::Body { patterns, .. } = subsig else {
                    sub_slots.push(SubsigSlot::External);
                    always = true;
                    continue;
                };
                match all_pattern_atoms(patterns) {
                    Some(atoms) => {
                        let slot_id = slots.len() as SlotId;
                        let sig_index = (log_subsig_slots.len()) as u32;
                        let subsig_index = sub_slots.len() as u32;
                        slots.push(SlotDef {
                            target: SlotTarget::LogicalSubsig { sig_index, subsig_index },
                            threshold: 1,
                            file_type_target: sig.target.unwrap_or(0),
                        });
                        for a in &atoms {
                            acc.register(a, slot_id);
                        }
                        sub_slots.push(SubsigSlot::Atom(slot_id));
                    }
                    None => {
                        sub_slots.push(SubsigSlot::AutoMatch);
                        always = true;
                    }
                }
            }
            if always {
                log_always_scan.push(si as u32);
            }
            log_subsig_slots.push(sub_slots.into_boxed_slice());
        }

        AtomFilterDb {
            buckets: build_buckets(acc.exact),
            buckets_nocase: build_buckets(acc.nocase),
            slots,
            ext_slot,
            log_subsig_slots,
            log_always_scan,
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

    #[test]
    fn extended_signature_gets_one_atom_slot() {
        // "HydraDragonTestAtom" hex-encoded body signature.
        let hex: String = b"HydraDragonTestAtom"
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
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
            SlotTarget::Extended { sig_index: 0 }
        );

        // The atom must resolve through some bucket.
        let clamped = short_atom(b"HydraDragonTestAtom");
        let key = hash_window(&clamped[..bucket_len(clamped.len()).unwrap()]);
        let found = afdb.buckets.iter().flatten().any(|b| b.resolve(key).is_some());
        assert!(found, "expected the extended signature's atom to resolve");
    }

    #[test]
    fn logical_subsignature_gets_its_own_slot() {
        let hex_a: String = b"AtomAlphaLiteral"
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let hex_b: String = b"AtomBravoLiteral"
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
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
                SlotTarget::LogicalSubsig {
                    sig_index: 0,
                    subsig_index: subsig_index as u32
                }
            );
        }
    }
}
