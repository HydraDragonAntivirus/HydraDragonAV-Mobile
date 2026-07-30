use daachorse::prefilter::MultiPatternShiftOr;
use daachorse::DoubleArrayAhoCorasick;

pub type SlotId = u32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotTarget {
    Extended { sig_index: u32 },
    LogicalSubsig { sig_index: u32, subsig_index: u32 },
}

#[derive(Clone, Debug)]
pub struct SlotDef {
    pub target: SlotTarget,
    pub threshold: u32,
    pub file_type_target: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtSlot {
    Atom(SlotId),
    AutoMatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubsigSlot {
    Atom(SlotId),
    AutoMatch,
    External,
}

/// Automata and mappings for a single file-type target.
pub struct PerTarget {
    pub target: u32,
    pub exact: Option<DoubleArrayAhoCorasick<u32>>,
    pub nocase: Option<DoubleArrayAhoCorasick<u32>>,
    pub atom_to_slots: Vec<Box<[SlotId]>>,
    pub pattern_lens: Vec<usize>,
    pub slot_to_values: Vec<Box<[u32]>>,
}

impl std::fmt::Debug for PerTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerTarget")
            .field("target", &self.target)
            .field("exact", &self.exact.as_ref().map(|_| "Some(automaton)"))
            .field("nocase", &self.nocase.as_ref().map(|_| "Some(automaton)"))
            .field("atom_to_slots", &self.atom_to_slots)
            .field("pattern_lens", &self.pattern_lens)
            .finish()
    }
}

/// The full atom-filter database: per-target daachorse automata (exact + nocase)
/// and shared slot/ext/logical metadata.  At scan time the appropriate per-target
/// automaton is selected based on the buffer's detected file type.
pub struct AtomFilterDb {
    /// Per-target automata, indexed by file_type_target.
    /// `per_target[0]` is the "full" automaton (target 0 = any file) containing
    /// ALL patterns regardless of target.  `per_target[1..]` are specific
    /// targets (3, 5, 6, …).
    pub per_target: Vec<PerTarget>,
    pub slots: Vec<SlotDef>,
    pub ext_slot: Vec<ExtSlot>,
    pub log_subsig_slots: Vec<Box<[SubsigSlot]>>,
    pub prefilter: Option<MultiPatternShiftOr>,
}

impl std::fmt::Debug for AtomFilterDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtomFilterDb")
            .field("per_target", &self.per_target)
            .field("slots", &self.slots)
            .field("ext_slot", &self.ext_slot)
            .field("log_subsig_slots", &self.log_subsig_slots)
            .finish()
    }
}

impl AtomFilterDb {
    pub fn empty() -> Self {
        AtomFilterDb {
            per_target: Vec::new(),
            slots: Vec::new(),
            ext_slot: Vec::new(),
            log_subsig_slots: Vec::new(),
            prefilter: None,
        }
    }

    /// Serialise the entire atomfilter into a byte vector.
    ///
    /// Format (all integers little-endian):
    ///   1. version (u8) = 3
    ///   2. per_target count (u32)
    ///   3. for each per_target:
    ///        target (u32)
    ///
    ///        exact automaton: has (u8) + len (u32) + bytes (daachorse wire format)
    ///        nocase automaton: has (u8) + len (u32) + bytes
    ///
    ///        atom_to_slots count (u32)
    ///        for each: slot_id count (u32) + [SlotId; count]
    ///
    ///        pattern_lens count (u32)
    ///        for each: u64
    ///
    ///        slot_to_values count (u32)
    ///        for each: u32 count (u32) + [u32; count]
    ///
    ///   4. slots count (u32)
    ///   5. for each slot: target_tag (u32: 0=Extended, 1=LogicalSubsig),
    ///        sig_index (u32), subsig_index (u32, 0 if Extended),
    ///        threshold (u32), file_type_target (u32)
    ///
    ///   6. ext_slot count (u32)
    ///   7. for each: u32 (SlotId, or u32::MAX for AutoMatch)
    ///
    ///   8. log_subsig_slots count (u32)
    ///   9. for each: subsig count (u32) + for each: u32
    ///        (SlotId, u32::MAX for AutoMatch, u32::MAX-1 for External)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // 1. version
        buf.push(3u8);

        // 2. per_target
        buf.extend_from_slice(&(self.per_target.len() as u32).to_le_bytes());
        for pt in &self.per_target {
            buf.extend_from_slice(&pt.target.to_le_bytes());

            // exact automaton
            write_auto(&mut buf, pt.exact.as_ref());
            // nocase automaton
            write_auto(&mut buf, pt.nocase.as_ref());

            // atom_to_slots
            buf.extend_from_slice(&(pt.atom_to_slots.len() as u32).to_le_bytes());
            for ids in &pt.atom_to_slots {
                buf.extend_from_slice(&(ids.len() as u32).to_le_bytes());
                for &id in ids.iter() {
                    buf.extend_from_slice(&id.to_le_bytes());
                }
            }

            // pattern_lens
            buf.extend_from_slice(&(pt.pattern_lens.len() as u32).to_le_bytes());
            for &len in &pt.pattern_lens {
                buf.extend_from_slice(&(len as u64).to_le_bytes());
            }

            // slot_to_values
            buf.extend_from_slice(&(pt.slot_to_values.len() as u32).to_le_bytes());
            for ids in &pt.slot_to_values {
                buf.extend_from_slice(&(ids.len() as u32).to_le_bytes());
                for &id in ids.iter() {
                    buf.extend_from_slice(&id.to_le_bytes());
                }
            }
        }

        // 4+5. slots
        buf.extend_from_slice(&(self.slots.len() as u32).to_le_bytes());
        for s in &self.slots {
            let (tag, si, ssi) = match s.target {
                SlotTarget::Extended { sig_index } => (0u32, sig_index, 0u32),
                SlotTarget::LogicalSubsig { sig_index, subsig_index } => (1u32, sig_index, subsig_index),
            };
            buf.extend_from_slice(&tag.to_le_bytes());
            buf.extend_from_slice(&si.to_le_bytes());
            buf.extend_from_slice(&ssi.to_le_bytes());
            buf.extend_from_slice(&s.threshold.to_le_bytes());
            buf.extend_from_slice(&s.file_type_target.to_le_bytes());
        }

        // 6+7. ext_slot
        buf.extend_from_slice(&(self.ext_slot.len() as u32).to_le_bytes());
        for es in &self.ext_slot {
            let v: u32 = match es {
                ExtSlot::Atom(id) => *id,
                ExtSlot::AutoMatch => u32::MAX,
            };
            buf.extend_from_slice(&v.to_le_bytes());
        }

        // 8+9. log_subsig_slots
        buf.extend_from_slice(&(self.log_subsig_slots.len() as u32).to_le_bytes());
        for ss in &self.log_subsig_slots {
            buf.extend_from_slice(&(ss.len() as u32).to_le_bytes());
            for slot in ss.iter() {
                let v: u32 = match slot {
                    SubsigSlot::Atom(id) => *id,
                    SubsigSlot::AutoMatch => u32::MAX,
                    SubsigSlot::External => u32::MAX - 1,
                };
                buf.extend_from_slice(&v.to_le_bytes());
            }
        }

        buf
    }

    /// Deserialise from a byte slice produced by [`to_bytes`].
    /// Returns `None` on any format error.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut pos = 0usize;
        let version = *bytes.get(pos)?;
        pos += 1;
        match version {
            1 => {
                // v1 had prefilter tables + dense tables. Skip both then read common.
                pos += 786432;
                let pt_count = read_u32(bytes, &mut pos)? as usize;
                let mut per_target = Vec::with_capacity(pt_count);
                for _ in 0..pt_count {
                    let target = read_u32(bytes, &mut pos)?;
                    let exact = read_auto(bytes, &mut pos)?;
                    let nocase = read_auto(bytes, &mut pos)?;
                    // skip dense tables
                    pos += read_u32(bytes, &mut pos)? as usize * 4;
                    pos += read_u32(bytes, &mut pos)? as usize * 4;
                    let (atom_to_slots, pattern_lens, slot_to_values) = read_per_target_atoms(bytes, &mut pos)?;
                    per_target.push(PerTarget { target, exact, nocase, atom_to_slots, pattern_lens, slot_to_values });
                }
                let (slots, ext_slot, log_subsig_slots) = read_slots_ext(bytes, &mut pos)?;
                Some(AtomFilterDb { per_target, slots, ext_slot, log_subsig_slots, prefilter: None })
            }
            2 => {
                // v2 had prefilter tables. Skip them.
                pos += 786432;
                let pt_count = read_u32(bytes, &mut pos)? as usize;
                let mut per_target = Vec::with_capacity(pt_count);
                for _ in 0..pt_count {
                    let target = read_u32(bytes, &mut pos)?;
                    let exact = read_auto(bytes, &mut pos)?;
                    let nocase = read_auto(bytes, &mut pos)?;
                    let (atom_to_slots, pattern_lens, slot_to_values) = read_per_target_atoms(bytes, &mut pos)?;
                    per_target.push(PerTarget { target, exact, nocase, atom_to_slots, pattern_lens, slot_to_values });
                }
                let (slots, ext_slot, log_subsig_slots) = read_slots_ext(bytes, &mut pos)?;
                Some(AtomFilterDb { per_target, slots, ext_slot, log_subsig_slots, prefilter: None })
            }
            3 => {
                let pt_count = read_u32(bytes, &mut pos)? as usize;
                let mut per_target = Vec::with_capacity(pt_count);
                for _ in 0..pt_count {
                    let target = read_u32(bytes, &mut pos)?;
                    let exact = read_auto(bytes, &mut pos)?;
                    let nocase = read_auto(bytes, &mut pos)?;
                    let (atom_to_slots, pattern_lens, slot_to_values) = read_per_target_atoms(bytes, &mut pos)?;
                    per_target.push(PerTarget { target, exact, nocase, atom_to_slots, pattern_lens, slot_to_values });
                }
                let (slots, ext_slot, log_subsig_slots) = read_slots_ext(bytes, &mut pos)?;
                Some(AtomFilterDb { per_target, slots, ext_slot, log_subsig_slots, prefilter: None })
            }
            _ => None,
        }
    }
}

// -- helpers --

fn write_auto(buf: &mut Vec<u8>, auto: Option<&DoubleArrayAhoCorasick<u32>>) {
    match auto {
        Some(pma) => {
            let bytes = pma.serialize();
            buf.push(1u8);
            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&bytes);
        }
        None => {
            buf.push(0u8);
            buf.extend_from_slice(&0u32.to_le_bytes());
        }
    }
}

fn read_auto(bytes: &[u8], pos: &mut usize) -> Option<Option<DoubleArrayAhoCorasick<u32>>> {
    let has = bytes.get(*pos).copied()?;
    *pos += 1;
    let len = read_u32(bytes, pos)? as usize;
    if has == 0 {
        if len != 0 { return None; }
        return Some(None);
    }
    let slice = bytes.get(*pos..*pos + len)?;
    *pos += len;
    let (pma, _rest) = DoubleArrayAhoCorasick::<u32>::deserialize(slice).ok()?;
    Some(Some(pma))
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    let slice = bytes.get(*pos..*pos + 4)?;
    *pos += 4;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let slice = bytes.get(*pos..*pos + 8)?;
    *pos += 8;
    Some(u64::from_le_bytes([slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7]]))
}

fn read_per_target_atoms(bytes: &[u8], pos: &mut usize) -> Option<(Vec<Box<[SlotId]>>, Vec<usize>, Vec<Box<[u32]>>)> {
    let ats_count = read_u32(bytes, pos)? as usize;
    let mut atom_to_slots = Vec::with_capacity(ats_count);
    for _ in 0..ats_count {
        let ids_count = read_u32(bytes, pos)? as usize;
        let mut ids = Vec::with_capacity(ids_count);
        for _ in 0..ids_count {
            ids.push(read_u32(bytes, pos)?);
        }
        atom_to_slots.push(ids.into_boxed_slice());
    }
    let pl_count = read_u32(bytes, pos)? as usize;
    let mut pattern_lens = Vec::with_capacity(pl_count);
    for _ in 0..pl_count {
        pattern_lens.push(read_u64(bytes, pos)? as usize);
    }
    let stv_count = read_u32(bytes, pos)? as usize;
    let mut slot_to_values = Vec::with_capacity(stv_count);
    for _ in 0..stv_count {
        let ids_count = read_u32(bytes, pos)? as usize;
        let mut ids = Vec::with_capacity(ids_count);
        for _ in 0..ids_count {
            ids.push(read_u32(bytes, pos)?);
        }
        slot_to_values.push(ids.into_boxed_slice());
    }
    Some((atom_to_slots, pattern_lens, slot_to_values))
}

fn read_slots_ext(bytes: &[u8], pos: &mut usize) -> Option<(Vec<SlotDef>, Vec<ExtSlot>, Vec<Box<[SubsigSlot]>>)> {
    let slots_count = read_u32(bytes, pos)? as usize;
    let mut slots = Vec::with_capacity(slots_count);
    for _ in 0..slots_count {
        let tag = read_u32(bytes, pos)?;
        let si = read_u32(bytes, pos)?;
        let ssi = read_u32(bytes, pos)?;
        let threshold = read_u32(bytes, pos)?;
        let file_type_target = read_u32(bytes, pos)?;
        let target = match tag {
            0 => SlotTarget::Extended { sig_index: si },
            1 => SlotTarget::LogicalSubsig { sig_index: si, subsig_index: ssi },
            _ => return None,
        };
        slots.push(SlotDef { target, threshold, file_type_target });
    }
    let es_count = read_u32(bytes, pos)? as usize;
    let mut ext_slot = Vec::with_capacity(es_count);
    for _ in 0..es_count {
        let v = read_u32(bytes, pos)?;
        ext_slot.push(if v == u32::MAX { ExtSlot::AutoMatch } else { ExtSlot::Atom(v) });
    }
    let lss_count = read_u32(bytes, pos)? as usize;
    let mut log_subsig_slots = Vec::with_capacity(lss_count);
    for _ in 0..lss_count {
        let count = read_u32(bytes, pos)? as usize;
        let mut ss = Vec::with_capacity(count);
        for _ in 0..count {
            let v = read_u32(bytes, pos)?;
            ss.push(if v == u32::MAX { SubsigSlot::AutoMatch }
                else if v == u32::MAX - 1 { SubsigSlot::External }
                else { SubsigSlot::Atom(v) });
        }
        log_subsig_slots.push(ss.into_boxed_slice());
    }
    Some((slots, ext_slot, log_subsig_slots))
}
