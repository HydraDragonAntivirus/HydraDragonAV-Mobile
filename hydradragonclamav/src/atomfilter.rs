use daachorse::{ClamavMultilevelPrefilter, DoubleArrayAhoCorasick};

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
    pub exact_dense: Vec<u32>,
    pub nocase_dense: Vec<u32>,
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
    pub prefilter: ClamavMultilevelPrefilter,
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
            prefilter: ClamavMultilevelPrefilter::from_patterns(&[]),
        }
    }
}
