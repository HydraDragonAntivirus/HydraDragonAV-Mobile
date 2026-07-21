//! Data model for the daachorse-based atom prefilter.
//!
//! Replaces the old Binary-Fuse16 / rolling-hash approach with a single
//! Aho-Corasick automaton (daachorse) that matches every exact and nocase
//! atom in one pass per automaton. No more 5 separate rolling-hash sweeps.

use daachorse::DoubleArrayAhoCorasick;

/// Index into [`AtomFilterDb::slots`]. One "thing" (a whole extended
/// signature, or one subsignature of a logical signature) with its own hit
/// counter at scan time.
pub type SlotId = u32;

/// What a slot promotes to once its counter reaches [`SlotDef::threshold`].
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

/// How an extended signature's match state is determined at scan time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtSlot {
    Atom(SlotId),
    AutoMatch,
}

/// How one logical signature's subsignature contributes to `LogicalExpr::eval`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubsigSlot {
    Atom(SlotId),
    AutoMatch,
    External,
}

/// The full atom-filter database: two daachorse automata (exact + nocase) and
/// a value-to-slot mapping that resolves each automaton match to the owning
/// signature slot(s).
pub struct AtomFilterDb {
    /// Exact-match automaton: patterns are the raw atom bytes.
    /// Value = index into `atom_to_slots`.
    pub exact: Option<DoubleArrayAhoCorasick<u32>>,
    /// Nocase-match automaton: patterns are ASCII-lowercased atom bytes.
    /// Value = index into `atom_to_slots`.
    pub nocase: Option<DoubleArrayAhoCorasick<u32>>,
    /// Maps daachorse value → slot ID list. Both automata index into this
    /// same array (a nocase atom and an exact atom that happen to share the
    /// same value index are resolved independently via different automata).
    pub atom_to_slots: Vec<Box<[SlotId]>>,
    /// Pattern length for each value index, so the scanner can compute
    /// the start offset from daachorse's end offset.
    pub pattern_lens: Vec<usize>,
    pub slots: Vec<SlotDef>,
    pub ext_slot: Vec<ExtSlot>,
    pub log_subsig_slots: Vec<Box<[SubsigSlot]>>,
}

impl std::fmt::Debug for AtomFilterDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtomFilterDb")
            .field("exact", &self.exact.as_ref().map(|_| "Some(automaton)"))
            .field("nocase", &self.nocase.as_ref().map(|_| "Some(automaton)"))
            .field("atom_to_slots", &self.atom_to_slots)
            .field("pattern_lens", &self.pattern_lens)
            .field("slots", &self.slots)
            .field("ext_slot", &self.ext_slot)
            .field("log_subsig_slots", &self.log_subsig_slots)
            .finish()
    }
}

impl AtomFilterDb {
    pub fn empty() -> Self {
        AtomFilterDb {
            exact: None,
            nocase: None,
            atom_to_slots: Vec::new(),
            pattern_lens: Vec::new(),
            slots: Vec::new(),
            ext_slot: Vec::new(),
            log_subsig_slots: Vec::new(),
        }
    }
}
