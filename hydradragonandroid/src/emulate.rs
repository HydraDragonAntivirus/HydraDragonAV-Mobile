//! Native-code emulation (Unicorn Engine) to reveal strings a malicious `.so`
//! only produces at RUNTIME — a rolling-XOR/RC4/custom-cipher decode loop
//! run over an embedded blob before it's used (e.g. a C2 URL, in
//! `JNI_OnLoad` or the ELF entry stub) never appears as plaintext in a static
//! strings scan, only after that loop executes. This maps the library's
//! `PT_LOAD` segments into an emulated CPU (matching the ELF's own
//! architecture), runs a bounded number of instructions starting at
//! `JNI_OnLoad` (falling back to the ELF entry point if that symbol isn't
//! exported), and returns whatever NEW printable strings appear in memory
//! afterwards that weren't already present in the static file bytes.
//!
//! Safety/scope, by design:
//!   * Pure CPU emulation only — no syscalls, no JNI, no libc are emulated,
//!     so the code can't do anything to the real device even if malicious.
//!     This also means execution will simply halt (an invalid memory access)
//!     the moment the code calls out to a real imported function — this
//!     catches self-contained decode loops before their first real call,
//!     not multi-stage unpackers that need actual OS/libc behavior.
//!   * Bounded by both an instruction count AND a wall-clock timeout, so a
//!     hostile infinite loop can't hang or stall a scan.
//!   * Any Unicorn error (unmapped read/write, invalid instruction, decoding
//!     a corrupt/adversarial ELF) is treated as "stop here", never a panic —
//!     wrapped in `catch_unwind` at the call site in `lib.rs`.

use crate::elf::{self, EM_AARCH64, EM_ARM, EM_386, EM_X86_64};
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine::{RegisterARM, RegisterARM64, RegisterX86, Unicorn};

const PAGE: u64 = 0x1000;
const MAX_INSN: usize = 200_000;
const TIMEOUT_US: u64 = 500_000; // 500ms wall-clock cap
const STACK_BASE: u64 = 0x7000_0000;
const STACK_SIZE: u64 = 4 * PAGE;
const MIN_STRING_LEN: usize = 6;

fn align_down(x: u64, a: u64) -> u64 {
    x & !(a - 1)
}
fn align_up(x: u64, a: u64) -> u64 {
    align_down(x + a - 1, a)
}

/// Emulate `so_bytes` (a native library extracted from an APK) and return
/// every printable ASCII string (>= MIN_STRING_LEN) that appears in the
/// emulated memory afterwards but was NOT already present as a substring of
/// the original file — i.e. genuinely produced at runtime, not just a static
/// string the emulation happened to touch. Returns an empty Vec for anything
/// that isn't a supported/parseable ELF, or if nothing new appeared.
pub fn emulate_and_extract_strings(so_bytes: &[u8]) -> Vec<String> {
    let info = match elf::parse_elf(so_bytes) {
        Some(i) => i,
        None => return Vec::new(),
    };
    if info.segments.is_empty() {
        return Vec::new();
    }

    let (arch, mode, sp_reg, pc_reg): (Arch, Mode, i32, i32) = match info.machine {
        EM_ARM => (Arch::ARM, Mode::LITTLE_ENDIAN, RegisterARM::SP as i32, RegisterARM::PC as i32),
        EM_AARCH64 => (Arch::ARM64, Mode::LITTLE_ENDIAN, RegisterARM64::SP as i32, RegisterARM64::PC as i32),
        EM_386 => (Arch::X86, Mode::MODE_32, RegisterX86::ESP as i32, RegisterX86::EIP as i32),
        EM_X86_64 => (Arch::X86, Mode::MODE_64, RegisterX86::RSP as i32, RegisterX86::RIP as i32),
        _ => return Vec::new(), // unsupported/unknown machine — skip, not an error
    };

    let entry = elf::find_dynsym(so_bytes, "JNI_OnLoad").unwrap_or(info.entry);
    if entry == 0 {
        return Vec::new();
    }

    let mut uc = match Unicorn::new(arch, mode) {
        Ok(u) => u,
        Err(_) => return Vec::new(),
    };

    // Map every PT_LOAD segment, page-aligned, RWX (we don't model per-segment
    // permissions — the goal is "does it run and decode something", not a
    // faithful memory-protection model, and being permissive here avoids
    // false negatives from a self-modifying decode stub writing into what
    // would normally be a read-only/executable region).
    for seg in &info.segments {
        let start = align_down(seg.vaddr, PAGE);
        let end = align_up(seg.vaddr + seg.memsz, PAGE);
        let size = end - start;
        if size == 0 || size > 64 * 1024 * 1024 {
            continue; // guardrail against a corrupt/adversarial segment table
        }
        if uc.mem_map(start, size, Prot::ALL).is_err() {
            continue; // likely overlaps a previously-mapped region — skip it
        }
        let file_end = (seg.offset + seg.filesz) as usize;
        if seg.offset as usize <= so_bytes.len() && file_end <= so_bytes.len() {
            let bytes = &so_bytes[seg.offset as usize..file_end];
            let _ = uc.mem_write(seg.vaddr, bytes);
        }
    }

    // A small dedicated stack, well away from the loaded segments.
    if uc.mem_map(STACK_BASE, STACK_SIZE, Prot::ALL).is_err() {
        return Vec::new();
    }
    let sp = STACK_BASE + STACK_SIZE - PAGE;
    let _ = uc.reg_write(sp_reg, sp);

    // JNI_OnLoad(JavaVM*, void*) — args don't matter (we never emulate the
    // JNI functions those pointers would call through), just need something
    // in the calling-convention registers so the prologue doesn't fault
    // immediately on a null-deref before any real decode logic runs.
    let _ = uc.reg_write(sp_reg, sp); // re-affirm after any arch-specific setup above

    // Run — errors (unmapped access, invalid instruction, timeout) are all
    // just "stop here"; whatever got decoded before that point still counts.
    let _ = uc.emu_start(entry, 0, TIMEOUT_US, MAX_INSN);
    let _ = pc_reg; // only needed if we wanted to inspect where it halted

    // Harvest every mapped region's live memory and extract new strings.
    let mut found = Vec::new();
    if let Ok(regions) = uc.mem_regions() {
        for r in regions {
            let size = (r.end.saturating_sub(r.begin)) as usize;
            if size == 0 || size > 64 * 1024 * 1024 {
                continue;
            }
            if let Ok(buf) = uc.mem_read_as_vec(r.begin, size) {
                extract_new_ascii_strings(&buf, so_bytes, &mut found);
            }
        }
    }
    found
}

/// Standard "strings"-style scan (consecutive printable ASCII, length >=
/// MIN_STRING_LEN) over `buf`, keeping only the ones that do NOT already
/// occur verbatim in `original` — i.e. genuinely new content produced by
/// emulation, not just static data the CPU happened to read into a register
/// or copy around unchanged.
fn extract_new_ascii_strings(buf: &[u8], original: &[u8], out: &mut Vec<String>) {
    if out.len() >= 64 {
        return; // already have plenty of candidates, stop scanning further regions
    }
    let mut start = None;
    for i in 0..=buf.len() {
        let is_printable = i < buf.len() && (0x20..0x7f).contains(&buf[i]);
        if is_printable {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            if i - s >= MIN_STRING_LEN {
                let candidate = &buf[s..i];
                if !contains_subslice(original, candidate) {
                    out.push(String::from_utf8_lossy(candidate).to_string());
                    if out.len() >= 64 {
                        return;
                    }
                }
            }
        }
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
