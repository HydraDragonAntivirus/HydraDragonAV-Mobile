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
//!
//! Watchdog mechanism for the known Unicorn ARM64-host JIT hang bug:
//! On real ARM64 devices (Vivo etc.) Unicorn's `emu_start` can hang
//! indefinitely due to a bug in its TCG (JIT) backend, even though Unicorn's
//! own TIMEOUT_US is set. To work around this, the emulation thread shares a
//! raw uc_engine handle via an atomic before calling `emu_start`. If the
//! caller's `HARD_DEADLINE` expires, it calls `uc_emu_stop()` directly
//! through C FFI (which is explicitly documented as thread-safe in Unicorn's
//! API) to unblock the emulation thread, so the `EmulationSlot` is released
//! promptly instead of leaking forever.

use crate::elf::{self, EM_AARCH64, EM_ARM, EM_386, EM_X86_64};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicI8, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine::{RegisterARM, RegisterARM64, RegisterX86, Unicorn};

// Direct FFI call to `uc_emu_stop` — Unicorn's C API guarantees this is
// thread-safe and can be called from any thread to stop an ongoing
// `emu_start` on another thread. We cannot use the Rust wrapper
// `Unicorn::emu_stop()` here because it takes `&mut self` and the emulation
// thread holds the mutable reference inside `emu_start`.
unsafe extern "C" {
    fn uc_emu_stop(engine: *mut std::ffi::c_void) -> std::ffi::c_int;
}

// ── Startup probe: detect ARM64-host JIT hang once ──────────────────────
//
// Unicorn's ARM64-host TCG backend has a known bug that causes emu_start to
// hang indefinitely on real ARM64 devices (Vivo etc.).  We probe once at
// startup: run a trivial one-instruction snippet with a tight timeout.  If
// the probe itself hangs (detected via channel timeout), emulation is
// permanently disabled for this process lifetime.

/// Tri-state: 0 = untested, 1 = available, -1 = unavailable.
static EMULATION_PROBE: AtomicI8 = AtomicI8::new(0);

/// Number of consecutive hard timeouts before we permanently disable
/// emulation.  Set low (1) because a single hang on this ARM64 device
/// proves the JIT backend is broken — no need to waste more scans.
const MAX_HARD_TIMEOUTS: u8 = 1;
static HARD_TIMEOUT_COUNT: AtomicU8 = AtomicU8::new(0);

/// Runs a quick Unicorn smoke test for ARM64 (the most commonly broken host
/// backend).  Called once from lib.rs at startup.  Safe to call multiple
/// times — only the first call actually probes; subsequent calls return the
/// cached result.
pub fn probe_emulation() -> bool {
    match EMULATION_PROBE.load(Ordering::Acquire) {
        1 => return true,
        -1 => return false,
        _ => {}
    }
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    std::thread::spawn(move || {
        // Minimal ARM64 test: one NOP (0xD503201F).
        let code = &[0x1f, 0x20, 0x03, 0xd5];
        let mut uc = match Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN) {
            Ok(u) => u,
            Err(_) => {
                let _ = tx.send(false);
                return;
            }
        };
        let base: u64 = 0x1000;
        if uc.mem_map(base, 0x1000, Prot::ALL).is_err()
            || uc.mem_write(base, code).is_err()
            || uc.emu_start(base, base + 4, 5_000, 1).is_err()
        {
            let _ = tx.send(false);
            return;
        }
        let _ = tx.send(true);
    });
    let ok = rx.recv_timeout(std::time::Duration::from_millis(300)).unwrap_or(false);
    EMULATION_PROBE.store(if ok { 1 } else { -1 }, Ordering::Release);
    // Don't consume the slot — not needed for the probe.
    ok
}

/// Returns `true` if the startup probe succeeded (Unicorn emulation is
/// usable on this device).
pub fn emulation_available() -> bool {
    let v = EMULATION_PROBE.load(Ordering::Acquire);
    if v == 0 {
        // Not yet probed — assume yes (the scan path has a per-call
        // HARD_DEADLINE safety net anyway).  The caller should still call
        // `probe_emulation()` at startup for the fast-path skip to work.
        true
    } else {
        v > 0
    }
}

// ── Host architecture hint ──────────────────────────────────────────────

/// Returns a human-readable host-CPU description (used in the unsupported-
/// environment message below).
pub fn host_arch() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    { "ARM64 (AArch64)" }
    #[cfg(target_arch = "arm")]
    { "ARMv7 (32-bit)" }
    #[cfg(target_arch = "x86_64")]
    { "x86_64" }
    #[cfg(target_arch = "x86")]
    { "x86 (32-bit)" }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "arm", target_arch = "x86_64", target_arch = "x86")))]
    { "unknown" }
}

// ── Unsupported-environment reason ──────────────────────────────────────

/// Short English diagnostic string for logcat.  The Java side reads
/// `nativeIsEmulationAvailable()` and shows `R.string.unicorn_unsupported`
/// from `strings.xml` (available in 20 languages).
pub fn unsupported_reason() -> &'static str {
    "ARM64 JIT backend hang detected — Unicorn emulation disabled for this session"
}

const PAGE: u64 = 0x1000;
const MAX_INSN: usize = 200_000;
const TIMEOUT_US: u64 = 500_000; // 500ms wall-clock cap
const STACK_BASE: u64 = 0x7000_0000;
const STACK_SIZE: u64 = 4 * PAGE;
const MIN_STRING_LEN: usize = 6;

// How many `emulate()` calls may actually be running Unicorn AT THE SAME
// TIME, process-wide — this is the real fix for the ANR we root-caused:
// logcat showed 6 concurrent "native-init" threads each independently
// running this emulation loop, together pegging every core (Unicorn's
// memory-map/page-table bookkeeping is kernel-heavy, not just user-CPU,
// which is exactly what the ANR's CPU breakdown showed). A single 500ms/
// 200k-instruction cap on ONE call is meaningless if N files' worth of
// calls run truly in parallel — the cap needs to live at the point where
// the expensive work actually happens, not as a generic lock somewhere
// upstream that also serializes unrelated cheap work.
//
// 2 slots (not 1) so a single slow emulation can't fully idle every other
// core on a multi-core device, but low enough that this can never again be
// the thing that saturates every core simultaneously.
const MAX_CONCURRENT_EMULATIONS: usize = 2;

static EMULATION_SLOTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// RAII guard: holds one of the `MAX_CONCURRENT_EMULATIONS` slots until
/// dropped (i.e. for the duration of one `emulate()` call, including on
/// early return or panic-unwind through `catch_unwind` at the call site).
struct EmulationSlot;
impl Drop for EmulationSlot {
    fn drop(&mut self) {
        EMULATION_SLOTS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// Try to claim one of the concurrent-emulation slots. Non-blocking — no
/// wait at all, not even a short one: waiting here would add latency to
/// EVERY file's scan under load, not just the ones that actually need
/// emulation. If both slots are busy right now, skip emulation for this
/// buffer immediately (returns `None`) rather than costing anything.
fn try_acquire_emulation_slot() -> Option<EmulationSlot> {
    use std::sync::atomic::Ordering;
    let cur = EMULATION_SLOTS.load(Ordering::Acquire);
    if cur >= MAX_CONCURRENT_EMULATIONS {
        return None;
    }
    if EMULATION_SLOTS
        .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        Some(EmulationSlot)
    } else {
        None // lost the race to another thread — just skip, don't retry/wait
    }
}

// Fake import stubs live in their own tiny mapped page, far from any real
// segment/stack address, so a hit on one of these addresses unambiguously
// means "code just tried to call this imported function".
const STUB_BASE: u64 = 0x6000_0000;
const STUB_SIZE: u64 = PAGE;
const STUB_STEP: u64 = 4; // one stub slot per 4 bytes — plenty for arm/thumb/x86 sizes
const MAX_STUBS: u64 = STUB_SIZE / STUB_STEP;

/// Imported APIs whose invocation is itself an interesting behavioral signal
/// (network, filesystem, process/exec, dynamic loading, anti-analysis,
/// device-fingerprinting) — everything else is left unresolved so the
/// emulation still halts naturally on a "real" unmodeled call, exactly as
/// before this tracing was added.
const TRACKED_APIS: &[&str] = &[
    // network
    "socket", "connect", "send", "sendto", "recv", "recvfrom", "gethostbyname",
    "getaddrinfo", "inet_addr", "inet_pton",
    // filesystem
    "open", "open64", "fopen", "creat", "unlink", "remove", "rename",
    // process / exec / dynamic loading
    "system", "popen", "execve", "execl", "execvp", "fork", "vfork",
    "dlopen", "dlsym",
    // anti-debug / anti-analysis
    "ptrace", "kill",
    // device fingerprinting
    "__system_property_get",
];

/// One observed attempt to call an imported, tracked API during emulation.
#[derive(Clone, Debug)]
pub struct ApiCall {
    pub name: String,
}

/// Result of emulating a native library: both the existing runtime-decoded
/// strings and, additionally, which tracked imported APIs the code attempted
/// to call (network/file/exec/anti-debug/etc.) — a lightweight behavioral
/// signal alongside the pre-existing string-decoding one.
#[derive(Clone, Debug, Default)]
pub struct EmulationResult {
    pub strings: Vec<String>,
    pub api_calls: Vec<ApiCall>,
}

fn align_down(x: u64, a: u64) -> u64 {
    x & !(a - 1)
}
fn align_up(x: u64, a: u64) -> u64 {
    align_down(x + a - 1, a)
}

/// How long `emulate()` waits for the emulation thread before
/// force-stopping it via `uc_emu_stop()`. Set just above `TIMEOUT_US`
/// (500ms) to absorb thread startup overhead without adding unnecessary
/// delay when Unicorn's own timeout is broken on ARM64 hosts.
const HARD_DEADLINE: std::time::Duration = std::time::Duration::from_millis(600);

/// Emulate `so_bytes` (a native library extracted from an APK), returning
/// both runtime-decoded strings and traced calls into suspicious APIs — see
/// the module doc comment for the full picture. This function itself never
/// runs Unicorn directly: it does the cheap validity checks, claims a
/// concurrency slot, and hands the actual work to `emulate_body` on a
/// dedicated thread it does not wait on indefinitely (see `HARD_DEADLINE`).
pub fn emulate(so_bytes: &[u8]) -> EmulationResult {
    let result = EmulationResult::default();

    // Fast-path skip if the startup probe detected an unsupported host
    // (Unicorn ARM64 JIT hang on real phone hardware).
    if !emulation_available() {
        return result;
    }

    let info = match elf::parse_elf(so_bytes) {
        Some(i) => i,
        None => return result,
    };
    if info.segments.is_empty() {
        return result;
    }
    if !matches!(info.machine, EM_ARM | EM_AARCH64 | EM_386 | EM_X86_64) {
        return result; // unsupported/unknown machine — skip, not an error
    }
    let entry = elf::find_dynsym(so_bytes, "JNI_OnLoad").unwrap_or(info.entry);
    if entry == 0 {
        return result;
    }

    // Claim a concurrency slot BEFORE spawning anything — this is the fix
    // for N files simultaneously running this loop and pegging every core.
    // No wait: if both slots are busy right now, skip emulation for this
    // buffer immediately rather than adding latency to every file's scan.
    let slot = match try_acquire_emulation_slot() {
        Some(slot) => slot,
        None => return result,
    };

    let owned = so_bytes.to_vec();
    let (tx, rx) = std::sync::mpsc::channel();
    let stop_handle = Arc::new(AtomicUsize::new(0));
    let stop_clone = Arc::clone(&stop_handle);
    std::thread::spawn(move || {
        let _slot = slot;
        let r = emulate_body(&owned, &stop_clone);
        let _ = tx.send(r);
    });

    match rx.recv_timeout(HARD_DEADLINE) {
        Ok(r) => r,
        Err(_) => {
            // Force-stop the hung emulation so the worker thread unblocks
            // and releases its EMULATION_SLOTS slot immediately.
            let handle = stop_handle.load(Ordering::Acquire);
            if handle != 0 {
                unsafe { uc_emu_stop(handle as *mut std::ffi::c_void); }
            }

            // A hard timeout on real code means the ARM64 JIT backend is
            // broken — auto-disable emulation for the rest of this process
            // lifetime so subsequent calls skip immediately instead of
            // burning another 600ms each.
            let prev = HARD_TIMEOUT_COUNT.fetch_add(1, Ordering::AcqRel);
            if prev + 1 >= MAX_HARD_TIMEOUTS {
                EMULATION_PROBE.store(-1, Ordering::Release);
            }

            EmulationResult::default()
        },
    }
}

/// The actual Unicorn setup/run/harvest. Always runs on its own dedicated
/// thread now (spawned from `emulate()`), so it's fine for this to take
/// however long it takes on a given device — the caller already stopped
/// waiting on it past `HARD_DEADLINE` regardless of what happens in here.
///
/// Additionally traces attempted calls into a curated set of suspicious
/// imported APIs (network, filesystem, exec, dynamic loading, anti-debug,
/// device fingerprinting).
///
/// Tracing works by patching every resolved import's GOT slot to point at a
/// small unique "stub" address (in a dedicated page the real code never
/// otherwise touches) instead of leaving it unresolved. A code hook watches
/// for execution reaching one of those stub addresses; when it does, we
/// record the call, then immediately redirect PC to the caller's return
/// address (LR on ARM/ARM64, top-of-stack on x86/x86_64, popping it like a
/// `ret` would) so emulation resumes as if the call had returned — this is
/// still pure CPU emulation: the stub never executes real code, no syscall or
/// libc function ever actually runs, only bookkeeping in the hook callback.
fn emulate_body(so_bytes: &[u8], stop_handle: &AtomicUsize) -> EmulationResult {
    let mut result = EmulationResult::default();
    let info = match elf::parse_elf(so_bytes) {
        Some(i) => i,
        None => return result,
    };
    if info.segments.is_empty() {
        return result;
    }

    let (arch, mode, sp_reg, pc_reg): (Arch, Mode, i32, i32) = match info.machine {
        EM_ARM => (Arch::ARM, Mode::LITTLE_ENDIAN, RegisterARM::SP as i32, RegisterARM::PC as i32),
        EM_AARCH64 => (Arch::ARM64, Mode::LITTLE_ENDIAN, RegisterARM64::SP as i32, RegisterARM64::PC as i32),
        EM_386 => (Arch::X86, Mode::MODE_32, RegisterX86::ESP as i32, RegisterX86::EIP as i32),
        EM_X86_64 => (Arch::X86, Mode::MODE_64, RegisterX86::RSP as i32, RegisterX86::RIP as i32),
        _ => return result, // unsupported/unknown machine — skip, not an error
    };
    let is_x86 = matches!(info.machine, EM_386 | EM_X86_64);
    let is_64 = matches!(info.machine, EM_AARCH64 | EM_X86_64);
    let lr_reg: Option<i32> = match info.machine {
        EM_ARM => Some(RegisterARM::LR as i32),
        EM_AARCH64 => Some(RegisterARM64::LR as i32),
        _ => None, // x86/x86_64 return address lives on the stack, not a register
    };

    let entry = elf::find_dynsym(so_bytes, "JNI_OnLoad").unwrap_or(info.entry);
    if entry == 0 {
        return result;
    }

    let mut uc = match Unicorn::new(arch, mode) {
        Ok(u) => u,
        Err(_) => return result,
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
        return result;
    }
    let sp = STACK_BASE + STACK_SIZE - PAGE;
    let _ = uc.reg_write(sp_reg, sp);

    // JNI_OnLoad(JavaVM*, void*) — args don't matter (we never emulate the
    // JNI functions those pointers would call through), just need something
    // in the calling-convention registers so the prologue doesn't fault
    // immediately on a null-deref before any real decode logic runs.
    let _ = uc.reg_write(sp_reg, sp); // re-affirm after any arch-specific setup above

    // Set up the fake-import-stub page and patch resolved GOT slots for any
    // tracked import to point into it, one unique stub address per import.
    let stub_names: Rc<RefCell<std::collections::HashMap<u64, String>>> =
        Rc::new(RefCell::new(std::collections::HashMap::new()));
    if uc.mem_map(STUB_BASE, STUB_SIZE, Prot::ALL).is_ok() {
        let imports = elf::find_imports(so_bytes);
        let ptr_size: u64 = if is_64 { 8 } else { 4 };
        let mut next_slot: u64 = 0;
        for imp in imports {
            if !TRACKED_APIS.contains(&imp.name.as_str()) {
                continue;
            }
            if next_slot >= MAX_STUBS {
                break; // guardrail — plenty of headroom for any real library
            }
            let stub_addr = STUB_BASE + next_slot * STUB_STEP;
            next_slot += 1;
            // Patch the GOT slot itself so any code that has already loaded
            // the pointer, or loads it later, jumps to our stub instead of
            // an unmapped/garbage address.
            let bytes = if is_64 {
                stub_addr.to_le_bytes().to_vec()
            } else {
                (stub_addr as u32).to_le_bytes().to_vec()
            };
            let _ = uc.mem_write(imp.got_addr, &bytes[..ptr_size as usize]);
            stub_names.borrow_mut().insert(stub_addr, imp.name);
        }
    }

    let api_calls: Rc<RefCell<Vec<ApiCall>>> = Rc::new(RefCell::new(Vec::new()));
    if !stub_names.borrow().is_empty() {
        let names = Rc::clone(&stub_names);
        let calls = Rc::clone(&api_calls);
        let _ = uc.add_code_hook(STUB_BASE, STUB_BASE + STUB_SIZE, move |uc, addr, _size| {
            let name = match names.borrow().get(&addr) {
                Some(n) => n.clone(),
                None => return,
            };
            if calls.borrow().len() < 256 {
                calls.borrow_mut().push(ApiCall { name });
            }
            // "Return" from the fake call: redirect PC to the real caller's
            // return address instead of executing anything at the stub.
            let ret = if let Some(lr) = lr_reg {
                uc.reg_read(lr).unwrap_or(0)
            } else {
                // x86/x86_64: `call` pushed the return address at [SP]; pop it.
                let ptr_size = if is_x86 && is_64 { 8u64 } else { 4u64 };
                let sp_val = uc.reg_read(sp_reg).unwrap_or(0);
                let mut ret_bytes = [0u8; 8];
                let ret = if uc.mem_read(sp_val, &mut ret_bytes[..ptr_size as usize]).is_ok() {
                    if ptr_size == 8 {
                        u64::from_le_bytes(ret_bytes)
                    } else {
                        u32::from_le_bytes(ret_bytes[..4].try_into().unwrap_or([0; 4])) as u64
                    }
                } else {
                    0
                };
                let _ = uc.reg_write(sp_reg, sp_val + ptr_size);
                ret
            };
            if ret == 0 {
                let _ = uc.emu_stop();
                return;
            }
            let _ = uc.reg_write(pc_reg, ret);
        });
    }

    // Run — errors (unmapped access, invalid instruction, timeout) are all
    // just "stop here"; whatever got decoded before that point still counts.
    //
    // Arm the stop handle BEFORE emu_start so the watchdog (in `emulate()`)
    // can force-unblock us via uc_emu_stop() if we hang past HARD_DEADLINE.
    // Clear it immediately after emu_start returns — the watchdog either
    // already fired (and we're responding to the forced stop) or didn't need
    // to (emu_start returned normally within the deadline).
    stop_handle.store(uc.get_handle() as usize, Ordering::Release);
    let _ = uc.emu_start(entry, 0, TIMEOUT_US, MAX_INSN);
    stop_handle.store(0, Ordering::Release);

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
    result.strings = found;
    result.api_calls = Rc::try_unwrap(api_calls).map(|c| c.into_inner()).unwrap_or_default();
    result
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
