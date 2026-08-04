//! Minimal ELF32/ELF64 parser used to derive real features from native
//! libraries (`lib/**/*.so`) packaged inside an APK.
//!
//! Format reference: ELF header/section layout is the standard, publicly
//! documented System V ABI format. The behavior categories below (network,
//! file, exec, anti-debug, emulator-detection strings) are the same
//! categories used in published Android sandbox-evasion / native-library
//! malware analysis, e.g. Vidas & Christin, "Evading Android Runtime
//! Analysis via Sandbox Detection" (ASIACCS 2014), and are just standard
//! Bionic/libc function names and build-fingerprint strings — not exploit
//! code.

const NETWORK_SYMS: &[&str] = &[
    "socket",
    "connect",
    "send",
    "sendto",
    "recv",
    "recvfrom",
    "gethostbyname",
    "getaddrinfo",
    "inet_addr",
    "inet_aton",
];

const FILE_SYMS: &[&str] = &[
    "open", "open64", "fopen", "read", "write", "unlink", "remove", "rename", "chmod", "mkdir",
    "creat",
];

const EXEC_SYMS: &[&str] = &[
    "system", "execve", "execl", "execlp", "execvp", "fork", "vfork", "popen", "dlopen",
];

const ANTI_DEBUG_SYMS: &[&str] = &["ptrace", "kill", "signal", "sigaction"];

/// Strings that, when found in a native library, indicate anti-analysis or
/// emulator/sandbox-detection logic (publicly documented indicators).
const ANTI_DEBUG_STRINGS: &[&str] = &[
    "tracerpid",
    "/proc/self/status",
    "frida",
    "xposed",
    "gdbserver",
    "/proc/self/maps",
];
const EMULATOR_STRINGS: &[&str] = &[
    "goldfish",
    "ranchu",
    "vbox86",
    "sdk_gphone",
    "generic_x86",
    "genymotion",
    "google_sdk",
    "/dev/qemu_pipe",
    "andy",
];

const MIN_STR_LEN: usize = 5;

#[derive(Debug, Default, Clone)]
pub struct ElfFeatures {
    pub emulated_strings: u32,
    pub network_calls: u32,
    pub file_calls: u32,
    pub exec_calls: u32,
    pub anti_debug: u32,
}

fn read_u16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}
fn read_u32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}
fn read_u64(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

#[allow(dead_code)]
struct SectionHeader {
    name_off: u32,
    sh_type: u32,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

/// Parses the section header table and returns imported dynamic symbol
/// names (from `.dynsym`/`.dynstr`). Works for both 32- and 64-bit ELF.
fn parse_sections(b: &[u8]) -> Option<Vec<SectionHeader>> {
    if b.len() < 20 || &b[0..4] != b"\x7fELF" {
        return None;
    }
    let is64 = b[4] == 2;
    let (e_shoff, e_shentsize, e_shnum, e_shstrndx): (u64, u16, u16, u16) = if is64 {
        (
            read_u64(b, 0x28)?,
            read_u16(b, 0x3a)?,
            read_u16(b, 0x3c)?,
            read_u16(b, 0x3e)?,
        )
    } else {
        (
            read_u32(b, 0x20)? as u64,
            read_u16(b, 0x2e)?,
            read_u16(b, 0x30)?,
            read_u16(b, 0x32)?,
        )
    };
    let _ = e_shstrndx;

    let mut sections = Vec::with_capacity(e_shnum as usize);
    for i in 0..e_shnum as u64 {
        let sh_off = e_shoff as usize + (i as usize) * e_shentsize as usize;
        if sh_off + 64 > b.len() {
            break;
        }
        if is64 {
            sections.push(SectionHeader {
                name_off: read_u32(b, sh_off)?,
                sh_type: read_u32(b, sh_off + 4)?,
                offset: read_u64(b, sh_off + 24)?,
                size: read_u64(b, sh_off + 32)?,
                link: read_u32(b, sh_off + 40)?,
                entsize: read_u64(b, sh_off + 56)?,
            });
        } else {
            sections.push(SectionHeader {
                name_off: read_u32(b, sh_off)?,
                sh_type: read_u32(b, sh_off + 4)?,
                offset: read_u32(b, sh_off + 16)? as u64,
                size: read_u32(b, sh_off + 20)? as u64,
                link: read_u32(b, sh_off + 24)?,
                entsize: read_u32(b, sh_off + 36)? as u64,
            });
        }
    }
    Some(sections)
}

fn c_str_at(b: &[u8], off: usize) -> String {
    let end = b[off..]
        .iter()
        .position(|&c| c == 0)
        .map(|p| off + p)
        .unwrap_or(b.len());
    String::from_utf8_lossy(&b[off..end]).into_owned()
}

/// Extracts imported dynamic symbol names via `.dynsym` (SHT_DYNSYM = 11),
/// resolving names through the linked `.dynstr` string table section.
fn dynamic_symbol_names(b: &[u8], sections: &[SectionHeader]) -> Vec<String> {
    const SHT_DYNSYM: u32 = 11;
    let is64 = b.len() > 4 && b[4] == 2;
    let mut names = Vec::new();

    for sec in sections.iter().filter(|s| s.sh_type == SHT_DYNSYM) {
        let strtab = match sections.get(sec.link as usize) {
            Some(s) => s,
            None => continue,
        };
        let entsize = if sec.entsize > 0 {
            sec.entsize as usize
        } else if is64 {
            24
        } else {
            16
        };
        let count = if entsize > 0 {
            sec.size as usize / entsize
        } else {
            0
        };
        for i in 0..count {
            let sym_off = sec.offset as usize + i * entsize;
            // st_name is a u32 at offset 0 in both Elf32_Sym and Elf64_Sym.
            let name_idx = match read_u32(b, sym_off) {
                Some(v) => v as usize,
                None => continue,
            };
            if name_idx == 0 {
                continue;
            }
            let str_off = strtab.offset as usize + name_idx;
            if str_off < b.len() {
                let name = c_str_at(b, str_off);
                if !name.is_empty() {
                    names.push(name);
                }
            }
        }
    }
    names
}

/// Harvests printable ASCII strings (len >= MIN_STR_LEN) from the whole
/// file, for matching against known anti-debug / emulator-detection
/// indicators that may appear as plain string literals rather than symbol
/// names.
fn harvest_strings(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in data.iter().enumerate() {
        let printable = (0x20..0x7f).contains(&b);
        if printable {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            if i - s >= MIN_STR_LEN {
                if let Ok(t) = std::str::from_utf8(&data[s..i]) {
                    out.push(t.to_string());
                }
            }
        }
    }
    if let Some(s) = start {
        if data.len() - s >= MIN_STR_LEN {
            if let Ok(t) = std::str::from_utf8(&data[s..]) {
                out.push(t.to_string());
            }
        }
    }
    out
}

/// Analyzes a single native library (`.so`) and returns real, content-based
/// counts. Returns `None` if `data` is not a recognizable ELF file.
pub fn analyze(data: &[u8]) -> Option<ElfFeatures> {
    let sections = parse_sections(data)?;
    let symbols = dynamic_symbol_names(data, &sections);
    let strings = harvest_strings(data);

    let mut feats = ElfFeatures::default();

    for sym in &symbols {
        if NETWORK_SYMS.contains(&sym.as_str()) {
            feats.network_calls += 1;
        }
        if FILE_SYMS.contains(&sym.as_str()) {
            feats.file_calls += 1;
        }
        if EXEC_SYMS.contains(&sym.as_str()) {
            feats.exec_calls += 1;
        }
        if ANTI_DEBUG_SYMS.contains(&sym.as_str()) {
            feats.anti_debug += 1;
        }
    }

    for s in &strings {
        let lower = s.to_ascii_lowercase();
        if EMULATOR_STRINGS.iter().any(|e| lower.contains(e)) {
            feats.emulated_strings += 1;
        }
        if ANTI_DEBUG_STRINGS.iter().any(|e| lower.contains(e)) {
            feats.anti_debug += 1;
        }
    }

    Some(feats)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf() {
        assert!(analyze(b"not an elf file").is_none());
    }

    /// Builds a minimal, structurally real ELF64 file with a .dynsym /
    /// .dynstr section pair referencing a few symbol names, to exercise the
    /// actual section-header-table + dynamic-symbol-table parsing path
    /// (not just string harvesting).
    pub(crate) fn build_minimal_elf64(symbol_names: &[&str]) -> Vec<u8> {
        let mut dynstr = vec![0u8]; // index 0 is the empty string
        let mut name_offsets = Vec::new();
        for name in symbol_names {
            name_offsets.push(dynstr.len() as u32);
            dynstr.extend_from_slice(name.as_bytes());
            dynstr.push(0);
        }

        // Layout: [ELF header 64][dynstr][dynsym entries][2 section headers]
        let ehdr_size = 64usize;
        let dynstr_off = ehdr_size;
        let dynstr_size = dynstr.len();
        let dynsym_off = dynstr_off + dynstr_size;
        let sym_entsize = 24usize; // Elf64_Sym
        let dynsym_size = symbol_names.len() * sym_entsize;
        let shoff = dynsym_off + dynsym_size;

        let mut buf = vec![0u8; shoff + 2 * 64];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // little endian
        // e_shoff (offset 0x28), e_shentsize(0x3a)=64, e_shnum(0x3c)=2, e_shstrndx(0x3e)=0
        buf[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
        buf[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        buf[0x3c..0x3e].copy_from_slice(&2u16.to_le_bytes());

        buf[dynstr_off..dynstr_off + dynstr_size].copy_from_slice(&dynstr);

        for (i, &off) in name_offsets.iter().enumerate() {
            let sym_off = dynsym_off + i * sym_entsize;
            buf[sym_off..sym_off + 4].copy_from_slice(&off.to_le_bytes()); // st_name
            // remaining Elf64_Sym fields left as zero (info/other/shndx/value/size)
        }

        // Section 0: .dynstr (SHT_STRTAB = 3)
        let sh0 = shoff;
        buf[sh0 + 4..sh0 + 8].copy_from_slice(&3u32.to_le_bytes()); // sh_type
        buf[sh0 + 24..sh0 + 32].copy_from_slice(&(dynstr_off as u64).to_le_bytes()); // sh_offset
        buf[sh0 + 32..sh0 + 40].copy_from_slice(&(dynstr_size as u64).to_le_bytes()); // sh_size

        // Section 1: .dynsym (SHT_DYNSYM = 11), sh_link -> section 0
        let sh1 = shoff + 64;
        buf[sh1 + 4..sh1 + 8].copy_from_slice(&11u32.to_le_bytes()); // sh_type
        buf[sh1 + 24..sh1 + 32].copy_from_slice(&(dynsym_off as u64).to_le_bytes()); // sh_offset
        buf[sh1 + 32..sh1 + 40].copy_from_slice(&(dynsym_size as u64).to_le_bytes()); // sh_size
        buf[sh1 + 40..sh1 + 44].copy_from_slice(&0u32.to_le_bytes()); // sh_link -> .dynstr
        buf[sh1 + 56..sh1 + 64].copy_from_slice(&(sym_entsize as u64).to_le_bytes()); // sh_entsize

        buf
    }

    #[test]
    fn parses_real_dynsym_section_and_categorizes_symbols() {
        let elf = build_minimal_elf64(&["ptrace", "connect", "open", "system", "some_app_func"]);
        let feats = analyze(&elf).expect("should parse as ELF");
        assert_eq!(feats.anti_debug, 1);
        assert_eq!(feats.network_calls, 1);
        assert_eq!(feats.file_calls, 1);
        assert_eq!(feats.exec_calls, 1);
    }

    #[test]
    fn finds_emulator_strings_in_raw_bytes() {
        // A file that isn't a parseable ELF still gets rejected outright;
        // but harvest_strings itself should find known indicators.
        let data = b"junk....goldfish....more junk....ptrace_thing";
        let strs = harvest_strings(data);
        assert!(
            strs.iter()
                .any(|s| s.to_ascii_lowercase().contains("goldfish"))
        );
    }
}
