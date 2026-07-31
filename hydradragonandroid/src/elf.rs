//! Minimal ELF32/ELF64 parser — just enough to drive Unicorn emulation
//! (see `emulate.rs`): machine type, entry point, loadable (`PT_LOAD`)
//! segments, and a linear scan of `.dynsym`/`.dynstr` to locate exported
//! symbols by name (specifically `JNI_OnLoad`). Hand-rolled in the same
//! byte-offset-reading style as `pe.rs`, rather than pulling in a generic
//! ELF crate, to keep this dependency-free like the rest of this module.

pub const EM_ARM: u16 = 40;
pub const EM_AARCH64: u16 = 183;
pub const EM_386: u16 = 3;
pub const EM_X86_64: u16 = 62;

const PT_LOAD: u32 = 1;

#[derive(Clone, Debug)]
pub struct Segment {
    pub vaddr: u64,
    pub offset: u64,
    pub filesz: u64,
    pub memsz: u64,
}

#[derive(Clone, Debug)]
pub struct ElfInfo {
    pub is_64: bool,
    pub machine: u16,
    pub entry: u64,
    pub segments: Vec<Segment>,
}

fn read_u16(d: &[u8], off: usize, le: bool) -> Option<u16> {
    let b: [u8; 2] = d.get(off..off + 2)?.try_into().ok()?;
    Some(if le { u16::from_le_bytes(b) } else { u16::from_be_bytes(b) })
}

fn read_u32(d: &[u8], off: usize, le: bool) -> Option<u32> {
    let b: [u8; 4] = d.get(off..off + 4)?.try_into().ok()?;
    Some(if le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) })
}

fn read_u64(d: &[u8], off: usize, le: bool) -> Option<u64> {
    let b: [u8; 8] = d.get(off..off + 8)?.try_into().ok()?;
    Some(if le { u64::from_le_bytes(b) } else { u64::from_be_bytes(b) })
}

/// Parse an ELF file's header + program headers. Returns `None` for anything
/// that isn't a well-formed, little-endian ELF (every Android ABI is LE).
pub fn parse_elf(data: &[u8]) -> Option<ElfInfo> {
    if data.len() < 20 || &data[0..4] != b"\x7fELF" {
        return None;
    }
    let ei_class = data[4]; // 1 = 32-bit, 2 = 64-bit
    let ei_data = data[5]; // 1 = little-endian, 2 = big-endian
    if ei_data != 1 {
        return None; // big-endian ELF — not an Android target, skip
    }
    let is_64 = match ei_class {
        1 => false,
        2 => true,
        _ => return None,
    };

    let machine = read_u16(data, 18, true)?;

    let (entry, phoff, phentsize, phnum) = if is_64 {
        (
            read_u64(data, 24, true)?,
            read_u64(data, 32, true)?,
            read_u16(data, 54, true)? as u64,
            read_u16(data, 56, true)? as u64,
        )
    } else {
        (
            read_u32(data, 24, true)? as u64,
            read_u32(data, 28, true)? as u64,
            read_u16(data, 42, true)? as u64,
            read_u16(data, 44, true)? as u64,
        )
    };

    let mut segments = Vec::new();
    for i in 0..phnum.min(4096) {
        let base = (phoff + i * phentsize) as usize;
        if base + phentsize as usize > data.len() {
            break;
        }
        let p_type = read_u32(data, base, true)?;
        if p_type != PT_LOAD {
            continue;
        }
        let seg = if is_64 {
            // Elf64_Phdr: type(4) flags(4) offset(8) vaddr(8) paddr(8) filesz(8) memsz(8) align(8)
            Segment {
                offset: read_u64(data, base + 8, true)?,
                vaddr: read_u64(data, base + 16, true)?,
                filesz: read_u64(data, base + 32, true)?,
                memsz: read_u64(data, base + 40, true)?,
            }
        } else {
            // Elf32_Phdr: type(4) offset(4) vaddr(4) paddr(4) filesz(4) memsz(4) flags(4) align(4)
            Segment {
                offset: read_u32(data, base + 4, true)? as u64,
                vaddr: read_u32(data, base + 8, true)? as u64,
                filesz: read_u32(data, base + 16, true)? as u64,
                memsz: read_u32(data, base + 20, true)? as u64,
            }
        };
        if seg.memsz > 0 && seg.memsz < 0x1000_0000 {
            segments.push(seg);
        }
    }

    Some(ElfInfo { is_64, machine, entry, segments })
}

/// Linear scan of every section header for `.dynsym`/`.dynstr`, returning the
/// virtual address of the exported symbol named `want` (e.g. `"JNI_OnLoad"`),
/// or `None` if not found / not present. A full hash-table symbol lookup
/// (`.hash`/`.gnu.hash`) isn't needed here — native libraries export at most a
/// few hundred dynamic symbols, so a linear scan is cheap and much simpler.
pub fn find_dynsym(data: &[u8], want: &str) -> Option<u64> {
    if data.len() < 20 || &data[0..4] != b"\x7fELF" || data[5] != 1 {
        return None;
    }
    let is_64 = data[4] == 2;

    let (shoff, shentsize, shnum, shstrndx) = if is_64 {
        (
            read_u64(data, 40, true)?,
            read_u16(data, 58, true)? as u64,
            read_u16(data, 60, true)? as u64,
            read_u16(data, 62, true)? as u64,
        )
    } else {
        (
            read_u32(data, 32, true)? as u64,
            read_u16(data, 46, true)? as u64,
            read_u16(data, 48, true)? as u64,
            read_u16(data, 50, true)? as u64,
        )
    };

    // Section header fields we need: name(4) type(4) ... offset ... size ...
    // link(4, the index of the paired string-table section) entsize.
    let sh = |idx: u64| -> Option<(u32, u64, u64, u32, u64)> {
        let base = (shoff + idx * shentsize) as usize;
        if base + shentsize as usize > data.len() {
            return None;
        }
        if is_64 {
            Some((
                read_u32(data, base, true)?,       // sh_name
                read_u64(data, base + 24, true)?,   // sh_offset
                read_u64(data, base + 32, true)?,   // sh_size
                read_u32(data, base + 40, true)?,   // sh_link
                read_u64(data, base + 56, true)?,   // sh_entsize
            ))
        } else {
            Some((
                read_u32(data, base, true)?,
                read_u32(data, base + 16, true)? as u64,
                read_u32(data, base + 20, true)? as u64,
                read_u32(data, base + 24, true)?,
                read_u32(data, base + 36, true)? as u64,
            ))
        }
    };

    let shstr = sh(shstrndx)?;
    let name_at = |strtab_off: u64, strtab_size: u64, name_off: u32| -> Option<String> {
        let start = (strtab_off + name_off as u64) as usize;
        if start >= data.len() || (strtab_off + strtab_size) as usize > data.len() {
            return None;
        }
        let end = data[start..].iter().position(|&b| b == 0)? + start;
        Some(String::from_utf8_lossy(&data[start..end]).to_string())
    };

    let mut dynsym: Option<(u64, u64, u64, u32)> = None; // offset,size,entsize,link
    for i in 0..shnum.min(4096) {
        let (name_off, offset, size, link, entsize) = sh(i)?;
        let name = name_at(shstr.1, shstr.2, name_off).unwrap_or_default();
        if name == ".dynsym" && entsize > 0 {
            dynsym = Some((offset, size, entsize, link));
            break;
        }
    }
    let (sym_off, sym_size, sym_entsize, strtab_link) = dynsym?;
    let (_, strtab_off, strtab_size, _, _) = sh(strtab_link as u64)?;

    let count = sym_size / sym_entsize;
    for i in 0..count.min(65536) {
        let base = (sym_off + i * sym_entsize) as usize;
        if base + sym_entsize as usize > data.len() {
            break;
        }
        // Elf64_Sym: name(4) info(1) other(1) shndx(2) value(8) size(8)
        // Elf32_Sym: name(4) value(4) size(4) info(1) other(1) shndx(2)
        let (st_name, st_value) = if is_64 {
            (read_u32(data, base, true)?, read_u64(data, base + 8, true)?)
        } else {
            (read_u32(data, base, true)?, read_u32(data, base + 4, true)? as u64)
        };
        if st_value == 0 {
            continue; // undefined/imported, not exported here
        }
        if let Some(sym_name) = name_at(strtab_off, strtab_size, st_name) {
            if sym_name == want {
                return Some(st_value);
            }
        }
    }
    None
}

/// An imported (undefined) dynamic symbol along with the GOT/data address a
/// relocation says should hold its resolved address — i.e. "this library
/// calls `<name>` through the value stored at `got_addr`".
#[derive(Clone, Debug)]
pub struct Import {
    pub name: String,
    pub got_addr: u64,
}

/// Resolve every `R_*_JUMP_SLOT`/`R_*_GLOB_DAT`/`R_*_ABS` relocation against
/// an undefined `.dynsym` entry, from `.rela.dyn`/`.rela.plt` (or the 32-bit
/// `.rel.dyn`/`.rel.plt` variants). This is a standard SysV relocation walk —
/// Android's packed `.android.rela` (APS2, LEB128-encoded) format is a
/// distinct encoding and is intentionally NOT handled here.
pub fn find_imports(data: &[u8]) -> Vec<Import> {
    let mut out = Vec::new();
    if data.len() < 20 || &data[0..4] != b"\x7fELF" || data[5] != 1 {
        return out;
    }
    let is_64 = data[4] == 2;

    let (shoff, shentsize, shnum, shstrndx) = match (|| -> Option<(u64, u64, u64, u64)> {
        if is_64 {
            Some((
                read_u64(data, 40, true)?,
                read_u16(data, 58, true)? as u64,
                read_u16(data, 60, true)? as u64,
                read_u16(data, 62, true)? as u64,
            ))
        } else {
            Some((
                read_u32(data, 32, true)? as u64,
                read_u16(data, 46, true)? as u64,
                read_u16(data, 48, true)? as u64,
                read_u16(data, 50, true)? as u64,
            ))
        }
    })() {
        Some(v) => v,
        None => return out,
    };

    let sh = |idx: u64| -> Option<(u32, u32, u64, u64, u32, u64)> {
        let base = (shoff + idx * shentsize) as usize;
        if base + shentsize as usize > data.len() {
            return None;
        }
        if is_64 {
            Some((
                read_u32(data, base, true)?,       // sh_name
                read_u32(data, base + 4, true)?,    // sh_type
                read_u64(data, base + 24, true)?,   // sh_offset
                read_u64(data, base + 32, true)?,   // sh_size
                read_u32(data, base + 40, true)?,   // sh_link
                read_u64(data, base + 56, true)?,   // sh_entsize
            ))
        } else {
            Some((
                read_u32(data, base, true)?,
                read_u32(data, base + 4, true)?,
                read_u32(data, base + 16, true)? as u64,
                read_u32(data, base + 20, true)? as u64,
                read_u32(data, base + 24, true)?,
                read_u32(data, base + 36, true)? as u64,
            ))
        }
    };

    let shstr = match sh(shstrndx) {
        Some(v) => v,
        None => return out,
    };
    let name_at = |strtab_off: u64, strtab_size: u64, name_off: u32| -> Option<String> {
        let start = (strtab_off + name_off as u64) as usize;
        if start >= data.len() || (strtab_off + strtab_size) as usize > data.len() {
            return None;
        }
        let end = data[start..].iter().position(|&b| b == 0)? + start;
        Some(String::from_utf8_lossy(&data[start..end]).to_string())
    };

    // Locate .dynsym (+ its paired .dynstr via sh_link) and every relocation
    // section (SHT_REL = 9, SHT_RELA = 4).
    const SHT_REL: u32 = 9;
    const SHT_RELA: u32 = 4;
    let mut dynsym: Option<(u64, u64, u64, u32)> = None; // offset,size,entsize,link
    let mut reloc_sections: Vec<(u32, u64, u64, u64)> = Vec::new(); // type,offset,size,entsize
    for i in 0..shnum.min(4096) {
        let (name_off, sh_type, offset, size, link, entsize) = match sh(i) {
            Some(v) => v,
            None => break,
        };
        let name = name_at(shstr.2, shstr.3, name_off).unwrap_or_default();
        if name == ".dynsym" && entsize > 0 {
            dynsym = Some((offset, size, entsize, link));
        } else if (sh_type == SHT_REL || sh_type == SHT_RELA) && entsize > 0 {
            reloc_sections.push((sh_type, offset, size, entsize));
        }
    }
    let (sym_off, sym_size, sym_entsize, strtab_link) = match dynsym {
        Some(v) => v,
        None => return out,
    };
    let (_, _, strtab_off, strtab_size, _, _) = match sh(strtab_link as u64) {
        Some(v) => v,
        None => return out,
    };
    let sym_count = sym_size / sym_entsize;

    // Resolve a dynsym index -> import name, but only for UNDEFINED entries
    // (st_value == 0) — i.e. symbols this library imports rather than exports.
    let undefined_name = |sym_idx: u64| -> Option<String> {
        if sym_idx >= sym_count {
            return None;
        }
        let base = (sym_off + sym_idx * sym_entsize) as usize;
        if base + sym_entsize as usize > data.len() {
            return None;
        }
        let (st_name, st_value) = if is_64 {
            (read_u32(data, base, true)?, read_u64(data, base + 8, true)?)
        } else {
            (read_u32(data, base, true)?, read_u32(data, base + 4, true)? as u64)
        };
        if st_value != 0 {
            return None; // exported/defined, not an import
        }
        name_at(strtab_off, strtab_size, st_name)
    };

    for (sh_type, offset, size, entsize) in reloc_sections {
        let count = size / entsize;
        for i in 0..count.min(1_000_000) {
            let base = (offset + i * entsize) as usize;
            if base + entsize as usize > data.len() {
                break;
            }
            let (r_offset, r_info) = if is_64 {
                let off = match read_u64(data, base, true) {
                    Some(v) => v,
                    None => break,
                };
                let info = match read_u64(data, base + 8, true) {
                    Some(v) => v,
                    None => break,
                };
                (off, info)
            } else {
                let off = match read_u32(data, base, true) {
                    Some(v) => v as u64,
                    None => break,
                };
                let info = match read_u32(data, base + 4, true) {
                    Some(v) => v as u64,
                    None => break,
                };
                (off, info)
            };
            let sym_idx = if is_64 { r_info >> 32 } else { r_info >> 8 };
            if sym_idx == 0 {
                continue;
            }
            if let Some(name) = undefined_name(sym_idx) {
                let _ = sh_type; // REL vs RELA only affects addend layout, irrelevant here
                out.push(Import { name, got_addr: r_offset });
            }
        }
    }

    out
}
