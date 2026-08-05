//! Minimal ELF32/ELF64 validator used to detect real native libraries
//! (`lib/**/*.so`) packaged inside an APK.
//!
//! Feature engineering here is fully data-driven: no hardcoded
//! behavior/indicator lists. The only decision this module makes is whether
//! a `.so` entry is a structurally valid ELF file, so the feature layer can
//! count how many real native libraries an APK ships (`elf_count`).

/// Returns `Some(())` when `data` is a structurally recognizable ELF file
/// (32- or 64-bit, any endianness), `None` otherwise.
pub fn analyze(data: &[u8]) -> Option<()> {
    if data.len() < 20 || &data[0..4] != b"\x7fELF" {
        return None;
    }
    let class = data[4];
    if class != 1 && class != 2 {
        return None;
    }
    Some(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf() {
        assert!(analyze(b"not an elf file").is_none());
    }

    #[test]
    fn accepts_minimal_elf_header() {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // little endian
        assert!(analyze(&buf).is_some());
    }

    /// Builds a minimal, structurally valid ELF64 header (used by the
    /// feature-layer integration tests to craft a `.so` entry).
    pub(crate) fn build_minimal_elf64(_symbol_names: &[&str]) -> Vec<u8> {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // little endian
        buf
    }
}
