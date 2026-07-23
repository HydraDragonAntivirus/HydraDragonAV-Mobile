use std::path::{Path, PathBuf};

use crate::{collect_files, ExtractError, ExtractedEntry, Result};

/// Extract a RAR archive to a directory on disk.
pub fn extract_to_dir(path: &Path, output_dir: &Path) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(output_dir)?;
    let mut archive =
        unrar::Archive::new(path)
            .open_for_processing()
            .map_err(|e| ExtractError::OperationFailed {
                reason: format!("rar open failed: {e}"),
            })?;

    loop {
        let header = match archive.read_header() {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) => {
                return Err(ExtractError::OperationFailed {
                    reason: format!("rar read_header failed: {e}"),
                })
            }
        };

        archive = if header.entry().is_directory() {
            header.skip().map_err(|e| ExtractError::OperationFailed {
                reason: format!("rar skip failed: {e}"),
            })?
        } else {
            header
                .extract_with_base(output_dir)
                .map_err(|e| ExtractError::OperationFailed {
                    reason: format!("rar extraction failed: {e}"),
                })?
        };
    }

    let mut files = Vec::new();
    collect_files(output_dir, &mut files);
    Ok(files)
}

/// Extract a RAR archive entirely in memory — reads each entry into `Vec<u8>`,
/// paired with its in-archive name.
pub fn extract_from_bytes(data: &[u8]) -> Result<Vec<ExtractedEntry>> {
    let archive_len = data.len();

    // Write to a temp file since `unrar` needs a file path.
    let tmp_dir = std::env::temp_dir().join(format!("hdrartmp_{:x}", crate::rand_byte()));
    let tmp_rar = tmp_dir.join("archive.rar");
    std::fs::create_dir_all(&tmp_dir)?;
    std::fs::write(&tmp_rar, data)?;

    let mut out: Vec<ExtractedEntry> = Vec::new();
    let mut archive = match unrar::Archive::new(&tmp_rar).open_for_processing() {
        Ok(a) => a,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(ExtractError::OperationFailed {
                reason: format!("rar open failed: {e}"),
            });
        }
    };

    loop {
        if out.len() >= crate::MAX_ARCHIVE_ENTRIES {
            break;
        }
        let header = match archive.read_header() {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(ExtractError::OperationFailed {
                    reason: format!("rar read_header failed: {e}"),
                });
            }
        };

        // Skip directory entries; read file entries into memory.
        if header.entry().is_directory() {
            archive = match header.skip() {
                Ok(rest) => rest,
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&tmp_dir);
                    return Err(ExtractError::OperationFailed {
                        reason: format!("rar skip failed: {e}"),
                    });
                }
            };
            continue;
        }

        let entry_name = header.entry().filename.to_string_lossy().into_owned();
        let size_real = header.entry().unpacked_size;
        let (data, rest) = match header.read() {
            Ok(pair) => pair,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(ExtractError::OperationFailed {
                    reason: format!("rar read failed: {e}"),
                });
            }
        };
        if crate::is_decompression_bomb(archive_len, data.len()) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(ExtractError::DecompressionBomb { format: "rar" });
        }
        out.push(ExtractedEntry {
            name: entry_name,
            size_real,
            file_pos: 0,
            data,
        });
        archive = rest;
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
    Ok(out)
}

/// List RAR entry names without extracting their content.
pub fn list_entries(data: &[u8]) -> crate::Result<Vec<crate::EntryInfo>> {
    let tmp_dir = std::env::temp_dir().join(format!("hdrartmp_{:x}", crate::rand_byte()));
    let tmp_rar = tmp_dir.join("archive.rar");
    std::fs::create_dir_all(&tmp_dir)?;
    std::fs::write(&tmp_rar, data)?;

    let mut out = Vec::new();
    let mut archive = match unrar::Archive::new(&tmp_rar).open_for_processing() {
        Ok(a) => a,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(crate::ExtractError::OperationFailed {
                reason: format!("rar open failed: {e}"),
            });
        }
    };

    loop {
        if out.len() >= crate::MAX_ARCHIVE_ENTRIES {
            break;
        }
        let header = match archive.read_header() {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(crate::ExtractError::OperationFailed {
                    reason: format!("rar read_header failed: {e}"),
                });
            }
        };
        let name = header.entry().filename.to_string_lossy().into_owned();
        if !header.entry().is_directory() {
            out.push(crate::EntryInfo {
                name,
                size: header.entry().unpacked_size,
            });
        }
        archive = match header.skip() {
            Ok(rest) => rest,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(crate::ExtractError::OperationFailed {
                    reason: format!("rar skip failed: {e}"),
                });
            }
        };
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
    Ok(out)
}

/// Extract a single RAR entry by name.
pub fn extract_entry(data: &[u8], name: &str) -> crate::Result<Vec<u8>> {
    let archive_len = data.len();
    let tmp_dir = std::env::temp_dir().join(format!("hdrartmp_{:x}", crate::rand_byte()));
    let tmp_rar = tmp_dir.join("archive.rar");
    std::fs::create_dir_all(&tmp_dir)?;
    std::fs::write(&tmp_rar, data)?;

    let mut archive = match unrar::Archive::new(&tmp_rar).open_for_processing() {
        Ok(a) => a,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(crate::ExtractError::OperationFailed {
                reason: format!("rar open failed: {e}"),
            });
        }
    };

    loop {
        let header = match archive.read_header() {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(crate::ExtractError::OperationFailed {
                    reason: format!("rar read_header failed: {e}"),
                });
            }
        };

        let entry_name = header.entry().filename.to_string_lossy().into_owned();
        if header.entry().is_directory() || entry_name != name {
            archive = match header.skip() {
                Ok(rest) => rest,
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&tmp_dir);
                    return Err(crate::ExtractError::OperationFailed {
                        reason: format!("rar skip failed: {e}"),
                    });
                }
            };
            continue;
        }

        let (extracted, _rest) = match header.read() {
            Ok(pair) => pair,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(crate::ExtractError::OperationFailed {
                    reason: format!("rar read failed: {e}"),
                });
            }
        };
        if crate::is_decompression_bomb(archive_len, extracted.len()) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(crate::ExtractError::DecompressionBomb { format: "rar" });
        }
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Ok(extracted);
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
    Err(crate::ExtractError::OperationFailed {
        reason: format!("entry not found in rar: {name}"),
    })
}
