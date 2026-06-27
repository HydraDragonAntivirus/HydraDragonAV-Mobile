use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

/// Magic bytes for detection.
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
const ZIP_LOCAL_MAGIC: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const XZ_MAGIC: [u8; 6] = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
const LZMA_STREAM_MAGIC: [u8; 2] = [0x5d, 0x00];
/// ustar tar has "ustar" at offset 257.
const TAR_USTAR_OFFSET: usize = 257;
const TAR_USTAR_MAGIC: [u8; 5] = *b"ustar";
/// RAR v1.5: `Rar!\x1a\x07\x00`
const RAR15_MAGIC: [u8; 7] = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];
/// RAR v5: `Rar!\x1a\x07\x01\x00`
const RAR5_MAGIC: [u8; 8] = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00];

mod rar;

/// Result of extracting an archive: list of extracted file paths.
pub struct ExtractResult {
    pub files: Vec<PathBuf>,
    pub output_dir: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("extraction failed: {reason}")]
    OperationFailed { reason: String },
}

pub(crate) type Result<T> = std::result::Result<T, ExtractError>;

/// Detect archive/compression format by content sniffing.
pub fn detect_format(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(&GZIP_MAGIC) {
        Some("gz")
    } else if data.starts_with(&ZIP_LOCAL_MAGIC) {
        Some("zip")
    } else if data.starts_with(&XZ_MAGIC) {
        Some("xz")
    } else if data.starts_with(&LZMA_STREAM_MAGIC) {
        Some("lzma")
    } else if data.len() > TAR_USTAR_OFFSET + 5
        && data[TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + 5] == TAR_USTAR_MAGIC
    {
        Some("tar")
    } else if is_rar(data) {
        Some("rar")
    } else {
        None
    }
}

fn is_tar(data: &[u8]) -> bool {
    data.len() > TAR_USTAR_OFFSET + 5
        && data[TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + 5] == TAR_USTAR_MAGIC
}

fn is_gzip(data: &[u8]) -> bool {
    data.starts_with(&GZIP_MAGIC)
}

fn is_zip(data: &[u8]) -> bool {
    data.starts_with(&ZIP_LOCAL_MAGIC)
}

fn is_xz(data: &[u8]) -> bool {
    data.starts_with(&XZ_MAGIC)
}

fn is_lzma(data: &[u8]) -> bool {
    data.starts_with(&LZMA_STREAM_MAGIC) || (data.len() > 13 && data[..2] == LZMA_STREAM_MAGIC)
}

fn is_rar(data: &[u8]) -> bool {
    data.starts_with(&RAR5_MAGIC) || data.starts_with(&RAR15_MAGIC)
}

// ---------------------------------------------------------------------------
// Extractors
// ---------------------------------------------------------------------------

fn extract_tar<R: Read>(reader: R, output_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut archive = tar::Archive::new(reader);
    archive
        .unpack(output_dir)
        .map_err(|e| ExtractError::OperationFailed {
            reason: format!("tar extraction failed: {e}"),
        })?;
    let mut files = Vec::new();
    collect_files(output_dir, &mut files);
    Ok(files)
}

fn extract_gzip(path: &Path, output_dir: &Path) -> Result<Vec<PathBuf>> {
    let file = std::fs::File::open(path)?;
    let decoder = flate2::read::GzDecoder::new(file);

    let mut decompressed = Vec::new();
    std::io::Read::take(&mut std::io::BufReader::new(decoder), u64::MAX)
        .read_to_end(&mut decompressed)
        .map_err(|e| ExtractError::OperationFailed {
            reason: format!("gzip decompression failed: {e}"),
        })?;

    if is_tar(&decompressed) {
        extract_tar(Cursor::new(decompressed), output_dir)
    } else {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("decompressed");
        let out_path = output_dir.join(stem);
        std::fs::write(&out_path, &decompressed)?;
        Ok(vec![out_path])
    }
}

fn extract_xz(path: &Path, output_dir: &Path) -> Result<Vec<PathBuf>> {
    let file = std::fs::File::open(path)?;
    let mut decoder = lzma_rust2::XzReader::new(file, true);

    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| ExtractError::OperationFailed {
            reason: format!("xz decompression failed: {e}"),
        })?;

    if is_tar(&decompressed) {
        extract_tar(Cursor::new(decompressed), output_dir)
    } else {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("decompressed");
        let out_path = output_dir.join(stem);
        std::fs::write(&out_path, &decompressed)?;
        Ok(vec![out_path])
    }
}

fn extract_lzma(path: &Path, output_dir: &Path) -> Result<Vec<PathBuf>> {
    let file = std::fs::File::open(path)?;
    let mut decoder = lzma_rust2::LzmaReader::new_mem_limit(file, u32::MAX, None).map_err(|e| {
        ExtractError::OperationFailed {
            reason: format!("lzma decoder init failed: {e}"),
        }
    })?;

    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| ExtractError::OperationFailed {
            reason: format!("lzma decompression failed: {e}"),
        })?;

    if is_tar(&decompressed) {
        extract_tar(Cursor::new(decompressed), output_dir)
    } else {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("decompressed");
        let out_path = output_dir.join(stem);
        std::fs::write(&out_path, &decompressed)?;
        Ok(vec![out_path])
    }
}

fn extract_plain_tar(path: &Path, output_dir: &Path) -> Result<Vec<PathBuf>> {
    let file = std::fs::File::open(path)?;
    extract_tar(file, output_dir)
}

fn extract_zip(data: &[u8], output_dir: &Path) -> Result<Vec<PathBuf>> {
    let eocd = find_eocd(data).ok_or_else(|| ExtractError::OperationFailed {
        reason: "zip end-of-central-directory not found".to_string(),
    })?;
    let total_entries = read_u16(data, eocd + 10).unwrap_or(0) as usize;
    let central_offset = read_u32(data, eocd + 16).unwrap_or(0) as usize;
    let mut cursor = central_offset;
    let mut files = Vec::new();

    for _ in 0..total_entries {
        if data.get(cursor..cursor + 4) != Some(b"PK\x01\x02") {
            break;
        }
        let method = read_u16(data, cursor + 10).unwrap_or(0);
        let compressed_size = read_u32(data, cursor + 20).unwrap_or(0) as usize;
        let name_len = read_u16(data, cursor + 28).unwrap_or(0) as usize;
        let extra_len = read_u16(data, cursor + 30).unwrap_or(0) as usize;
        let comment_len = read_u16(data, cursor + 32).unwrap_or(0) as usize;
        let local_offset = read_u32(data, cursor + 42).unwrap_or(0) as usize;
        let name_start = cursor + 46;
        let name_end = name_start.saturating_add(name_len);
        let Some(name_bytes) = data.get(name_start..name_end) else {
            break;
        };
        let name = String::from_utf8_lossy(name_bytes).replace('\\', "/");

        if !name.ends_with('/') {
            if let Some(output_path) = safe_output_path(output_dir, &name) {
                if data.get(local_offset..local_offset + 4) == Some(b"PK\x03\x04") {
                    let local_name_len = read_u16(data, local_offset + 26).unwrap_or(0) as usize;
                    let local_extra_len = read_u16(data, local_offset + 28).unwrap_or(0) as usize;
                    let data_start = local_offset
                        .saturating_add(30)
                        .saturating_add(local_name_len)
                        .saturating_add(local_extra_len);
                    let data_end = data_start.saturating_add(compressed_size);
                    if let Some(compressed) = data.get(data_start..data_end) {
                        let extracted = match method {
                            0 => compressed.to_vec(),
                            8 => {
                                let mut decoder =
                                    flate2::read::DeflateDecoder::new(Cursor::new(compressed));
                                let mut out = Vec::new();
                                decoder.read_to_end(&mut out).map_err(|e| {
                                    ExtractError::OperationFailed {
                                        reason: format!("zip deflate failed: {e}"),
                                    }
                                })?;
                                out
                            }
                            _ => Vec::new(),
                        };
                        if !extracted.is_empty() || method == 0 {
                            if let Some(parent) = output_path.parent() {
                                std::fs::create_dir_all(parent)?;
                            }
                            std::fs::write(&output_path, extracted)?;
                            files.push(output_path);
                        }
                    }
                }
            }
        }

        cursor = name_end
            .saturating_add(extra_len)
            .saturating_add(comment_len);
    }

    Ok(files)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Extract any supported archive by content sniffing.
///
/// Supported formats: .tar, .tar.gz/.tgz, .tar.xz, .tar.lzma,
/// .gz, .xz, .lzma, .7z, .rar.
/// Detects format by magic bytes, not file extension.
pub fn extract_archive(path: &Path, output_dir: &Path) -> Result<ExtractResult> {
    std::fs::create_dir_all(output_dir)?;
    let data = std::fs::read(path)?;

    let files = if is_gzip(&data) {
        extract_gzip(path, output_dir)?
    } else if is_zip(&data) {
        extract_zip(&data, output_dir)?
    } else if is_xz(&data) {
        extract_xz(path, output_dir)?
    } else if is_lzma(&data) {
        extract_lzma(path, output_dir)?
    } else if is_tar(&data) {
        extract_plain_tar(path, output_dir)?
    } else if is_rar(&data) {
        rar::extract_to_dir(path, output_dir)?
    } else {
        // Try 7z as fallback (it has its own magic check)
        sevenz_rust2::decompress_file(path, output_dir).map_err(|e| {
            ExtractError::OperationFailed {
                reason: format!("7z extraction failed: {e}"),
            }
        })?;
        let mut files = Vec::new();
        collect_files(output_dir, &mut files);
        files
    };

    Ok(ExtractResult {
        files,
        output_dir: output_dir.to_path_buf(),
    })
}

/// Extract an archive from an in-memory byte buffer — entirely in memory,
/// no temp files written to disk.
pub fn extract_archive_from_bytes(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    if is_gzip(data) {
        let decoder = flate2::read::GzDecoder::new(Cursor::new(data));
        let mut decompressed = Vec::new();
        std::io::Read::take(
            &mut std::io::BufReader::new(decoder),
            u64::MAX,
        )
        .read_to_end(&mut decompressed)
        .map_err(|e| ExtractError::OperationFailed {
            reason: format!("gzip decompression failed: {e}"),
        })?;
        if is_tar(&decompressed) {
            return extract_tar_from_bytes(&decompressed);
        }
        return Ok(vec![decompressed]);
    }
    if is_zip(data) {
        return extract_zip_from_bytes(data);
    }
    if is_xz(data) {
        let mut decoder = lzma_rust2::XzReader::new(Cursor::new(data), true);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| ExtractError::OperationFailed {
                reason: format!("xz decompression failed: {e}"),
            })?;
        if is_tar(&decompressed) {
            return extract_tar_from_bytes(&decompressed);
        }
        return Ok(vec![decompressed]);
    }
    if is_lzma(data) {
        let mut decoder =
            lzma_rust2::LzmaReader::new_mem_limit(Cursor::new(data), u32::MAX, None).map_err(
                |e| ExtractError::OperationFailed {
                    reason: format!("lzma decoder init failed: {e}"),
                },
            )?;
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| ExtractError::OperationFailed {
                reason: format!("lzma decompression failed: {e}"),
            })?;
        if is_tar(&decompressed) {
            return extract_tar_from_bytes(&decompressed);
        }
        return Ok(vec![decompressed]);
    }
    if is_tar(data) {
        return extract_tar_from_bytes(data);
    }
    if is_rar(data) {
        return rar::extract_from_bytes(data);
    }
    // 7z as fallback (in-memory via reader-based API)
    extract_7z_from_bytes(data)
}

fn extract_tar_from_bytes(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut archive = tar::Archive::new(Cursor::new(data));
    let mut out: Vec<Vec<u8>> = Vec::new();
    for entry in archive.entries().map_err(|e| ExtractError::OperationFailed {
        reason: format!("tar entries failed: {e}"),
    })? {
        let mut entry = entry.map_err(|e| ExtractError::OperationFailed {
            reason: format!("tar entry read failed: {e}"),
        })?;
        if entry.header().entry_type().is_file() {
            let mut content = Vec::new();
            entry
                .read_to_end(&mut content)
                .map_err(|e| ExtractError::OperationFailed {
                    reason: format!("tar entry decompress failed: {e}"),
                })?;
            out.push(content);
        }
    }
    Ok(out)
}

fn extract_zip_from_bytes(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let eocd = find_eocd(data).ok_or_else(|| ExtractError::OperationFailed {
        reason: "zip end-of-central-directory not found".to_string(),
    })?;
    let total_entries = read_u16(data, eocd + 10).unwrap_or(0) as usize;
    let central_offset = read_u32(data, eocd + 16).unwrap_or(0) as usize;
    let mut cursor = central_offset;
    let mut out: Vec<Vec<u8>> = Vec::new();

    for _ in 0..total_entries {
        if data.get(cursor..cursor + 4) != Some(b"PK\x01\x02") {
            break;
        }
        let method = read_u16(data, cursor + 10).unwrap_or(0);
        let compressed_size = read_u32(data, cursor + 20).unwrap_or(0) as usize;
        let name_len = read_u16(data, cursor + 28).unwrap_or(0) as usize;
        let extra_len = read_u16(data, cursor + 30).unwrap_or(0) as usize;
        let comment_len = read_u16(data, cursor + 32).unwrap_or(0) as usize;
        let local_offset = read_u32(data, cursor + 42).unwrap_or(0) as usize;
        let name_start = cursor + 46;
        let name_end = name_start.saturating_add(name_len);
        let Some(name_bytes) = data.get(name_start..name_end) else {
            break;
        };
        let name = String::from_utf8_lossy(name_bytes).replace('\\', "/");

        if !name.ends_with('/') {
            if data.get(local_offset..local_offset + 4) == Some(b"PK\x03\x04") {
                let local_name_len = read_u16(data, local_offset + 26).unwrap_or(0) as usize;
                let local_extra_len = read_u16(data, local_offset + 28).unwrap_or(0) as usize;
                let data_start = local_offset
                    .saturating_add(30)
                    .saturating_add(local_name_len)
                    .saturating_add(local_extra_len);
                let data_end = data_start.saturating_add(compressed_size);
                if let Some(compressed) = data.get(data_start..data_end) {
                    let extracted = match method {
                        0 => compressed.to_vec(),
                        8 => {
                            let mut decoder =
                                flate2::read::DeflateDecoder::new(Cursor::new(compressed));
                            let mut buf = Vec::new();
                            decoder.read_to_end(&mut buf).map_err(|e| {
                                ExtractError::OperationFailed {
                                    reason: format!("zip deflate failed: {e}"),
                                }
                            })?;
                            buf
                        }
                        _ => Vec::new(),
                    };
                    if !extracted.is_empty() || method == 0 {
                        out.push(extracted);
                    }
                }
            }
        }

        cursor = name_end
            .saturating_add(extra_len)
            .saturating_add(comment_len);
    }

    Ok(out)
}

fn extract_7z_from_bytes(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let dest = std::env::temp_dir().join(format!("hdext7z_{:x}", rand_byte()));

    let result = sevenz_rust2::decompress_with_extract_fn(
        Cursor::new(data),
        &dest,
        |_entry, reader, _suggested| {
            let mut content = Vec::new();
            reader
                .read_to_end(&mut content)
                .map_err(sevenz_rust2::Error::from)?;
            out.push(content);
            Ok(true)
        },
    );

    let _ = std::fs::remove_dir_all(&dest);

    result.map_err(|e| ExtractError::OperationFailed {
        reason: format!("7z extraction failed: {e}"),
    })?;

    Ok(out)
}

/// Generate a random byte for directory name uniqueness.
pub(crate) fn rand_byte() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    // Mix with a simple counter-like value from the process
    (nanos as u32).wrapping_mul(6364136223846793005u64 as u32)
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    let min = data.len().saturating_sub(65_557);
    (min..data.len().saturating_sub(3))
        .rev()
        .find(|offset| data.get(*offset..offset + 4) == Some(b"PK\x05\x06"))
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn safe_output_path(output_dir: &Path, name: &str) -> Option<PathBuf> {
    let mut out = output_dir.to_path_buf();
    for component in Path::new(name).components() {
        match component {
            std::path::Component::Normal(part) => out.push(part),
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }
    Some(out)
}

pub(crate) fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_files(&path, out);
            } else {
                out.push(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_rar_signature() {
        let rar5 = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00];
        assert_eq!(detect_format(&rar5), Some("rar"));

        let rar15 = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];
        assert_eq!(detect_format(&rar15), Some("rar"));

        let not_rar = [0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_format(&not_rar), None);
    }
}
