const MAX_METADATA_BYTES: usize = 50 * 1024 * 1024;

pub fn is_media_file(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    if &data[4..8] != b"ftyp" {
        return false;
    }
    let brand = &data[8..12];
    !matches!(brand, b"heic" | b"heif" | b"avif" | b"mif1" | b"msf1")
}

pub fn extract_metadata(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset + 8 <= data.len() && out.len() < MAX_METADATA_BYTES {
        let box_size = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let box_type = &data[offset + 4..offset + 8];
        let (actual_size, header_size) = if box_size == 1 {
            if offset + 16 > data.len() {
                break;
            }
            let extended = u64::from_be_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]);
            (extended as usize, 16)
        } else if box_size == 0 {
            (data.len() - offset, 8)
        } else {
            (box_size as usize, 8)
        };
        if actual_size < header_size {
            break;
        }
        if box_type == b"mdat" {
            break;
        }
        let end = (offset + actual_size).min(data.len());
        out.extend_from_slice(&data[offset..end]);
        offset += actual_size;
        if offset > data.len() {
            break;
        }
    }
    out
}

pub fn has_hidden_data(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    let mut offset = 0;
    let mut last_box_end = 0;
    while offset + 8 <= data.len() {
        let box_size = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let (actual_size, header_size) = if box_size == 1 {
            if offset + 16 > data.len() {
                break;
            }
            let extended = u64::from_be_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]);
            (extended as usize, 16)
        } else if box_size == 0 {
            (data.len() - offset, 8)
        } else {
            (box_size as usize, 8)
        };
        if actual_size < header_size {
            break;
        }
        let box_end = offset + actual_size;
        if box_end > data.len() {
            break;
        }
        last_box_end = box_end;
        offset = box_end;
    }
    if last_box_end == 0 || last_box_end >= data.len() {
        return false;
    }
    let tail = &data[last_box_end..];
    if tail.len() < 4 {
        return false;
    }
    tail.windows(4).any(|w| {
        w == b"PK\x03\x04" || w == b"dex\n" || w == b"\x7fELF" || w == b"\xca\xfe\xba\xbe"
    })
}
