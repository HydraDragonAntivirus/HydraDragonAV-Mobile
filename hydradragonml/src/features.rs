use std::collections::HashSet;
use std::io::{Cursor, Read};

pub const DENSE_DIM: usize = 256;

const MIN_STR_LEN: usize = 5;
const MAX_TOKENS: usize = 120_000;
const MAX_ENTRY_SCAN: usize = 16 * 1024 * 1024;

pub struct ApkFeatures {
    pub tokens: HashSet<u64>,
    pub dense: Vec<f32>,
}

pub fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn token(prefix: &str, s: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in prefix.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    for &b in s {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

pub fn extract(apk: &[u8]) -> Option<ApkFeatures> {
    let mut tokens: HashSet<u64> = HashSet::new();
    let reader = Cursor::new(apk);
    let mut archive = zip::ZipArchive::new(reader).ok()?;

    for i in 0..archive.len() {
        if tokens.len() >= MAX_TOKENS {
            break;
        }
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.name().to_owned();
        tokens.insert(token("name:", name.as_bytes()));

        let name_bytes = name.as_bytes();
        let scan = name_bytes.len() == "androidmanifest.xml".len()
            && name_bytes.eq_ignore_ascii_case(b"androidmanifest.xml")
            || name_bytes.len() == "resources.arsc".len()
                && name_bytes.eq_ignore_ascii_case(b"resources.arsc")
            || name_bytes.ends_with(b".dex")
            || name_bytes.starts_with(b"META-INF/");
        if !scan {
            continue;
        }

        let mut buf = Vec::with_capacity(MAX_ENTRY_SCAN.min(65536));
        if entry.by_ref().take(MAX_ENTRY_SCAN as u64).read_to_end(&mut buf).is_err() {
            continue;
        }

        let prefix = if name_bytes.ends_with(b".dex") {
            "dex:"
        } else if name_bytes.eq_ignore_ascii_case(b"androidmanifest.xml") {
            "manifest:"
        } else {
            "res:"
        };
        harvest_strings(&buf, prefix, &mut tokens);
    }

    if tokens.is_empty() {
        return None;
    }

    let dense = dense_vector(&tokens);
    Some(ApkFeatures { tokens, dense })
}

fn harvest_strings(data: &[u8], prefix: &str, tokens: &mut HashSet<u64>) {
    let mut ascii_start: Option<usize> = None;
    let mut utf16_buf: Vec<u8> = Vec::new();

    for i in 0..data.len() {
        let b = data[i];
        let printable = (0x20..0x7f).contains(&b);

        if printable {
            if ascii_start.is_none() {
                ascii_start = Some(i);
            }
        } else if let Some(s) = ascii_start.take() {
            if i - s >= MIN_STR_LEN {
                insert_string(&data[s..i], prefix, tokens);
                if tokens.len() >= MAX_TOKENS {
                    return;
                }
            }
        }

        if i & 1 == 0 && i + 1 < data.len() {
            let hi = data[i + 1];
            if hi == 0 && printable {
                utf16_buf.push(b);
            } else if utf16_buf.len() >= MIN_STR_LEN {
                insert_string(&utf16_buf, prefix, tokens);
                if tokens.len() >= MAX_TOKENS {
                    return;
                }
                utf16_buf.clear();
            } else {
                utf16_buf.clear();
            }
        }
    }

    if let Some(s) = ascii_start {
        if data.len() - s >= MIN_STR_LEN {
            insert_string(&data[s..], prefix, tokens);
        }
    }
    if utf16_buf.len() >= MIN_STR_LEN {
        insert_string(&utf16_buf, prefix, tokens);
    }
}

fn insert_string(s: &[u8], prefix: &str, tokens: &mut HashSet<u64>) {
    tokens.insert(token(prefix, s));

    // permission. - case-insensitive byte search, no allocation
    if s.len() >= 11 {
        let mut found = false;
        for w in s.windows(11) {
            if w.iter()
                .zip(b"permission.")
                .all(|(&a, &b)| a.eq_ignore_ascii_case(&b))
            {
                let after = &s[(w.as_ptr() as usize - s.as_ptr() as usize) + 11..];
                let end = after
                    .iter()
                    .position(|&c| !c.is_ascii_alphanumeric() && c != b'_')
                    .unwrap_or(after.len());
                if end > 0 {
                    let mut perm = Vec::with_capacity(end);
                    for &c in &after[..end] {
                        perm.push(c.to_ascii_lowercase());
                    }
                    tokens.insert(token("perm:", &perm));
                }
                found = true;
                break;
            }
        }
        let _ = found;
    }

    // API descriptor: L.../
    if s.len() > 1 && s[0] == b'L' && s[1..].contains(&b'/') {
        tokens.insert(token("api:", s));
    }

    // URL: contains ://
    if s.len() >= 3 && s.windows(3).any(|w| w == b"://") {
        tokens.insert(token("url:", s));
    }
}

fn dense_vector(tokens: &HashSet<u64>) -> Vec<f32> {
    let mut counts = vec![0u32; DENSE_DIM];
    for &t in tokens {
        let bucket = (t % DENSE_DIM as u64) as usize;
        counts[bucket] = counts[bucket].saturating_add(1);
    }
    let mut v: Vec<f32> = counts.iter().map(|&c| (1.0 + c as f32).ln()).collect();
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in &mut v {
            *x /= norm;
        }
    }
    v
}
