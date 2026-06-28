//! APK feature extraction.
//!
//! An APK is a ZIP. We do not fully parse binary `AndroidManifest.xml` (AXML);
//! instead we harvest printable strings from the manifest, `resources.arsc`,
//! and every `classes*.dex`, plus the archive entry names. Permission strings,
//! API descriptors (`Landroid/...`), URLs, native lib names, etc. all survive
//! as plain UTF-8 / UTF-16LE inside those blobs, which is robust against the
//! many AXML encoder quirks found in real malware.
//!
//! Two representations come out:
//!   * `tokens`  — a set of 64-bit hashed tokens, used for MinHash/Jaccard.
//!   * `dense`   — a fixed-width feature-hashed vector, used for Isolation Forest.

use std::collections::HashSet;
use std::io::{Cursor, Read};

/// Width of the dense feature-hashed vector fed to the Isolation Forest.
pub const DENSE_DIM: usize = 256;

/// Minimum length (in chars) for an extracted string to be kept.
const MIN_STR_LEN: usize = 5;
/// Hard cap on token-set size so a pathological APK can't blow up memory/time.
const MAX_TOKENS: usize = 120_000;
/// Cap on bytes scanned per entry (DEX files can be large; this bounds cost).
const MAX_ENTRY_SCAN: usize = 16 * 1024 * 1024;

pub struct ApkFeatures {
    pub tokens: HashSet<u64>,
    pub dense: Vec<f32>,
}

/// FNV-1a 64-bit — stable across runs/platforms (unlike `DefaultHasher`).
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

/// Extract features from raw APK bytes. Returns `None` only if the bytes are
/// not a readable ZIP at all.
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
        let name = entry.name().to_string();
        // Entry path itself is a feature (e.g. native lib names, asset layout).
        tokens.insert(token("name:", name.as_bytes()));

        let lname = name.to_ascii_lowercase();
        let scan_contents = lname == "androidmanifest.xml"
            || lname == "resources.arsc"
            || lname.ends_with(".dex")
            || lname.starts_with("meta-inf/");
        if !scan_contents {
            continue;
        }

        let mut buf = Vec::new();
        if entry
            .by_ref()
            .take(MAX_ENTRY_SCAN as u64)
            .read_to_end(&mut buf)
            .is_err()
        {
            continue;
        }

        let prefix = if lname.ends_with(".dex") {
            "dex:"
        } else if lname == "androidmanifest.xml" {
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

/// Pull ASCII and UTF-16LE printable runs and insert them as tokens.
fn harvest_strings(data: &[u8], prefix: &str, tokens: &mut HashSet<u64>) {
    // ASCII runs.
    let mut start: Option<usize> = None;
    for (i, &b) in data.iter().enumerate() {
        let printable = (0x20..0x7f).contains(&b);
        if printable {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            if i - s >= MIN_STR_LEN {
                insert_string(&data[s..i], prefix, tokens);
                if tokens.len() >= MAX_TOKENS {
                    return;
                }
            }
        }
    }
    if let Some(s) = start {
        if data.len() - s >= MIN_STR_LEN {
            insert_string(&data[s..], prefix, tokens);
        }
    }

    // UTF-16LE runs (manifest/resources string pools are commonly UTF-16).
    let mut buf: Vec<u8> = Vec::new();
    let mut j = 0;
    while j + 1 < data.len() {
        let lo = data[j];
        let hi = data[j + 1];
        if hi == 0 && (0x20..0x7f).contains(&lo) {
            buf.push(lo);
        } else {
            if buf.len() >= MIN_STR_LEN {
                insert_string(&buf, prefix, tokens);
                if tokens.len() >= MAX_TOKENS {
                    return;
                }
            }
            buf.clear();
        }
        j += 2;
    }
    if buf.len() >= MIN_STR_LEN {
        insert_string(&buf, prefix, tokens);
    }
}

fn insert_string(s: &[u8], prefix: &str, tokens: &mut HashSet<u64>) {
    tokens.insert(token(prefix, s));

    // Promote high-signal substrings to their own (prefix-free) tokens so two
    // APKs that share a permission/API but little else still collide.
    if let Ok(text) = std::str::from_utf8(s) {
        let lower = text.to_ascii_lowercase();
        if lower.contains("permission.") {
            if let Some(p) = lower.split("permission.").nth(1) {
                let perm: String = p
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !perm.is_empty() {
                    tokens.insert(token("perm:", perm.as_bytes()));
                }
            }
        }
        // DEX type/method descriptors and URLs.
        if text.starts_with('L') && text.contains('/') {
            tokens.insert(token("api:", text.as_bytes()));
        }
        if lower.starts_with("http://") || lower.starts_with("https://") || lower.contains("://") {
            tokens.insert(token("url:", lower.as_bytes()));
        }
    }
}

/// Feature-hash the token set into a fixed-width, L2-normalised vector.
fn dense_vector(tokens: &HashSet<u64>) -> Vec<f32> {
    let mut counts = vec![0u32; DENSE_DIM];
    for &t in tokens {
        // Signed hashing trick reduces collision bias.
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
