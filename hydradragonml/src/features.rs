use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};

pub const VOCAB_SIZE: usize = 20000;
pub const EMBED_DIM: usize = 64;
pub const MIN_STR_LEN: usize = 5;
pub const MAX_TOKENS: usize = 120_000;
pub const MAX_ENTRY_SCAN: usize = 16 * 1024 * 1024;

pub const ENGINE_FEATURE_COUNT: usize = 26;

#[derive(Clone, Debug, Default)]
pub struct EngineFeatures {
    // DEX
    pub dex_class_count: f32,
    pub dex_string_count: f32,
    pub dex_api_call_count: f32,
    pub dex_finding_high: f32,
    pub dex_finding_critical: f32,
    // ELF
    pub elf_count: f32,
    pub elf_emulated_strings: f32,
    pub elf_network_calls: f32,
    pub elf_file_calls: f32,
    pub elf_exec_calls: f32,
    pub elf_anti_debug: f32,
    // Manifest
    pub manifest_dangerous_permissions: f32,
    pub manifest_total_permissions: f32,
    pub manifest_activities: f32,
    pub manifest_services: f32,
    pub manifest_receivers: f32,
    pub manifest_min_sdk: f32,
    pub manifest_target_sdk: f32,
    // URL
    pub url_malicious_count: f32,
    pub url_phishing_count: f32,
    // IP
    pub ip_malicious_count: f32,
    // TLSH
    pub tlsh_min_distance: f32,
    // Certificate
    pub is_testkey: f32,
    // Benign DB
    pub benign_jaccard: f32,
    // Media
    pub media_hidden_count: f32,
    // HIPS
    pub hips_findings: f32,
}

impl EngineFeatures {
    pub fn to_vec(&self) -> Vec<f32> {
        vec![
            self.dex_class_count.min(5000.0) / 5000.0,
            self.dex_string_count.min(50000.0) / 50000.0,
            self.dex_api_call_count.min(5000.0) / 5000.0,
            (self.dex_finding_high / 20.0).min(1.0),
            (self.dex_finding_critical / 10.0).min(1.0),
            (self.elf_count / 20.0).min(1.0),
            (self.elf_emulated_strings / 100.0).min(1.0),
            (self.elf_network_calls / 50.0).min(1.0),
            (self.elf_file_calls / 50.0).min(1.0),
            (self.elf_exec_calls / 20.0).min(1.0),
            (self.elf_anti_debug / 20.0).min(1.0),
            (self.manifest_dangerous_permissions / 30.0).min(1.0),
            (self.manifest_total_permissions / 50.0).min(1.0),
            (self.manifest_activities / 50.0).min(1.0),
            (self.manifest_services / 20.0).min(1.0),
            (self.manifest_receivers / 20.0).min(1.0),
            ((self.manifest_min_sdk - 1.0) / 34.0).clamp(0.0, 1.0),
            ((self.manifest_target_sdk - 1.0) / 34.0).clamp(0.0, 1.0),
            (self.url_malicious_count / 20.0).min(1.0),
            (self.url_phishing_count / 20.0).min(1.0),
            (self.ip_malicious_count / 10.0).min(1.0),
            (1.0 - (self.tlsh_min_distance / 200.0)).clamp(0.0, 1.0),
            self.is_testkey,
            self.benign_jaccard,
            (self.media_hidden_count / 10.0).min(1.0),
            (self.hips_findings / 20.0).min(1.0),
        ]
    }
}

// Tokenizer for the EmbeddingBag ML pipeline.

pub struct Tokenizer {
    vocab: HashMap<String, i64>,
}

impl Tokenizer {
    pub fn new(vocab: HashMap<String, i64>) -> Self {
        Self { vocab }
    }

    pub fn load_json(bytes: &[u8]) -> Option<Self> {
        let map: HashMap<String, i64> = serde_json::from_slice(bytes).ok()?;
        Some(Self::new(map))
    }

    pub fn tokenize(&self, apk: &[u8]) -> Option<Vec<i64>> {
        let mut tokens: Vec<i64> = Vec::new();
        let reader = Cursor::new(apk);
        let mut archive = zip::ZipArchive::new(reader).ok()?;
        let mut has_content = false;

        for i in 0..archive.len() {
            if tokens.len() >= MAX_TOKENS {
                break;
            }
            let mut entry = match archive.by_index(i) {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = entry.name().to_string();
            self.sub_tokenize(name.as_str(), &mut tokens);

            let lname = name.to_ascii_lowercase();
            let scan = lname == "androidmanifest.xml"
                || lname == "resources.arsc"
                || lname.ends_with(".dex")
                || lname.starts_with("meta-inf/");
            if !scan {
                continue;
            }
            has_content = true;

            let mut buf = Vec::new();
            if entry
                .by_ref()
                .take(MAX_ENTRY_SCAN as u64)
                .read_to_end(&mut buf)
                .is_err()
            {
                continue;
            }
            self.harvest_strings(&buf, &mut tokens);
        }

        if !has_content || tokens.is_empty() {
            return None;
        }
        Some(tokens)
    }

    fn sub_tokenize(&self, text: &str, out: &mut Vec<i64>) {
        for part in text.split(|c: char| {
            c == '.' || c == '/' || c == ';' || c == ':' || c == '-' || c == '\\' || c == '_'
        }) {
            if part.len() >= 2 {
                let key = part.to_ascii_lowercase();
                let id = self.vocab.get(&key).copied().unwrap_or(0);
                out.push(id);
                if out.len() >= MAX_TOKENS {
                    return;
                }
            }
        }
    }

    fn harvest_strings(&self, data: &[u8], out: &mut Vec<i64>) {
        // ASCII runs
        let mut start: Option<usize> = None;
        for (i, &b) in data.iter().enumerate() {
            let printable = (0x20..0x7f).contains(&b);
            if printable {
                if start.is_none() {
                    start = Some(i);
                }
            } else if let Some(s) = start.take() {
                if i - s >= MIN_STR_LEN {
                    if let Ok(text) = std::str::from_utf8(&data[s..i]) {
                        self.sub_tokenize(text, out);
                        if out.len() >= MAX_TOKENS {
                            return;
                        }
                    }
                }
            }
        }
        if let Some(s) = start {
            if data.len() - s >= MIN_STR_LEN {
                if let Ok(text) = std::str::from_utf8(&data[s..]) {
                    self.sub_tokenize(text, out);
                }
            }
        }

        // UTF-16LE runs
        let mut utf_buf: Vec<u8> = Vec::new();
        let mut j = 0;
        while j + 1 < data.len() {
            let lo = data[j];
            let hi = data[j + 1];
            if hi == 0 && (0x20..0x7f).contains(&lo) {
                utf_buf.push(lo);
            } else {
                if utf_buf.len() >= MIN_STR_LEN {
                    if let Ok(text) = std::str::from_utf8(&utf_buf) {
                        self.sub_tokenize(text, out);
                        if out.len() >= MAX_TOKENS {
                            return;
                        }
                    }
                }
                utf_buf.clear();
            }
            j += 2;
        }
        if utf_buf.len() >= MIN_STR_LEN {
            if let Ok(text) = std::str::from_utf8(&utf_buf) {
                self.sub_tokenize(text, out);
            }
        }
    }
}

// MinHash token extraction (FNV-1a hashed string tokens, used for benign DB lookup).

pub struct ApkFeatures {
    pub tokens: HashSet<u64>,
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

pub fn extract_minhash(apk: &[u8]) -> Option<ApkFeatures> {
    let mut tokens: HashSet<u64> = HashSet::new();
    let reader = Cursor::new(apk);
    let mut archive = zip::ZipArchive::new(reader).ok()?;
    let mut has_content_entry = false;

    for i in 0..archive.len() {
        if tokens.len() >= MAX_TOKENS {
            break;
        }
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.name().to_string();
        tokens.insert(token("name:", name.as_bytes()));

        let lname = name.to_ascii_lowercase();
        let scan_contents = lname == "androidmanifest.xml"
            || lname == "resources.arsc"
            || lname.ends_with(".dex")
            || lname.starts_with("meta-inf/");
        if !scan_contents {
            continue;
        }
        has_content_entry = true;

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
        harvest_minhash_strings(&buf, prefix, &mut tokens);
    }

    if !has_content_entry || tokens.is_empty() {
        return None;
    }
    Some(ApkFeatures { tokens })
}

fn harvest_minhash_strings(data: &[u8], prefix: &str, tokens: &mut HashSet<u64>) {
    let mut start: Option<usize> = None;
    for (i, &b) in data.iter().enumerate() {
        let printable = (0x20..0x7f).contains(&b);
        if printable {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            if i - s >= MIN_STR_LEN {
                insert_minhash_string(&data[s..i], prefix, tokens);
                if tokens.len() >= MAX_TOKENS {
                    return;
                }
            }
        }
    }
    if let Some(s) = start {
        if data.len() - s >= MIN_STR_LEN {
            insert_minhash_string(&data[s..], prefix, tokens);
        }
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut j = 0;
    while j + 1 < data.len() {
        let lo = data[j];
        let hi = data[j + 1];
        if hi == 0 && (0x20..0x7f).contains(&lo) {
            buf.push(lo);
        } else {
            if buf.len() >= MIN_STR_LEN {
                insert_minhash_string(&buf, prefix, tokens);
                if tokens.len() >= MAX_TOKENS {
                    return;
                }
            }
            buf.clear();
        }
        j += 2;
    }
    if buf.len() >= MIN_STR_LEN {
        insert_minhash_string(&buf, prefix, tokens);
    }
}

fn insert_minhash_string(s: &[u8], prefix: &str, tokens: &mut HashSet<u64>) {
    tokens.insert(token(prefix, s));

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
        if text.starts_with('L') && text.contains('/') {
            tokens.insert(token("api:", text.as_bytes()));
        }
        if lower.starts_with("http://") || lower.starts_with("https://") || lower.contains("://") {
            tokens.insert(token("url:", lower.as_bytes()));
        }
    }
}
