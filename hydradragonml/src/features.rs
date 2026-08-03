use std::collections::{HashMap, HashSet};

use ripzip::extract::zip_reader::{parse_archive, parse_local_header_data_offset, ZipEntry};
use ripzip::zip_format::{COMPRESSION_DEFLATED, COMPRESSION_STORED};

use crate::dex;
use crate::axml;
use crate::elf;

pub const VOCAB_SIZE: usize = 20000;
pub const EMBED_DIM: usize = 64;
pub const MIN_STR_LEN: usize = 5;
pub const MAX_TOKENS: usize = 4096;
pub const MAX_ENTRY_SCAN: usize = 16 * 1024 * 1024;

/// 5 DEX fields + 6 ELF fields + 7 manifest fields. Every one of these is
/// computed from the APK's actual content (see `EngineFeatures::extract_from_apk`)
/// — there are no placeholder/default-only fields left in this struct.
pub const ENGINE_FEATURE_COUNT: usize = 18;

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
        ]
    }

    /// Builds real, content-derived DEX/ELF/manifest features by scanning
    /// the actual entries of an APK (a zip archive), using `ripzip` to parse
    /// the archive directly out of an in-memory byte slice.
    pub fn extract_from_apk(apk: &[u8]) -> Option<Self> {
        let archive = parse_archive(apk).ok()?;

        let mut feats = EngineFeatures::default();
        let mut saw_any_entry = false;

        for entry in &archive.entries {
            if entry.is_dir {
                continue;
            }
            let lname = entry.file_name.to_ascii_lowercase();

            let is_dex = lname.ends_with(".dex");
            let is_manifest = lname == "androidmanifest.xml";
            let is_native_lib = lname.starts_with("lib/") && lname.ends_with(".so");
            if !is_dex && !is_manifest && !is_native_lib {
                continue;
            }

            let buf = match read_entry_data(apk, entry) {
                Some(b) => b,
                None => continue,
            };

            if is_dex {
                if let Some(d) = dex::analyze(&buf) {
                    saw_any_entry = true;
                    // A single APK can contain multiple classes*.dex files
                    // (multidex); accumulate real counts across all of them.
                    feats.dex_class_count += d.class_count as f32;
                    feats.dex_string_count += d.string_count as f32;
                    feats.dex_api_call_count += d.api_call_count as f32;
                    feats.dex_finding_high += d.finding_high as f32;
                    feats.dex_finding_critical += d.finding_critical as f32;
                }
            } else if is_manifest {
                if let Some(m) = axml::analyze_manifest(&buf) {
                    saw_any_entry = true;
                    feats.manifest_dangerous_permissions = m.dangerous_permissions as f32;
                    feats.manifest_total_permissions = m.total_permissions as f32;
                    feats.manifest_activities = m.activities as f32;
                    feats.manifest_services = m.services as f32;
                    feats.manifest_receivers = m.receivers as f32;
                    feats.manifest_min_sdk = m.min_sdk as f32;
                    feats.manifest_target_sdk = m.target_sdk as f32;
                }
            } else if is_native_lib {
                if let Some(e) = elf::analyze(&buf) {
                    saw_any_entry = true;
                    feats.elf_count += 1.0;
                    feats.elf_emulated_strings += e.emulated_strings as f32;
                    feats.elf_network_calls += e.network_calls as f32;
                    feats.elf_file_calls += e.file_calls as f32;
                    feats.elf_exec_calls += e.exec_calls as f32;
                    feats.elf_anti_debug += e.anti_debug as f32;
                }
            }
        }

        if !saw_any_entry {
            return None;
        }
        Some(feats)
    }
}

/// Reads and decompresses a single ZIP entry's data out of the full APK
/// byte slice, using `ripzip` to locate the entry's actual data offset
/// (skipping past the variable-length local file header) and `flate2` to
/// inflate it if the entry uses DEFLATE (the near-universal compression
/// method used inside real-world APKs; STORED entries are returned as-is).
/// Any other/unsupported compression method returns `None` rather than
/// guessing at decoded content.
fn read_entry_data(apk: &[u8], entry: &ZipEntry) -> Option<Vec<u8>> {
    let data_offset = parse_local_header_data_offset(apk, entry.local_header_offset).ok()? as usize;
    let comp_len = entry.compressed_size as usize;
    let compressed = apk.get(data_offset..data_offset.checked_add(comp_len)?)?;

    match entry.compression_method {
        m if m == COMPRESSION_STORED => Some(compressed.to_vec()),
        m if m == COMPRESSION_DEFLATED => {
            use flate2::read::DeflateDecoder;
            use std::io::Read;
            let cap = (entry.uncompressed_size as usize).min(MAX_ENTRY_SCAN);
            let mut out = Vec::with_capacity(cap.min(1 << 20));
            let mut decoder = DeflateDecoder::new(compressed);
            decoder.by_ref().take(MAX_ENTRY_SCAN as u64).read_to_end(&mut out).ok()?;
            Some(out)
        }
        _ => None, // unsupported compression method (e.g. AES-encrypted, LZMA) — skip rather than guess
    }
}

/// Iterates every entry of `apk`, applying `f(name, decompressed_bytes)` to
/// each non-directory entry. Used by the tokenizers below, which (unlike
/// `EngineFeatures::extract_from_apk`) need to look at every entry name and
/// the contents of a broader set of files (AndroidManifest.xml,
/// resources.arsc, *.dex, META-INF/*).
fn for_each_entry(apk: &[u8], mut f: impl FnMut(&str, &[u8])) -> Option<()> {
    let archive = parse_archive(apk).ok()?;
    for entry in &archive.entries {
        if entry.is_dir {
            continue;
        }
        let name = entry.file_name.clone();
        let lname = name.to_ascii_lowercase();
        let scan = lname == "androidmanifest.xml"
            || lname == "resources.arsc"
            || lname.ends_with(".dex")
            || lname.starts_with("meta-inf/");

        // Entry *names* are always cheap to look at; only decompress
        // content for entries we actually want to harvest strings from.
        if scan {
            if let Some(buf) = read_entry_data(apk, entry) {
                f(&name, &buf);
                continue;
            }
        }
        f(&name, &[]);
    }
    Some(())
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
        let raw = Self::raw_tokens(apk)?;
        Some(
            raw.iter()
                .map(|token| self.vocab.get(token).copied().unwrap_or(0))
                .collect(),
        )
    }

    /// Extract the same lowercase, delimiter-split subword tokens used at
    /// inference, without mapping them to vocabulary ids. Used by the
    /// vocabulary builder to count token frequencies over a corpus.
    pub fn raw_tokens(apk: &[u8]) -> Option<Vec<String>> {
        let mut tokens: Vec<String> = Vec::new();
        let mut has_content = false;

        for_each_entry(apk, |name, content| {
            if tokens.len() >= MAX_TOKENS {
                return;
            }
            Self::sub_tokenize_raw(name, &mut tokens);
            if !content.is_empty() {
                has_content = true;
                Self::harvest_strings_raw(content, &mut tokens);
            }
        })?;

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

    fn sub_tokenize_raw(text: &str, out: &mut Vec<String>) {
        for part in text.split(|c: char| {
            c == '.' || c == '/' || c == ';' || c == ':' || c == '-' || c == '\\' || c == '_'
        }) {
            if part.len() >= 2 {
                out.push(part.to_ascii_lowercase());
                if out.len() >= MAX_TOKENS {
                    return;
                }
            }
        }
    }

    fn harvest_strings_raw(data: &[u8], out: &mut Vec<String>) {
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
                        Self::sub_tokenize_raw(text, out);
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
                    Self::sub_tokenize_raw(text, out);
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
                        Self::sub_tokenize_raw(text, out);
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
                Self::sub_tokenize_raw(text, out);
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
    let mut has_content_entry = false;

    for_each_entry(apk, |name, content| {
        if tokens.len() >= MAX_TOKENS {
            return;
        }
        tokens.insert(token("name:", name.as_bytes()));
        if content.is_empty() {
            return;
        }
        has_content_entry = true;
        let lname = name.to_ascii_lowercase();
        let prefix = if lname.ends_with(".dex") {
            "dex:"
        } else if lname == "androidmanifest.xml" {
            "manifest:"
        } else {
            "res:"
        };
        harvest_minhash_strings(content, prefix, &mut tokens);
    })?;

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

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::io::Write;

    fn make_test_apk(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut zip = zip::ZipWriter::new(cursor);
            for (name, data) in entries {
                zip.start_file::<&str, ()>(*name, zip::write::FileOptions::default())
                    .unwrap();
                zip.write_all(data).unwrap();
            }
            zip.finish().unwrap();
        }
        buf
    }

    #[test]
    fn extract_from_apk_returns_none_without_relevant_entries() {
        let apk = make_test_apk(&[("res/layout/main.xml", vec![1, 2, 3])]);
        assert!(EngineFeatures::extract_from_apk(&apk).is_none());
    }

    #[test]
    fn tokenizer_and_minhash_work_through_ripzip() {
        let mut vocab = std::collections::HashMap::new();
        vocab.insert("classes".to_string(), 1);
        let tok = Tokenizer::new(vocab);

        // "hello world permission strings" repeated to be long enough to
        // survive MIN_STR_LEN and get harvested from the manifest entry.
        let manifest_bytes = b"android.permission.SEND_SMS androidmanifest test content".to_vec();
        let apk = make_test_apk(&[
            ("classes.dex", vec![b'd', b'e', b'x', b'\n', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            ("AndroidManifest.xml", manifest_bytes),
        ]);

        let ids = tok.tokenize(&apk).expect("tokenizer should find content");
        assert!(!ids.is_empty());

        let feats = extract_minhash(&apk).expect("minhash should find content");
        assert!(!feats.tokens.is_empty());
    }

    #[test]
    fn extract_from_apk_reads_real_values_from_dex_manifest_and_elf() {
        // --- real DEX with one critical-severity API call (Runtime.exec) ---
        let dex_strings = ["Ljava/lang/Runtime;", "exec"];
        let dex_bytes = dex::tests::build_minimal_dex(&dex_strings, &[0u32], &[(0u16, 1u32)]);

        // --- real binary AndroidManifest.xml with one dangerous permission,
        //     one activity, and explicit min/target SDK ---
        let manifest_strings = axml::tests::build_string_pool_chunk(&[
            "manifest",
            "uses-permission",
            "android.permission.READ_SMS",
            "uses-sdk",
            "activity",
        ]);
        let res_map = axml::tests::build_resource_map_chunk(&[
            axml::ATTR_NAME,
            axml::ATTR_MIN_SDK_VERSION,
            axml::ATTR_TARGET_SDK_VERSION,
        ]);
        let perm_elem = axml::tests::build_start_element(1, &[(0, 2, axml::TYPE_STRING, 0)]);
        let sdk_elem = axml::tests::build_start_element(3, &[(1, -1, 0x10, 24), (2, -1, 0x10, 34)]);
        let activity_elem = axml::tests::build_start_element(4, &[]);
        let mut manifest_body = Vec::new();
        manifest_body.extend_from_slice(&manifest_strings);
        manifest_body.extend_from_slice(&res_map);
        manifest_body.extend_from_slice(&perm_elem);
        manifest_body.extend_from_slice(&sdk_elem);
        manifest_body.extend_from_slice(&activity_elem);
        let mut manifest_bytes = Vec::new();
        manifest_bytes.extend_from_slice(&3u16.to_le_bytes()); // RES_XML_TYPE
        manifest_bytes.extend_from_slice(&8u16.to_le_bytes());
        manifest_bytes.extend_from_slice(&((8 + manifest_body.len()) as u32).to_le_bytes());
        manifest_bytes.extend_from_slice(&manifest_body);

        // --- real ELF with a ptrace import (anti-debug) ---
        let elf_bytes = elf::tests::build_minimal_elf64(&["ptrace", "connect"]);

        let apk = make_test_apk(&[
            ("classes.dex", dex_bytes),
            ("AndroidManifest.xml", manifest_bytes),
            ("lib/arm64-v8a/libnative.so", elf_bytes),
        ]);

        let feats = EngineFeatures::extract_from_apk(&apk).expect("should extract real features");
        assert_eq!(feats.dex_class_count, 1.0);
        assert_eq!(feats.dex_finding_critical, 1.0);
        assert_eq!(feats.manifest_dangerous_permissions, 1.0);
        assert_eq!(feats.manifest_activities, 1.0);
        assert_eq!(feats.manifest_min_sdk, 24.0);
        assert_eq!(feats.manifest_target_sdk, 34.0);
        assert_eq!(feats.elf_count, 1.0);
        assert_eq!(feats.elf_anti_debug, 1.0);
        assert_eq!(feats.elf_network_calls, 1.0);

        // Values are real and finite; to_vec() should still normalize cleanly.
        let v = feats.to_vec();
        assert_eq!(v.len(), ENGINE_FEATURE_COUNT);
        assert!(v.iter().all(|&x| (0.0..=1.0).contains(&x)));
    }
}
