use std::collections::{HashMap, HashSet};

use ripzip::extract::zip_reader::{parse_archive, parse_local_header_data_offset, ZipEntry};
use ripzip::zip_format::{COMPRESSION_DEFLATED, COMPRESSION_STORED};

use crate::dex;
use crate::axml;
use crate::elf;

pub const VOCAB_SIZE: usize = 20000;
pub const EMBED_DIM: usize = 64;
pub const MIN_STR_LEN: usize = 5;
pub const MAX_TOKENS: usize = 8192;
pub const MAX_ENTRY_SCAN: usize = 16 * 1024 * 1024;

/// 3 DEX fields + 1 ELF field + 6 manifest fields + 1 content-entropy field.
/// Every one of these is computed from the APK's actual content (see
/// `EngineFeatures::extract_from_apk`) — there are no placeholder/default-only
/// fields left in this struct. The final field carries the Shannon entropy
/// (bits, 0..8) of the decompressed DEX/ELF/AndroidManifest.xml content, which
/// catches packed/obfuscated payloads that otherwise hide behind normal counts.
///
/// No hardcoded normalization caps or behavior/indicator lists exist anywhere
/// in this crate: features are plain counts/sizes, and raw values are
/// normalized against the training corpus via `FeaturePercentiles` (see
/// below), which is persisted next to the model so inference normalizes with
/// the exact same distribution.
pub const ENGINE_FEATURE_COUNT: usize = 11;

/// Display names for the engine features, in the same order as `to_vec()`.
pub const ENGINE_FEATURE_NAMES: [&str; ENGINE_FEATURE_COUNT] = [
    "dex_class_count",
    "dex_string_count",
    "dex_api_call_count",
    "elf_count",
    "manifest_total_permissions",
    "manifest_activities",
    "manifest_services",
    "manifest_receivers",
    "manifest_min_sdk",
    "manifest_target_sdk",
    "entropy",
];

#[derive(Clone, Debug, Default)]
pub struct EngineFeatures {
    // DEX
    pub dex_class_count: f32,
    pub dex_string_count: f32,
    pub dex_api_call_count: f32,
    // ELF
    pub elf_count: f32,
    // Manifest
    pub manifest_total_permissions: f32,
    pub manifest_activities: f32,
    pub manifest_services: f32,
    pub manifest_receivers: f32,
    pub manifest_min_sdk: f32,
    pub manifest_target_sdk: f32,
    // Content entropy
    pub entropy: f32,
}

impl EngineFeatures {
    /// Raw, un-normalized feature values in a fixed order (matched by
    /// `FeaturePercentiles` and the model's engine branch). All normalization
    /// is corpus-derived at train time — no hardcoded caps or scales.
    pub fn to_vec(&self) -> Vec<f32> {
        vec![
            self.dex_class_count,
            self.dex_string_count,
            self.dex_api_call_count,
            self.elf_count,
            self.manifest_total_permissions,
            self.manifest_activities,
            self.manifest_services,
            self.manifest_receivers,
            self.manifest_min_sdk,
            self.manifest_target_sdk,
            self.entropy,
        ]
    }

    /// Builds real, content-derived DEX/ELF/manifest features by scanning
    /// the actual entries of an APK (a zip archive), using `ripzip` to parse
    /// the archive directly out of an in-memory byte slice.
    pub fn extract_from_apk(apk: &[u8]) -> Option<Self> {
        let archive = parse_archive(apk).ok()?;

        let mut feats = EngineFeatures::default();
        let mut saw_any_entry = false;
        let mut content_hist = [0u64; 256];
        let mut content_total = 0u64;

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

            // Accumulate a byte histogram over the decompressed content of the
            // code-bearing entries so we can derive a single Shannon-entropy
            // feature covering DEX + ELF + manifest payloads.
            update_entropy_histogram(&mut content_hist, &mut content_total, &buf);

            if is_dex {
                if let Some(d) = dex::analyze(&buf) {
                    saw_any_entry = true;
                    // A single APK can contain multiple classes*.dex files
                    // (multidex); accumulate real counts across all of them.
                    feats.dex_class_count += d.class_count as f32;
                    feats.dex_string_count += d.string_count as f32;
                    feats.dex_api_call_count += d.api_call_count as f32;
                }
            } else if is_manifest {
                if let Some(m) = axml::analyze_manifest(&buf) {
                    saw_any_entry = true;
                    feats.manifest_total_permissions = m.total_permissions as f32;
                    feats.manifest_activities = m.activities as f32;
                    feats.manifest_services = m.services as f32;
                    feats.manifest_receivers = m.receivers as f32;
                    feats.manifest_min_sdk = m.min_sdk as f32;
                    feats.manifest_target_sdk = m.target_sdk as f32;
                }
            } else if is_native_lib {
                if elf::analyze(&buf).is_some() {
                    saw_any_entry = true;
                    feats.elf_count += 1.0;
                }
            }
        }

        if !saw_any_entry {
            return None;
        }
        feats.entropy = shannon_entropy(&content_hist, content_total);
        Some(feats)
    }
}

/// Corpus-derived, zero-hardcoded normalization for engine features.
///
/// At train time `from_samples` collects every sample's raw feature values
/// per dimension, sorts each column, and persists those sorted arrays to JSON
/// (`features.json`). At inference `normalize` maps a raw value to its
/// interpolated rank percentile in the training distribution, producing
/// values in `[0, 1]`. Because the mapping is the corpus rank rather than a
/// fixed cap, an out-of-distribution giant like TTech lands *at the top of
/// the benign cluster* instead of being clipped to an arbitrary 1.0 cap.
#[derive(Clone, Debug)]
pub struct FeaturePercentiles {
    /// Per-feature sorted raw values, in the same order as `to_vec()`.
    pub per_feature: Vec<Vec<f32>>,
}

impl FeaturePercentiles {
    pub fn from_samples(feature_count: usize, samples: &[Vec<f32>]) -> Self {
        let mut per_feature: Vec<Vec<f32>> = vec![Vec::with_capacity(samples.len()); feature_count];
        for sample in samples {
            for (i, v) in sample.iter().enumerate().take(feature_count) {
                per_feature[i].push(*v);
            }
        }
        for column in per_feature.iter_mut() {
            column.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        }
        Self { per_feature }
    }

    pub fn normalize(&self, raw: &[f32]) -> Vec<f32> {
        raw.iter()
            .zip(self.per_feature.iter())
            .map(|(x, sorted)| percentile_value(sorted, *x))
            .collect()
    }

    pub fn to_json_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.per_feature).unwrap_or_default()
    }

    pub fn from_json_bytes(bytes: &[u8]) -> Option<Self> {
        let per_feature: Vec<Vec<f32>> = serde_json::from_slice(bytes).ok()?;
        Some(Self { per_feature })
    }
}

/// Linear-interpolated rank percentile of `x` within `sorted`. Returns 0.0
/// at/below the minimum, 1.0 at/above the maximum.
pub fn percentile_value(sorted: &[f32], x: f32) -> f32 {
    let n = sorted.len();
    if n == 0 {
        return 0.0;
    }
    if x <= sorted[0] {
        return 0.0;
    }
    if x >= sorted[n - 1] {
        return 1.0;
    }
    // First index with sorted[i] > x (upper bound); i in 1..=n-1.
    let mut lo = 0usize;
    let mut hi = n;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if sorted[mid] <= x {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let i = lo;
    let a = sorted[i - 1];
    let b = sorted[i];
    let t = if b > a { (x - a) / (b - a) } else { 0.0 };
    ((i - 1) as f32 + t) / ((n - 1) as f32)
}

/// Accumulates a per-byte-value histogram of `data` into `hist`, bumping
/// `total` by the number of bytes seen. Meant to be called once per
/// decompressed code-bearing entry so the caller can later derive a single
/// bytes-weighted Shannon-entropy feature across all of them.
pub fn update_entropy_histogram(hist: &mut [u64; 256], total: &mut u64, data: &[u8]) {
    for &b in data {
        hist[b as usize] += 1;
    }
    *total += data.len() as u64;
}

/// Shannon entropy in bits (0.0..8.0) of the byte distribution described by
/// `hist`/`total`: `-sum(p_i * log2(p_i))`. Returns 0.0 when there are no
/// bytes (empty/zero-length input).
pub fn shannon_entropy(hist: &[u64; 256], total: u64) -> f32 {
    if total == 0 {
        return 0.0;
    }
    let n = total as f64;
    let mut e = 0.0f64;
    for &c in hist {
        if c > 0 {
            let p = c as f64 / n;
            e -= p * p.log2();
        }
    }
    e as f32
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
        let mut tokens: Vec<i64> = Vec::new();
        let mut has_content = false;

        for_each_entry(apk, |name, content| {
            if tokens.len() >= MAX_TOKENS {
                return;
            }
            self.sub_tokenize(name, &mut tokens);
            if !content.is_empty() {
                has_content = true;
                self.harvest_strings(content, &mut tokens);
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

/// Collects the raw (still un-id-mapped) sub-tokens that
/// `Tokenizer::tokenize` would produce for `apk`, using exactly the same
/// entry-name splitting and ASCII/UTF-16LE string-harvesting rules. This is
/// the vocabulary builder's counterpart to `Tokenizer::tokenize`: given a
/// corpus it yields the token *strings* needed to build a `vocab.json`
/// before any ids exist.
pub fn harvest_raw_tokens(apk: &[u8]) -> Option<Vec<String>> {
    let mut tokens: Vec<String> = Vec::new();
    let mut has_content = false;

    for_each_entry(apk, |name, content| {
        if tokens.len() >= MAX_TOKENS {
            return;
        }
        push_token_parts(name, &mut tokens);
        if !content.is_empty() {
            has_content = true;
            harvest_raw_strings(content, &mut tokens);
        }
    })?;

    if !has_content || tokens.is_empty() {
        return None;
    }
    Some(tokens)
}

fn push_token_parts(text: &str, out: &mut Vec<String>) {
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

fn harvest_raw_strings(data: &[u8], out: &mut Vec<String>) {
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
                    push_token_parts(text, out);
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
                push_token_parts(text, out);
            }
        }
    }

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
                    push_token_parts(text, out);
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
            push_token_parts(text, out);
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

    /// Builds an in-memory APK (ZIP) from the given `(name, data)` entries
    /// using ripzip's own writer so tests never depend on the `zip` crate:
    /// entries are STORED (uncompressed) and round-trip through
    /// `write_zip`/`parse_archive` like real on-disk archives do.
    fn make_test_apk(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        use ripzip::compress::parallel::{CompressedData, CompressedEntry};
        use ripzip::compress::zip_writer::write_zip;
        use ripzip::zip_format::crc::crc32;
        use ripzip::zip_format::COMPRESSION_STORED;

        let zip_entries: Vec<CompressedEntry> = entries
            .iter()
            .map(|(name, data)| CompressedEntry {
                archive_name: name.to_string(),
                compression_method: COMPRESSION_STORED,
                crc32: crc32(data),
                compressed_size: data.len() as u64,
                uncompressed_size: data.len() as u64,
                is_dir: false,
                last_mod_time: 0,
                last_mod_date: 0,
                data: CompressedData::InMemory(data.clone()),
            })
            .collect();

        let unique = format!(
            "hd_test_{}_{:?}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            std::thread::current().id()
        );
        let path = std::env::temp_dir().join(unique);
        write_zip(zip_entries, &path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        bytes
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

        // --- real binary AndroidManifest.xml with one permission, one
        //     activity, and explicit min/target SDK ---
        let manifest_strings = axml::tests::build_string_pool_chunk(&[
            "manifest",
            "uses-permission",
            "android.permission.READ_SMS",
            "uses-sdk",
            "activity",
        ]);
        let res_map = axml::tests::build_resource_map_chunk(&[
            axml::ATTR_MIN_SDK_VERSION,
            axml::ATTR_TARGET_SDK_VERSION,
        ]);
        let perm_elem = axml::tests::build_start_element(1, &[]);
        let sdk_elem = axml::tests::build_start_element(3, &[(0, -1, 0x10, 24), (1, -1, 0x10, 34)]);
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
        assert_eq!(feats.manifest_activities, 1.0);
        assert_eq!(feats.manifest_min_sdk, 24.0);
        assert_eq!(feats.manifest_target_sdk, 34.0);
        assert_eq!(feats.elf_count, 1.0);

        // Values are real and finite; to_vec() returns them raw.
        let v = feats.to_vec();
        assert_eq!(v.len(), ENGINE_FEATURE_COUNT);
        assert!(v.iter().all(|x| x.is_finite()));
    }

    #[test]
    fn percentile_normalization_maps_min_to_zero_max_to_one() {
        let sorted = vec![0.0f32, 1.0, 2.0, 3.0, 4.0];
        assert_eq!(percentile_value(&sorted, 0.0), 0.0);
        assert_eq!(percentile_value(&sorted, 4.0), 1.0);
        assert_eq!(percentile_value(&sorted, -5.0), 0.0);
        assert_eq!(percentile_value(&sorted, 99.0), 1.0);
        // 2.0 is exactly the midpoint of the range -> 0.5.
        assert!((percentile_value(&sorted, 2.0) - 0.5).abs() < 1e-6);
    }
}
