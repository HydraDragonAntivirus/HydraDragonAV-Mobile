//! JNI bridge for the Android app.
//!
//! Exposes two native methods on `com.hydradragon.antivirus.engine.NativeScanner`:
//!   * `nativeInit(String dir)`     — load the compiled `.yrc` rulesets and the
//!                                    ML model from a directory (the app copies
//!                                    its bundled assets there at first launch).
//!   * `nativeScanApk(String path)` — scan one APK, return a JSON verdict string.
//!
//! Detection combines three signals; an APK is flagged if ANY fires:
//!   1. clean_rules_filtered_verified.yrc  (generic Android/Linux malware)
//!   2. valhalla-rules_filtered_verified.yrc
//!   3. AndroidOS_filtered.yrc             (AndroidOS-family signatures)
//!   4. the one-class MinHash/LSH + Isolation Forest model (apk_model.json)

use std::sync::OnceLock;

use hydradragonclamav::{Engine as ClamavEngine, ScanOptions};
use hydradragonml::Model;

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;

/// Asset file names expected inside the init directory.
const YRC_FILES: &[&str] = &[
    "clean_rules_filtered_verified.yrc",
    "valhalla-rules_filtered_verified.yrc",
    "AndroidOS_filtered.yrc",
];
const MODEL_BIN: &str = "apk_model.bin";

struct Engine {
    /// ClamAV engine: loaded from the bundled signature DB with the compiled
    /// `.yrc` YARA rulesets added. It does the whole scan — file-type detection,
    /// supported-type gating (`is_target_allowed`), clamav signatures AND YARA,
    /// all in one pass. `None` if no clamav DB was bundled.
    clamav: Option<ClamavEngine>,
    model: Option<Model>,
}

static ENGINE: OnceLock<Engine> = OnceLock::new();

/// Last panic's "message @ file:line", captured by our hook so we can report
/// WHY a scan panicked (root cause) instead of just swallowing it.
static LAST_PANIC: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

fn install_panic_hook() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            let loc = info
                .location()
                .map(|l| format!("{}:{}", l.file(), l.line()))
                .unwrap_or_default();
            let msg = info
                .payload()
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| info.payload().downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic".to_string());
            if let Ok(mut g) = LAST_PANIC.lock() {
                *g = Some(format!("{} @ {}", msg, loc));
            }
        }));
    });
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Human-readable record of what loaded (and what failed) during the last
/// `do_init`, so the Java side can log/show the ROOT CAUSE when native scanning
/// silently does nothing (clamav DB unparsable, model format mismatch, .yrc
/// version mismatch, …) instead of swallowing it.
static INIT_STATUS: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

fn set_status(s: String) {
    if let Ok(mut g) = INIT_STATUS.lock() {
        *g = s;
    }
}

fn do_init(dir: &str) -> Engine {
    let base = std::path::Path::new(dir);
    let mut report = String::new();
    // ClamAV engine from the bundled DB, then add the compiled .yrc rulesets
    // (compiled only — never .yar source on-device).
    let clamav = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ClamavEngine::from_database_dir(base)
    })) {
        Ok(Ok((mut eng, _report))) => {
            report.push_str("clamav=ok");
            for name in YRC_FILES {
                let path = base.join(name);
                let added = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    eng.add_compiled_yara_file(&path)
                }));
                match added {
                    Ok(Some(_)) => report.push_str(&format!(" yrc[{}]=ok", name)),
                    Ok(None) => report.push_str(&format!(" yrc[{}]=ERR(load/deserialize)", name)),
                    Err(_) => report.push_str(&format!(" yrc[{}]=PANIC({})", name, last_panic())),
                }
            }
            Some(eng)
        }
        Ok(Err(e)) => {
            report.push_str(&format!("clamav=ERR({})", e));
            None
        }
        Err(_) => {
            report.push_str(&format!("clamav=PANIC({})", last_panic()));
            None
        }
    };
    let model = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Model::load_bin(&base.join(MODEL_BIN))
    })) {
        Ok(Ok(m)) => {
            report.push_str(" model=ok");
            Some(m)
        }
        Ok(Err(e)) => {
            report.push_str(&format!(" model=ERR({})", e));
            None
        }
        Err(_) => {
            report.push_str(&format!(" model=PANIC({})", last_panic()));
            None
        }
    };
    set_status(report);
    Engine { clamav, model }
}

/// Run `f` on a thread with a LARGE stack and return its result. yara_x's rule
/// deserialization (and clamav matching) can recurse deeply — far past the ~1 MB
/// stack of the JNI/app thread, which causes a stack overflow that aborts the
/// whole process (not a catchable panic). A roomy stack avoids it. Returns the
/// thread's join result (Err on a panic inside).
fn on_big_stack<F, R>(f: F) -> std::thread::Result<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(f)
        .expect("spawn worker thread")
        .join()
}

/// `boolean nativeInit(String dir)`
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeInit(
    mut env: JNIEnv,
    _class: JClass,
    dir: JString,
) -> jboolean {
    let dir: String = match env.get_string(&dir) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };
    install_panic_hook();
    // Init on a big-stack thread: yara_x deserialization of the .yrc recurses
    // deeply enough to overflow the JNI thread's stack (the on-device crash).
    let engine = match on_big_stack(move || do_init(&dir)) {
        Ok(e) => e,
        Err(_) => return JNI_FALSE,
    };
    let ok = engine.clamav.is_some() || engine.model.is_some();
    let _ = ENGINE.set(engine);
    if ok && ENGINE.get().is_some() {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// `String nativeStatus()` — what loaded / failed during init (diagnostics).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeStatus(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let s = INIT_STATUS.lock().map(|g| g.clone()).unwrap_or_default();
    match env.new_string(&s) {
        Ok(j) => j.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// `String nativeScanApk(String path)` — returns a JSON verdict.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeScanApk(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
) -> jstring {
    let result = scan_apk(&mut env, path);
    match env.new_string(&result) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn scan_apk(env: &mut JNIEnv, path: JString) -> String {
    let path: String = match env.get_string(&path) {
        Ok(s) => s.into(),
        Err(_) => return r#"{"error":"bad path"}"#.to_string(),
    };
    let Some(engine) = ENGINE.get() else {
        return r#"{"error":"not initialised"}"#.to_string();
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => return format!(r#"{{"error":"{}"}}"#, json_escape(&e.to_string())),
    };

    // Scan on a big-stack thread (deep clamav/yara recursion) which also catches
    // any panic — so neither a deep stack nor a panic on a malformed/adversarial
    // APK can SIGABRT the whole app process.
    let scanned = on_big_stack(move || run_scan(engine, &bytes, &path));
    match scanned {
        Ok(s) => s,
        Err(_) => {
            let reason = LAST_PANIC
                .lock()
                .ok()
                .and_then(|g| g.clone())
                .unwrap_or_else(|| "unknown".to_string());
            format!(
                r#"{{"error":"scan panicked: {}","malicious":false}}"#,
                json_escape(&reason)
            )
        }
    }
}

fn run_scan(engine: &Engine, bytes: &[u8], path: &str) -> String {
    // Extract ONCE here in the bridge: `buffers` holds the top-level file plus
    // every buffer reachable by recursively unpacking archives (APK = zip, plus
    // gz/tar/xz/lzma/7z/rar). BOTH engines then scan every buffer, so a malicious
    // classes*.dex, native lib, or an APK nested inside a zip is seen DECOMPRESSED
    // — the compressed container bytes never match clamav signatures or YARA on
    // their own (which is why a raw scan previously only lit up the
    // compression-agnostic ML model). Extraction lives only here, not inside the
    // clamav engine, so the file is unpacked a single time for both signals.
    //
    // Each engine is isolated: a panic in clamav doesn't lose the ML result (and
    // vice-versa), and `err` names WHICH engine + the panic location so the root
    // cause is pinpointed, not just swallowed.
    let mut err: Option<String> = None;
    let buffers = collect_buffers(bytes);
    // Dangerous-permission count from the (in-memory) manifest bytes, so an APK
    // reached only by extraction still gets permission-based detection. Java
    // applies the suspicious(5)/malware(6) threshold.
    let perm_count = max_dangerous_perms(&buffers);
    // Package name(s) of any APK reachable in the buffers (parsed from the
    // in-memory AndroidManifest.xml). Java matches these against its package
    // whitelist so a whitelisted app packed inside a zip is not a false positive.
    let packages = collect_packages(&buffers);
    // SHA-256 of each APK/zip buffer, for the hash-keyed whitelist bloom filter.
    let hashes = collect_apk_hashes(&buffers);
    // SHA-256 of the whole top-level file (its "main hash") — Java builds a
    // VirusTotal lookup link from this so the user can inspect it themselves.
    let file_sha256 = sha256_hex(bytes);

    // Each detection carries the APK lineage of the buffer it fired on, so Java
    // can suppress it iff one of those ancestor-APK hashes is whitelisted.
    let yara_dets: Vec<(String, Vec<String>)> = match &engine.clamav {
        Some(clamav) => {
            let opts = ScanOptions {
                strict_targets: true,
                max_matches: 64,
                ..ScanOptions::default()
            };
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut dets: Vec<(String, Vec<String>)> = Vec::new();
                for (i, b) in buffers.iter().enumerate() {
                    let name = if i == 0 {
                        path.to_string()
                    } else {
                        format!("{path}#extract[{i}]")
                    };
                    for m in clamav.scan_bytes_named(&b.data, &name, opts) {
                        dets.push((m.name, b.apk_lineage.clone()));
                        if dets.len() >= opts.max_matches {
                            return dets;
                        }
                    }
                }
                dets
            })) {
                Ok(v) => v,
                Err(_) => {
                    err = Some(format!("clamav: {}", last_panic()));
                    Vec::new()
                }
            }
        }
        None => Vec::new(),
    };

    // one-class ML model (independent of clamav's type gate), over the SAME
    // buffers — so an APK nested inside a zip (or any other extracted member)
    // also gets an ML verdict. The strongest signal across all buffers wins.
    let (ml_malicious, ml_jaccard, ml_anomaly, ml_nearest, ml_lineages) = match &engine.model {
        Some(model) => {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut malicious = false;
                let mut best_jaccard = 0.0_f32;
                let mut worst_anomaly = 0.0_f64;
                let mut nearest: Option<String> = None;
                // Lineage of every APK/zip buffer the model flagged malicious, so
                // the ML detection is suppressible by a whitelisted ancestor too.
                let mut lineages: Vec<Vec<String>> = Vec::new();
                for b in &buffers {
                    // The model is trained on whole APKs (= zip). Running it on
                    // raw extracted members (classes.dex, resources, .so, images)
                    // produces false positives, so only score APK/zip buffers
                    // (the top-level APK and any APK nested inside a zip).
                    if hydradragonextractor::detect_format(&b.data) != Some("zip") {
                        continue;
                    }
                    if let Some(r) = model.scan(&b.data) {
                        if r.malicious {
                            malicious = true;
                            lineages.push(b.apk_lineage.clone());
                        }
                        if r.best_jaccard > best_jaccard {
                            best_jaccard = r.best_jaccard;
                            nearest = r.nearest.clone();
                        }
                        if r.anomaly_score > worst_anomaly {
                            worst_anomaly = r.anomaly_score;
                        }
                    }
                }
                (malicious, best_jaccard, worst_anomaly, nearest, lineages)
            })) {
                Ok(t) => t,
                Err(_) => {
                    if err.is_none() {
                        err = Some(format!("ml: {}", last_panic()));
                    }
                    (false, 0.0, 0.0, None, Vec::new())
                }
            }
        }
        None => (false, 0.0, 0.0, None, Vec::new()),
    };

    // `matches` stays the clamav/YARA names only (display + PUA classification).
    let hits_json = yara_dets
        .iter()
        .map(|(h, _)| format!("\"{}\"", json_escape(h)))
        .collect::<Vec<_>>()
        .join(",");

    // Unified detection list: clamav/YARA hits plus one "ML" detection per
    // ml-flagged APK buffer, each tagged with its suppressible APK lineage.
    let mut detections: Vec<(String, Vec<String>)> = yara_dets;
    for lin in ml_lineages {
        detections.push(("ML".to_string(), lin));
    }

    let malicious = !detections.is_empty();
    let detections_json = detections
        .iter()
        .map(|(name, lineage)| {
            let hs = lineage
                .iter()
                .map(|h| format!("\"{}\"", h))
                .collect::<Vec<_>>()
                .join(",");
            format!("{{\"name\":\"{}\",\"hashes\":[{}]}}", json_escape(name), hs)
        })
        .collect::<Vec<_>>()
        .join(",");
    let nearest_json = match ml_nearest {
        Some(n) => format!("\"{}\"", json_escape(&n)),
        None => "null".to_string(),
    };
    let packages_json = packages
        .iter()
        .map(|p| format!("\"{}\"", json_escape(p)))
        .collect::<Vec<_>>()
        .join(",");
    let hashes_json = hashes
        .iter()
        .map(|h| format!("\"{}\"", h))
        .collect::<Vec<_>>()
        .join(",");

    let err_json = match err {
        Some(e) => format!(",\"error\":\"{}\"", json_escape(&e)),
        None => String::new(),
    };

    format!(
        r#"{{"malicious":{},"matches":[{}],"detections":[{}],"permissions":{},"packages":[{}],"hashes":[{}],"sha256":"{}","ml":{{"malicious":{},"jaccard":{:.4},"anomaly":{:.4},"nearest":{}}}{}}}"#,
        malicious, hits_json, detections_json, perm_count, packages_json, hashes_json, file_sha256, ml_malicious, ml_jaccard, ml_anomaly, nearest_json, err_json
    )
}

/// The most dangerous Android permissions (mirrors the Java `DANGEROUS_PERMISSIONS`
/// list). Used to give APKs reached only in-memory — e.g. an APK extracted from a
/// zip and never written to disk, so `PackageManager` can't read it — the same
/// permission-based detection, straight from the bytes (no temp file).
const DANGEROUS_PERMS: &[&str] = &[
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_CALL_LOG",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
];

fn to_utf16le(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

fn contains_sub(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Count the distinct dangerous permissions present in any single extracted
/// buffer. An APK's binary `AndroidManifest.xml` keeps permission names in its
/// string pool as readable UTF-8 OR UTF-16LE, so we look for both encodings.
/// Returns the max over buffers (not the sum) so unrelated files don't inflate
/// the count. Large buffers (dex/resources/native libs) are skipped — a manifest
/// is small — both for speed and to avoid stray matches in code string tables.
fn max_dangerous_perms(buffers: &[Buf]) -> usize {
    const MAX_MANIFEST_SCAN: usize = 4 * 1024 * 1024;
    let needles: Vec<(Vec<u8>, Vec<u8>)> = DANGEROUS_PERMS
        .iter()
        .map(|p| (p.as_bytes().to_vec(), to_utf16le(p)))
        .collect();
    let mut max = 0usize;
    for b in buffers {
        let buf = &b.data;
        if buf.len() > MAX_MANIFEST_SCAN {
            continue;
        }
        let mut count = 0usize;
        for (u8n, u16n) in &needles {
            if contains_sub(buf, u8n) || contains_sub(buf, u16n) {
                count += 1;
            }
        }
        if count > max {
            max = count;
        }
    }
    max
}

// ── Binary AndroidManifest.xml (AXML) package-name parser ───────────────────
// Lets Java apply its package-name whitelist to an APK reached only in-memory
// (e.g. extracted from a zip), so a whitelisted app packed inside an archive is
// NOT a false positive. Pure byte parsing — no temp file, no PackageManager.

fn rd_u16(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn rd_u32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// AXML varint length for UTF-8 string-pool entries (1 or 2 bytes; high bit of
/// the first byte signals a 2-byte length). Returns (next_offset, length).
fn axml_len8(d: &[u8], o: usize) -> Option<(usize, usize)> {
    let b0 = *d.get(o)? as usize;
    if b0 & 0x80 != 0 {
        let b1 = *d.get(o + 1)? as usize;
        Some((o + 2, ((b0 & 0x7f) << 8) | b1))
    } else {
        Some((o + 1, b0))
    }
}

/// AXML length for UTF-16 string-pool entries (1 or 2 u16 units). Returns
/// (next_offset, unit_count).
fn axml_len16(d: &[u8], o: usize) -> Option<(usize, usize)> {
    let w0 = rd_u16(d, o)? as usize;
    if w0 & 0x8000 != 0 {
        let w1 = rd_u16(d, o + 2)? as usize;
        Some((o + 4, ((w0 & 0x7fff) << 16) | w1))
    } else {
        Some((o + 2, w0))
    }
}

/// Parse the AXML string pool (chunk right after the 8-byte file header).
fn axml_strings(data: &[u8]) -> Option<Vec<String>> {
    let pool = 8usize;
    if rd_u16(data, pool)? != 0x0001 {
        return None; // not a string-pool chunk
    }
    let count = rd_u32(data, pool + 8)? as usize;
    let flags = rd_u32(data, pool + 16)?;
    let strings_start = rd_u32(data, pool + 20)? as usize;
    let is_utf8 = flags & (1 << 8) != 0;
    let offsets_base = pool + 28;
    let data_base = pool + strings_start;
    let mut out = Vec::with_capacity(count.min(8192));
    for i in 0..count.min(50000) {
        let off = rd_u32(data, offsets_base + i * 4)? as usize;
        let p = data_base + off;
        let s = if is_utf8 {
            let (q, _) = axml_len8(data, p)?; // utf-16 char count (skip)
            let (q, n) = axml_len8(data, q)?; // utf-8 byte count
            String::from_utf8_lossy(data.get(q..q + n)?).into_owned()
        } else {
            let (q, n) = axml_len16(data, p)?;
            let mut s = String::with_capacity(n);
            for j in 0..n {
                s.push(char::from_u32(rd_u16(data, q + j * 2)? as u32).unwrap_or('\u{FFFD}'));
            }
            s
        };
        out.push(s);
    }
    Some(out)
}

/// Extract the `package` attribute of the `<manifest>` element from a binary
/// AndroidManifest.xml. Returns `None` for non-AXML data or if absent.
fn axml_package(data: &[u8]) -> Option<String> {
    if rd_u16(data, 0)? != 0x0003 {
        return None; // not RES_XML_TYPE
    }
    let strings = axml_strings(data)?;
    let pool_size = rd_u32(data, 8 + 4)? as usize;
    let mut off = 8 + pool_size;
    let mut guard = 0;
    while off + 8 <= data.len() && guard < 100_000 {
        guard += 1;
        let ctype = rd_u16(data, off)?;
        let csize = rd_u32(data, off + 4)? as usize;
        if csize == 0 {
            break;
        }
        if ctype == 0x0102 {
            // RES_XML_START_ELEMENT. name index at off+20; attrExt starts at
            // off+16, so attributes begin at off+16+attributeStart.
            let name_idx = rd_u32(data, off + 20)? as usize;
            if strings.get(name_idx).map(|s| s == "manifest").unwrap_or(false) {
                let attr_start = rd_u16(data, off + 24)? as usize;
                let attr_count = rd_u16(data, off + 28)? as usize;
                let abase = off + 16 + attr_start;
                for i in 0..attr_count.min(256) {
                    let a = abase + i * 20;
                    let aname = rd_u32(data, a + 4)? as usize;
                    if strings.get(aname).map(|s| s == "package").unwrap_or(false) {
                        let raw = rd_u32(data, a + 8)?;
                        let idx = if raw != 0xFFFF_FFFF {
                            raw as usize
                        } else {
                            rd_u32(data, a + 16)? as usize
                        };
                        return strings.get(idx).cloned();
                    }
                }
                return None;
            }
        }
        off = off.checked_add(csize)?;
    }
    None
}

/// Lowercase hex SHA-256 of `data`.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Lowercase hex SHA-256 of every APK/zip buffer reachable in `buffers`, so Java
/// can match an in-memory (e.g. zip-nested) APK against a hash-keyed whitelist
/// bloom filter. Deduped, bounded.
fn collect_apk_hashes(buffers: &[Buf]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for b in buffers {
        if hydradragonextractor::detect_format(&b.data) != Some("zip") {
            continue; // only APK/zip containers
        }
        let s = sha256_hex(&b.data);
        if !out.contains(&s) {
            out.push(s);
            if out.len() >= 64 {
                break;
            }
        }
    }
    out
}

/// Package names of every APK reachable in `buffers` (each APK's extracted
/// AndroidManifest.xml). Deduped, bounded.
fn collect_packages(buffers: &[Buf]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for b in buffers {
        if let Some(p) = axml_package(&b.data) {
            if !p.is_empty() && !out.contains(&p) {
                out.push(p);
                if out.len() >= 64 {
                    break;
                }
            }
        }
    }
    out
}

/// Recursively unpack archives starting from `data`, returning every buffer —
/// the top-level file included — so both the clamav/YARA engine and the ML model
/// can scan each one decompressed. An APK is a zip; a zip may itself contain an
/// APK, a `.so`, a nested archive, etc. Non-archive buffers contribute only
/// themselves. Bounded so a malicious "zip bomb" can't exhaust memory: capped
/// buffer count, recursion depth and per-buffer size. `detect_format` gates the
/// extractor so plain files never fall through to its 7z fallback.
/// A decompressed buffer plus the SHA-256s of every ancestor APK/zip in its
/// extraction lineage (including its OWN hash when it is itself a zip/APK). A
/// malicious hit on this buffer can be suppressed only if one of these lineage
/// hashes is whitelisted — so a known-good APK clears every component extracted
/// from it, while a non-APK file sitting alongside a whitelisted APK (empty or
/// non-whitelisted lineage) is still flagged.
struct Buf {
    data: Vec<u8>,
    apk_lineage: Vec<String>,
}

fn collect_buffers(data: &[u8]) -> Vec<Buf> {
    const MAX_BUFFERS: usize = 4096;
    const MAX_DEPTH: usize = 8;
    const MAX_SIZE: usize = 128 * 1024 * 1024;

    let mut out: Vec<Buf> = Vec::new();
    let mut stack: Vec<(Vec<u8>, usize, Vec<String>)> = vec![(data.to_vec(), 0, Vec::new())];
    while let Some((buf, depth, parent_lineage)) = stack.pop() {
        if out.len() >= MAX_BUFFERS {
            break;
        }
        if buf.len() > MAX_SIZE {
            continue;
        }
        let mut lineage = parent_lineage;
        // A zip/APK contributes its own hash to its (and its children's) lineage.
        if hydradragonextractor::detect_format(&buf) == Some("zip") {
            lineage.push(sha256_hex(&buf));
        }
        if depth < MAX_DEPTH && hydradragonextractor::detect_format(&buf).is_some() {
            if let Ok(children) = hydradragonextractor::extract_archive_from_bytes(&buf) {
                for child in children {
                    stack.push((child, depth + 1, lineage.clone()));
                }
            }
        }
        out.push(Buf {
            data: buf,
            apk_lineage: lineage,
        });
    }
    out
}

/// The last captured panic ("message @ file:line"), for diagnostics.
fn last_panic() -> String {
    LAST_PANIC
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_else(|| "?".to_string())
}
