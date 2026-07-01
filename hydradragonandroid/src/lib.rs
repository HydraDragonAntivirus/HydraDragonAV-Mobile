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
use hydradragonxorfilter::XorFilter;

mod dex_scan;
mod ip_scan;
mod url_scan;

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
/// Malware TLSH similarity database (one T1 digest per line), built from the
/// MalwareBazaar dump filtered to apk/elf/so/dex (`gen_tlsh_db.py`).
const TLSH_DB: &str = "malware_tlsh.txt";
/// NSRL known-good SHA-256 whitelist as a serialized Binary-Fuse (xor) filter
/// (built offline by `xorfilter_writer`). Decoded once at init into an owned
/// buffer on the native heap; binary-fuse encodings are far smaller than the
/// equivalent quotient filter, so the whitelist stays modest in RAM.
const WHITELIST_XF: &str = "whitelist.xf";
/// Same whitelist_packages.db Java's ScanEngine.loadPackageWhitelist reads
/// (table whitelist_package: key TEXT, md5 TEXT, ...). Loaded once at init into
/// an owned key->md5 map so a nested APK buffer whose package name AND md5
/// exactly match a row can skip the heavy scan below instead of Rust redoing
/// work Java's whitelist already vouches for. Matching BOTH fields (not just
/// the package name) keeps this safe against a spoofed package name — only an
/// exact known-good file is skipped, and only that one buffer: a sibling
/// non-whitelisted file/APK inside the same archive is scanned normally.
const WHITELIST_PACKAGES_DB: &str = "whitelist_packages.db";

/// A scanned buffer whose TLSH distance to a known-malware digest is at or below
/// this is flagged as similar. Lower = stricter (fewer FP). TLSH distance: 0 =
/// identical, <30 very close, <70 related (per the TLSH paper).
const TLSH_THRESHOLD: i32 = 40;

struct Engine {
    /// ClamAV engine: loaded from the bundled signature DB with the compiled
    /// `.yrc` YARA rulesets added. It does the whole scan — file-type detection,
    /// supported-type gating (`is_target_allowed`), clamav signatures AND YARA,
    /// all in one pass. `None` if no clamav DB was bundled.
    clamav: Option<ClamavEngine>,
    model: Option<Model>,
    /// Known-malware TLSH digests (apk/elf/so/dex) for fuzzy-similarity detection.
    tlsh_db: Vec<tlsh_rs::TlshDigest>,
    /// NSRL known-good SHA-256 whitelist (Binary-Fuse xor filter).
    whitelist: Option<XorFilter>,
    /// NSRL known-good package -> md5 map, read from whitelist_packages.db.
    /// See WHITELIST_PACKAGES_DB.
    package_whitelist: std::collections::HashMap<String, String>,
    /// Malicious domain/URL xor filters + public-suffix list.
    url_scanner: Option<url_scan::UrlScanner>,
    /// Malicious-IP xor filters (per category).
    ip_scanner: Option<ip_scan::IpScanner>,
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
    let tlsh_db = load_tlsh_db(&base.join(TLSH_DB));
    report.push_str(&format!(" tlsh={}", tlsh_db.len()));

    let whitelist = load_whitelist(&base.join(WHITELIST_XF));
    report.push_str(&format!(" whitelist={}", if whitelist.is_some() { "ok" } else { "none" }));

    let package_whitelist = load_package_whitelist(&base.join(WHITELIST_PACKAGES_DB));
    report.push_str(&format!(" package_whitelist={}", package_whitelist.len()));

    let url_scanner = std::panic::catch_unwind(|| url_scan::UrlScanner::load(base))
        .ok()
        .flatten();
    report.push_str(&format!(" url={}", if url_scanner.is_some() { "ok" } else { "none" }));

    let ip_scanner = std::panic::catch_unwind(|| ip_scan::IpScanner::load(base))
        .ok()
        .flatten();
    report.push_str(&format!(" ip={}", if ip_scanner.is_some() { "ok" } else { "none" }));

    set_status(report);
    Engine {
        clamav,
        model,
        tlsh_db,
        whitelist,
        package_whitelist,
        url_scanner,
        ip_scanner,
    }
}

/// Load `key -> md5` from whitelist_packages.db's `whitelist_package` table
/// (read-only; same file Java reads). Empty map if absent/unreadable — the
/// heavy scan then just runs on every buffer as before.
fn load_package_whitelist(path: &std::path::Path) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let Ok(conn) = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) else {
        return out;
    };
    let Ok(mut stmt) = conn.prepare("SELECT key, md5 FROM whitelist_package WHERE md5 IS NOT NULL")
    else {
        return out;
    };
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    });
    if let Ok(rows) = rows {
        for row in rows.flatten() {
            out.insert(row.0, row.1.to_lowercase());
        }
    }
    out
}

/// Load a serialized Binary-Fuse (xor) filter from a `.xf` asset. The file is
/// mmap'd to back the decode (pages come from the OS page cache); the returned
/// filter owns its data. None if the file is absent or not a valid `.xf`.
pub(crate) fn load_xor_filter(path: &std::path::Path) -> Option<XorFilter> {
    XorFilter::load(path)
}

/// Load the NSRL whitelist xor filter. None if absent.
fn load_whitelist(path: &std::path::Path) -> Option<XorFilter> {
    load_xor_filter(path)
}

/// Load the malware TLSH digests (one `T1...` per line) into parsed digests.
/// Unparsable lines are skipped. Returns empty if the file is absent.
fn load_tlsh_db(path: &std::path::Path) -> Vec<tlsh_rs::TlshDigest> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(d) = line.parse::<tlsh_rs::TlshDigest>() {
            out.push(d);
        }
    }
    out
}

/// Whether `buf` is a file type we have TLSH malware digests for (apk/zip, ELF,
/// or DEX) — so we only fuzzy-compare relevant buffers, not every PNG/XML.
fn tlsh_relevant(buf: &[u8]) -> bool {
    hydradragonextractor::detect_format(buf) == Some("zip")
        || buf.starts_with(b"\x7fELF")
        || buf.starts_with(b"dex\n")
}

/// Smallest TLSH distance from `buf` to any known-malware digest, or None when
/// `buf` is too small/low-variance to hash or nothing is close enough.
fn tlsh_nearest(engine: &Engine, buf: &[u8]) -> Option<i32> {
    if engine.tlsh_db.is_empty() {
        return None;
    }
    let digest = tlsh_rs::hash_bytes(buf).ok()?;
    let mut best = i32::MAX;
    for known in &engine.tlsh_db {
        let d = digest.diff(known);
        if d < best {
            best = d;
            if best == 0 {
                break;
            }
        }
    }
    (best <= TLSH_THRESHOLD).then_some(best)
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

/// `boolean nativeIsHashWhitelisted(String md5)` — true if the MD5 is in the
/// NSRL whitelist (Binary-Fuse xor filter). Lets Java suppress false positives
/// by hash without holding the filter in the Java heap.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeIsHashWhitelisted<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    hash: JString<'local>,
) -> jboolean {
    let h: String = match env.get_string(&hash) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };
    let hit = ENGINE
        .get()
        .and_then(|e| e.whitelist.as_ref())
        // XorFilter::contains lowercases internally, so pass the hash as-is.
        .map(|wl| wl.contains(&h))
        .unwrap_or(false);
    if hit { JNI_TRUE } else { JNI_FALSE }
}

/// `String nativeScanUrl(String url)` — malicious category (e.g. "PHISHING")
/// for an http(s) URL, or "" if clean / not a URL. All membership is the native
/// xor-filter URL/domain scanner, so no filter sits in the Java heap.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeScanUrl<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    url: JString<'local>,
) -> jstring {
    let u: String = match env.get_string(&url) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };
    let cat = ENGINE
        .get()
        .and_then(|e| e.url_scanner.as_ref())
        .and_then(|s| s.scan(&u))
        .unwrap_or("");
    match env.new_string(cat) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// `String nativeScanIp(String ip)` — category (e.g. "MALWARE_IP") for a
/// blocklisted IP, or "" if clean. Exact match against the per-category xor
/// filters (allips non-CIDR); no subnet/CIDR matching.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeScanIp<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    ip: JString<'local>,
) -> jstring {
    let ip: String = match env.get_string(&ip) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };
    let cat = ENGINE
        .get()
        .and_then(|e| e.ip_scanner.as_ref())
        .and_then(|s| s.scan(&ip))
        .unwrap_or("");
    match env.new_string(cat) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// `String nativeScanText(String text, String packageName)` — runs the
/// clamav/YARA engine (hydradragon.screen_text + plain-string rules) against
/// OCR'd on-screen text and returns a comma-joined list of matched rule/sig
/// names ("" if clean or the engine isn't ready). Used by ScreenCaptureService
/// so a scam/ransomware message actually rendered on screen can be caught even
/// when it never touches the APK's own bytes.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeScanText<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    text: JString<'local>,
) -> jstring {
    let t: String = match env.get_string(&text) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };
    let result = scan_text(&t);
    match env.new_string(&result) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn scan_text(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let Some(engine) = ENGINE.get() else {
        return String::new();
    };
    let Some(clamav) = &engine.clamav else {
        return String::new();
    };
    // Cap: OCR text is display-sized, never worth scanning megabytes of it.
    let bytes = if text.len() > 8192 { &text.as_bytes()[..8192] } else { text.as_bytes() };
    let meta_json = format!(r#"{{"screen_text":"{}"}}"#, json_escape(text));
    let module_meta: Vec<(&str, &[u8])> = vec![("hydradragon", meta_json.as_bytes())];
    let opts = ScanOptions {
        strict_targets: false,
        max_matches: 16,
        ..ScanOptions::default()
    };
    let names = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        clamav
            .scan_bytes_named(bytes, "screen_text", opts, &module_meta)
            .into_iter()
            .map(|m| m.name)
            .collect::<Vec<_>>()
    }))
    .unwrap_or_default();
    names.join(",")
}

/// `String nativeScanApk(String path)` — returns a JSON verdict.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeScanApk<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    path: JString<'local>,
    hydradragon_json: JString<'local>,
    file_md5: JString<'local>,
) -> jstring {
    let result = scan_apk(&mut env, path, hydradragon_json, file_md5);
    match env.new_string(&result) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn scan_apk(
    env: &mut JNIEnv,
    path: JString,
    hydradragon_json: JString,
    file_md5: JString,
) -> String {
    let path: String = match env.get_string(&path) {
        Ok(s) => s.into(),
        Err(_) => return r#"{"error":"bad path"}"#.to_string(),
    };
    // Live-network report from Java (hydradragon module). Empty/absent → None.
    let hydradragon: Option<Vec<u8>> = env
        .get_string(&hydradragon_json)
        .ok()
        .map(|s| String::from(s).into_bytes())
        .filter(|b| !b.is_empty());
    // MD5 Java already computed for the whole file (hash-first fast path). Reused
    // for the top-level buffer so it isn't hashed again here. Empty → None.
    let file_md5: Option<String> = env
        .get_string(&file_md5)
        .ok()
        .map(String::from)
        .filter(|s| !s.is_empty());
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
    let scanned = on_big_stack(move || {
        run_scan(engine, &bytes, &path, hydradragon.as_deref(), file_md5.as_deref())
    });
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

fn run_scan(
    engine: &Engine,
    bytes: &[u8],
    path: &str,
    hydradragon: Option<&[u8]>,
    file_md5: Option<&str>,
) -> String {
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
    let buffers = collect_buffers(bytes, file_md5);
    // Dangerous-permission count from the (in-memory) manifest bytes, so an APK
    // reached only by extraction still gets permission-based detection. Java
    // applies the suspicious(5)/malware(6) threshold.
    let perm_count = max_dangerous_perms(&buffers);
    // Package name(s) of any APK reachable in the buffers (parsed from the
    // in-memory AndroidManifest.xml). Java matches these against its package
    // whitelist so a whitelisted app packed inside a zip is not a false positive.
    let packages = collect_packages(&buffers);
    // MD5 of each APK/zip buffer, for the hash-keyed whitelist.
    let hashes = collect_apk_hashes(&buffers, file_md5);
    // MD5 of the whole top-level file (its "main hash") — Java builds a
    // VirusTotal lookup link from this (VT accepts md5). Reuses Java's md5.
    let file_hash = match file_md5 {
        Some(md5) => md5.to_string(),
        None => md5_hex(bytes),
    };
    // androguard JSON report (manifest + URL sweep), fed to the YARA-X
    // `androguard` module so its rules (permission/url/package_name/...) work.
    // None when no AndroidManifest.xml is reachable (not an APK).
    let androguard_json = build_androguard_json(&buffers);
    // Per-module metadata fed to YARA-X: the `androguard` static report and the
    // `hydradragon` live-network report (passed in from Java's network monitor).
    let mut module_meta: Vec<(&str, &[u8])> = Vec::new();
    if let Some(j) = androguard_json.as_deref() {
        module_meta.push(("androguard", j.as_bytes()));
    }
    if let Some(h) = hydradragon {
        if !h.is_empty() {
            module_meta.push(("hydradragon", h));
        }
    }

    // Per-buffer "already vouched for by Java's whitelist_packages.db" flag:
    // true only when the buffer's OWN package name AND md5 exactly match a row
    // (see WHITELIST_PACKAGES_DB) — never propagated to children/siblings, so a
    // non-whitelisted file/APK sitting next to a whitelisted one in the same
    // archive is still fully scanned below.
    let skip_heavy: Vec<bool> = buffers
        .iter()
        .map(|b| {
            if engine.package_whitelist.is_empty() {
                return false;
            }
            let Some(pkg) = axml_package(&b.data) else {
                return false;
            };
            if pkg.is_empty() {
                return false;
            }
            match engine.package_whitelist.get(&pkg) {
                Some(known_md5) => known_md5.eq_ignore_ascii_case(&md5_hex(&b.data)),
                None => false,
            }
        })
        .collect();

    // Decode + statically analyse every DEX buffer once (strings + method/class
    // names), reused below for both the clamav/YARA text pass and findings.
    let dex_scans: Vec<Option<dex_scan::DexScan>> = buffers
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if !skip_heavy[i] && b.data.starts_with(b"dex\n") {
                dex_scan::scan(&b.data)
            } else {
                None
            }
        })
        .collect();

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
                    if skip_heavy[i] {
                        continue;
                    }
                    let name = if i == 0 {
                        path.to_string()
                    } else {
                        format!("{path}#extract[{i}]")
                    };
                    for m in clamav.scan_bytes_named(&b.data, &name, opts, &module_meta) {
                        dets.push((m.name, b.apk_lineage.clone()));
                        if dets.len() >= opts.max_matches {
                            return dets;
                        }
                    }
                    // Also scan the DEX's decoded string pool (method/class names
                    // contiguous, no MUTF-8/length-prefix noise).
                    if let Some(ds) = &dex_scans[i] {
                        let dname = format!("{name}#dex");
                        for m in clamav.scan_bytes_named(ds.text.as_bytes(), &dname, opts, &module_meta) {
                            dets.push((m.name, b.apk_lineage.clone()));
                            if dets.len() >= opts.max_matches {
                                return dets;
                            }
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
                for (i, b) in buffers.iter().enumerate() {
                    if skip_heavy[i] {
                        continue;
                    }
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

    // DEX static-analysis: only High/Critical findings count as malicious.
    for (i, b) in buffers.iter().enumerate() {
        if let Some(ds) = &dex_scans[i] {
            for (sev, msg) in &ds.findings {
                if dex_scan::is_severe(*sev) {
                    detections.push((format!("DEX/{sev:?}: {msg}"), b.apk_lineage.clone()));
                }
            }
        }
    }

    // TLSH fuzzy-similarity to known malware: compare each apk/elf/dex buffer's
    // TLSH against the MalwareBazaar database; a small distance => a likely
    // variant. Tagged with the buffer's APK lineage so a whitelisted APK is
    // still suppressed.
    for (i, b) in buffers.iter().enumerate() {
        if skip_heavy[i] {
            continue;
        }
        if tlsh_relevant(&b.data) {
            if let Some(dist) = tlsh_nearest(engine, &b.data) {
                detections.push((format!("TLSH.Malware/dist={}", dist), b.apk_lineage.clone()));
            }
        }
    }

    let malicious = !detections.is_empty();
    // yarGen-style auto-generated rule for THIS malicious sample only — every
    // string comes straight from this sample's own DEX string pool, no
    // goodware/whitelist DB filtering (unlike real yarGen). References the
    // androguard and hydradragon modules in its condition, not just literal
    // strings, so it also fires on package-name/network reruns of the same
    // family. None for a clean scan.
    let generated_rule = if malicious {
        generate_yara_rule(&file_hash, &packages, &detections, &dex_scans)
    } else {
        None
    };
    let generated_rule_json = match &generated_rule {
        Some(r) => format!("\"{}\"", json_escape(r)),
        None => "null".to_string(),
    };
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
        r#"{{"malicious":{},"matches":[{}],"detections":[{}],"permissions":{},"packages":[{}],"hashes":[{}],"md5":"{}","ml":{{"malicious":{},"jaccard":{:.4},"anomaly":{:.4},"nearest":{}}},"generated_rule":{}{}}}"#,
        malicious, hits_json, detections_json, perm_count, packages_json, hashes_json, file_hash, ml_malicious, ml_jaccard, ml_anomaly, nearest_json, generated_rule_json, err_json
    )
}

/// Build a yarGen-style YARA rule from THIS scan's own results (no
/// goodware/whitelist-DB string filtering — every string here comes straight
/// from the sample itself). Only called when the scan is malicious, so a
/// clean app never gets an ad-hoc rule generated for it. `import`s the
/// androguard and hydradragon modules and references them in the condition
/// (package name / network) rather than relying on literal strings alone.
fn generate_yara_rule(
    file_hash: &str,
    packages: &[String],
    detections: &[(String, Vec<String>)],
    dex_scans: &[Option<dex_scan::DexScan>],
) -> Option<String> {
    if detections.is_empty() {
        return None;
    }
    let mut strings: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    'outer: for ds in dex_scans.iter().flatten() {
        for line in ds.text.lines() {
            let l = line.trim();
            if l.len() < 8 || l.len() > 128 || l.chars().any(|c| c.is_control()) {
                continue;
            }
            if !seen.insert(l.to_string()) {
                continue;
            }
            strings.push(l.to_string());
            if strings.len() >= 40 {
                break 'outer;
            }
        }
    }
    if strings.is_empty() && packages.is_empty() {
        return None;
    }

    let rule_name = format!("auto_{}", file_hash);
    let mut out = String::new();
    out.push_str("import \"androguard\"\nimport \"hydradragon\"\n\n");
    out.push_str(&format!("rule {} {{\n", rule_name));
    out.push_str("  meta:\n");
    out.push_str("    generator = \"hydradragon-autogen (yarGen-style, no whitelist filtering)\"\n");
    out.push_str(&format!("    sample_md5 = \"{}\"\n", file_hash));
    let det_names: Vec<String> = detections.iter().map(|(n, _)| n.replace('"', "'")).collect();
    out.push_str(&format!(
        "    based_on_detections = \"{}\"\n",
        det_names.join(", ")
    ));
    if !strings.is_empty() {
        out.push_str("  strings:\n");
        for (i, s) in strings.iter().enumerate() {
            out.push_str(&format!(
                "    $s{} = \"{}\" ascii wide\n",
                i,
                s.replace('\\', "\\\\").replace('"', "\\\"")
            ));
        }
    }
    out.push_str("  condition:\n");
    let mut clauses: Vec<String> = Vec::new();
    for pkg in packages {
        clauses.push(format!(
            "androguard.package_name(\"{}\")",
            pkg.replace('"', "'")
        ));
    }
    if !strings.is_empty() {
        let threshold = strings.len().min(6).max(1);
        clauses.push(format!("{} of them", threshold));
    }
    if clauses.is_empty() {
        clauses.push("false".to_string());
    }
    out.push_str(&format!("    {}\n", clauses.join(" or\n    ")));
    out.push_str("}\n");
    Some(out)
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

// ── androguard report producer ──────────────────────────────────────────────
// Builds the JSON report consumed by the YARA-X `androguard` module
// (set_module_metadata("androguard", ...)). Mirrors the keys the original
// Koodous module read: package_name, app_name, activities, services, receivers,
// permissions, urls, min/max/target_sdk_version, certificate{subjectDN,
// IssuerDN, sha1}. Parsed straight from the binary AndroidManifest.xml plus a
// URL sweep of the decompressed buffers — no androguard/Python dependency.
//
// NOTE: `certificate.*` requires parsing the PKCS#7 signature block (X.509),
// which isn't available here yet, so it is emitted empty (rules using
// certificate.sha1/issuer/subject simply won't match). Everything else
// (permission, package_name, activity, service, receiver, url,
// permissions_number, sdk) is populated.

/// Read a string-typed AXML attribute value (raw string-pool ref, or a typed
/// TYPE_STRING). Returns None for non-string attributes.
fn axml_attr_string(data: &[u8], strings: &[String], a: usize) -> Option<String> {
    let raw = rd_u32(data, a + 8)?;
    if raw != 0xFFFF_FFFF {
        return strings.get(raw as usize).cloned();
    }
    // Typed value: a+12 = size(u16)+res0(u8)+dataType(u8); a+16 = data(u32).
    let dtype = *data.get(a + 15)?;
    if dtype == 0x03 {
        // TYPE_STRING
        strings.get(rd_u32(data, a + 16)? as usize).cloned()
    } else {
        None
    }
}

/// Read an int-typed AXML attribute (TYPE_INT_DEC etc.): data u32 at a+16.
fn axml_attr_int(data: &[u8], a: usize) -> Option<i64> {
    Some(rd_u32(data, a + 16)? as i64)
}

/// Find a named attribute (`attr_name`) within a START_ELEMENT at `off`.
/// Returns the absolute attribute offset, or None.
fn axml_find_attr(
    data: &[u8],
    strings: &[String],
    off: usize,
    attr_name: &str,
) -> Option<usize> {
    let attr_start = rd_u16(data, off + 24)? as usize;
    let attr_count = rd_u16(data, off + 28)? as usize;
    let abase = off + 16 + attr_start;
    for i in 0..attr_count.min(256) {
        let a = abase + i * 20;
        let aname = rd_u32(data, a + 4)? as usize;
        if strings.get(aname).map(|s| s == attr_name).unwrap_or(false) {
            return Some(a);
        }
    }
    None
}

/// Parse a binary AndroidManifest.xml into the fields androguard exposes.
struct Manifest {
    package: Option<String>,
    app_name: Option<String>,
    permissions: Vec<String>,
    activities: Vec<String>,
    services: Vec<String>,
    receivers: Vec<String>,
    min_sdk: Option<i64>,
    max_sdk: Option<i64>,
    target_sdk: Option<i64>,
}

fn parse_manifest(data: &[u8]) -> Option<Manifest> {
    if rd_u16(data, 0)? != 0x0003 {
        return None; // not RES_XML_TYPE
    }
    let strings = axml_strings(data)?;
    let pool_size = rd_u32(data, 8 + 4)? as usize;
    let mut off = 8 + pool_size;
    let mut guard = 0;
    let mut m = Manifest {
        package: None,
        app_name: None,
        permissions: Vec::new(),
        activities: Vec::new(),
        services: Vec::new(),
        receivers: Vec::new(),
        min_sdk: None,
        max_sdk: None,
        target_sdk: None,
    };
    while off + 8 <= data.len() && guard < 200_000 {
        guard += 1;
        let ctype = rd_u16(data, off)?;
        let csize = rd_u32(data, off + 4)? as usize;
        if csize == 0 {
            break;
        }
        if ctype == 0x0102 {
            // RES_XML_START_ELEMENT: element name at off+20.
            let name_idx = rd_u32(data, off + 20)? as usize;
            let ename = strings.get(name_idx).map(|s| s.as_str()).unwrap_or("");
            match ename {
                "manifest" => {
                    if let Some(a) = axml_find_attr(data, &strings, off, "package") {
                        m.package = axml_attr_string(data, &strings, a);
                    }
                }
                "uses-sdk" => {
                    if let Some(a) = axml_find_attr(data, &strings, off, "minSdkVersion") {
                        m.min_sdk = axml_attr_int(data, a);
                    }
                    if let Some(a) = axml_find_attr(data, &strings, off, "maxSdkVersion") {
                        m.max_sdk = axml_attr_int(data, a);
                    }
                    if let Some(a) = axml_find_attr(data, &strings, off, "targetSdkVersion") {
                        m.target_sdk = axml_attr_int(data, a);
                    }
                }
                "uses-permission" | "permission" => {
                    if let Some(a) = axml_find_attr(data, &strings, off, "name") {
                        if let Some(v) = axml_attr_string(data, &strings, a) {
                            m.permissions.push(v);
                        }
                    }
                }
                "application" => {
                    if let Some(a) = axml_find_attr(data, &strings, off, "label") {
                        // Only a literal label is usable; a @resource ref needs
                        // resources.arsc resolution (not done here).
                        m.app_name = axml_attr_string(data, &strings, a);
                    }
                }
                "activity" | "activity-alias" => push_component(data, &strings, off, &mut m.activities),
                "service" => push_component(data, &strings, off, &mut m.services),
                "receiver" => push_component(data, &strings, off, &mut m.receivers),
                _ => {}
            }
        }
        off = off.checked_add(csize)?;
    }
    Some(m)
}

fn push_component(data: &[u8], strings: &[String], off: usize, out: &mut Vec<String>) {
    if out.len() >= 4096 {
        return;
    }
    if let Some(a) = axml_find_attr(data, strings, off, "name") {
        if let Some(v) = axml_attr_string(data, strings, a) {
            out.push(v);
        }
    }
}

/// Sweep decompressed buffers for http(s) URLs (androguard's `urls`). Deduped,
/// bounded. Scans dex/resources/etc. as raw bytes — URLs are ASCII.
fn collect_urls(buffers: &[Buf]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for b in buffers {
        let data = &b.data;
        let n = data.len();
        let mut i = 0;
        while i + 7 < n {
            let is_http = &data[i..i + 7] == b"http://";
            let is_https = i + 8 < n && &data[i..i + 8] == b"https://";
            if is_http || is_https {
                let start = i;
                let mut j = i;
                // URL chars until whitespace, quote, or control byte.
                while j < n {
                    let c = data[j];
                    if c <= 0x20 || c == b'"' || c == b'\'' || c == b'<' || c == b'>'
                        || c == b'\\' || c == 0x7f || c >= 0x80
                    {
                        break;
                    }
                    j += 1;
                }
                if j - start >= 10 && j - start <= 2048 {
                    if let Ok(s) = std::str::from_utf8(&data[start..j]) {
                        let s = s.to_string();
                        if seen.insert(s.clone()) {
                            out.push(s);
                            if out.len() >= 4096 {
                                return out;
                            }
                        }
                    }
                }
                i = j;
            } else {
                i += 1;
            }
        }
    }
    out
}

/// Build the androguard JSON report for the scanned APK, or None if no binary
/// AndroidManifest.xml is reachable in the buffers (not an APK).
fn build_androguard_json(buffers: &[Buf]) -> Option<String> {
    let manifest = buffers.iter().find_map(|b| parse_manifest(&b.data))?;
    let urls = collect_urls(buffers);

    let arr = |items: &[String]| -> String {
        items
            .iter()
            .map(|s| format!("\"{}\"", json_escape(s)))
            .collect::<Vec<_>>()
            .join(",")
    };
    let opt_str = |o: &Option<String>| -> String {
        match o {
            Some(s) => format!("\"{}\"", json_escape(s)),
            None => "null".to_string(),
        }
    };
    // SDK versions are emitted as strings (the C module ran atoi over strings).
    let opt_sdk = |o: Option<i64>| -> String {
        match o {
            Some(v) => format!("\"{}\"", v),
            None => "null".to_string(),
        }
    };

    Some(format!(
        concat!(
            "{{\"package_name\":{},\"app_name\":{},\"main_activity\":null,",
            "\"activities\":[{}],\"services\":[{}],\"receivers\":[{}],",
            "\"permissions\":[{}],\"new_permissions\":[{}],\"urls\":[{}],",
            "\"min_sdk_version\":{},\"max_sdk_version\":{},\"target_sdk_version\":{},",
            "\"certificate\":{{\"subjectDN\":null,\"IssuerDN\":null,\"sha1\":null}}}}"
        ),
        opt_str(&manifest.package),
        opt_str(&manifest.app_name),
        arr(&manifest.activities),
        arr(&manifest.services),
        arr(&manifest.receivers),
        arr(&manifest.permissions),
        arr(&manifest.permissions), // new_permissions mirrors permissions here
        arr(&urls),
        opt_sdk(manifest.min_sdk),
        opt_sdk(manifest.max_sdk),
        opt_sdk(manifest.target_sdk),
    ))
}

/// Lowercase hex MD5 of `data` (the whitelist is keyed on MD5).
fn md5_hex(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    let digest = Md5::digest(data);
    let mut s = String::with_capacity(32);
    for b in digest {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Lowercase hex MD5 of every APK/zip buffer reachable in `buffers`, so Java can
/// match an in-memory (e.g. zip-nested) APK against the hash-keyed whitelist.
/// Deduped, bounded.
fn collect_apk_hashes(buffers: &[Buf], top_md5: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (i, b) in buffers.iter().enumerate() {
        if hydradragonextractor::detect_format(&b.data) != Some("zip") {
            continue; // only APK/zip containers
        }
        // buffers[0] is the top-level file — reuse Java's MD5 for it.
        let s = match top_md5 {
            Some(md5) if i == 0 => md5.to_string(),
            _ => md5_hex(&b.data),
        };
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
/// A decompressed buffer plus the MD5s of every ancestor APK/zip in its
/// extraction lineage (including its OWN hash when it is itself a zip/APK). A
/// malicious hit on this buffer can be suppressed only if one of these lineage
/// hashes is whitelisted — so a known-good APK clears every component extracted
/// from it, while a non-APK file sitting alongside a whitelisted APK (empty or
/// non-whitelisted lineage) is still flagged.
struct Buf {
    data: Vec<u8>,
    apk_lineage: Vec<String>,
}

/// `top_md5` is Java's already-computed MD5 of the whole scanned file, reused for
/// the top-level (depth 0) buffer so the largest buffer isn't hashed twice.
fn collect_buffers(data: &[u8], top_md5: Option<&str>) -> Vec<Buf> {
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
            let h = match top_md5 {
                Some(md5) if depth == 0 => md5.to_string(),
                _ => md5_hex(&buf),
            };
            lineage.push(h);
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
