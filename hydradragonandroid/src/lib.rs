//! JNI bridge for the Android app.
//!
//! Exposes native methods on `com.hydradragon.antivirus.engine.NativeScanner`.
//!
//! YARA rules loaded at init:
//!   - clean_rules_filtered_verified.yrc
//!   - valhalla-rules_filtered_verified.yrc
//!   - machine_learning_apk.yrc
//!   - androguard.yrc
//!   - hips_rules_filtered_verified.yrc
//!
//! Suricata-format rule engine initialised on-demand when VPN starts:
//!   - emerging-all.rules parsed at runtime via suricata_scan::RuleEngine
//!
//! ML model:
//!   - model.mpk

use std::sync::atomic::Ordering;
use std::sync::OnceLock;

use hydradragonclamav::{Engine as ClamavEngine, is_apk_zip, is_text_like, ScanOptions};
use hydradragonml::features::EngineFeatures;
use hydradragonml::Model;
use hydradragonxorfilter::XorFilter;
use base64::Engine as Base64Engine;

#[cfg(target_os = "android")]
mod asset_reader;
#[cfg(not(target_os = "android"))]
#[path = "asset_reader_stub.rs"]
mod asset_reader;
mod dex_scan;
#[cfg(target_os = "android")]
mod elf;
mod tlsh_db;
#[cfg(target_os = "android")]
#[path = "emulate.rs"]
mod emulate;
#[cfg(not(target_os = "android"))]
#[path = "emulate_stub.rs"]
mod emulate;
mod ip_scan;
mod media_scan;
mod suricata_scan;
mod url_scan;
mod benign_db;
mod riskware;

use jni::errors::LogErrorAndDefault;
use jni::objects::{JClass, JObject, JString};
use jni::sys::{jboolean, jint, jstring, JNI_FALSE, JNI_TRUE};
use jni::EnvUnowned;
use std::fmt::Write;

// Direct FFI into Android's liblog.so (always present in an app process,
#[cfg(target_os = "android")]
#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(
        prio: std::os::raw::c_int,
        tag: *const std::os::raw::c_char,
        text: *const std::os::raw::c_char,
    ) -> std::os::raw::c_int;
}
#[cfg(target_os = "android")]
const ANDROID_LOG_INFO: std::os::raw::c_int = 4;

/// Writes one line to logcat, or prints to stderr on host builds.
pub(crate) fn android_log(msg: &str) {
    #[cfg(target_os = "android")]
    unsafe {
        use std::ffi::CString;
        let (Ok(tag), Ok(text)) = (
            CString::new("HydraDragon-RustTiming"),
            CString::new(msg),
        ) else {
            return;
        };
        __android_log_write(ANDROID_LOG_INFO, tag.as_ptr(), text.as_ptr());
    }
    #[cfg(not(target_os = "android"))]
    eprintln!("[HydraDragon-RustTiming] {msg}");
}

/// Writes a `HydraDragon-RustTiming` performance/diagnostic line to logcat
/// (per-file init/load timings, `collect_buffers`'s extraction stats, etc.).
#[macro_export]
macro_rules! rust_timing_log {
    ($($arg:tt)*) => {
        $crate::android_log(&format!($($arg)*))
    };
}

/// All compiled YARA rule files loaded at init (everything except the
/// 45 MB emerging-all.rules loaded on-demand when VPN starts).
const YRC_FILES: &[&str] = &[
    "clean_rules_filtered_verified.yrc",
    "valhalla-rules_filtered_verified.yrc",
    "machine_learning_apk.yrc",
];
/// YARA rulesets that depend on Phase 2 module metadata (androguard, hydradragon).
/// These are rescanned once module_meta is available.
const MODULE_DEPENDENT_YRC: &[&str] = &[
    "androguard.yrc",
    "hips_rules_filtered_verified.yrc",
];
/// Suricata-format rule engine for VPN packet scan — loaded lazily via
/// suricata_scan::RuleEngine::get() when nativeEnableVpnScan(true) is called.
/// Parses emerging-all.rules at runtime and builds a daachorse double-array
/// automaton for hex-pattern matching.
const MODEL_MPK: &str = "model.mpk";
const VOCAB_JSON: &str = "vocab.json";
/// Per-type malware TLSH similarity databases (one T1 digest per line), built
/// from the MalwareBazaar dump separated by file type (`gen_tlsh_db.py`).
/// Each type is stored in its own file so the scanner only compares a buffer
/// against digests of the same type (ELF vs ELF, APK vs APK, DEX vs DEX),
/// avoiding cross-type false matches and reducing per-buffer scan time.
const TLSH_DB_ELF: &str = "malware_tlsh_elf.txt";
const TLSH_DB_APK: &str = "malware_tlsh_apk.txt";
const TLSH_DB_DEX: &str = "malware_tlsh_dex.txt";
/// NSRL known-good SHA-256 whitelist as a serialized Binary-Fuse (xor) filter
/// (built offline by `xorfilter_writer`). Decoded once at init into an owned
/// buffer on the native heap; binary-fuse encodings are far smaller than the
/// equivalent quotient filter, so the whitelist stays modest in RAM.
const WHITELIST_XF: &str = "whitelist.xf";
/// Same whitelist_packages.csv Java's ScanEngine.loadPackageWhitelist reads
/// (CSV: "key,md5" per line). Loaded once at init into an owned key->md5 map so
/// a nested APK buffer whose package name AND md5 exactly match a row can skip
/// the heavy scan below instead of Rust redoing work Java's whitelist already
/// vouches for. Matching BOTH fields (not just the package name) keeps this
/// safe against a spoofed package name — only an exact known-good file is
/// skipped, and only that one buffer: a sibling non-whitelisted file/APK
/// inside the same archive is scanned normally.
const WHITELIST_PACKAGES_DB: &str = "whitelist_packages.csv";
const BENIGN_SIGNATURES: &str = "benign_signatures.bin";

/// A scanned buffer whose TLSH distance to a known-malware digest is at or below
/// this is flagged as similar. Lower = stricter (fewer FP). TLSH distance: 0 =
/// identical, <30 very close, <70 related (per the TLSH paper).
/// Made mutable via an atomic so the user's Settings slider (anti_fp_tlsh_threshold)
/// takes effect immediately without an engine restart.
static TLSH_THRESHOLD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(30);

struct Engine {
    /// ClamAV engine: loaded from the bundled signature DB with the compiled
    /// `.yrc` YARA rulesets added. It does the whole scan — file-type detection,
    /// supported-type gating (`is_target_allowed`), clamav signatures AND YARA,
    /// all in one pass. `None` if no clamav DB was bundled.
    clamav: Option<ClamavEngine>,
    model: Option<Model>,
    /// Known-malware TLSH digests for ELF (.so) files, flat [u8; 35] form
    /// (see tlsh_db.rs) — no per-digest heap allocations.
    tlsh_db_elf: Vec<tlsh_db::TlshFlat>,
    /// Known-malware TLSH digests for APK (ZIP) files.
    tlsh_db_apk: Vec<tlsh_db::TlshFlat>,
    /// Known-malware TLSH digests for DEX files.
    tlsh_db_dex: Vec<tlsh_db::TlshFlat>,
    /// NSRL known-good SHA-256 whitelist (Binary-Fuse xor filter).
    whitelist: Option<XorFilter>,
    /// NSRL known-good package -> md5 map, read from whitelist_packages.db.
    /// See WHITELIST_PACKAGES_DB.
    package_whitelist: std::collections::HashMap<String, String>,
    /// Content-based MinHash benign signatures whitelist.
    benign_db: Option<benign_db::BenignDb>,
    /// Malicious domain/URL xor filters + public-suffix list.
    url_scanner: Option<url_scan::UrlScanner>,
    /// Malicious-IP xor filters (per category).
    ip_scanner: Option<ip_scan::IpScanner>,
}

/// Saved so background threads can call back into Java.
static JAVA_VM: OnceLock<jni::JavaVM> = OnceLock::new();

/// `RwLock` (not a bare `Engine`) so a freshly auto-generated rule can be
/// hot-added to the LIVE engine mid-session (write lock, brief) — see
/// `nativeLearnRule` — instead of only taking effect after the next process
/// restart reloads `generated_rules/*.yar` in `do_init_from_assets`.
static ENGINE: OnceLock<std::sync::RwLock<Engine>> = OnceLock::new();

/// Java-side "Native code emulation" Settings toggle (DetectionCategories.
/// NATIVE_EMULATION) — checked once per ELF buffer in run_scan(), so turning
/// it off actually skips the emulation cost, not just its results. Settable
/// at any time (see nativeSetEmulationEnabled), independent of engine init.
static NATIVE_EMULATION_ENABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

/// User-configurable ceiling from {@link MaxScanFileSize} — extracted archive
/// entries larger than this (in MB) are excluded from all scan passes (ClamAV,
/// YARA, ML model). Default 650 MB. Set via nativeSetMaxScanSizeMb JNI call.
/// Max bytes for text-like files submitted to ClamAV. Files beyond this are
/// skipped — they're unlikely to contain malware signatures. Default 5 MB.
/// Set via nativeSetMaxTextScanBytes JNI. Applied immediately.
static MAX_TEXT_SCAN_BYTES: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(10_000_000);

static MAX_SCAN_SIZE_MB: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(650);

/// User-configurable ceiling from {@link MaxArchiveSize} — a NON-zip archive
/// (tar, gz, xz, 7z, rar, bz2, zst, lz4, cab, iso, etc.) larger than this (in
/// MB) is NOT extracted; its contents are skipped. APKs and plain .zip files
/// are unaffected (they stay under the {@link MaxScanFileSize} scan ceiling).
/// Default 100 MB. 0 means "never extract non-zip archives". Set via
/// nativeSetMaxArchiveSizeMb JNI call. Applied immediately; no reinit needed.
static MAX_ARCHIVE_SIZE_MB: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(100);

/// User-configurable toggle (recommended): when true, only APK/ZIP archives are
/// extracted and only Android-relevant buffers inside them are scanned — DEX,
/// ELF (.so), JAR (extracted for nested DEX), AndroidManifest.xml, and
/// relevant text-like files. Non-zip archives (tar, gz, 7z, rar, etc.) and
/// standalone non-APK files are skipped entirely. Default true (recommended).
/// Applied immediately; no reinit needed. Set via nativeSetScanRelevantOnly.
static SCAN_RELEVANT_ONLY: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

/// User-configurable toggle: when true, photos (PNG/JPEG/GIF/BMP/WebP/TIFF/
/// ICO/HEIC/HEIF/AVIF) and videos (MP4/MKV/WebM/3GP and other ISOBMFF media)
/// are scanned for hidden/polyglot payloads and ClamAV signatures. Default
/// false — media files are a large scan-cost and low-yield target, so they are
/// skipped unless the user explicitly opts in. Set via nativeSetScanMediaEnabled.
static SCAN_MEDIA_ENABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether the Suricata rule engine has been initialised (set once on first
/// nativeEnableVpnScan(true) call). The suricata_scan::RuleEngine uses its
/// own OnceLock internally; this flag avoids re-triggering it on every call.
static VPN_RULES_LOADED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether VPN packet scanning is active. When false, nativeScanPackets is
/// a no-op even if VPN rules happen to be loaded.
static VPN_SCAN_ENABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether the Suricata rule engine was successfully initialised.
/// Separate from VPN_SCAN_ENABLED so scan_packets can return a distinct
/// error when the rules failed to load vs. when scanning is intentionally off.
static VPN_RULES_READY: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Asset map read at init time. Held ONLY while `do_init_from_assets` runs;
/// dropped as soon as the engine is built so the ~200 MB of raw asset bytes
/// are released back to the OS instead of staying pinned for the process
/// lifetime. Lazy consumers (VPN Suricata rules) re-read their file on demand
/// via `asset_reader::read_file_bytes` from the AAssetManager.
static ASSET_FILES: std::sync::Mutex<Option<std::collections::HashMap<String, Vec<u8>>>> =
    std::sync::Mutex::new(None);

/// Asset subdirectory the engine was loaded from (e.g. "scan"), stored so
/// lazy re-reads (`load_vpn_rules`) can build the full relative asset path.
static ASSET_DIR: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Base directory path, set once during native-init (`do_init_from_assets`),
/// so generated_rule loading
/// knows where to find the writable rules directory.
static INIT_DIR: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Guards against duplicate calls to `nativeInit` while the first async
/// background thread is still loading the engine (~70 s).
static INIT_STARTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Scan result cache: keyed by MD5 of the whole file. Only stores CLEAN
/// results. A subsequent scan of the same file (same MD5) returns the cached
/// JSON instantly — no extract, no ClamAV, no YARA, no ML.
/// Persisted to `{SCAN_CACHE_DIR}/hydra_scan_cache.json` across restarts.
/// LRU eviction at `SCAN_CACHE_MAX` entries (oldest discarded).
static SCAN_CACHE: std::sync::Mutex<Option<ScanCache>> = std::sync::Mutex::new(None);
/// Directory path for the cache file, set by Java via `nativeSetScanCacheDir`.
static SCAN_CACHE_DIR: OnceLock<String> = OnceLock::new();
const SCAN_CACHE_FILE: &str = "hydra_scan_cache.json";
const SCAN_CACHE_MAX: usize = 1000;

struct ScanCache {
    map: std::collections::HashMap<String, CachedEntry>,
    /// Insertion-ordered keys for LRU eviction.
    order: Vec<String>,
    /// Whether the cache has been modified since last save.
    dirty: bool,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct CachedEntry {
    json: String,
    timestamp: u64,
}

fn scan_cache_path() -> Option<String> {
    SCAN_CACHE_DIR.get().map(|d| format!("{d}/{SCAN_CACHE_FILE}"))
}

fn load_scan_cache() {
    let path = match scan_cache_path() {
        Some(p) => p,
        None => return,
    };
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return,
    };
    let map: std::collections::HashMap<String, CachedEntry> = match serde_json::from_str(&data) {
        Ok(m) => m,
        Err(_) => return,
    };
    let order: Vec<String> = map.keys().cloned().collect();
    if let Ok(mut g) = SCAN_CACHE.lock() {
        *g = Some(ScanCache { map, order, dirty: false });
    }
}

fn save_scan_cache() {
    let path = match scan_cache_path() {
        Some(p) => p,
        None => return,
    };
    let (map, dirty) = {
        let mut g = match SCAN_CACHE.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let cache = match g.as_mut() {
            Some(c) => c,
            None => return,
        };
        if !cache.dirty { return; }
        cache.dirty = false;
        (cache.map.clone(), true)
    };
    if !dirty { return; }
    if let Ok(json) = serde_json::to_string(&map) {
        let _ = std::fs::write(&path, &json);
    }
}

fn cache_scan_result(md5: &str, json: &str) {
    {
        let mut g = match SCAN_CACHE.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let cache = match g.as_mut() {
            Some(c) => c,
            None => return,
        };
        while cache.order.len() >= SCAN_CACHE_MAX {
            let oldest = cache.order.remove(0);
            cache.map.remove(&oldest);
        }
        cache.map.insert(md5.to_string(), CachedEntry {
            json: json.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        });
        cache.order.push(md5.to_string());
        cache.dirty = true;
    } // g dropped here → lock released
    save_scan_cache();
}

fn check_scan_cache(md5: &str) -> Option<String> {
    let g = match SCAN_CACHE.lock() {
        Ok(g) => g,
        Err(_) => return None,
    };
    let cache = match g.as_ref() {
        Some(c) => c,
        None => return None,
    };
    cache.map.get(md5).map(|e| e.json.clone())
}

/// Last panic's "message @ file:line", captured by our hook so we can report
/// WHY a scan panicked (root cause) instead of just swallowing it.
static LAST_PANIC: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Serializes whole-file scan pipelines (`run_scan`) — but only up to
/// `SCAN_SERIAL_MAX_WAIT`. `collect_buffers`/`run_scan`
/// `emulate` each spin up their own worker pool, so ideally only one file's
/// pipeline runs at a time to avoid two files' pools thrashing the same
/// cores together (this is what caused 6 concurrent "native-init" threads
/// all running Unicorn emulation simultaneously — an ANR).
///
/// BUT: Java's cancellation (`ScanEngine.runNativeInterruptible`) ABANDONS a
/// slow/stuck native call rather than killing it — the call keeps running
/// here regardless of what Java thinks happened. An unconditional blocking
/// `Mutex` combined with that is dangerous: one pathological or abandoned
/// file can hold this lock indefinitely and freeze EVERY OTHER scan in the
/// whole app behind it. Observed in the field: one file held this for
/// ~17 minutes, during which an unrelated full-scan's file sat queued the
/// entire time, timed out to the user as "stuck", and by the time it finally
/// got the lock, cancellation had already fired — see the NativeScanner
/// timings on `msf:*` (1,042,804ms) and the queued `revancedmanager` result
/// finishing 44ms later with verdict=NULL(cancelled/error).
///
/// So this is now bounded: wait up to SCAN_SERIAL_MAX_WAIT, then proceed
/// WITHOUT the lock if it's still held. That caps the worst case at "a few
/// seconds of extra core contention" instead of "however long the slowest
/// file in the app takes, unbounded."
static SCAN_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
const SCAN_SERIAL_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// See `SCAN_SERIAL`'s doc comment. Returns `Some(guard)` if the lock was
/// acquired within the wait budget, `None` if we gave up and the caller
/// should proceed without it (better than freezing the whole app).
fn acquire_scan_serial_bounded() -> Option<std::sync::MutexGuard<'static, ()>> {
    let start = std::time::Instant::now();
    loop {
        match SCAN_SERIAL.try_lock() {
            Ok(g) => return Some(g),
            Err(std::sync::TryLockError::Poisoned(p)) => return Some(p.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => {
                if start.elapsed() >= SCAN_SERIAL_MAX_WAIT {
                    rust_timing_log!(
                        "run_scan :: SCAN_SERIAL busy for {}ms — proceeding without it \
                         (another file's scan is taking unusually long)",
                        start.elapsed().as_millis()
                    );
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
}

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
/// `do_init_from_assets`, so the Java side can log/show the ROOT CAUSE when
/// native scanning silently does nothing (clamav DB unparsable, model format
/// mismatch, .yrc version mismatch, …) instead of swallowing it.
static INIT_STATUS: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

fn set_status(s: String) {
    if let Ok(mut g) = INIT_STATUS.lock() {
        *g = s;
    }
}

fn do_init_from_assets(files: &std::collections::HashMap<String, Vec<u8>>, load_auto_rules: bool) -> Engine {
    let t0 = std::time::Instant::now();

    let atomfilter_cache = INIT_DIR.get().map(|base| {
        let path = std::path::Path::new(base).join("atomfilter.cache");
        std::fs::read(&path).ok().and_then(|bytes| {
            let t0 = std::time::Instant::now();
            let result = hydradragonclamav::atomfilter::AtomFilterDb::from_bytes(&bytes);
            let ms = t0.elapsed().as_millis();
            rust_timing_log!("init :: atomfilter_cache read={ms}ms ok={}", result.is_some());
            result
        })
    }).flatten();

    let (clamav_out, model_out, tlsh_elf_out, tlsh_apk_out, tlsh_dex_out, whitelist_out, pkg_out, url_out, ip_out, benign_out) =
        std::thread::scope(|s| {
            let clamav_handle = s.spawn(move || {
                let t_db = std::time::Instant::now();
                let mut report = String::new();
                let clamav = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    match atomfilter_cache {
                        Some(cache) => hydradragonclamav::Engine::from_bytes_map_with_atomfilter(files, cache),
                        None => hydradragonclamav::Engine::from_bytes_map(files),
                    }
                })) {
                    Ok((mut eng, _c_report)) => {
                        let db_ms = t_db.elapsed().as_millis();
                        rust_timing_log!("init :: from_bytes_map={db_ms}ms");
                        report.push_str(&format!("clamav=ok({db_ms}ms)"));
                        let yrc_results: Vec<(
                            String,
                            u128,
                            Option<hydradragonclamav::yara_scan::YaraEngine>,
                        )> = std::thread::scope(|s2| {
                            YRC_FILES.iter().chain(MODULE_DEPENDENT_YRC.iter())
                                .map(|name| {
                                    let name_str = name.to_string();
                                    let bytes = files.get(*name).cloned();
                                    s2.spawn(move || {
                                        let t0 = std::time::Instant::now();
                                        let engine = bytes.and_then(|b| {
                                            std::panic::catch_unwind(
                                                std::panic::AssertUnwindSafe(
                                                    || -> Option<hydradragonclamav::yara_scan::YaraEngine> {
                                                        hydradragonclamav::yara_scan::YaraEngine::from_compiled(&b, name_str)
                                                    },
                                                ),
                                            )
                                            .ok()
                                            .flatten()
                                        });
                                        (name.to_string(), t0.elapsed().as_millis(), engine)
                                    })
                                })
                                .collect::<Vec<_>>()
                                .into_iter()
                                .map(|h| h.join().unwrap_or_default())
                                .collect()
                        });
                        for (name, yrc_ms, engine) in yrc_results {
                            match engine {
                                Some(e) => {
                                    eng.add_compiled_yara(e);
                                    report.push_str(&format!(" yrc[{}]=ok({yrc_ms}ms)", name));
                                }
                                None => report.push_str(&format!(" yrc[{}]=ERR({yrc_ms}ms)", name)),
                            }
                        }
                        let mut learned = 0usize;
                        if load_auto_rules {
                            // Generated rules are on the filesystem, not in assets,
                            // so we still read from the init dir path.
                            if let Some(base_str) = INIT_DIR.get() {
                                let base = std::path::Path::new(base_str);
                                let learned_dir = base.join("generated_rules");
                                if let Ok(entries) = std::fs::read_dir(&learned_dir) {
                                    for entry in entries.flatten() {
                                        let path = entry.path();
                                        if path.extension().and_then(|e| e.to_str()) != Some("yar") {
                                            continue;
                                        }
                                        let t_learn = std::time::Instant::now();
                                        let added =
                                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                                eng.add_yara_source_file(&path)
                                            }));
                                        if matches!(added, Ok(Some(_))) {
                                            learned += 1;
                                        }
                                        let learn_ms = t_learn.elapsed().as_millis();
                                        if learn_ms > 50 {
                                            rust_timing_log!(
                                                "init :: learned[{learned}] {} {learn_ms}ms",
                                                path.display()
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        report.push_str(&format!(" learned={}", learned));
                        // Write atomfilter cache for next start.
                        if let Some(base_str) = INIT_DIR.get() {
                            let cache_path = std::path::Path::new(base_str).join("atomfilter.cache");
                            let cache_bytes = eng.atomfilter_cache_bytes();
                            let t_cache = std::time::Instant::now();
                            if std::fs::write(&cache_path, &cache_bytes).is_ok() {
                                let cache_ms = t_cache.elapsed().as_millis();
                                rust_timing_log!("init :: atomfilter_cache wrote={cache_ms}ms size={}", cache_bytes.len());
                            }
                            drop(cache_bytes);
                            drop(cache_path);
                        }
                        Some(eng)
                    }
                    _ => {
                        report.push_str("clamav=ERR");
                        None
                    }
                };
                (clamav, report)
            });

            let model_handle = s.spawn(move || {
                let t_model = std::time::Instant::now();
                let mut report = String::new();
                let model_bytes = files.get(MODEL_MPK);
                let vocab_bytes = files.get(VOCAB_JSON);
                let device = burn_wgpu::WgpuDevice::default();
                let model = match model_bytes.zip(vocab_bytes) {
                    Some((m, v)) => {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            hydradragonml::Model::load(m, v, device)
                        }));
                        match result {
                            Ok(Ok(m)) => {
                                let model_ms = t_model.elapsed().as_millis();
                                rust_timing_log!("init :: model={model_ms}ms");
                                report.push_str(&format!(" model=ok({model_ms}ms)"));
                                Some(m)
                            }
                            Ok(Err(e)) => {
                                rust_timing_log!("init :: model=ERR: {e}");
                                report.push_str(" model=ERR");
                                None
                            }
                            Err(_) => {
                                rust_timing_log!("init :: model=PANIC: {}", last_panic());
                                report.push_str(" model=ERR(panic)");
                                None
                            }
                        }
                    }
                    None => {
                        report.push_str(" model=ERR(no assets)");
                        None
                    }
                };
                (model, report)
            });

            let tlsh_elf_handle = s.spawn(move || {
                let t = std::time::Instant::now();
                let db = load_tlsh_file(files.get(TLSH_DB_ELF).map(|v| &v[..]));
                let n = db.len();
                let ms = t.elapsed().as_millis();
                (db, format!(" tlsh_elf={n}({ms}ms)"))
            });
            let tlsh_apk_handle = s.spawn(move || {
                let t = std::time::Instant::now();
                let db = load_tlsh_file(files.get(TLSH_DB_APK).map(|v| &v[..]));
                let n = db.len();
                let ms = t.elapsed().as_millis();
                (db, format!(" tlsh_apk={n}({ms}ms)"))
            });
            let tlsh_dex_handle = s.spawn(move || {
                let t = std::time::Instant::now();
                let db = load_tlsh_file(files.get(TLSH_DB_DEX).map(|v| &v[..]));
                let n = db.len();
                let ms = t.elapsed().as_millis();
                (db, format!(" tlsh_dex={n}({ms}ms)"))
            });

            let whitelist_handle = s.spawn(move || {
                let t_wl = std::time::Instant::now();
                let whitelist = load_whitelist_xor(files);
                let wl_ms = t_wl.elapsed().as_millis();
                (whitelist, format!(" whitelist={wl_ms}ms"))
            });

            let pkg_handle = s.spawn(move || {
                let t_pkg = std::time::Instant::now();
                let package_whitelist = match files.get(WHITELIST_PACKAGES_DB) {
                    Some(bytes) => load_package_whitelist_from_bytes(bytes),
                    None => std::collections::HashMap::new(),
                };
                let pkg_ms = t_pkg.elapsed().as_millis();
                let report = format!(" pkg_wl={pkg_ms}ms({})", package_whitelist.len());
                (package_whitelist, report)
            });

            let url_handle = s.spawn(move || {
                let t_url = std::time::Instant::now();
                let url_scanner = std::panic::catch_unwind(|| {
                    let dir = ASSET_DIR.get().map(String::as_str).unwrap_or("scan");
                    url_scan::UrlScanner::load_from_assets(dir, files)
                })
                .ok()
                .flatten();
                let url_ms = t_url.elapsed().as_millis();
                (url_scanner, format!(" url={url_ms}ms"))
            });

            let ip_handle = s.spawn(move || {
                let t_ip = std::time::Instant::now();
                let ip_scanner = std::panic::catch_unwind(|| {
                    let dir = ASSET_DIR.get().map(String::as_str).unwrap_or("scan");
                    ip_scan::IpScanner::from_bytes_map(dir, files)
                })
                .ok()
                .flatten();
                let ip_ms = t_ip.elapsed().as_millis();
                (ip_scanner, format!(" ip={ip_ms}ms"))
            });

            let benign_handle = s.spawn(move || {
                let t_benign = std::time::Instant::now();
                let benign_db = match files.get(BENIGN_SIGNATURES) {
                    Some(bytes) => benign_db::BenignDb::load(bytes),
                    None => None,
                };
                let benign_ms = t_benign.elapsed().as_millis();
                let pkg_count = benign_db.as_ref().map(|db| db.package_count()).unwrap_or(0);
                let sig_count = benign_db.as_ref().map(|db| db.signature_count()).unwrap_or(0);
                (benign_db, format!(" benign_wl={benign_ms}ms(pkg={pkg_count} sig={sig_count})"))
            });

            (
                clamav_handle.join().unwrap_or_else(|_| {
                    (None, format!("clamav=PANIC({})", last_panic()))
                }),
                model_handle.join().unwrap_or_else(|_| {
                    (None, format!(" model=PANIC({})", last_panic()))
                }),
                tlsh_elf_handle.join().unwrap_or_else(|_| {
                    (Vec::new(), format!(" tlsh_elf=PANIC({})", last_panic()))
                }),
                tlsh_apk_handle.join().unwrap_or_else(|_| {
                    (Vec::new(), format!(" tlsh_apk=PANIC({})", last_panic()))
                }),
                tlsh_dex_handle.join().unwrap_or_else(|_| {
                    (Vec::new(), format!(" tlsh_dex=PANIC({})", last_panic()))
                }),
                whitelist_handle.join().unwrap_or_else(|_| {
                    (None, format!(" whitelist=PANIC({})", last_panic()))
                }),
                pkg_handle.join().unwrap_or_else(|_| {
                    (std::collections::HashMap::new(), format!(" pkg_wl=PANIC({})", last_panic()))
                }),
                url_handle.join().unwrap_or_else(|_| {
                    (None, format!(" url=PANIC({})", last_panic()))
                }),
                ip_handle.join().unwrap_or_else(|_| {
                    (None, format!(" ip=PANIC({})", last_panic()))
                }),
                benign_handle.join().unwrap_or_else(|_| {
                    (None, format!(" benign_wl=PANIC({})", last_panic()))
                }),
            )
        });

    let (clamav, clamav_report) = clamav_out;
    let (model, model_report) = model_out;
    let (tlsh_db_elf, tlsh_elf_report) = tlsh_elf_out;
    let (tlsh_db_apk, tlsh_apk_report) = tlsh_apk_out;
    let (tlsh_db_dex, tlsh_dex_report) = tlsh_dex_out;
    let (whitelist, whitelist_report) = whitelist_out;
    let (package_whitelist, pkg_report) = pkg_out;
    let (url_scanner, url_report) = url_out;
    let (ip_scanner, ip_report) = ip_out;
    let (benign_db, benign_report) = benign_out;

    let report = format!(
        "{clamav_report}{model_report}{tlsh_elf_report}{tlsh_apk_report}{tlsh_dex_report}{whitelist_report}{pkg_report}{url_report}{ip_report}{benign_report}"
    );

    let total_ms = t0.elapsed().as_millis();
    rust_timing_log!("init :: TOTAL={total_ms}ms | {report}");
    set_status(report);
    Engine {
        clamav,
        model,
        tlsh_db_elf,
        tlsh_db_apk,
        tlsh_db_dex,
        whitelist,
        package_whitelist,
        benign_db,
        url_scanner,
        ip_scanner,
    }
}

/// Load `key -> md5` from pre-read whitelist_packages.csv bytes.
/// Format: one "key,md5" per line (RFC-4180: fields with commas/quotes are
/// quoted). Produced by gen_whitelist_packages.py. Key is the NSRL
/// "id^^name" package string; md5 is the whole-APK MD5 (lowercased).
fn load_package_whitelist_from_bytes(bytes: &[u8]) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Split on the FIRST comma only; the key may itself contain commas
        // (it is quoted then). md5 is a 32-char hex string, never quoted.
        let (key_field, md5_field) = match line.find(',') {
            Some(comma) => (&line[..comma], &line[comma + 1..]),
            None => (line, ""),
        };
        let key = unquote_csv_field(key_field);
        if key.is_empty() || md5_field.trim().is_empty() {
            continue;
        }
        out.insert(key, md5_field.trim().to_ascii_lowercase());
    }
    out
}

/// Unwrap one RFC-4180 CSV field: strips surrounding double quotes and
/// unescapes "" -> ".
fn unquote_csv_field(field: &str) -> String {
    let field = field.trim();
    if field.len() >= 2 && field.starts_with('"') && field.ends_with('"') {
        let inner = &field[1..field.len() - 1];
        inner.replace("\"\"", "\"")
    } else {
        field.to_string()
    }
}

/// Load the NSRL SHA-256 whitelist xor filter, PREFERRING a zero-copy view
/// straight into the APK's stored (noCompress) `.xf` asset data
/// (`AAsset_getBuffer`) so the ~114 MB fingerprint array is file-backed page
/// cache (evictable under memory pressure) instead of an anonymous heap copy
/// pinned for the whole process lifetime. Falls back to a heap copy only when
/// the asset is compressed/absent (getBuffer returns NULL).
fn load_whitelist_xor(
    files: &std::collections::HashMap<String, Vec<u8>>,
) -> Option<XorFilter> {
    let dir = ASSET_DIR.get().map(String::as_str).unwrap_or("scan");
    let relative = format!("{dir}/{WHITELIST_XF}");
    match asset_reader::open_asset_buffer(&relative) {
        // SAFETY: the AAsset handle stays open for the filter's whole lifetime
        // (it moves into the filter's backing), and the buffer is immutable.
        Some(buf) => unsafe { XorFilter::from_asset_buffer(buf.ptr, buf.len, buf.asset) },
        None => files.get(WHITELIST_XF).and_then(|b| XorFilter::from_owned(b.clone())),
    }
}

/// Whether `buf` should be skipped by every scan pass: too small (<=12 bytes,
/// can't carry a payload) or over the user's {@link MaxScanFileSize} ceiling.
/// Single shared gate so this rule lives in exactly one place.
fn skip_by_size(buf: &[u8]) -> bool {
    buf.len() <= 12 || buf.len() > (MAX_SCAN_SIZE_MB.load(Ordering::Relaxed) as usize) * 1024 * 1024
}

/// Cached CPU count, capped at 4. `std::thread::available_parallelism()` probes
/// cgroup-v2 CPU-quota files under `/sys/fs/cgroup` on Android, which the app
/// sandbox is denied `search` on — each call emits an SELinux `avc: denied
/// { search } … cgroup2` audit line. This is called once per file for the
/// collect_buffers pool and the TLSH pool; the value can't change over a
/// process's lifetime, so resolve it once and reuse the cached value to avoid
/// both the repeated probe cost and the logcat AVC spam.
fn worker_count() -> usize {
    static CACHED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 0 {
        return cached as usize;
    }
    let n = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 4);
    CACHED.store(n as u32, Ordering::Relaxed);
    n
}

/// Shared ML-scan loop: run the ONNX model on every APK buffer, collecting
/// malicious lineages and tracking the highest confidence score. Used by both
/// `run_scan` (callers wrap it in `catch_unwind`).
fn run_ml_on_mmap(
    model: &Model,
    data: &[u8],
    path: &str,
    fmt: Option<&'static str>,
    engine_features: &EngineFeatures,
) -> (bool, f32, Vec<(String, Vec<String>)>) {
    if skip_by_size(data) {
        return (false, 0.0, Vec::new());
    }
    // Use pre-computed fmt to avoid a redundant detect_format call
    if fmt != Some("zip") {
        return (false, 0.0, Vec::new());
    }
    if !is_apk_zip(data) {
        return (false, 0.0, Vec::new());
    }
    match model.scan_with_features(data, engine_features) {
        Some(r) => {
            let lineages = if r.malicious {
                vec![(path.to_string(), Vec::new())]
            } else {
                Vec::new()
            };
            (r.malicious, r.confidence, lineages)
        }
        None => (false, 0.0, Vec::new()),
    }
}

/// Aggregate every engine analysis result that has already been computed for
/// this APK (DEX static analysis, native emulation, manifest, URLs/IPs,
/// TLSH, certificate, benign DB, media hidden-data) into the `EngineFeatures`
/// vector consumed by the Burn classifier. Runs once per file, after Phase 2,
/// so the ML thread can reuse one feature vector for every buffer in the APK.
#[allow(clippy::too_many_arguments)]
fn build_engine_features(
    engine: &Engine,
    buffers: &[Buf],
    dex_scans: &[Option<dex_scan::DexScan>],
    emulated: &[emulate::EmulationResult],
    perm_count: usize,
) -> EngineFeatures {
    use dex_analysis::Severity;

    let mut feats = EngineFeatures::default();

    // ── DEX static analysis ──────────────────────────────────────────────
    for ds in dex_scans.iter().flatten() {
        feats.dex_string_count += ds.text.lines().count() as f32;
        feats.dex_api_call_count += ds.api_calls.len() as f32;
        let mut classes: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for call in &ds.api_calls {
            // api_calls are "Lpkg/Cls;->method(params)return\tcount"; the
            // class descriptor is the part before "->".
            if let Some(cls) = call.split("->").next() {
                classes.insert(cls.trim());
            }
        }
        feats.dex_class_count += classes.len() as f32;
        for f in &ds.findings {
            match f.severity {
                Severity::High => feats.dex_finding_high += 1.0,
                Severity::Critical => feats.dex_finding_critical += 1.0,
                _ => {}
            }
        }
    }

    // ── Native code emulation (ELF) ──────────────────────────────────────
    for (i, r) in emulated.iter().enumerate() {
        if r.strings.is_empty() && r.api_calls.is_empty() {
            continue;
        }
        // Only ELF buffers get non-default EmulationResults (see the emulation
        // thread in run_full_apk_scan), so a populated result = one ELF.
        let _ = buffers.get(i);
        feats.elf_count += 1.0;
        feats.elf_emulated_strings += r.strings.len() as f32;
        for call in &r.api_calls {
            let name = call.name.as_str();
            if matches!(
                name,
                "socket" | "connect" | "send" | "sendto" | "recv" | "recvfrom"
                    | "gethostbyname" | "getaddrinfo" | "inet_addr" | "inet_pton"
            ) {
                feats.elf_network_calls += 1.0;
            } else if matches!(
                name,
                "open" | "open64" | "fopen" | "creat" | "unlink" | "remove" | "rename"
            ) {
                feats.elf_file_calls += 1.0;
            } else if matches!(
                name,
                "system" | "popen" | "execve" | "execl" | "execvp" | "fork" | "vfork"
                    | "dlopen" | "dlsym"
            ) {
                feats.elf_exec_calls += 1.0;
            } else if matches!(name, "ptrace" | "kill") {
                feats.elf_anti_debug += 1.0;
            }
        }
    }

    // ── Manifest ─────────────────────────────────────────────────────────
    feats.manifest_dangerous_permissions = perm_count as f32;
    if let Some(manifest) = buffers.iter().find_map(|b| parse_manifest(&b.data)) {
        feats.manifest_total_permissions = manifest.permissions.len() as f32;
        feats.manifest_activities = manifest.activities.len() as f32;
        feats.manifest_services = manifest.services.len() as f32;
        feats.manifest_receivers = manifest.receivers.len() as f32;
        feats.manifest_min_sdk = manifest.min_sdk.unwrap_or(0) as f32;
        feats.manifest_target_sdk = manifest.target_sdk.unwrap_or(0) as f32;
    }

    // ── URLs & IPs from DEX strings + emulated strings ───────────────────
    let mut text_parts: Vec<Vec<u8>> = Vec::new();
    for ds in dex_scans.iter().flatten() {
        text_parts.push(ds.text.as_bytes().to_vec());
    }
    text_parts.extend(emulated_strings_from(emulated));
    for part in text_parts {
        for line in part.split(|&b| b == b'\n') {
            let s = String::from_utf8_lossy(line);
            let s = s.trim();
            if s.starts_with("http://") || s.starts_with("https://") {
                if let Some(scanner) = &engine.url_scanner {
                    if let Some(cat) = scanner.scan_url_only(s) {
                        if cat.contains("PHISHING") {
                            feats.url_phishing_count += 1.0;
                        } else {
                            feats.url_malicious_count += 1.0;
                        }
                    }
                }
            }
            // IPv4 dotted-quad literals checked against the IP blocklists.
            if let Some(scanner) = &engine.ip_scanner {
                for ip in extract_ipv4(s) {
                    if scanner.scan(&ip).is_some() {
                        feats.ip_malicious_count += 1.0;
                    }
                }
            }
        }
    }

    // ── TLSH (nearest known-malware distance per buffer type) ────────────
    let mut min_dist = i32::MAX;
    for b in buffers {
        if skip_by_size(&b.data) {
            continue;
        }
        let db = if b.data.starts_with(b"\x7fELF") {
            Some(&engine.tlsh_db_elf[..])
        } else if b.data.starts_with(b"dex\n") {
            Some(&engine.tlsh_db_dex[..])
        } else if is_apk_zip(&b.data) {
            Some(&engine.tlsh_db_apk[..])
        } else {
            None
        };
        if let Some(db) = db {
            if let Some(dist) = tlsh_nearest(db, &b.data) {
                if dist < min_dist {
                    min_dist = dist;
                }
            }
        }
    }
    feats.tlsh_min_distance = if min_dist != i32::MAX {
        min_dist as f32
    } else {
        200.0 // no similarity to any known-malware digest → feature ~0.0
    };

    // ── Certificate / testkey signing ────────────────────────────────────
    if riskware::is_testkey_detection_enabled() {
        if let Some(cert) = extract_certificate(buffers) {
            if riskware::check_testkey(&cert.sha1, &cert.subject, &cert.issuer) {
                feats.is_testkey = 1.0;
            }
        }
    }

    // ── Benign DB (content-based MinHash Jaccard) ────────────────────────
    if let Some(bdb) = &engine.benign_db {
        for b in buffers {
            if b.data.starts_with(b"PK\x03\x04") || is_apk_zip(&b.data) {
                if let Some(pkg) = axml_package(&b.data) {
                    if let Some(feats_minhash) = hydradragonml::features::extract_minhash(&b.data) {
                        let j = bdb.max_jaccard(&pkg, &feats_minhash.tokens);
                        if j > feats.benign_jaccard {
                            feats.benign_jaccard = j;
                        }
                    }
                }
            }
        }
    }

    // ── Media hidden/polyglot data ───────────────────────────────────────
    for b in buffers {
        if media_scan::has_hidden_data(&b.data) || has_polyglot_or_hidden_data(&b.data) {
            feats.media_hidden_count += 1.0;
        }
    }

    feats
}

/// Decoded-string slices from the emulation results, re-joined the same way
/// the emulation pass builds `emulated_strings` (strings + API-call names,
/// '\n'-separated) so URL/IP extraction sees the identical content.
fn emulated_strings_from(emulated: &[emulate::EmulationResult]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for r in emulated {
        if r.strings.is_empty() && r.api_calls.is_empty() {
            continue;
        }
        let mut joined: Vec<u8> = Vec::new();
        if !r.strings.is_empty() {
            joined.extend(r.strings.join("\n").into_bytes());
        }
        if !r.api_calls.is_empty() {
            if !joined.is_empty() {
                joined.push(b'\n');
            }
            joined.extend(
                r.api_calls
                    .iter()
                    .map(|a| a.name.clone())
                    .collect::<Vec<_>>()
                    .join("\n")
                    .into_bytes(),
            );
        }
        if !joined.is_empty() {
            out.push(joined);
        }
    }
    out
}

/// Extract IPv4 dotted-quad literals from a string (no validation of octet
/// range beyond 0-255 — the blocklist lookups are textual anyway).
fn extract_ipv4(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 7 <= bytes.len() {
        if bytes[i].is_ascii_digit() {
            let mut j = i;
            while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b'.') {
                j += 1;
            }
            let cand = &s[i..j];
            let parts: Vec<&str> = cand.split('.').collect();
            if parts.len() == 4 {
                let valid = parts.iter().all(|p| {
                    !p.is_empty()
                        && p.len() <= 3
                        && p.bytes().all(|b| b.is_ascii_digit())
                        && p.parse::<u32>().map_or(false, |n| n <= 255)
                });
                if valid {
                    out.push(cand.to_string());
                    i = j;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

/// Parse a TLSH database file (one T1 digest per line) into a flat Vec of
/// [u8; 35] digests (see tlsh_db.rs). Returns an empty Vec if `bytes` is
/// None (file not found).
fn load_tlsh_file(bytes: Option<&[u8]>) -> Vec<tlsh_db::TlshFlat> {
    match bytes {
        Some(bytes) => {
            let text = String::from_utf8_lossy(bytes);
            let mut out = Vec::with_capacity(text.lines().count());
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() { continue; }
                if let Some(d) = tlsh_db::TlshFlat::parse(line) {
                    out.push(d);
                }
            }
            out
        }
        None => Vec::new(),
    }
}

/// Whether `buf` is a file type we have a per-type TLSH malware database for
/// (ELF .so, APK/ZIP, or DEX) — so we only fuzzy-compare relevant buffers,
/// not every PNG/XML resource in an APK.
/// Whether the first 256 bytes look like human-readable text (ASCII or UTF-8).
/// Returns true when ≥90% of the sample bytes are either ASCII printable,
/// whitespace, or valid UTF-8 multi-byte sequence bytes.
fn is_obfuscated_xml(data: &[u8]) -> bool {
    let sample = if data.len() > 1024 { &data[..1024] } else { data };
    let non_ascii = sample.iter().filter(|&&b| !b.is_ascii()).count();
    non_ascii > sample.len() / 4
}

fn is_resource_path(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("res/layout/")
        || lower.starts_with("res/values/")
        || lower.starts_with("res/menu/")
        || lower.starts_with("res/drawable/")
        || lower.starts_with("res/anim/")
        || lower.starts_with("res/color/")
        || lower.starts_with("res/raw/")
        || lower.starts_with("res/xml/")
}

/// Check if a buffer's content is relevant for malware scanning: DEX, ELF,
/// AndroidManifest.xml, and text-like files (ASCII, UTF-8, scripts, EICAR test
/// strings, etc.). Uses entry name when available, falls back to content check
/// for renamed/misnamed files.
/// Returns true when the buffer should receive the full ClamAV scanning pass
/// (atom prefilter + extended + logical sigs + phishing heuristic).  The
/// following formats are included:
///
///   * **Android-executable** — DEX, ODEX, VDEX, ELF (.so)
///   * **Archives** — any format `hydradragonextractor::detect_format`
///     recognises (zip, gz, tar, xz, lzma, 7z, rar, bz2, zst, lz4, br,
///     snappy, cab, lzh, iso) — container sigs + archive-targeted ClamAV
///     rules
///   * **HTML/text** — phishing heuristic (`<a href>` spoof detection)
///   * **Images** — steganographic payloads / hidden strings (PNG, JPEG, GIF,
///     BMP, WebP, TIFF, ICO, HEIC, AVIF)
///
/// Truly Android-irrelevant desktop formats (PE, Mach-O, OLE2, SWF, etc.) and
/// unknown binaries skip ClamAV — their signatures never match in practice and
/// the atom-prefilter overhead on hundreds of APK resource entries is waste.
/// `fmt` is the already-computed `hydradragonextractor::detect_format` result for `data`
/// (passed in to avoid calling detect_format twice per buffer in collect_buffers).
fn is_executable_buffer(name: Option<&str>, data: &[u8], fmt: Option<&'static str>) -> bool {
    // DEX/VDEX/ELF — Android's executable formats
    if data.starts_with(b"dex\n") || data.starts_with(b"vdex") || data.starts_with(b"\x7fELF") {
        return true;
    }
    // Known archive formats — use pre-computed fmt to avoid a second detect_format call
    if fmt.is_some() {
        return true;
    }
    match name {
        Some(n) => {
            let lower = n.to_ascii_lowercase();
            if lower.ends_with(".dex") || lower.ends_with(".odex") || lower.ends_with(".vdex") || lower.ends_with(".so") {
                return true;
            }
            // Image extensions
            if lower.ends_with(".png") || lower.ends_with(".jpg") || lower.ends_with(".jpeg")
                || lower.ends_with(".gif") || lower.ends_with(".bmp") || lower.ends_with(".webp")
                || lower.ends_with(".tiff") || lower.ends_with(".tif")
                || lower.ends_with(".ico") || lower.ends_with(".svg")
                || lower.ends_with(".heic") || lower.ends_with(".heif")
                || lower.ends_with(".avif")
            {
                return true;
            }
        }
        None => {}
    }
    // HTML/text — phishing heuristic (<a href> spoof detection).
    // Skip files larger than MAX_TEXT_SCAN_BYTES: they're unlikely to
    // contain embedded malware signatures and scanning them burns ClamAV
    // time with no gain. Configurable via settings.
    let max_text = MAX_TEXT_SCAN_BYTES.load(Ordering::Relaxed) as usize;
    if is_text_like(data) && data.len() <= max_text {
        return true;
    }
    // Image magic bytes — catches renamed/misnamed image files
    data.len() > 4 && (
        data.starts_with(&[0x89, 0x50, 0x4E, 0x47])              // PNG
        || data.starts_with(&[0xFF, 0xD8, 0xFF])                 // JPEG
        || data.starts_with(b"GIF8")                             // GIF
        || data.starts_with(b"BM")                               // BMP
        || (data.starts_with(b"RIFF") && data.len() > 12 && &data[8..12] == b"WEBP") // WebP
        || data.starts_with(&[0x49, 0x49, 0x2A, 0x00])           // TIFF LE
        || data.starts_with(&[0x4D, 0x4D, 0x00, 0x2A])           // TIFF BE
        || data.starts_with(&[0x00, 0x00, 0x01, 0x00])           // ICO
        || (data.len() > 12 && &data[4..8] == b"ftyp"            // HEIC / HEIF / AVIF
            && (&data[8..12] == b"heic" || &data[8..12] == b"heif"
                || &data[8..12] == b"avif" || &data[8..12] == b"mif1"
                || &data[8..12] == b"msf1"))
    )
}

fn is_media_file(data: &[u8]) -> bool {
    media_scan::is_media_file(data)
}

/// Cheap direct check for the EICAR standard antivirus test file — a fixed
/// 68-byte ASCII string. Per the EICAR spec the string must be at the very
/// start of the file, and the file may be padded up to 128 bytes with trailing
/// whitespace. This lets a loose (standalone) EICAR file be flagged instantly
/// without routing it through the full ClamAV/YARA pass — used for the depth-0
/// standalone case where "scan relevant only" would otherwise skip it. The
/// EICAR detection-category toggle is applied later on the Java side.
fn is_eicar(data: &[u8]) -> bool {
    const EICAR: &[u8] =
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    if data.len() < EICAR.len() || data.len() > 128 {
        return false;
    }
    if &data[..EICAR.len()] != EICAR {
        return false;
    }
    // Anything after the 68-byte string must be whitespace-only padding.
    data[EICAR.len()..].iter().all(|b| b.is_ascii_whitespace())
}

/// True when a buffer is a still image — by file extension or by magic bytes.
/// Used to gate photo scanning behind the `SCAN_MEDIA_ENABLED` toggle
/// (videos are covered separately by `is_media_file`).
fn is_image_buffer(name: Option<&str>, data: &[u8]) -> bool {
    if let Some(n) = name {
        let lower = n.to_ascii_lowercase();
        if lower.ends_with(".png") || lower.ends_with(".jpg") || lower.ends_with(".jpeg")
            || lower.ends_with(".gif") || lower.ends_with(".bmp") || lower.ends_with(".webp")
            || lower.ends_with(".tiff") || lower.ends_with(".tif")
            || lower.ends_with(".ico") || lower.ends_with(".svg")
            || lower.ends_with(".heic") || lower.ends_with(".heif")
            || lower.ends_with(".avif")
        {
            return true;
        }
    }
    data.len() > 4 && (
        data.starts_with(&[0x89, 0x50, 0x4E, 0x47])              // PNG
        || data.starts_with(&[0xFF, 0xD8, 0xFF])                 // JPEG
        || data.starts_with(b"GIF8")                             // GIF
        || data.starts_with(b"BM")                               // BMP
        || (data.starts_with(b"RIFF") && data.len() > 12 && &data[8..12] == b"WEBP") // WebP
        || data.starts_with(&[0x49, 0x49, 0x2A, 0x00])           // TIFF LE
        || data.starts_with(&[0x4D, 0x4D, 0x00, 0x2A])           // TIFF BE
        || data.starts_with(&[0x00, 0x00, 0x01, 0x00])           // ICO
        || (data.len() > 12 && &data[4..8] == b"ftyp"            // HEIC / HEIF / AVIF
            && (&data[8..12] == b"heic" || &data[8..12] == b"heif"
                || &data[8..12] == b"avif" || &data[8..12] == b"mif1"
                || &data[8..12] == b"msf1"))
    )
}

fn is_harmless_resource_extension(lower: &str) -> bool {
    lower.ends_with(".png")
        || lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".gif")
        || lower.ends_with(".bmp")
        || lower.ends_with(".webp")
        || lower.ends_with(".tiff")
        || lower.ends_with(".tif")
        || lower.ends_with(".ico")
        || lower.ends_with(".svg")
        || lower.ends_with(".heic")
        || lower.ends_with(".heif")
        || lower.ends_with(".avif")
        || lower.ends_with(".mp3")
        || lower.ends_with(".wav")
        || lower.ends_with(".ogg")
        || lower.ends_with(".aac")
        || lower.ends_with(".flac")
        || lower.ends_with(".m4a")
        || lower.ends_with(".mp4")
        || lower.ends_with(".mkv")
        || lower.ends_with(".webm")
        || lower.ends_with(".3gp")
        || lower.ends_with(".ttf")
        || lower.ends_with(".otf")
        || lower.ends_with(".woff")
        || lower.ends_with(".woff2")
        || lower.ends_with(".arsc")
}

fn is_relevant_buffer(name: Option<&str>, data: &[u8]) -> bool {
    if name.is_none() {
        return true;
    }

    // Always scan executable/archive/bytecode magic headers regardless of filename
    if data.starts_with(b"dex\n")
        || data.starts_with(b"vdex")
        || data.starts_with(b"\x7fELF")
        || data.starts_with(b"PK\x03\x04")
        || data.starts_with(b"\xca\xfe\xba\xbe")
    {
        return true;
    }

    let name = name.unwrap();
    let lower = name.to_ascii_lowercase();
    let filename = lower.split(['/', '!']).last().unwrap_or(&lower);

    // High-value security targets
    if filename == "androidmanifest.xml"
        || (lower.contains("classes") && (lower.ends_with(".dex") || lower.ends_with(".vdex") || lower.ends_with(".odex")))
        || lower.ends_with(".so")
        || lower.ends_with(".apk")
        || lower.ends_with(".jar")
        || lower.ends_with(".class")
        || lower.ends_with(".sh")
        || lower.ends_with(".elf")
        || lower.ends_with(".rsa")
        || lower.ends_with(".dsa")
        || lower.ends_with(".ec")
        || lower.ends_with(".sf")
        || lower.ends_with(".mf")
    {
        return true;
    }

    // Drop harmless resource types — but keep them if they contain hidden/polyglot data
    // (appended data after JPEG FFD9 / PNG IEND, PNG text-chunk payloads,
    //  JPEG comment/APPn segments, or executable magic at non-zero offsets)
    if is_harmless_resource_extension(&lower) {
        return has_polyglot_or_hidden_data(data);
    }

    // Resource paths (res/...) - scan only if obfuscated XML or contains embedded payload
    if is_resource_path(&lower) {
        let is_xml = data.starts_with(b"<?xml");
        return is_xml && (is_obfuscated_xml(data) || has_embedded_data(data));
    }

    if data.starts_with(b"<?xml") {
        return is_obfuscated_xml(data) || has_embedded_data(data);
    }

    false
}



fn has_embedded_data(data: &[u8]) -> bool {
    let sample = if data.len() > 4096 { &data[..4096] } else { data };
    let printable = sample
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();
    printable > sample.len() / 4
}

// ── Image hidden-data / polyglot detection ────────────────────────────────────

/// True if `slice` contains any executable magic sequence:
/// ZIP (`PK\x03\x04`), DEX (`dex\n`), ELF (`\x7fELF`), Java class (`\xca\xfe\xba\xbe`).
///
/// Only call this on small regions (metadata, post-EOF tail) — not on raw pixel data.
#[inline]
fn image_magic_in_slice(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    data.windows(4).any(|w| {
        w == b"PK\x03\x04"
            || w == b"dex\n"
            || w == b"\x7fELF"
            || w == b"\xca\xfe\xba\xbe"
    })
}

/// PNG chunk-aware scanner. Inspects text chunks (`tEXt`, `iTXt`, `zTXt`) and
/// detects any data appended after the `IEND` marker.  Never touches `IDAT`
/// (compressed pixel data), so it is fast even on multi-megabyte images.
fn png_has_hidden(data: &[u8]) -> bool {
    // PNG signature is 8 bytes
    let mut pos = 8usize;
    let limit = data.len();

    while pos + 12 <= limit {
        // Chunk layout: [4 length][4 type][<length> data][4 CRC]
        let chunk_len = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
        let chunk_type = &data[pos+4..pos+8];
        let payload_start = pos + 8;

        // Sanity cap — individual PNG chunks ≤ 2^31-1; 64 MB is more than enough
        if chunk_len > 64 * 1024 * 1024 {
            break;
        }
        let next_pos = pos + 8 + chunk_len + 4; // skip payload + CRC
        if next_pos > limit {
            break; // truncated chunk
        }

        match chunk_type {
            b"IEND" => {
                // Data after IEND is only suspicious when it carries executable
                // magic (appended ZIP/APK/DEX/ELF polyglot). Trailing padding or
                // benign metadata after IEND is common and must not FP.
                return next_pos < limit && image_magic_in_slice(&data[next_pos..]);
            }
            b"tEXt" | b"iTXt" | b"zTXt" => {
                // Only flag embedded executable magic. Text metadata routinely
                // carries URLs (Adobe XMP namespaces) and base64 blobs (ICC
                // profiles, thumbnails), so a text-heuristic here FPs heavily.
                if chunk_len > 0 {
                    let payload = &data[payload_start..payload_start + chunk_len];
                    if image_magic_in_slice(payload) {
                        return true;
                    }
                }
            }
            _ => {}
        }
        pos = next_pos;
    }
    false
}

/// JPEG segment-aware scanner. Inspects comment (`FF FE`) and APPn (`FF E0`–`FF EF`)
/// segments for embedded executables or suspicious text, and detects executable
/// magic appended after the `FF D9` (EOI) marker.  Skips past the SOS (Start of
/// Scan) compressed payload without decoding it.
fn jpeg_has_hidden(data: &[u8]) -> bool {
    let mut pos = 2usize; // skip FF D8 (SOI)
    let limit = data.len();

    while pos + 2 <= limit {
        if data[pos] != 0xFF {
            break; // not on a marker boundary — malformed
        }
        let marker = data[pos + 1];

        // EOI — data after this is only suspicious when it carries executable
        // magic (appended ZIP/APK/DEX/ELF polyglot). Trailing padding, MPF
        // multi-picture second images, and thumbnails are legitimate and very
        // common on phone photos, so a bare "bytes after EOI" check FPs heavily.
        if marker == 0xD9 {
            let tail_start = pos + 2;
            return tail_start < limit && image_magic_in_slice(&data[tail_start..]);
        }

        // Standalone markers (no length): RST0–RST7, SOI, TEM
        if matches!(marker, 0xD0..=0xD8 | 0x01) {
            pos += 2;
            continue;
        }

        // All other markers carry a 2-byte length (inclusive)
        if pos + 4 > limit {
            break;
        }
        let seg_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        if seg_len < 2 {
            break; // malformed length
        }
        let payload_start = pos + 4;
        let payload_len = seg_len - 2;
        if payload_start + payload_len > limit {
            break; // truncated
        }

        match marker {
            // Comment (FF FE) — only flag executable magic, not text content
            // (camera-generated binary metadata routinely fails UTF-8 check)
            0xFE => {
                if image_magic_in_slice(&data[payload_start..payload_start + payload_len]) {
                    return true;
                }
            }
            // APPn segments (FF E0 – FF EF): JFIF, EXIF, XMP, ICC, …
            0xE0..=0xEF => {
                let app_data = &data[payload_start..payload_start + payload_len];
                // Executable magic anywhere in an APPn payload → polyglot.
                // Text heuristics are deliberately NOT applied here: XMP/EXIF
                // legitimately carry namespace URLs and base64 thumbnails.
                if image_magic_in_slice(app_data) {
                    return true;
                }
            }
            // SOS — compressed image data starts here; we can't reliably parse
            // it without a full decoder, so jump straight to EOI detection.
            0xDA => {
                let rest = &data[pos..];
                if let Some(eoi_rel) = rest.windows(2).position(|w| w == b"\xFF\xD9") {
                    // Only appended executable magic after EOI is suspicious —
                    // benign trailing data (padding, MPF images) is common.
                    let tail_start = pos + eoi_rel + 2;
                    return tail_start < limit && image_magic_in_slice(&data[tail_start..]);
                }
                break; // no EOI found — truncated / odd file
            }
            _ => {}
        }

        pos += 2 + seg_len;
    }
    false
}

/// Check an image buffer for polyglot/steganographic indicators without
/// ever scanning raw pixel data (which would be slow and produce false positives).
///
/// Covers:
/// * **PNG** — `tEXt`/`iTXt`/`zTXt` chunk payloads; data appended after `IEND`
/// * **JPEG** — `FF FE` comment and APPn (`FF E0`–`FF EF`) payloads; data after `FF D9`
/// * **ISOBMFF media** (MP4, M4V, 3GP, MOV) — appended data after the box tree
/// * **Other images / video / audio** (BMP, GIF, WebP, TIFF, ICO, Matroska/WebM,
///   WAV, OGG, FLAC, MP3/AAC) — executable magic in the last 4 KB
fn has_polyglot_or_hidden_data(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    // PNG signature: 89 50 4E 47 0D 0A 1A 0A
    if data.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return png_has_hidden(data);
    }
    // JPEG signature: FF D8 FF
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return jpeg_has_hidden(data);
    }
    // ISOBMFF media files (MP4, M4V, 3GP, MOV, etc.): walk the box tree to
    // find the structural end of the file, then check for appended data.
    if is_media_file(data) {
        return media_scan::has_hidden_data(data);
    }
    // Other known image / media / audio types: scan only the last 4 KB for
    // appended executable magic (ZIP/APK/DEX/ELF/class).  Only run when the
    // file actually starts with a recognised container magic — ZIPs, ELFs,
    // DEXs etc. have their own magic and checking their tail would FP on valid
    // archive structures (PK\x03\x04 in the central directory, dex\n etc.).
    //
    // These formats have no lightweight structural parser here, so the tail
    // heuristic is the pragmatic check: it never inspects the raw
    // pixel/audio/video payload and only flags a real appended executable.
    let starts_with_container_magic = data.len() > 4 && (
        // Images
        data.starts_with(b"GIF8")                                       // GIF
        || data.starts_with(b"BM")                                      // BMP
        || (data.starts_with(b"RIFF") && data.len() > 12 && &data[8..12] == b"WEBP") // WebP
        || data.starts_with(&[0x49, 0x49, 0x2A, 0x00])                  // TIFF LE
        || data.starts_with(&[0x4D, 0x4D, 0x00, 0x2A])                  // TIFF BE
        || data.starts_with(&[0x00, 0x00, 0x01, 0x00])                  // ICO
        // Video / container
        || data.starts_with(&[0x1A, 0x45, 0xDF, 0xA3])                  // Matroska / WebM (EBML)
        // Audio
        || (data.starts_with(b"RIFF") && data.len() > 12 && &data[8..12] == b"WAVE") // WAV
        || data.starts_with(b"OggS")                                    // OGG (Ogg/Vorbis/Opus)
        || data.starts_with(b"fLaC")                                    // FLAC
        || data.starts_with(b"ID3")                                     // MP3 with ID3 tag
        || (data.len() > 2 && data[0] == 0xFF && (data[1] & 0xE0) == 0xE0) // MP3/AAC(ADTS) frame sync
    );
    if starts_with_container_magic {
        let tail_start = data.len().saturating_sub(4096);
        return image_magic_in_slice(&data[tail_start..]);
    }
    false
}

/// Smallest TLSH distance from `buf` to any digest in `db`, or None when
/// `buf` is too small/low-variance to hash or nothing is close enough.
fn tlsh_nearest(db: &[tlsh_db::TlshFlat], buf: &[u8]) -> Option<i32> {
    if db.is_empty() {
        return None;
    }
    let digest = tlsh_rs::hash_bytes(buf).ok()?;
    let flat = tlsh_db::TlshFlat::from_tlsh_rs(&digest)?;
    let mut best = i32::MAX;
    for known in db {
        let d = flat.diff(known);
        if d < best {
            best = d;
            if best == 0 {
                break;
            }
        }
    }
    let threshold = TLSH_THRESHOLD.load(std::sync::atomic::Ordering::Relaxed);
    (best <= threshold).then_some(best)
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

/// `boolean nativeInit(String assetDir, boolean loadAutoRules, Object assetManager,
///                      String filesDir)`
///
/// Returns immediately after spawning a thread that loads the engine (~70 s
/// on a cold start). Reads every bundled asset file via AAssetManager; the
/// `filesDir` parameter is the writable filesystem path for
/// `generated_rules/*.yar` (auto-learned rules). No filesystem I/O for the
/// bundled 330+ MB of scan data, no Java-side `copyAsset`.
/// Use [`nativeIsReady`] to check whether the engine has finished loading.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeInit(
    mut env: EnvUnowned,
    _class: JClass,
    asset_dir: JString,
    load_auto_rules: jboolean,
    asset_manager: JObject,
    files_dir: JString,
) -> jboolean {
    env.with_env(|env| -> jni::errors::Result<_> {
        if ENGINE.get().is_some() {
            return Ok(JNI_TRUE);
        }
        if INIT_STARTED.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(JNI_FALSE);
        }

        // Store the JVM so Rust background threads can call back into Java.
        let _ = JAVA_VM.set(env.get_java_vm()?);

        let load_auto_rules = load_auto_rules != JNI_FALSE;
        install_panic_hook();

        let asset_dir: String = match asset_dir.try_to_string(env) {
            Ok(s) => s,
            Err(_) => return Ok(JNI_FALSE),
        };
        let files_dir: String = match files_dir.try_to_string(env) {
            Ok(s) => s,
            Err(_) => return Ok(JNI_FALSE),
        };

        #[cfg(target_os = "android")]
        let mgr_addr = {
            let mgr = asset_reader::from_java(
                env.get_raw() as *mut std::ffi::c_void,
                asset_manager.into_raw() as *mut std::ffi::c_void,
            );
            mgr as usize
        };
        #[cfg(not(target_os = "android"))]
        let mgr_addr = 0;
        #[cfg(not(target_os = "android"))]
        let _ = (&asset_dir, &asset_manager, mgr_addr);
        INIT_STARTED.store(true, std::sync::atomic::Ordering::Release);

        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .name("native-init".into())
            .spawn(move || {
                // This spawn() happens on the app's main thread (Application.onCreate),
                // so by default the new thread inherits its scheduler priority too —
                // fine for the JNI call itself, but this closure then burns ~8s of CPU
                // decompressing/parsing ClamAV+YARA+ML+TLSH data, starving the UI
                // thread of cycles at cold start (observed as Choreographer "Skipped
                // N frames"/HWUI "Davey" and even an ANR in logcat). Nice value 10 ==
                // Android's ANDROID_PRIORITY_BACKGROUND, the same value ScanEngine.java
                // gives its background scan pools via THREAD_PRIORITY_BACKGROUND.
                #[cfg(target_os = "android")]
                unsafe {
                    libc::setpriority(libc::PRIO_PROCESS, libc::gettid() as libc::id_t, 10);
                }
                #[cfg(target_os = "android")]
                let files = {
                    let mgr = mgr_addr as *mut std::ffi::c_void;
                    asset_reader::init(mgr);
                    asset_reader::read_all_assets(&asset_dir)
                };
                #[cfg(not(target_os = "android"))]
                let files = std::collections::HashMap::new();
                if files.is_empty() {
                    android_log("native-init FAILED — no assets read");
                    return;
                }
                let _ = ASSET_DIR.set(asset_dir);
                // Only the raw bytes needed to BUILD the engine are kept in
                // ASSET_FILES; the map is dropped once do_init_from_assets
                // returns. Lazy consumers re-read from the AAssetManager.
                if let Ok(mut g) = ASSET_FILES.lock() {
                    *g = Some(files);
                }
                // files_dir is the writable path for generated_rules/
                let _ = INIT_DIR.set(files_dir);
                let engine = {
                    let guard = ASSET_FILES.lock().unwrap();
                    let asset_files = guard.as_ref().unwrap();
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        do_init_from_assets(asset_files, load_auto_rules)
                    }))
                };
                // Release the raw asset bytes now that every component parsed
                // its input: this frees ~200 MB of anonymous heap that was
                // previously pinned for the whole process lifetime.
                if let Ok(mut g) = ASSET_FILES.lock() {
                    *g = None;
                }
                let engine = match engine {
                    Ok(e) => e,
                    Err(_) => {
                        android_log(&format!("native-init PANIC: {}", last_panic()));
                        return;
                    }
                };
                let ok = engine.clamav.is_some() || engine.model.is_some();
                if ok {
                    let _ = ENGINE.set(std::sync::RwLock::new(engine));
                    android_log("native-init completed");
                    rust_timing_log!("mem :: {}", native_memory_report().replace('\n', " | "));
                } else {
                    android_log("native-init FAILED — no clamav or model");
                }
            })
            .expect("spawn native-init thread");

        Ok(JNI_FALSE)
    }).resolve::<LogErrorAndDefault>()
}

/// `boolean nativeIsReady()` — true when the async background init has
/// finished populating the `ENGINE` global. Replaces the Java-side `ready`
/// flag so the Java layer is always in sync with the actual Rust engine state.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeIsReady(
    _env: EnvUnowned,
    _class: JClass,
) -> jboolean {
    if ENGINE.get().is_some() { JNI_TRUE } else { JNI_FALSE }
}

/// `void nativeSetEmulationEnabled(boolean enabled)` — Settings toggle for the
/// Unicorn-based native-code emulation pass (see emulate.rs), applied
/// immediately without needing an engine reinit or app restart.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeSetEmulationEnabled(
    _env: EnvUnowned,
    _class: JClass,
    enabled: jboolean,
) {
    NATIVE_EMULATION_ENABLED.store(enabled != JNI_FALSE, Ordering::Relaxed);
}

/// `void nativeSetRiskwareTestKeyEnabled(boolean enabled)` — Settings toggle
/// for the Andr.Riskware.TestKey detection (APKs signed with Android test/debug
/// certificates). Disabled by default because many legitimate dev builds use
/// testkey signing — only enable if you specifically want to flag them.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeSetRiskwareTestKeyEnabled(
    _env: EnvUnowned,
    _class: JClass,
    enabled: jboolean,
) {
    riskware::set_testkey_detection_enabled(enabled != JNI_FALSE);
}

/// `boolean nativeIsEmulationAvailable()` — probes Unicorn once per
/// process lifetime.  Returns the cached result: Java shows
/// `R.string.unicorn_unsupported` when this is false.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeIsEmulationAvailable(
    _env: EnvUnowned,
    _class: JClass,
) -> jboolean {
    if emulate::probe_emulation() { JNI_TRUE } else { JNI_FALSE }
}

/// `String nativeEmulationReason()` — short English diagnostic explaining
/// why emulation was disabled (for logcat / Java-side logging).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeEmulationReason<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jstring {
    env.with_env(|env| -> jni::errors::Result<_> {
        env.new_string(emulate::unsupported_reason()).map(|j| j.into_raw())
    }).resolve::<LogErrorAndDefault>()
}

/// `String nativeHostArch()` — returns the host CPU architecture string
/// (e.g. "ARM64 (AArch64)", "x86_64") for diagnostics.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeHostArch<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jstring {
    env.with_env(|env| -> jni::errors::Result<_> {
        env.new_string(emulate::host_arch()).map(|j| j.into_raw())
    }).resolve::<LogErrorAndDefault>()
}

/// `void nativeSetMaxScanSizeMb(int maxMb)` — push the
/// user's {@link MaxScanFileSize} ceiling into the native engine so extracted
/// entries larger than this are excluded from the scan passes. Applied
/// immediately; no reinit needed.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeSetMaxScanSizeMb(
    _env: EnvUnowned,
    _class: JClass,
    max_mb: jint,
) {
    // 0 is a valid "disable" value (scan nothing); only guard against negatives.
    let mb = max_mb.max(0) as u32;
    MAX_SCAN_SIZE_MB.store(mb, Ordering::Relaxed);
}

/// `void nativeSetMaxTextScanBytes(int maxBytes)` — push the user's
/// {@link MaxTextScanBytes} ceiling into the native engine so text-like
/// files larger than this are excluded from ClamAV scanning. Applied
/// immediately.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeSetMaxTextScanBytes(
    _env: EnvUnowned,
    _class: JClass,
    max_bytes: jint,
) {
    // 0 is a valid "disable" value; only guard against negatives.
    let bytes = max_bytes.max(0) as u32;
    MAX_TEXT_SCAN_BYTES.store(bytes, Ordering::Relaxed);
}

/// `void nativeSetMaxArchiveSizeMb(int maxMb)` — push the user's
/// {@link MaxArchiveSize} ceiling into the native engine so a NON-zip archive
/// (tar, gz, xz, 7z, rar, etc.) larger than this is not extracted. Applied
/// immediately; no reinit needed.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeSetMaxArchiveSizeMb(
    _env: EnvUnowned,
    _class: JClass,
    max_mb: jint,
) {
    // 0 is a valid "disable" value (never extract non-zip archives); only
    // guard against negatives.
    let mb = max_mb.max(0) as u32;
    MAX_ARCHIVE_SIZE_MB.store(mb, Ordering::Relaxed);
}

/// `void nativeSetDetectZipBomb(boolean enabled)` — Settings toggle for
/// decompression-bomb rejection during archive extraction (see
/// hydradragonextractor's `is_decompression_bomb`). Applied immediately.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeSetDetectZipBomb(
    _env: EnvUnowned,
    _class: JClass,
    enabled: jboolean,
) {
    hydradragonextractor::set_bomb_detection_enabled(enabled != JNI_FALSE);
}

/// `void nativeSetScanRelevantOnly(boolean on)` — Settings toggle: when true,
/// only scan DEX, ELF, and AndroidManifest.xml inside APKs; skip all other
/// assets. Applied immediately; no reinit needed.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeSetScanRelevantOnly(
    _env: EnvUnowned,
    _class: JClass,
    on: jboolean,
) {
    SCAN_RELEVANT_ONLY.store(on != JNI_FALSE, Ordering::Relaxed);
}

/// `void nativeSetScanMediaEnabled(boolean enabled)` — Settings toggle: when
/// true, photos and videos are scanned (hidden/polyglot payload detection +
/// ClamAV signatures on image bytes / media metadata). Default false — media
/// scanning is high-cost, low-yield, so it is opt-in. Applied immediately; no
/// reinit needed.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeSetScanMediaEnabled(
    _env: EnvUnowned,
    _class: JClass,
    enabled: jboolean,
) {
    SCAN_MEDIA_ENABLED.store(enabled != JNI_FALSE, Ordering::Relaxed);
}

/// `void nativeSetScanCacheDir(String cacheDir)` — sets the directory for
/// the scan result cache file. Called from Java after NativeScanner.init(),
/// before any scan. The cache persists clean results across restarts.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeSetScanCacheDir<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    cache_dir: JString<'local>,
) {
    let dir: String = env.with_env(|env| cache_dir.try_to_string(env)).resolve::<LogErrorAndDefault>();
    if !dir.is_empty() {
        let _ = SCAN_CACHE_DIR.set(dir);
        load_scan_cache();
    }
}

/// `boolean nativeLearnRule(String yarPath)` — hot-load ONE freshly
/// auto-generated `.yar` file (already written to disk by
/// ScanEngine.saveGeneratedRule) into the LIVE engine via a brief write lock,
/// so a family this device just caught is detected by every scan for the
/// REST OF THIS SESSION too — not only after the next process restart, which
/// already reloads every past `generated_rules/*.yar` file from `do_init_from_assets`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeLearnRule<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    yar_path: JString<'local>,
) -> jboolean {
    env.with_env(|env| -> jni::errors::Result<_> {
        let path: String = match yar_path.try_to_string(env) {
            Ok(s) => s,
            Err(_) => return Ok(JNI_FALSE),
        };
        let Some(lock) = ENGINE.get() else { return Ok(JNI_FALSE) };
        let Ok(mut guard) = lock.write() else { return Ok(JNI_FALSE) };
        let Some(clamav) = guard.clamav.as_mut() else { return Ok(JNI_FALSE) };
        let added = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            clamav.add_yara_source_file(&path)
        }));
        Ok(if matches!(added, Ok(Some(_))) { JNI_TRUE } else { JNI_FALSE })
    }).resolve::<LogErrorAndDefault>()
}

/// Attribute an asset filename to the engine component that consumes it.
fn asset_category(name: &str) -> &'static str {
    if name == MODEL_MPK || name == VOCAB_JSON {
        "ml model"
    } else if name.ends_with(".yrc") {
        "yara rules"
    } else if name.starts_with("malware_tlsh_") {
        "tlsh dbs"
    } else if name == WHITELIST_XF {
        "nsrl whitelist"
    } else if name == WHITELIST_PACKAGES_DB {
        "pkg whitelist db"
    } else if name == BENIGN_SIGNATURES {
        "benign db"
    } else if name == "emerging-all.rules" {
        "vpn suricata rules"
    } else if name == "public_suffixes.txt" {
        "url psl"
    } else if name.ends_with(".xf") {
        if name.starts_with("ip") { "ip xor filters" } else { "url xor filters" }
    } else if is_clamav_sig_asset(name) {
        "clamav signatures"
    } else {
        "other"
    }
}

/// Whether `name` is a ClamAV signature-database asset (parsed by
/// `hydradragonclamav::Database::from_bytes_map`).
fn is_clamav_sig_asset(name: &str) -> bool {
    const SIG_EXTS: &[&str] = &[
        "hdb", "hsb", "hdu", "hsu", "ndb", "ndu", "ldb", "ldu", "sdb", "db",
        "mdb", "cvd", "cld", "cud", "cbc", "cbd", "fp", "ign", "ign2", "crb",
        "idb", "info", "cfg",
    ];
    let Some(ext) = name.rsplit('.').next() else { return false };
    SIG_EXTS.iter().any(|&e| e.eq_ignore_ascii_case(ext))
}

/// Debug diagnostics: what is holding memory on the native heap. Reads
/// `/proc/self/status` for process-level RSS/VmSize, attributes the raw asset
/// bytes retained in `ASSET_FILES` by component, and reports the measured
/// parsed-buffer footprints. Exposed via `nativeMemoryReport()`.
fn native_memory_report() -> String {
    use std::fmt::Write as _;

    fn human(b: usize) -> String {
        if b >= 1024 * 1024 {
            format!("{:.2} MB", b as f64 / (1024.0 * 1024.0))
        } else {
            format!("{:.1} KB", b as f64 / 1024.0)
        }
    }

    let mut out = String::with_capacity(1024);

    // ── process-level memory (Linux/Android: /proc/self/status) ──────────
    let mut rss_kb = 0usize;
    let mut vsize_kb = 0usize;
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                rss_kb = rest.split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0);
            } else if let Some(rest) = line.strip_prefix("VmSize:") {
                vsize_kb = rest.split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0);
            }
        }
    }
    let _ = writeln!(out, "PROCESS  RSS={} VmSize={}", human(rss_kb * 1024), human(vsize_kb * 1024));

    // ── raw asset bytes retained by ASSET_FILES, grouped per component ────
    // ASSET_FILES is dropped right after init, so this is normally "not held".
    let asset_guard = ASSET_FILES.lock().ok();
    if let Some(guard) = asset_guard.as_ref() {
        if let Some(files) = guard.as_ref() {
            let mut total = 0usize;
            let mut by_cat: std::collections::BTreeMap<&'static str, usize> = Default::default();
            for (name, bytes) in files.iter() {
                *by_cat.entry(asset_category(name)).or_insert(0) += bytes.len();
                total += bytes.len();
            }
            let _ = writeln!(out, "ASSETS  total={} across {} files", human(total), files.len());
            for (cat, n) in by_cat {
                let _ = writeln!(out, "   {:<24} {}", cat, human(n));
            }
        } else {
            out.push_str("ASSETS  not held (released after init)\n");
        }
    }

    // ── parsed in-memory structures (measured, not guessed) ───────────────
    // try_read: this runs on the UI thread (debug panel); never block on an
    // in-flight scan that holds the read lock.
    if let Some(engine) = ENGINE.get().and_then(|l| l.try_read().ok()) {
        let tlsh_digests =
            engine.tlsh_db_elf.capacity() + engine.tlsh_db_apk.capacity() + engine.tlsh_db_dex.capacity();
        let tlsh_bytes = tlsh_digests * std::mem::size_of::<tlsh_db::TlshFlat>();
        let pkg_wl: usize = engine
            .package_whitelist
            .iter()
            .map(|(k, v)| k.len() + 1 + v.len() + 32)
            .sum();
        let benign = engine.benign_db.as_ref().map(|b| b.heap_bytes()).unwrap_or(0);
        let _ = writeln!(out, "PARSED  tlsh_digests={tlsh_digests} {}", human(tlsh_bytes));
        let _ = writeln!(out, "PARSED  pkg_whitelist_entries={} {}", engine.package_whitelist.len(), human(pkg_wl));
        let _ = writeln!(out, "PARSED  benign_db {}", human(benign));
        let _ = writeln!(out, "PARSED  clamav_engine_struct {}", human(std::mem::size_of_val(&engine.clamav)));
        let _ = writeln!(out, "PARSED  model_struct {}", human(std::mem::size_of_val(&engine.model)));
        let _ = writeln!(out, "PARSED  whitelist_filter_struct {}", human(std::mem::size_of_val(&engine.whitelist)));
        let _ = writeln!(out, "PARSED  url_scanner_struct {}", human(std::mem::size_of_val(&engine.url_scanner)));
        let _ = writeln!(out, "PARSED  ip_scanner_struct {}", human(std::mem::size_of_val(&engine.ip_scanner)));
    } else {
        out.push_str("PARSED  engine not initialised\n");
    }

    // ── scan result cache ─────────────────────────────────────────────────
    if let Ok(cache) = SCAN_CACHE.try_lock() {
        let count = cache.as_ref().map(|c| c.map.len()).unwrap_or(0);
        let bytes: usize = cache.as_ref().map(|c| {
            c.map.iter().map(|(k, e)| k.len() + e.json.len() + 64).sum()
        }).unwrap_or(0);
        let _ = writeln!(out, "CACHE   scan_cache_entries={count} {}", human(bytes));
    }

    out
}

/// `String nativeStatus()` — what loaded / failed during init (diagnostics).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeStatus(
    mut env: EnvUnowned,
    _class: JClass,
) -> jstring {
    env.with_env(|env| -> jni::errors::Result<_> {
        let s = INIT_STATUS.lock().map(|g| g.clone()).unwrap_or_default();
        env.new_string(&s).map(|j| j.into_raw())
    }).resolve::<LogErrorAndDefault>()
}

/// `String nativeMemoryReport()` — debug diagnostics: what's holding memory on
/// the native heap (process RSS/VmSize, per-component asset bytes, parsed
/// buffer footprints). Backs the dashboard's debug memory panel.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeMemoryReport(
    mut env: EnvUnowned,
    _class: JClass,
) -> jstring {
    env.with_env(|env| -> jni::errors::Result<_> {
        let s = native_memory_report();
        env.new_string(&s).map(|j| j.into_raw())
    }).resolve::<LogErrorAndDefault>()
}

/// `boolean nativeIsHashWhitelisted(String md5)` — true if the MD5 is in the
/// NSRL whitelist (Binary-Fuse xor filter). Lets Java suppress false positives
/// by hash without holding the filter in the Java heap.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeIsHashWhitelisted<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    hash: JString<'local>,
) -> jboolean {
    env.with_env(|env| -> jni::errors::Result<_> {
        let h: String = match hash.try_to_string(env) {
            Ok(s) => s,
            Err(_) => return Ok(JNI_FALSE),
        };
        let hit = ENGINE
            .get()
            .and_then(|l| l.read().ok())
            .map(|e| e.whitelist.as_ref().map(|wl| wl.contains(&h)).unwrap_or(false))
            .unwrap_or(false);
        Ok(if hit { JNI_TRUE } else { JNI_FALSE })
    }).resolve::<LogErrorAndDefault>()
}

/// `boolean nativeIsHashWhitelistedForFile(String path, String md5)` — like
/// nativeIsHashWhitelisted, but first validates the file header (must begin
/// with ZIP magic bytes PK\x04\x03) so non-APK files are never whitelisted.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeIsHashWhitelistedForFile<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    path: JString<'local>,
    hash: JString<'local>,
) -> jboolean {
    env.with_env(|env| -> jni::errors::Result<_> {
        let p: String = match path.try_to_string(env) {
            Ok(s) => s,
            Err(_) => return Ok(JNI_FALSE),
        };
        let h: String = match hash.try_to_string(env) {
            Ok(s) => s,
            Err(_) => return Ok(JNI_FALSE),
        };
        // Reject non-ZIP files by checking magic bytes (PK\x04\x03 = 0x504B).
        match std::fs::File::open(&p) {
            Ok(mut f) => {
                let mut magic = [0u8; 2];
                if std::io::Read::read_exact(&mut f, &mut magic).is_err() || magic != [0x50, 0x4B] {
                    return Ok(JNI_FALSE);
                }
            }
            Err(_) => return Ok(JNI_FALSE),
        }
        let hit = ENGINE
            .get()
            .and_then(|l| l.read().ok())
            .map(|e| e.whitelist.as_ref().map(|wl| wl.contains(&h)).unwrap_or(false))
            .unwrap_or(false);
        Ok(if hit { JNI_TRUE } else { JNI_FALSE })
    }).resolve::<LogErrorAndDefault>()
}

/// `String nativeScanUrl(String url)` — malicious category (e.g. "PHISHING")
/// for an http(s) URL, or "" if clean / not a URL. All membership is the native
/// xor-filter URL/domain scanner, so no filter sits in the Java heap.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeScanUrl<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    url: JString<'local>,
) -> jstring {
    env.with_env(|env| -> jni::errors::Result<_> {
        let u: String = match url.try_to_string(env) {
            Ok(s) => s,
            Err(_) => return Ok(std::ptr::null_mut()),
        };
        let cat = ENGINE
            .get()
            .and_then(|l| l.read().ok())
            .and_then(|e| e.url_scanner.as_ref().and_then(|s| s.scan(&u)))
            .unwrap_or("");
        env.new_string(cat).map(|s| s.into_raw())
    }).resolve::<LogErrorAndDefault>()
}

/// `String nativeScanIp(String ip)` — category (e.g. "MALWARE_IP") for a
/// blocklisted IP, or "" if clean. Exact match against the per-category xor
/// filters (allips non-CIDR); no subnet/CIDR matching.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeScanIp<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    ip: JString<'local>,
) -> jstring {
    env.with_env(|env| -> jni::errors::Result<_> {
        let ip: String = match ip.try_to_string(env) {
            Ok(s) => s,
            Err(_) => return Ok(std::ptr::null_mut()),
        };
        let cat = ENGINE
            .get()
            .and_then(|l| l.read().ok())
            .and_then(|e| e.ip_scanner.as_ref().and_then(|s| s.scan(&ip)))
            .unwrap_or("");
        env.new_string(cat).map(|s| s.into_raw())
    }).resolve::<LogErrorAndDefault>()
}

/// `String nativeScanText(String text, String packageName)` — runs the
/// clamav/YARA engine (hydradragon.screen_text + plain-string rules) against
/// OCR'd on-screen text and returns a comma-joined list of matched rule/sig
/// names ("" if clean or the engine isn't ready). Used by ScreenCaptureService
/// so a scam/ransomware message actually rendered on screen can be caught even
/// when it never touches the APK's own bytes.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeScanText<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    text: JString<'local>,
) -> jstring {
    env.with_env(|env| -> jni::errors::Result<_> {
        let t: String = match text.try_to_string(env) {
            Ok(s) => s,
            Err(_) => return Ok(std::ptr::null_mut()),
        };
        let result = scan_text(&t);
        env.new_string(&result).map(|s| s.into_raw())
    }).resolve::<LogErrorAndDefault>()
}

/// `String nativeScanHips(String hipsJson)` — runs the
/// clamav/YARA engine (hips module) against behavioral metadata collected
/// by the Android HipsMonitor service and returns a JSON verdict with
/// matched rule names and suggested actions ("uninstall", "warn", "ignore").
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeScanHips<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    hips_json: JString<'local>,
) -> jstring {
    env.with_env(|env| -> jni::errors::Result<_> {
        let json: String = match hips_json.try_to_string(env) {
            Ok(s) => s,
            Err(_) => return Ok(std::ptr::null_mut()),
        };
        let result = scan_hips(&json);
        env.new_string(&result).map(|s| s.into_raw())
    }).resolve::<LogErrorAndDefault>()
}

/// Initialise the Suricata-format rule engine (parses emerging-all.rules
/// from assets and builds a daachorse automaton). Called once from
/// nativeEnableVpnScan(true). Thread-safe.
fn load_vpn_rules() -> bool {
    if VPN_RULES_LOADED.load(std::sync::atomic::Ordering::Relaxed) {
        return VPN_RULES_READY.load(std::sync::atomic::Ordering::Relaxed);
    }
    // emerging-all.rules (~44 MB) is deliberately NOT read during native-init
    // (ASSET_FILES is dropped right after the engine is built). It is fetched
    // on demand here, parsed, and the raw bytes released again — so the rule
    // text only ever occupies RAM while VPN scanning is actually in use.
    #[cfg(target_os = "android")]
    let rules_bytes: Option<Vec<u8>> = {
        let relative = ASSET_DIR
            .get()
            .map(|dir| format!("{dir}/emerging-all.rules"))
            .unwrap_or_else(|| "scan/emerging-all.rules".to_string());
        asset_reader::read_file_bytes(&relative)
    };
    #[cfg(not(target_os = "android"))]
    let rules_bytes: Option<Vec<u8>> = None;
    let ok = match rules_bytes {
        Some(bytes) => suricata_scan::RuleEngine::init(&bytes),
        None => {
            rust_timing_log!("SuricataEngine: emerging-all.rules not found in assets");
            false
        }
    };
    VPN_RULES_READY.store(ok, std::sync::atomic::Ordering::Relaxed);
    VPN_RULES_LOADED.store(true, std::sync::atomic::Ordering::Relaxed);
    ok
}

fn scan_hips(hips_json: &str) -> String {
    if hips_json.is_empty() {
        return r#"{"malicious":false}"#.to_string();
    }
    // Validate JSON early so we don't bother loading rules for garbage input.
    if serde_json::from_str::<serde_json::Value>(hips_json).is_err() {
        return r#"{"error":"invalid JSON"}"#.to_string();
    }
    let Some(guard) = ENGINE.get().and_then(|l| l.read().ok()) else {
        return r#"{"error":"not initialised"}"#.to_string();
    };
    let Some(clamav) = &guard.clamav else {
        return r#"{"error":"engine not ready"}"#.to_string();
    };
    let meta_json = hips_json.as_bytes();
    let module_meta: Vec<(&str, &[u8])> = vec![("hydradragon", meta_json)];
    let opts = ScanOptions::default();
    let detections = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        clamav
            .scan_bytes_named(meta_json, "hips_behavior", opts, &module_meta)
            .into_iter()
            .map(|m| m.name)
            .collect::<Vec<_>>()
    }))
    .unwrap_or_default();
    let malicious = !detections.is_empty();
    let hits_json = detections
        .iter()
        .map(|h| format!("\"{}\"", json_escape(h)))
        .collect::<Vec<_>>()
        .join(",");
    // If malicious, suggest uninstall
    let suggestion = if malicious { "uninstall" } else { "none" };
    format!(
        r#"{{"malicious":{},"matches":[{}],"suggestion":"{}"}}"#,
        malicious, hits_json, suggestion
    )
}

fn scan_text(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let Some(guard) = ENGINE.get().and_then(|l| l.read().ok()) else {
        return String::new();
    };
    let Some(clamav) = &guard.clamav else {
        return String::new();
    };
    // Cap: OCR text is display-sized, never worth scanning megabytes of it.
    let bytes = if text.len() > 8192 { &text.as_bytes()[..8192] } else { text.as_bytes() };
    let meta_json = format!(r#"{{"screen_text":"{}"}}"#, json_escape(text));
    let module_meta: Vec<(&str, &[u8])> = vec![("hydradragon", meta_json.as_bytes())];
    let opts = ScanOptions::default();
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

/// `boolean nativeEnableVpnScan(boolean enable)` — when true, lazily load VPN
/// Suricata rules (emerging-all.rules) and enable packet scanning. Returns
/// true if the engine was successfully initialised (or was already ready).
/// When false, disable packet scanning (rules stay loaded but are unused).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeEnableVpnScan(
    _env: EnvUnowned,
    _class: JClass,
    enable: jboolean,
) -> jboolean {
    if enable == JNI_TRUE {
        let ok = load_vpn_rules();
        VPN_SCAN_ENABLED.store(true, std::sync::atomic::Ordering::Relaxed);
        if ok { JNI_TRUE } else { JNI_FALSE }
    } else {
        VPN_SCAN_ENABLED.store(false, std::sync::atomic::Ordering::Relaxed);
        JNI_TRUE
    }
}

/// `String nativeScanPackets(String packetsJson)` — scan VPN-captured packets
/// against the Suricata-format rule engine (emerging-all.rules patterns).
/// Returns a JSON verdict: `{"malicious":true/false,"matches":[...]}`.
/// No-op if VPN scan disabled.
fn scan_packets(packets_json: &str) -> String {
    if !VPN_SCAN_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
        return r#"{"malicious":false}"#.to_string();
    }
    if !VPN_RULES_READY.load(std::sync::atomic::Ordering::Relaxed) {
        return r#"{"malicious":false,"error":"engine not initialised"}"#.to_string();
    }
    if packets_json.is_empty() {
        return r#"{"malicious":false}"#.to_string();
    }
    let engine = suricata_scan::RuleEngine::get();
    let result = engine.scan(packets_json);
    if let Some(ref err) = result.error {
        rust_timing_log!("SuricataScan: {}", err);
    }
    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"serialisation failed"}"#.to_string())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeScanPackets<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    packets_json: JString<'local>,
) -> jstring {
    env.with_env(|env| -> jni::errors::Result<_> {
        let json: String = match packets_json.try_to_string(env) {
            Ok(s) => s,
            Err(_) => return Ok(std::ptr::null_mut()),
        };
        let result = scan_packets(&json);
        env.new_string(&result).map(|s| s.into_raw())
    }).resolve::<LogErrorAndDefault>()
}

/// `String nativeScanApk(String path, String hydradragonJson, String fileMd5,
/// boolean zeroTrust)` — returns a JSON verdict. `zeroTrust` forces the
/// yarGen-style `generated_rule` to be built even for a clean verdict (Zero
/// Trust Mode never treats "nothing matched" as "nothing worth recording").
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeScanApk<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    path: JString<'local>,
    hydradragon_json: JString<'local>,
    file_md5: JString<'local>,
    zero_trust: jboolean,
) -> jstring {
    env.with_env(|env| -> jni::errors::Result<_> {
        let result = scan_apk(env, path, hydradragon_json, file_md5, zero_trust == JNI_TRUE);
        env.new_string(&result).map(|s| s.into_raw())
    }).resolve::<LogErrorAndDefault>()
}

fn scan_apk(
    env: &mut jni::Env,
    path: JString,
    hydradragon_json: JString,
    file_md5: JString,
    zero_trust: bool,
) -> String {
    let path: String = match path.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return r#"{"error":"bad path"}"#.to_string(),
    };
    // Live-network report from Java (hydradragon module). Empty/absent → None.
    let hydradragon: Option<Vec<u8>> = hydradragon_json
        .try_to_string(env)
        .ok()
        .map(|s| s.into_bytes())
        .filter(|b| !b.is_empty());
    // MD5 Java already computed for the whole file (hash-first fast path). Reused
    // for the top-level buffer so it isn't hashed again here. Empty → None.
    let file_md5: Option<String> = file_md5
        .try_to_string(env)
        .ok()
        .filter(|s| !s.is_empty());
    let Some(engine_lock) = ENGINE.get() else {
        return r#"{"error":"not initialised"}"#.to_string();
    };

    let scanned = on_big_stack(move || {
        let file_bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => return format!(r#"{{"error":"{}"}}"#, json_escape(&e.to_string())),
        };
        let guard = match engine_lock.read() {
            Ok(g) => g,
            Err(_) => return r#"{"error":"engine lock poisoned"}"#.to_string(),
        };
        run_scan(&guard, file_bytes, &path, hydradragon.as_deref(), file_md5.as_deref(), zero_trust)
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

/// `void nativeSetTlshThreshold(int threshold)` — sets the TLSH similarity
/// threshold used by `tlsh_nearest` during malware scanning. Applied
/// immediately; no engine reinit needed. Clamped to 1-200.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeSetTlshThreshold<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    threshold: jint,
) {
    let t = threshold.max(1).min(200);
    TLSH_THRESHOLD.store(t, std::sync::atomic::Ordering::Relaxed);
}

/// `int nativeTlshDiff(String tlsh1, String tlsh2)` — returns the TLSH diff
/// distance between two hashes, or -1 on error. Used by the Anti-FP cache to
/// compare a scanned entry's TLSH against known-good TLSH digests.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_hydradragon_antivirus_engine_NativeScanner_nativeTlshDiff<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    tlsh1: JString<'local>,
    tlsh2: JString<'local>,
) -> jint {
    env.with_env(|env| -> jni::errors::Result<_> {
        let s1: String = match tlsh1.try_to_string(env) {
            Ok(s) => s,
            Err(_) => return Ok(-1),
        };
        let s2: String = match tlsh2.try_to_string(env) {
            Ok(s) => s,
            Err(_) => return Ok(-1),
        };
        let d1 = match s1.parse::<tlsh_rs::TlshDigest>() {
            Ok(d) => d,
            Err(_) => return Ok(-1),
        };
        let d2 = match s2.parse::<tlsh_rs::TlshDigest>() {
            Ok(d) => d,
            Err(_) => return Ok(-1),
        };
        Ok(d1.diff(&d2))
    }).resolve::<LogErrorAndDefault>()
}

/// Check every emulation-decoded string (see emulate.rs) that looks like a
/// whole URL against the URL/domain xor filters (`engine.url_scanner`) — a decoded
/// C2 URL a signature/YARA rule was never written for can still be caught
/// this way, the same as any other URL this engine sees. Returns
/// "URL.<CATEGORY>: <url>" pseudo-detection names, matching the existing
/// "YARA.<rule>" naming convention closely enough for Java's per-detection
/// display to show something meaningful.
fn extract_and_scan_urls(engine: &Engine, decoded: &[u8]) -> Vec<String> {
    let Some(scanner) = engine.url_scanner.as_ref() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in decoded.split(|&b| b == b'\n') {
        let s = String::from_utf8_lossy(line);
        let s = s.trim();
        if !(s.starts_with("http://") || s.starts_with("https://")) {
            continue;
        }
        if let Some(cat) = scanner.scan_url_only(s) {
            out.push(format!("URL.{cat}: {s}"));
            if out.len() >= 16 {
                break;
            }
        }
    }
    out
}

/// Base64-encoded URL prefixes to search for in a buffer.
/// Derived from the InQuest Labs `Base64_Encoded_URL` YARA rule
/// (labs.inquest.net). The rule detects Base64-encoded `http://` and
/// `https://` prefixes in both standard and wide (UTF-16LE) encoding.
///
/// `aHR0cDovL`             = base64("http://")
/// `aHR0cHM6Ly`            = base64("https://")
/// `aAB0AHQAcAA2AC8ALw`    = base64 wide("http://")
/// `aAB0AHQAcABzADoALwAv`  = base64 wide("https://")
const B64_URL_PREFIXES: &[&[u8]] = &[
    b"aHR0cDovL",
    b"aHR0cHM6Ly",
    b"aAB0AHQAcAA2AC8ALw",
    b"aAB0AHQAcABzADoALwAv",
];

fn is_b64_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'+' || c == b'/'
}

/// Scan a byte buffer for Base64-encoded URLs, decode them, and check each
/// against the threat URL scanner. Returns detection strings like
/// `"URL.PHISHING: http://..."` for any matches.
/// Skips binary buffers (non-text) since base64-encoded URLs only appear in
/// text contexts.
fn extract_decode_base64_urls(data: &[u8], scanner: &url_scan::UrlScanner) -> Vec<String> {
    if !is_text_like(data) { return Vec::new(); }
    let mut out = Vec::new();
    let n = data.len();
    // All prefixes start with byte b'a'.
    let mut offset = 0;
    while let Some(hit) = memchr::memchr(b'a', &data[offset..]) {
        let pos = offset + hit;
        if pos + 8 > n { break; }
        if !B64_URL_PREFIXES.iter().any(|p| data[pos..].starts_with(p)) {
            offset = pos + 1;
            continue;
        }
        let mut end = pos + 8;
        while end < n && is_b64_char(data[end]) { end += 1; }
        while end < n && data[end] == b'=' && end - pos < 100 { end += 1; }
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&data[pos..end]) {
            if let Ok(s) = String::from_utf8(decoded) {
                let s = s.trim();
                if s.starts_with("http://") || s.starts_with("https://") {
                    if let Some(cat) = scanner.scan_url_only(s) {
                        out.push(format!("URL.{cat}: {s}"));
                        if out.len() >= 16 { return out; }
                    }
                }
            }
        }
        offset = end;
    }
    out
}


/// Owned decompressed or read-ahead buffer bytes.
enum OwnedBuf {
    Vec(Vec<u8>),
}

impl std::ops::Deref for OwnedBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            OwnedBuf::Vec(v) => v,
        }
    }
}

impl From<Vec<u8>> for OwnedBuf {
    fn from(v: Vec<u8>) -> Self {
        OwnedBuf::Vec(v)
    }
}

fn run_scan(
    engine: &Engine,
    apk_bytes: Vec<u8>,
    path: &str,
    hydradragon: Option<&[u8]>,
    file_md5: Option<&str>,
    zero_trust: bool,
) -> String {
    // Only one file's scan pipeline runs at a time, UP TO SCAN_SERIAL_MAX_WAIT
    // — see SCAN_SERIAL's doc comment for why this can't be an unconditional
    // block. If we give up waiting, we proceed anyway rather than freezing
    // every other scan in the app behind this one.
    let _scan_serial_guard = acquire_scan_serial_bounded();

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
    // MD5 of the whole top-level file — computed early so we can skip
    // extraction when the file is whitelisted.
    let file_hash = match file_md5 {
        Some(md5) => md5.to_string(),
        None => md5_hex(&apk_bytes),
    };
    // If the top-level file is hash-whitelisted, skip extraction entirely.
    let whitelisted = engine.whitelist.as_ref().is_some_and(|wl| wl.contains(&file_hash));
    // Scan result cache: if this file's MD5 was previously scanned and clean,
    // return the cached JSON immediately — no extract, no engines.
    if !whitelisted {
        if let Some(mut cached) = check_scan_cache(&file_hash) {
            // Flip "cached":false → "cached":true so Java knows it's from cache.
            if let Some(pos) = cached.find(r#""cached":"#) {
                let after = &cached[pos + 9..];
                if after.starts_with("false") {
                    let before = &cached[..pos + 9];
                    cached = format!("{}true{}", before, &after[5..]);
                }
            }
            rust_timing_log!("{path} :: cache HIT (MD5 {file_hash}) — returning cached result");
            return cached;
        }
    }

    // TLSH of the whole top-level file — computed early while `mmap` is still
    // available (before collect_buffers consumes it). Used in the skip_heavy
    // early-return and in the final result JSON.
    let file_tlsh = tlsh_rs::hash_bytes(&apk_bytes)
        .ok()
        .map(|d| d.to_string())
        .unwrap_or_default();
    // ML inference runs in Phase 3 parallel scope.
    if whitelisted {
        android_log(&format!("whitelist :: skipping extraction for {path} (MD5 {file_hash})"));
    }
    let t_extract = std::time::Instant::now();
    let (buffers, bomb_dets, mut streaming_dets, streaming_timing) = if whitelisted {
        (Vec::new(), Vec::new(), Vec::new(), hydradragonclamav::scanner::TimingBreakdown::default())
    } else {
        collect_buffers(apk_bytes, file_md5, path)
    };
    let extract_ms = t_extract.elapsed().as_millis();

    // Phase 2: collect all whitelist data, build skip_heavy, run fast passes
    // (DEX, permissions, androguard). Heavy passes (ClamAV, ML, emulation,
    // TLSH) are run here.
    let perm_count;
    let packages;
    let hashes;
    let androguard_json;
    let skip_heavy: Vec<bool>;
    let mut dex_scans: Vec<Option<dex_scan::DexScan>> = Vec::new();
    let mut dex_ms: u128 = 0;
    let hydradragon_meta;
    let mut module_meta: Vec<(&str, &[u8])>;
    let mut emulated: Vec<emulate::EmulationResult> = Vec::new();
    let emulated_strings: Vec<Option<Vec<u8>>>;
    let mut emulate_ms: u128 = 0;

    {
        // Dangerous-permission count from the (in-memory) manifest bytes.
        perm_count = max_dangerous_perms(&buffers);
        // Package name(s) from AndroidManifest.xml.
        packages = collect_packages(&buffers);
        // MD5 of each APK/zip buffer for the hash-keyed whitelist.
        hashes = collect_apk_hashes(&buffers, file_md5);
        // androguard JSON report (manifest + URL sweep).
        androguard_json = build_androguard_json(&buffers, &[]);

        // Per-buffer whitelist check.
        let mut apk_md5_to_pkg = std::collections::HashMap::new();
        for b in &buffers {
            if let Some(pkg) = axml_package(&b.data) {
                if !pkg.is_empty() {
                    if let Some(apk_md5) = b.apk_lineage.last() {
                        apk_md5_to_pkg.insert(apk_md5.to_lowercase(), pkg);
                    }
                }
            }
        }

        skip_heavy = buffers
            .iter()
            .map(|b| {
                let is_seed = b.entry_name.is_none();
                // 1. Check if the buffer's own MD5 is in the NSRL hash whitelist (whitelisted item)
                let self_md5 = if is_seed {
                    file_hash.to_lowercase()
                } else {
                    md5_hex(&b.data).to_lowercase()
                };
                if let Some(wl) = &engine.whitelist {
                    if wl.contains(&self_md5) {
                        return true;
                    }
                }

                // 2. Check if the buffer matches the content-based MinHash benign signatures whitelist
                if let Some(pkg) = axml_package(&b.data) {
                    if let Some(bdb) = &engine.benign_db {
                        if let Some(feats) = hydradragonml::features::extract_minhash(&b.data) {
                            if bdb.is_known_benign(&pkg, &feats.tokens) {
                                rust_timing_log!("whitelist :: MinHash match for package '{}'", pkg);
                                return true;
                            }
                        }
                    }
                }

                // 3. Check if any ancestor APK in its lineage is whitelisted
                let mut check_hashes = b.apk_lineage.clone();
                if is_seed {
                    check_hashes.push(file_hash.clone());
                }

                for apk_md5 in check_hashes {
                    let apk_md5_lower = apk_md5.to_lowercase();
                    // Check NSRL hash whitelist for ancestor
                    if let Some(wl) = &engine.whitelist {
                        if wl.contains(&apk_md5_lower) {
                            return true;
                        }
                    }
                    // Check package-name whitelist for ancestor
                    if let Some(pkg) = apk_md5_to_pkg.get(&apk_md5_lower) {
                        if let Some(known_md5) = engine.package_whitelist.get(pkg) {
                            if known_md5.eq_ignore_ascii_case(&apk_md5_lower) {
                                return true;
                            }
                        }
                    }
                }
                false
            })
            .collect();

        // DEX static analysis and native-code emulation are independent —
        // run them in parallel.
        std::thread::scope(|s| {
            // Thread 1: DEX static analysis
            s.spawn(|| {
                let t0 = std::time::Instant::now();
                dex_scans = buffers
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
                dex_ms = t0.elapsed().as_millis();
            });
            // Thread 2: Native code emulation (Unicorn)
            s.spawn(|| {
                let t0 = std::time::Instant::now();
                const MAX_EMULATED_BUFFERS: usize = 8;
                emulated = if NATIVE_EMULATION_ENABLED
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    let mut seen_hashes: std::collections::HashSet<String> = std::collections::HashSet::new();
                    let mut emulated_count = 0usize;
                    buffers
                        .iter()
                        .enumerate()
                        .map(|(i, b)| {
                            if skip_heavy[i] || !b.data.starts_with(b"\x7fELF") {
                                return emulate::EmulationResult::default();
                            }
                            if emulated_count >= MAX_EMULATED_BUFFERS {
                                return emulate::EmulationResult::default();
                            }
                            if !seen_hashes.insert(md5_hex(&b.data)) {
                                return emulate::EmulationResult::default();
                            }
                            emulated_count += 1;
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                emulate::emulate(&b.data)
                            }))
                            .unwrap_or_default()
                        })
                        .collect()
                } else {
                    buffers.iter().map(|_| emulate::EmulationResult::default()).collect()
                };
                emulate_ms = t0.elapsed().as_millis();
            });
        });

        // Emulated strings — derived from emulated results.
        emulated_strings = emulated
            .iter()
            .map(|r| {
                let mut parts: Vec<String> = Vec::new();
                if !r.strings.is_empty() {
                    parts.push(r.strings.join("\n"));
                }
                if !r.api_calls.is_empty() {
                    parts.push(r.api_calls.iter().map(|a| a.name.clone()).collect::<Vec<_>>().join("\n"));
                }
                if parts.is_empty() { None } else { Some(parts.join("\n").into_bytes()) }
            })
            .collect();

        // Merge DEX findings into hydradragon meta.
        hydradragon_meta = merge_dex_findings(hydradragon, &dex_scans);

        // Build module metadata.
        module_meta = Vec::new();
        if let Some(j) = androguard_json.as_deref() {
            module_meta.push(("androguard", j.as_bytes()));
        }
        if let Some(h) = hydradragon_meta.as_deref() {
            if !h.is_empty() {
                module_meta.push(("hydradragon", h));
            }
        }
    }

    // When every buffer is whitelisted (MinHash/NSRL), skip all Phase 3
    // (ML, ClamAV, YARA, TLSH) and return immediately.
    if skip_heavy.iter().all(|&s| s) {
        let file_tlsh_json = format!("\"{}\"", json_escape(&file_tlsh));
        if !bomb_dets.is_empty() {
            let bomb_dets_json: Vec<String> = bomb_dets.iter().map(|(n, op, lin)| {
                let hs: Vec<String> = lin.iter().map(|h| format!("\"{}\"", h)).collect();
                format!(r#"{{"name":"{}","object_path":"{}","hashes":[{}]}}"#,
                    json_escape(n), json_escape(op), hs.join(","))
            }).collect();
            let pkgs: Vec<String> = packages.iter().map(|p| format!("\"{}\"", json_escape(p))).collect();
            let hs: Vec<String> = hashes.iter().map(|h| format!("\"{}\"", h)).collect();
            return format!(
                r#"{{"malicious":true,"matches":[],"detections":[{}],"permissions":{},"packages":[{}],"hashes":[{}],"md5":"{}","file_tlsh":{},"ml":{{"malicious":false,"probability":0.0}},"generated_rule":null,"entry_md5s":{{}},"entry_tlshs":{{}}}}"#,
                bomb_dets_json.join(","),
                perm_count,
                pkgs.join(","),
                hs.join(","),
                file_hash,
                file_tlsh_json,
            );
        }
        let pkgs: Vec<String> = packages.iter().map(|p| format!("\"{}\"", json_escape(p))).collect();
        let hs: Vec<String> = hashes.iter().map(|h| format!("\"{}\"", h)).collect();
        return format!(
            r#"{{"malicious":false,"permissions":{},"packages":[{}],"hashes":[{}],"md5":"{}","file_tlsh":{},"ml":{{"malicious":false,"probability":0.0}}}}"#,
            perm_count, pkgs.join(","), hs.join(","), file_hash, file_tlsh_json,
        );
    }

    // Filter streaming detections from whitelisted buffers: during extraction
    // we scanned every buffer (whitelist wasn't known yet), but whitelisted
    // buffers should never contribute detections.
    if skip_heavy.iter().any(|&sk| sk) && !streaming_dets.is_empty() {
        // Build a set of object_paths for whitelisted buffers.  Buffers with
        // entry_name are matched exactly; for top-level (idx 0) it's `path`;
        // for unnamed archive children the streaming and Vec indices may
        // differ when SCAN_RELEVANT_ONLY skips buffers — we handle this by
        // checking both the Vec-index and emitted-index forms.
        let mut whitelisted_paths: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for (i, sk) in skip_heavy.iter().enumerate() {
            if !sk { continue; }
            if buffers[i].entry_name.is_none() {
                whitelisted_paths.insert(path.to_string());
            } else if let Some(entry) = &buffers[i].entry_name {
                whitelisted_paths.insert(format!("{path}!/{entry}"));
            }
        }
        streaming_dets.retain(|(_, obj_path, _)| !whitelisted_paths.contains(obj_path));
        // Timing contributions from whitelisted buffers are left in
        // streaming_timing — separating per-buffer timing would require
        // per-bucket accounting, and the data is diagnostic-only.
    }

    // ── Parallel heavy phases ──────────────────────────────────────────
    // Phase 3 YARA rescan, emulation signal, ML, TLSH, and URL scanning
    // all depend on read-only `buffers` / `dex_scans` / `module_meta` etc.
    // Run them concurrently so wall time = slowest phase, not sum of all.
    use std::sync::Mutex;

    let yara_dets = Mutex::new(streaming_dets);
    let scan_timing = Mutex::new(streaming_timing);
    let ml_out = Mutex::new((false, 0.0f32, Vec::<(String, Vec<String>)>::new(), 0u128));
    let tlsh_out = Mutex::new(Vec::<(String, String, Vec<String>)>::new());
    let tlsh_ms_out = Mutex::new(0u128);
    let _url_out = Mutex::new(Vec::<(String, String, Vec<String>)>::new());
    let err_shared = Mutex::new(None::<String>);

    let buffers_ref = &*buffers;
    let engine_ref = engine;
    let path_ref = path;
    let module_meta_ref = &module_meta[..];
    let emulated_ref = &emulated;

    // Aggregate every engine result computed in Phase 2 (DEX static analysis,
    // native emulation, manifest, URLs/IPs, TLSH, certificate, benign DB,
    // media hidden-data) into the Burn classifier's EngineFeatures vector.
    let engine_features = build_engine_features(engine_ref, buffers_ref, &dex_scans, &emulated, perm_count);

    // Precompute the set of buffers eligible for ClamAV/YARA content scanning
    // once, up front. The gating (size/relevance/media/executable checks) and
    // the per-video metadata extraction used to be recomputed inline inside a
    // single thread that ran ClamAV *and then* YARA on each buffer, so its wall
    // time was clamav_time + yara_time. Hoisting the work list out lets the
    // ClamAV and YARA passes run on two separate threads over the same
    // read-only slice, overlapping their runtimes (wall time ≈ max, not sum).
    // Non-video buffers are borrowed directly instead of copied with `to_vec`.
    struct ScanItem<'a> {
        idx: usize,
        obj_path: String,
        data: std::borrow::Cow<'a, [u8]>,
        is_vid: bool,
    }
    let scan_items: Vec<ScanItem> = {
        let scan_media = SCAN_MEDIA_ENABLED.load(std::sync::atomic::Ordering::Relaxed);
        let relevant_only = SCAN_RELEVANT_ONLY.load(std::sync::atomic::Ordering::Relaxed);
        buffers_ref
            .iter()
            .enumerate()
            .filter_map(|(i, b)| {
                if skip_by_size(&b.data) { return None; }
                if relevant_only && b.entry_name.is_some()
                    && !is_relevant_buffer(b.entry_name.as_deref(), &b.data) { return None; }
                let is_img = is_image_buffer(b.entry_name.as_deref(), &b.data);
                let is_vid = is_media_file(&b.data);
                let media_ok = scan_media || (!is_img && !is_vid);
                if !media_ok { return None; }
                if !(is_executable_buffer(b.entry_name.as_deref(), &b.data, b.fmt)
                    || is_vid || (scan_media && is_img)) { return None; }
                let obj_path = if b.entry_name.is_none() {
                    path_ref.to_string()
                } else {
                    match &b.entry_name {
                        Some(entry) => format!("{path_ref}!/{entry}"),
                        None => format!("{path_ref}!/unnamed_{i}"),
                    }
                };
                let data = if is_vid {
                    std::borrow::Cow::Owned(media_scan::extract_metadata(&b.data))
                } else {
                    std::borrow::Cow::Borrowed(&b.data[..])
                };
                Some(ScanItem { idx: i, obj_path, data, is_vid })
            })
            .collect()
    };
    let scan_items_ref = &scan_items;

    std::thread::scope(|s| {
        // Thread 1: Phase 3 YARA rescan + emulation signal
        s.spawn(|| {
            let mut rescan_timing = hydradragonclamav::scanner::TimingBreakdown::default();
            if let Some(clamav) = &engine_ref.clamav {
                if !module_meta_ref.is_empty() {
                    let flagged_paths: std::collections::HashSet<String> =
                        std::collections::HashSet::new();
                    let flagged_buffers: Vec<(usize, String)> = buffers_ref
                        .iter()
                        .enumerate()
                        .filter_map(|(i, b)| {
                            let base_path = if b.entry_name.is_none() {
                                path_ref.to_string()
                            } else {
                                match &b.entry_name {
                                    Some(entry) => format!("{path_ref}!/{entry}"),
                                    None => format!("{path_ref}!/unnamed_{i}"),
                                }
                            };
                            if flagged_paths.contains(base_path.as_str()) {
                                Some((i, base_path))
                            } else {
                                None
                            }
                        })
                        .collect();
                    if !flagged_buffers.is_empty() {
                        for yengine in &clamav.yara {
                            if !MODULE_DEPENDENT_YRC.contains(&yengine.name.as_str()) {
                                continue;
                            }
                            for (i, base_path) in &flagged_buffers {
                                let b = &buffers_ref[*i];
                                let per_buf_meta = if b.data.starts_with(b"dex\n") {
                                    module_meta_ref
                                } else {
                                    &[]
                                };
                                let t0 = std::time::Instant::now();
                                let matches = yengine.scan(&b.data, base_path, per_buf_meta);
                                rescan_timing.yara_per_engine.push((yengine.name.clone(), t0.elapsed().as_nanos()));
                                if let Ok(mut yg) = yara_dets.lock() {
                                    for m in matches {
                                        yg.push((m.name, m.object_path, b.apk_lineage.clone()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if let Ok(mut st) = scan_timing.lock() {
                st.accumulate(rescan_timing);
            }
            // Emulation signal
            for (i, b) in buffers_ref.iter().enumerate() {
                if emulated_ref[i].api_calls.is_empty() {
                    continue;
                }
                let base_path = if buffers_ref[i].entry_name.is_none() {
                    path_ref.to_string()
                } else {
                    match &b.entry_name {
                        Some(entry) => format!("{path_ref}!/{entry}"),
                        None => format!("{path_ref}!/unnamed_{i}"),
                    }
                };
                let mut seen_apis = std::collections::HashSet::new();
                for call in &emulated_ref[i].api_calls {
                    if !seen_apis.insert(call.name.clone()) { continue; }
                    if let Ok(mut yg) = yara_dets.lock() {
                        yg.push((
                            format!("Behavior.Native: {}", call.name),
                            base_path.clone(),
                            b.apk_lineage.clone(),
                        ));
                    }
                }
            }
        });

        // Thread 2: ClamAV signatures + phishing (no YARA — that runs on
        // Thread 5 concurrently). Also carries the steganography/polyglot
        // heuristics that were previously bundled with this pass.
        s.spawn(|| {
            if let Some(clamav) = &engine_ref.clamav {
                for item in scan_items_ref {
                    let b = &buffers_ref[item.idx];
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let (matches, bt) = clamav.scan_clamav_only_with_breakdown(
                            &item.data, &item.obj_path, Default::default(), &[],
                        );
                        if let Ok(mut yg) = yara_dets.lock() {
                            for m in &matches {
                                yg.push((m.name.clone(), m.object_path.clone(), b.apk_lineage.clone()));
                            }
                        }
                        if let Ok(mut st) = scan_timing.lock() {
                            st.accumulate(bt);
                        }
                    }));
                    if item.is_vid && media_scan::has_hidden_data(&b.data) {
                        if let Ok(mut yg) = yara_dets.lock() {
                            yg.push(("HDR.Media.Steganography".to_string(), item.obj_path.clone(), b.apk_lineage.clone()));
                        }
                    } else if has_polyglot_or_hidden_data(&b.data) {
                        if let Ok(mut yg) = yara_dets.lock() {
                            yg.push(("HDR.Image.Steganography".to_string(), item.obj_path.clone(), b.apk_lineage.clone()));
                        }
                    }
                }
            }
        });

        // Thread 5: YARA-x rulesets (non-module-dependent) — runs concurrently
        // with the ClamAV pass on Thread 2 instead of sequentially after it.
        s.spawn(|| {
            if let Some(clamav) = &engine_ref.clamav {
                for item in scan_items_ref {
                    let b = &buffers_ref[item.idx];
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let (matches, bt) = clamav.scan_yara_only_with_breakdown(
                            &item.data, &item.obj_path, &[],
                        );
                        if let Ok(mut yg) = yara_dets.lock() {
                            for m in &matches {
                                yg.push((m.name.clone(), m.object_path.clone(), b.apk_lineage.clone()));
                            }
                        }
                        if let Ok(mut st) = scan_timing.lock() {
                            st.accumulate(bt);
                        }
                    }));
                }
            }
        });

        // Thread 3: ML inference
        s.spawn(|| {
            let mut ml_mal = false;
            let mut ml_prob = 0.0f32;
            let mut ml_lin = Vec::<(String, Vec<String>)>::new();
            let mut ml_time = 0u128;
            if let Some(model) = &engine_ref.model {
                for (i, b) in buffers_ref.iter().enumerate() {
                    let obj_path = match &b.entry_name {
                        Some(entry) => format!("{path_ref}!/{entry}"),
                        None => format!("{path_ref}!/unnamed_{i}"),
                    };
                    let t0 = std::time::Instant::now();
                    let (mal, conf, lineages) = match std::panic::catch_unwind(
                        std::panic::AssertUnwindSafe(|| run_ml_on_mmap(model, &b.data, &obj_path, b.fmt, &engine_features)),
                    ) {
                        Ok(r) => r,
                        Err(_) => {
                            let _ = err_shared.lock().map(|mut e| {
                                *e = Some(format!("ml: {}", last_panic()));
                            });
                            (false, 0.0, Vec::new())
                        }
                    };
                    ml_time += t0.elapsed().as_millis();
                    if mal { ml_mal = true; }
                    if conf > ml_prob { ml_prob = conf; }
                    ml_lin.extend(lineages);
                }
            }
            let _ = ml_out.lock().map(|mut o| { *o = (ml_mal, ml_prob, ml_lin, ml_time); });
        });

        // Thread 4: TLSH (parallel inside, single worker launches its own scope)
        s.spawn(|| {
            let t_tlsh = std::time::Instant::now();
            let n = buffers_ref.len();
            let num_workers = worker_count();
            let inner_results = std::sync::Mutex::new(Vec::new());
            let inner_ref = &inner_results;
            let chunk_size = (n + num_workers - 1) / num_workers;
            std::thread::scope(|s2| {
                for worker in 0..num_workers {
                    let start = worker * chunk_size;
                    let end = (start + chunk_size).min(n);
                    if start >= end { continue; }
                    s2.spawn(move || {
                        let mut local_dets = Vec::new();
                        for i in start..end {
                            let b = &buffers_ref[i];
                            if skip_by_size(&b.data) { continue; }
                            let db = if b.data.starts_with(b"\x7fELF") {
                                Some(&engine_ref.tlsh_db_elf)
                            } else if b.data.starts_with(b"dex\n") {
                                Some(&engine_ref.tlsh_db_dex)
                            } else if is_apk_zip(&b.data) {
                                Some(&engine_ref.tlsh_db_apk)
                            } else {
                                None
                            };
                                if let Some(db) = db {
                                if let Some(dist) = tlsh_nearest(db, &b.data) {
                                    let obj_path = if b.entry_name.is_none() {
                                        path_ref.to_string()
                                    } else {
                                        match &b.entry_name {
                                            Some(entry) => format!("{path_ref}!/{entry}"),
                                            None => format!("{path_ref}!/unnamed_{i}"),
                                        }
                                    };
                                    local_dets.push((format!("TLSH.Malware/dist={}", dist), obj_path, b.apk_lineage.clone()));
                                }
                            }
                        }
                        if !local_dets.is_empty() {
                            let _ = inner_ref.lock().map(|mut r| r.extend(local_dets));
                        }
                    });
                }
            });
            let tlsh_dets = inner_results.into_inner().unwrap_or_default();
            let _ = tlsh_out.lock().map(|mut o| *o = tlsh_dets);
            let _ = tlsh_ms_out.lock().map(|mut o| *o = t_tlsh.elapsed().as_millis());
        });
    });

    // ── Merge results ────────────────────────────────────────────
    let scan_timing = scan_timing.into_inner().unwrap_or_default();
    let mut yara_dets = yara_dets.into_inner().unwrap_or_default();
    let (ml_malicious, ml_probability, ml_lineages, ml_ms) = ml_out.into_inner().unwrap_or_default();
    let tlsh_dets = tlsh_out.into_inner().unwrap_or_default();
    let tlsh_ms = tlsh_ms_out.into_inner().unwrap_or_default();
    let _ = err_shared.into_inner().map(|e| { if let Some(e) = e { err = Some(e); } });

    let clamav_ms = (scan_timing.clamav_ns / 1_000_000) as u128;
    let mut yara_agg: std::collections::HashMap<String, u128> = std::collections::HashMap::new();
    for (name, ns) in &scan_timing.yara_per_engine {
        *yara_agg.entry(name.clone()).or_insert(0) += ns;
    }
    let yara_total_ms = (yara_agg.values().sum::<u128>() / 1_000_000) as u128;

    let hits_json = yara_dets
        .iter()
        .map(|(h, _, _)| format!("\"{}\"", json_escape(h)))
        .collect::<Vec<_>>()
        .join(",");

    let mut detections: Vec<(String, String, Vec<String>)> = bomb_dets;
    detections.append(&mut yara_dets);
    detections.extend(tlsh_dets);
    for (obj_path, lin) in ml_lineages {
        detections.push(("ML".to_string(), obj_path, lin));
    }

    // URL scanning (lightweight, run on main thread after scope)
    if let Some(scanner) = &engine.url_scanner {
        let mut url_limit = 0u32;
        if url_limit < 16 {
            for b in &buffers {
                for url_det in extract_decode_base64_urls(&b.data, scanner) {
                    detections.push((format!("{url_det} (in {path})"), path.to_string(), Vec::new()));
                    url_limit += 1; if url_limit >= 16 { break; }
                }
                if url_limit >= 16 { break; }
            }
        }
        if url_limit < 16 {
            for ds in dex_scans.iter().flatten() {
                for url_det in extract_and_scan_urls(engine, ds.text.as_bytes()) {
                    detections.push((format!("{url_det} (in {path})"), path.to_string(), Vec::new()));
                    url_limit += 1; if url_limit >= 16 { break; }
                }
                if url_limit >= 16 { break; }
            }
        }
        if url_limit < 16 {
            for em in emulated_strings.iter().flatten() {
                for url_det in extract_and_scan_urls(engine, em) {
                    detections.push((format!("{url_det} (in {path})"), path.to_string(), Vec::new()));
                    url_limit += 1; if url_limit >= 16 { break; }
                }
                if url_limit >= 16 { break; }
            }
        }
    }

    if riskware::is_testkey_detection_enabled() {
        if let Some(cert) = extract_certificate(&buffers) {
            if riskware::check_testkey(&cert.sha1, &cert.subject, &cert.issuer) {
                detections.push(("Andr.Riskware.TestKey".to_string(), path.to_string(), Vec::new()));
            }
        }
    }

    for (i, b) in buffers.iter().enumerate() {
        if let Some(ds) = &dex_scans[i] {
            for f in &ds.findings {
                if dex_scan::is_severe(f.severity) {
                    let obj_path = if b.entry_name.is_none() {
                        path.to_string()
                    } else {
                        match &b.entry_name {
                            Some(entry) => format!("{path}!/{entry}"),
                            None => format!("{path}!/unnamed_{i}"),
                        }
                    };
                    detections.push((format!("DEX/{:?}: {}", f.severity, f.message), obj_path, b.apk_lineage.clone()));
                }
            }
        }
    }

    // Per-YARA-ruleset breakdown string.
    let mut yara_breakdown = String::new();
    let mut yara_sorted: Vec<_> = yara_agg.into_iter().collect();
    yara_sorted.sort_by(|a, b| b.1.cmp(&a.1));
    for (name, ns) in &yara_sorted {
        let ms = ns / 1_000_000;
        if ms > 0 || *ns > 0 {
            if !yara_breakdown.is_empty() { yara_breakdown.push(' '); }
            let _ = std::write!(yara_breakdown, "{name}={ms}ms");
        }
    }

    // Per-stage breakdown for THIS file
    let stages = [
        ("extract", extract_ms),
        ("dex", dex_ms),
        ("emulate", emulate_ms),
        ("clamav", clamav_ms),
        ("yara", yara_total_ms),
        ("ml", ml_ms),
        ("tlsh", tlsh_ms),
    ];
    let slowest = stages.iter().max_by_key(|(_, ms)| *ms);
    let mut breakdown = stages
        .iter()
        .map(|(name, ms)| format!("{name}={ms}ms"))
        .collect::<Vec<_>>()
        .join(" ");
    if !yara_breakdown.is_empty() {
        breakdown.push_str(&format!(" {{{yara_breakdown}}}"));
    }
    if let Some((slowest_name, slowest_ms)) = slowest {
        rust_timing_log!(
            "{path} :: {breakdown} :: slowest={slowest_name}({slowest_ms}ms)"
        );
    }

    let malicious = !detections.is_empty();
    // When every detection in this scan resolves to the SAME nested archive
    // entry (object_path "outer!/entry"), scope the auto-generated rule to
    // that entry alone: its own MD5 as sample_md5, and only its DexScan's
    // strings — not the whole session's pooled strings. Keeps the generated
    // signature specific to the actual malicious sub-file, not the container.
    fn entry_suffix(object_path: &str) -> Option<&str> {
        object_path.split_once("!/").map(|(_, e)| e)
    }
    let scoped_entry_idx: Option<usize> = if detections.is_empty() {
        None
    } else {
        let first = entry_suffix(&detections[0].1);
        match first {
            Some(fe) if detections.iter().all(|(_, op, _)| entry_suffix(op) == Some(fe)) => {
                buffers.iter().position(|b| b.entry_name.as_deref() == Some(fe))
            }
            _ => None,
        }
    };
    let scoped_file_hash: String = match scoped_entry_idx {
        Some(idx) => md5_hex(&buffers[idx].data),
        None => file_hash.clone(),
    };
    // yarGen-style auto-generated rule — strings come from this sample's own
    // DEX string pool. References the androguard and hydradragon modules in
    // its condition, not just literal strings, so it also fires on
    // package-name/network reruns of the same family. Built for a malicious
    // verdict OR (Java's) Zero Trust Mode — Zero Trust never treats "nothing
    // matched" as "nothing worth cataloguing"; the rule is then based on the
    // sample's own strings/package rather than a named detection.
    let generated_rule = if malicious || zero_trust {
        generate_yara_rule(&scoped_file_hash, &packages, &detections, &dex_scans, scoped_entry_idx)
    } else {
        None
    };
    let generated_rule_json = match &generated_rule {
        Some(r) => format!("\"{}\"", json_escape(r)),
        None => "null".to_string(),
    };
    let detections_json = detections
        .iter()
        .map(|(name, object_path, lineage)| {
            let hs = lineage
                .iter()
                .map(|h| format!("\"{}\"", h))
                .collect::<Vec<_>>()
                .join(",");
            format!("{{\"name\":\"{}\",\"object_path\":\"{}\",\"hashes\":[{}]}}", json_escape(name), json_escape(object_path), hs)
        })
        .collect::<Vec<_>>()
        .join(",");
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

    // Per-buffer MD5 + TLSH maps for the Anti-FP cache: maps each buffer's
    // entry name (relative path within the APK) to its MD5 and TLSH so Java
    // can suppress detections whose entry content matches a known-good
    // whitelisted APK's entry. Only MD5 is used for exact match; TLSH is
    // used for similarity matching.
    let mut entry_md5_pairs: Vec<String> = Vec::new();
    let mut entry_tlsh_pairs: Vec<String> = Vec::new();
    for b in buffers.iter() {
        if b.entry_name.is_none() { continue; }
        let Some(ref entry) = b.entry_name else { continue };
        if entry.is_empty() { continue; }
        let md5 = md5_hex(&b.data);
        entry_md5_pairs.push(format!(
            r#""{}":"{}""#,
            json_escape(entry),
            md5,
        ));
        let tlsh = tlsh_rs::hash_bytes(&b.data)
            .ok()
            .map(|d| d.to_string())
            .unwrap_or_default();
        if !tlsh.is_empty() {
            entry_tlsh_pairs.push(format!(
                r#""{}":"{}""#,
                json_escape(entry),
                tlsh,
            ));
        }
        if entry_md5_pairs.len() >= 1024 { break; }
    }
    let entry_md5s_json = if entry_md5_pairs.is_empty() {
        "{}".to_string()
    } else {
        format!("{{{}}}", entry_md5_pairs.join(","))
    };
    let entry_tlshs_json = if entry_tlsh_pairs.is_empty() {
        "{}".to_string()
    } else {
        format!("{{{}}}", entry_tlsh_pairs.join(","))
    };

    // TLSH of the whole top-level file reflects `file_tlsh` computed early
    // (before collect_buffers consumed mmap).
    let file_tlsh_json = format!("\"{}\"", json_escape(&file_tlsh));

    let err_json = match err {
        Some(e) => format!(",\"error\":\"{}\"", json_escape(&e)),
        None => String::new(),
    };

    let result = if malicious || zero_trust {
        // Full JSON: detections, generated rule, per-entry hashes (needed by
        // Java's Anti-FP cache and yarGen rule display).
        format!(
            r#"{{"cached":false,"malicious":{},"matches":[{}],"detections":[{}],"permissions":{},"packages":[{}],"hashes":[{}],"md5":"{}","file_tlsh":{},"ml":{{"malicious":{},"probability":{:.4}}},"generated_rule":{},"entry_md5s":{},"entry_tlshs":{}{}}}"#,
            malicious, hits_json, detections_json, perm_count, packages_json, hashes_json, file_hash, file_tlsh_json, ml_malicious, ml_probability, generated_rule_json, entry_md5s_json, entry_tlshs_json, err_json
        )
    } else {
        // Clean result: minimal JSON — Java only needs essential fields for
        // the clean path. No detections, no generated rule, no entry hashes.
        // This cuts JSON size from ~100KB+ to ~500B for clean scans.
        format!(
            r#"{{"cached":false,"malicious":false,"permissions":{},"packages":[{}],"hashes":[{}],"md5":"{}","file_tlsh":{},"ml":{{"malicious":false,"probability":0.0}}{}}}"#,
            perm_count, packages_json, hashes_json, file_hash, file_tlsh_json, err_json
        )
    };

    // Cache clean results so repeated scans return instantly.
    if !malicious && !whitelisted {
        cache_scan_result(&file_hash, &result);
    }

    result
}

/// Build a yarGen-style YARA rule from THIS scan's own results. Called when
/// the scan is malicious OR Zero Trust
/// Mode is on (so an unmatched/"unknown" sample is catalogued too, not just a
/// confirmed-bad one) — `detections` may be empty in the Zero Trust case, in
/// which case the rule is based on the sample's own strings/package instead
/// of a named detection. `import`s the androguard and hydradragon modules and
/// references them in the condition (package name / network) rather than
/// relying on literal strings alone.
fn generate_yara_rule(
    file_hash: &str,
    packages: &[String],
    detections: &[(String, String, Vec<String>)],
    dex_scans: &[Option<dex_scan::DexScan>],
    only_index: Option<usize>,
) -> Option<String> {
    let mut strings: Vec<String> = Vec::new();
    let mut has_launcher_hijack = false;
    let mut has_severe_findings = false;
    let mut suspicious_api_patterns: Vec<&str> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let scanned: Vec<&dex_scan::DexScan> = dex_scans.iter().enumerate().filter_map(|(i, o)| {
        if let Some(idx) = only_index {
            if i != idx { return None; }
        }
        o.as_ref()
    }).collect();
    for ds in &scanned {
        // Severe static-analysis findings
        for f in &ds.findings {
            if dex_scan::is_severe(f.severity) {
                has_severe_findings = true;
            }
        }
        // Launcher-hijacking API call detection
        if !has_launcher_hijack {
            has_launcher_hijack = ds.api_calls.iter().any(|call| {
                let launcher_patterns = [
                    "clearPackagePreferredActivities",
                    "addPreferredActivity",
                    "createRequestRoleIntent",
                ];
                launcher_patterns.iter().any(|p| call.contains(p))
            });
        }
        // Suspicious API call patterns (loader/dropper, SMS fraud, spyware)
        if suspicious_api_patterns.is_empty() {
            let patterns = [
                "Landroid/telephony/SmsManager;->sendTextMessage",
                "Landroid/telephony/TelephonyManager;->getDeviceId",
                "Landroid/app/admin/DevicePolicyManager;->lockNow",
                "dalvik/system/DexClassLoader",
                "Ljava/lang/Runtime;->exec",
                "Landroid/content/Intent;->setFlags",
            ];
            if ds.api_calls.iter().any(|call| patterns.iter().any(|p| call.contains(p))) {
                suspicious_api_patterns.extend(patterns);
            }
        }
        // Extract strings for YARA pattern matching
        for line in ds.text.lines() {
            if strings.len() >= 40 { break; }
            let l = line.trim();
            if l.len() < 8 || l.len() > 128 || l.chars().any(|c| c.is_control()) {
                continue;
            }
            if !seen.insert(l.to_string()) {
                continue;
            }
            strings.push(l.to_string());
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
    out.push_str("    generator = \"hydradragon-autogen (yarGen-style)\"\n");
    out.push_str(&format!("    sample_md5 = \"{}\"\n", file_hash));
    let det_names: Vec<String> = detections.iter().map(|(n, _, _)| n.replace('"', "'")).collect();
    let based_on = if det_names.is_empty() {
        "none (Zero Trust: unmatched/unknown sample, not a confirmed detection)".to_string()
    } else {
        det_names.join(", ")
    };
    out.push_str(&format!("    based_on_detections = \"{}\"\n", based_on));
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
    let mut groups: Vec<String> = Vec::new();
    // Package names: OR'd inside one group (an app has one package name)
    if !packages.is_empty() {
        let pkg_or: Vec<String> = packages.iter().map(|p| {
            format!("androguard.package_name(\"{}\")", p.replace('"', "'"))
        }).collect();
        if pkg_or.len() == 1 {
            groups.push(pkg_or.into_iter().next().unwrap());
        } else {
            groups.push(format!("({})", pkg_or.join(" or ")));
        }
    }
    if !strings.is_empty() {
        let threshold = strings.len().min(6).max(1);
        groups.push(format!("{} of them", threshold));
    }
    groups.push("androguard.rootkit_behavior() == 1".to_string());
    if has_launcher_hijack {
        groups.push(r#"hydradragon.api_call(/clearPackagePreferredActivities|addPreferredActivity|createRequestRoleIntent/) > 0"#.to_string());
    }
    if has_severe_findings {
        groups.push("hydradragon.dex_severe_finding_count() > 0".to_string());
    }
    if !suspicious_api_patterns.is_empty() {
        let re = suspicious_api_patterns.join("|");
        groups.push(format!("hydradragon.api_call(/{re}/) > 0"));
    }
    // Static condition: package + strings + rootkit + dex findings
    let static_cond = if groups.is_empty() {
        "false".to_string()
    } else {
        groups.join(" and\n        ")
    };
    // HIPS runtime behavioral conditions (fire at runtime, not at scan time)
    let mut hips_groups: Vec<String> = Vec::new();
    if !packages.is_empty() {
        let pkg_re: String = packages.iter().map(|p| {
            p.replace('\\', "\\\\").replace('/', "\\/").replace('.', "\\.")
        }).collect::<Vec<_>>().join("|");
        let pkg_re = format!("/({})/", pkg_re);
        for hips_cond in [
            format!("hydradragon.ui_spam{pkg_re} > 0"),
            format!("hydradragon.notification_spam{pkg_re} > 0"),
            format!("hydradragon.clickjack{pkg_re} > 0"),
            format!("hydradragon.ransomware{pkg_re} > 0"),
            format!("hydradragon.strandhogg{pkg_re} > 0"),
            format!("hydradragon.removal_resistance{pkg_re} > 0"),
            format!("hydradragon.launcher_change{pkg_re} > 0"),
            format!("hydradragon.network_connections{pkg_re} > 0"),
        ] {
            hips_groups.push(hips_cond);
        }
    }
    if !hips_groups.is_empty() {
        let hips_cond = hips_groups.join(" or\n        ");
        let pkg_prefix = if packages.len() == 1 {
            format!("androguard.package_name(\"{}\")", packages[0].replace('"', "'"))
        } else {
            let pkg_ors: Vec<String> = packages.iter().map(|p| {
                format!("androguard.package_name(\"{}\")", p.replace('"', "'"))
            }).collect();
            format!("({})", pkg_ors.join(" or "))
        };
        out.push_str(&format!(
            "    ({})\n    or\n    ({} and (\n        {}\n    ))\n",
            static_cond, pkg_prefix, hips_cond
        ));
    } else {
        out.push_str(&format!("    {}\n", static_cond));
    }
    out.push_str("}\n");
    Some(out)
}

/// The most dangerous Android permissions (mirrors the Java `DANGEROUS_PERMISSIONS`
/// list). Used to give APKs reached only in-memory — e.g. an APK extracted from a
/// zip and never written to disk, so `PackageManager` can't read it — the same
/// permission-based detection, straight from the bytes (no temp file).
/// The full Android "dangerous" protection-level permission set (all runtime-
/// prompted groups: SMS, call log/phone, contacts, location, microphone,
/// camera, calendar, sensors/activity recognition, nearby devices, storage),
/// plus SYSTEM_ALERT_WINDOW/MANAGE_EXTERNAL_STORAGE which aren't technically
/// "dangerous" protection level but are heavily malware-abused (overlay
/// attacks, ransomware file access) so they're included too. Previously this
/// list only had 9 entries hand-picked around SMS/overlay malware — a sample
/// requesting a different mix of 6-7 dangerous permissions (e.g. phone state +
/// call + contacts + accounts + coarse location + bluetooth) matched NONE of
/// them and was never flagged, even though it was clearly over-permissioned.
const DANGEROUS_PERMS: &[&str] = &[
    // SMS / MMS
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_WAP_PUSH",
    // Call log / phone
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    // Contacts / accounts
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    // Location
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    // Microphone / camera
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    // Calendar
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    // Sensors / activity
    "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND",
    "android.permission.ACTIVITY_RECOGNITION",
    // Nearby devices
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.UWB_RANGING",
    // Storage (legacy + scoped bypass)
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    // Not "dangerous" protection level, but classic malware tools:
    "android.permission.SYSTEM_ALERT_WINDOW",
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
        if skip_by_size(buf) || buf.len() > MAX_MANIFEST_SCAN {
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

// ── hydradragon report merger ───────────────────────────────────────────────
// Folds this scan's DEX static-analysis findings (any severity) into Java's
// live-network/HIPS JSON, under a `dex_findings` array, so `.yar` rules can
// query them via `hydradragon.dex_finding(regex)` /
// `hydradragon.dex_severe_finding_count()`.
// Also merges every unique API call from all DEX buffers into an `api_calls`
// array, queryable via `hydradragon.api_call(regex)`.

/// Returns `None` when there's neither a Java report nor any DEX data.
fn merge_dex_findings(
    hydradragon: Option<&[u8]>,
    dex_scans: &[Option<dex_scan::DexScan>],
) -> Option<Vec<u8>> {
    let findings: Vec<serde_json::Value> = dex_scans
        .iter()
        .flatten()
        .flat_map(|ds| &ds.findings)
        .map(|f| {
            serde_json::json!({
                "severity": format!("{:?}", f.severity),
                "kind": f.kind.clone(),
                "class_descriptor": f.class_descriptor.clone(),
                "message": f.message.clone(),
            })
        })
        .collect();

    // Aggregate invocation counts per API signature across all DEX buffers.
    let mut api_agg: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for ds in dex_scans.iter().flatten() {
        for entry in &ds.api_calls {
            // Each entry is "sig\tcount"
            if let Some(tab) = entry.rfind('\t') {
                let sig = &entry[..tab];
                let cnt: u32 = entry[tab + 1..].parse().unwrap_or(1);
                if api_agg.len() >= 4096 { break; }
                *api_agg.entry(sig.to_string()).or_insert(0) += cnt;
            }
        }
    }
    let mut api_keys: Vec<String> = api_agg.into_iter().map(|(k, v)| format!("{k}\t{v}")).collect();
    api_keys.sort();
    let api_json: Vec<serde_json::Value> = api_keys
        .into_iter()
        .map(serde_json::Value::String)
        .collect();

    let mut root: serde_json::Value = hydradragon
        .and_then(|h| serde_json::from_slice(h).ok())
        .filter(serde_json::Value::is_object)
        .unwrap_or_else(|| serde_json::json!({}));
    if !findings.is_empty() {
        root["dex_findings"] = serde_json::Value::Array(findings);
    }
    if !api_json.is_empty() {
        root["api_calls"] = serde_json::Value::Array(api_json);
    }

    if root.as_object().map(|m| m.is_empty()).unwrap_or(true) {
        None
    } else {
        serde_json::to_vec(&root).ok()
    }
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
    /// The activity with an enabled MAIN/LAUNCHER intent-filter, if any —
    /// `None` means the app declares no way to be opened from the home
    /// screen/app drawer (feeds `androguard.rootkit_behavior()` in yara-x).
    main_activity: Option<String>,
    min_sdk: Option<i64>,
    max_sdk: Option<i64>,
    target_sdk: Option<i64>,
    /// `<meta-data>` entries: (name, value) pairs from the manifest.
    meta_data: Vec<(String, String)>,
}

/// Read a boolean-typed AXML attribute (TYPE_INT_BOOLEAN: data u32 at a+16,
/// 0 = false, nonzero = true).
fn axml_attr_bool(data: &[u8], a: usize) -> Option<bool> {
    Some(rd_u32(data, a + 16)? != 0)
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
        main_activity: None,
        min_sdk: None,
        max_sdk: None,
        target_sdk: None,
        meta_data: Vec::new(),
    };

    // Small nesting-aware state for locating a MAIN/LAUNCHER activity: which
    // activity element we're currently inside (and whether it's explicitly
    // disabled — `android:enabled="false"` while keeping the intent-filter
    // in the manifest is a known icon-hiding trick), and whether the
    // intent-filter we're currently inside has seen MAIN and LAUNCHER.
    let mut activity_stack: Vec<(String, bool)> = Vec::new(); // (name, enabled)
    let mut in_intent_filter = false;
    let mut has_action_main = false;
    let mut has_category_launcher = false;

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
                "activity" | "activity-alias" => {
                    push_component(data, &strings, off, &mut m.activities);
                    let name = axml_find_attr(data, &strings, off, "name")
                        .and_then(|a| axml_attr_string(data, &strings, a))
                        .unwrap_or_default();
                    // Defaults to enabled unless explicitly set to false.
                    let enabled = axml_find_attr(data, &strings, off, "enabled")
                        .and_then(|a| axml_attr_bool(data, a))
                        .unwrap_or(true);
                    if activity_stack.len() < 64 {
                        activity_stack.push((name, enabled));
                    }
                }
                "service" => push_component(data, &strings, off, &mut m.services),
                "receiver" => push_component(data, &strings, off, &mut m.receivers),
                "meta-data" => {
                    let name = axml_find_attr(data, &strings, off, "name")
                        .and_then(|a| axml_attr_string(data, &strings, a));
                    let value = axml_find_attr(data, &strings, off, "value")
                        .and_then(|a| axml_attr_string(data, &strings, a));
                    if let (Some(n), Some(v)) = (name, value) {
                        if m.meta_data.len() < 256 {
                            m.meta_data.push((n, v));
                        }
                    }
                }
                "intent-filter" => {
                    in_intent_filter = true;
                    has_action_main = false;
                    has_category_launcher = false;
                }
                "action" if in_intent_filter => {
                    if let Some(a) = axml_find_attr(data, &strings, off, "name") {
                        if axml_attr_string(data, &strings, a).as_deref()
                            == Some("android.intent.action.MAIN")
                        {
                            has_action_main = true;
                        }
                    }
                }
                "category" if in_intent_filter => {
                    if let Some(a) = axml_find_attr(data, &strings, off, "name") {
                        if axml_attr_string(data, &strings, a).as_deref()
                            == Some("android.intent.category.LAUNCHER")
                        {
                            has_category_launcher = true;
                        }
                    }
                }
                _ => {}
            }
        } else if ctype == 0x0103 {
            // RES_XML_END_ELEMENT: element name at the same off+20 offset.
            let name_idx = rd_u32(data, off + 20)? as usize;
            let ename = strings.get(name_idx).map(|s| s.as_str()).unwrap_or("");
            match ename {
                "intent-filter" => {
                    if m.main_activity.is_none()
                        && has_action_main
                        && has_category_launcher
                    {
                        if let Some((name, enabled)) = activity_stack.last() {
                            if *enabled && !name.is_empty() {
                                m.main_activity = Some(name.clone());
                            }
                        }
                    }
                    in_intent_filter = false;
                }
                "activity" | "activity-alias" => {
                    activity_stack.pop();
                }
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

/// Build the androguard JSON report for the scanned APK, or None if no binary
/// AndroidManifest.xml is reachable in the buffers (not an APK).
fn build_androguard_json(buffers: &[Buf], urls: &[String]) -> Option<String> {
    let manifest = buffers.iter().find_map(|b| parse_manifest(&b.data))?;
    let cert = extract_certificate(buffers);

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
    let opt_sdk = |o: Option<i64>| -> String {
        match o {
            Some(v) => format!("\"{}\"", v),
            None => "null".to_string(),
        }
    };

    let meta_data_json = manifest.meta_data.iter()
        .map(|(n, v)| format!("{{\"name\":\"{}\",\"value\":\"{}\"}}",
            json_escape(n), json_escape(v)))
        .collect::<Vec<_>>()
        .join(",");

    Some(format!(
        concat!(
            "{{\"package_name\":{},\"app_name\":{},\"main_activity\":{},",
            "\"activities\":[{}],\"services\":[{}],\"receivers\":[{}],",
            "\"permissions\":[{}],\"new_permissions\":[{}],\"urls\":[{}],",
            "\"min_sdk_version\":{},\"max_sdk_version\":{},\"target_sdk_version\":{},",
            "\"certificate\":{{\"subjectDN\":{},\"IssuerDN\":{},\"sha1\":{}}},",
            "\"meta_data\":[{}]}}"
        ),
        opt_str(&manifest.package),
        opt_str(&manifest.app_name),
        opt_str(&manifest.main_activity),
        arr(&manifest.activities),
        arr(&manifest.services),
        arr(&manifest.receivers),
        arr(&manifest.permissions),
        arr(&manifest.permissions),
        arr(&urls),
        opt_sdk(manifest.min_sdk),
        opt_sdk(manifest.max_sdk),
        opt_sdk(manifest.target_sdk),
        opt_str(&cert.as_ref().map(|c| c.subject.clone())),
        opt_str(&cert.as_ref().map(|c| c.issuer.clone())),
        opt_str(&cert.as_ref().map(|c| c.sha1.clone())),
        meta_data_json,
    ))
}

struct CertInfo {
    subject: String,
    issuer: String,
    sha1: String,
}

fn extract_certificate(buffers: &[Buf]) -> Option<CertInfo> {
    // Find the signing-block entry (META-INF/*.RSA / .DSA / .EC).
    let sig_data = buffers.iter().find_map(|b| {
        let name = b.entry_name.as_deref()?;
        let upper = name.to_uppercase();
        if upper.starts_with("META-INF/")
            && (upper.ends_with(".RSA") || upper.ends_with(".DSA") || upper.ends_with(".EC"))
        {
            Some(&b.data[..])
        } else {
            None
        }
    })?;

    // Navigate PKCS7 ContentInfo → SignedData → first X.509 certificate.
    // DER structure:
    //   SEQUENCE (ContentInfo)
    //     OID (1.2.840.113549.1.7.2 = signedData)
    //     [0] EXPLICIT → SEQUENCE (SignedData)
    //       INTEGER (version, skip)
    //       SET (digestAlgorithms, skip)
    //       SEQUENCE (encapContentInfo, skip)
    //       [0] IMPLICIT → SET OF Certificate (take first)
    let mut off = 0;
    der_expect_tag(sig_data, &mut off, 0x30)?; // ContentInfo SEQUENCE
    let ci_len = der_len(sig_data, &mut off)?;
    let ci_end = off + ci_len;

    der_skip(sig_data, &mut off)?; // OID (must be 1.2.840.113549.1.7.2)
    if off > ci_end { return None; }
    der_expect_tag(sig_data, &mut off, 0xa0)?; // [0] EXPLICIT
    let explicit_len = der_len(sig_data, &mut off)?;
    let explicit_end = off + explicit_len;

    der_expect_tag(sig_data, &mut off, 0x30)?; // SignedData SEQUENCE
    let sd_len = der_len(sig_data, &mut off)?;
    let sd_end = off + sd_len;
    if sd_end > explicit_end { return None; }

    der_skip(sig_data, &mut off)?; // version INTEGER
    // digestAlgorithms — could be SET or SET OF, but we just skip it.
    // Count elements until we see [0] context tag (0xa0) or run out.
    while off < sd_end && sig_data.get(off).copied() != Some(0xa0) {
        der_skip(sig_data, &mut off)?;
    }
    if off >= sd_end {
        return None;
    }
    // [0] IMPLICIT → SET OF Certificate
    der_expect_tag(sig_data, &mut off, 0xa0)?;
    let cert_set_len = der_len(sig_data, &mut off)?;
    let cert_set_end = off + cert_set_len;

    // First certificate — capture full DER bytes before parsing.
    if off >= cert_set_end {
        return None;
    }
    let cert_start = off; // at the SEQUENCE tag byte
    der_expect_tag(sig_data, &mut off, 0x30)?; // Certificate SEQUENCE
    let cert_len = der_len(sig_data, &mut off)?; // advances past length
    let cert_end = off.checked_add(cert_len)?;
    let cert_der = sig_data.get(cert_start..cert_end)?; // tag + len + content

    let sha1 = sha1_hex(cert_der);

    // Parse TBSCertificate inside the certificate.
    der_expect_tag(sig_data, &mut off, 0x30)?; // TBSCertificate SEQUENCE
    let tbs_len = der_len(sig_data, &mut off)?;
    let tbs_end = off + tbs_len;

    // Skip version [0] EXPLICIT INTEGER (optional, context tag 0xa0)
    if off < tbs_end && sig_data.get(off).copied() == Some(0xa0) {
        der_skip(sig_data, &mut off)?;
    }
    der_skip(sig_data, &mut off)?; // serialNumber INTEGER
    der_skip(sig_data, &mut off)?; // signature SEQUENCE (AlgorithmIdentifier)

    let issuer = parse_dn(sig_data, &mut off)?; // issuer

    der_skip(sig_data, &mut off)?; // validity SEQUENCE (notBefore, notAfter)

    let subject = parse_dn(sig_data, &mut off)?; // subject

    Some(CertInfo { subject, issuer, sha1 })
}

// ── DER helpers ────────────────────────────────────────────────────────────

fn der_len(data: &[u8], off: &mut usize) -> Option<usize> {
    let b = *data.get(*off)?;
    *off += 1;
    if b & 0x80 == 0 {
        Some(b as usize)
    } else {
        let n = (b & 0x7f) as usize;
        if n > 4 || *off + n > data.len() {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | data[*off] as usize;
            *off += 1;
        }
        Some(len)
    }
}

fn der_expect_tag(data: &[u8], off: &mut usize, tag: u8) -> Option<()> {
    let b = *data.get(*off)?;
    if b != tag {
        return None;
    }
    *off += 1;
    Some(())
}

fn der_skip(data: &[u8], off: &mut usize) -> Option<()> {
    let _tag = *data.get(*off)?;
    *off += 1;
    let len = der_len(data, off)?;
    *off = off.checked_add(len)?;
    Some(())
}

// ── X.509 DN parser ────────────────────────────────────────────────────────

/// Parse a DistinguishedName (SEQUENCE OF SET OF SEQUENCE { OID, value })
/// into OpenSSL-style "/key=value/..." format.
fn parse_dn(data: &[u8], off: &mut usize) -> Option<String> {
    der_expect_tag(data, off, 0x30)?; // SEQUENCE
    let dn_len = der_len(data, off)?;
    let dn_end = off.checked_add(dn_len)?;

    let mut parts: Vec<String> = Vec::new();
    while *off < dn_end {
        der_expect_tag(data, off, 0x31)?; // SET
        let set_len = der_len(data, off)?;
        let set_end = off.checked_add(set_len)?;

        der_expect_tag(data, off, 0x30)?; // SEQUENCE
        let seq_len = der_len(data, off)?;
        let seq_end = off.checked_add(seq_len)?;
        let _seq_start = *off;

        // OID
        if *off >= seq_end || *data.get(*off)? != 0x06 {
            return None;
        }
        *off += 1;
        let oid_len = der_len(data, off)?;
        let oid_raw = data.get(*off..*off + oid_len)?;
        *off = off.checked_add(oid_len)?;
        let oid_str = oid_to_str(oid_raw);

        // Value (any string type: PrintableString, UTF8String, IA5String, TeletexString)
        if *off >= seq_end {
            return None;
        }
        let _val_tag = *data.get(*off)?;
        *off += 1;
        let val_len = der_len(data, off)?;
        let val_raw = data.get(*off..*off + val_len)?;
        *off = off.checked_add(val_len)?;
        let val_str = String::from_utf8_lossy(val_raw).into_owned();

        parts.push(format!("/{oid_str}={val_str}"));

        *off = set_end;
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.concat())
    }
}

fn oid_to_str(oid: &[u8]) -> &'static str {
    // Common X.509 DN OIDs (dotted-decimal form in the DER bytes).
    match oid {
        // 2.5.4.x
        [85, 4, 3] => "CN",
        [85, 4, 4] => "SN",
        [85, 4, 5] => "serialNumber",
        [85, 4, 6] => "C",
        [85, 4, 7] => "L",
        [85, 4, 8] => "ST",
        [85, 4, 9] => "STREET",
        [85, 4, 10] => "O",
        [85, 4, 11] => "OU",
        [85, 4, 12] => "T",
        [85, 4, 17] => "postalCode",
        [85, 4, 41] => "name",
        [85, 4, 42] => "GN",
        [85, 4, 43] => "initials",
        [85, 4, 44] => "generationQualifier",
        [85, 4, 46] => "DNQ",
        [85, 4, 65] => "pseudonym",
        // 0.9.2342.19200300.100.1.1 → UID
        [9, 130, 0x4a, 132, 0x14, 131, 0x1a, 100, 1, 1] => "UID",
        // 0.9.2342.19200300.100.1.25 → DC (domainComponent)
        [9, 130, 0x4a, 132, 0x14, 131, 0x1a, 100, 1, 25] => "DC",
        // 1.2.840.113549.1.9.1 → emailAddress
        [42, 134, 72, 134, 0xf7, 13, 1, 9, 1] => "emailAddress",
        // 1.3.6.1.4.1.311.60.2.1.3 → jurisdictionC
        [43, 6, 1, 4, 1, 0x93, 60, 2, 1, 3] => "jurisdictionC",
        // 1.3.6.1.4.1.311.60.2.1.2 → jurisdictionST
        [43, 6, 1, 4, 1, 0x93, 60, 2, 1, 2] => "jurisdictionST",
        // 1.3.6.1.4.1.311.60.2.1.1 → jurisdictionL
        [43, 6, 1, 4, 1, 0x93, 60, 2, 1, 1] => "jurisdictionL",
        // 2.5.4.97 → organizationIdentifier
        [85, 4, 97] => "organizationIdentifier",
        _ => "UNKNOWN",
    }
}

// ── SHA-1 (RFC 3174) ──────────────────────────────────────────────────────

fn sha1_hex(data: &[u8]) -> String {
    use std::fmt::Write;
    let digest = sha1_hash(data);
    let mut s = String::with_capacity(40);
    for b in digest {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

fn sha1_hash(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

    let ml = data.len() as u64 * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&ml.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for t in 0..16 {
            w[t] = u32::from_be_bytes([
                chunk[t * 4],
                chunk[t * 4 + 1],
                chunk[t * 4 + 2],
                chunk[t * 4 + 3],
            ]);
        }
        for t in 16..80 {
            w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];

        for t in 0..80 {
            let (f, k): (u32, u32) = match t {
                0..=19 => ((b & c) | (!b & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[t]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&v.to_be_bytes());
    }
    out
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
        if skip_by_size(&b.data) { continue; }
        // Use pre-computed fmt — no second detect_format call
        if b.fmt != Some("zip") {
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
        if skip_by_size(&b.data) { continue; }
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
    data: OwnedBuf,
    apk_lineage: Vec<String>,
    /// In-archive path of this buffer relative to its immediate parent
    /// archive (e.g. `lib/arm64-v8a/libfoo.so`), or `None` for the top-level
    /// scanned file (which already has its own real path/name).
    entry_name: Option<String>,
    /// Pre-computed `hydradragonextractor::detect_format` result for this buffer.
    /// Stored here so downstream phases (ML, hash collection, etc.) never
    /// call `detect_format` a second time on the same bytes.
    fmt: Option<&'static str>,
}

/// Phase 1 of the scan pipeline: extract ALL buffers from the file, running
/// ClamAV/YARA inline as each buffer is decompressed (streaming extract+scan).
/// `top_md5` is Java's already-computed MD5 of the whole scanned file, reused
/// for the top-level (depth 0) buffer so the largest buffer isn't hashed twice.
///
/// Zip-bomb guard: stops extraction when total decompressed bytes exceed ~2 GB
/// or when the number of extracted buffers exceeds 4096. Any bomb errors are
/// returned as detections in the second tuple element so they are never lost.
///
/// Returns (buffers, bomb_dets, streaming_dets, streaming_timing).
/// - `buffers`: every extracted buffer (used by Phase 2 and YARA-only rescan).
/// - `bomb_dets`: zip-bomb detection errors.
/// - `streaming_dets`: detections from EICAR checks during extraction.
/// - `streaming_timing`: timing breakdown (currently always empty — ClamAV
///   scanning moved to Phase 3 parallel scope).
fn collect_buffers(
    data: Vec<u8>,
    top_md5: Option<&str>,
    path: &str,
) -> (
    Vec<Buf>,
    Vec<(String, String, Vec<String>)>,
    Vec<(String, String, Vec<String>)>,
    hydradragonclamav::scanner::TimingBreakdown,
) {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering as AtomOrdering};
    use std::sync::Mutex;

    /// One unit of pending work: a buffer that still needs extracting+scanning.
    struct WorkItem {
        buf: OwnedBuf,
        depth: usize,
        lineage: Vec<String>,
        entry_name: Option<String>,
    }

    let stack: Mutex<Vec<WorkItem>> = Mutex::new(vec![WorkItem {
        buf: OwnedBuf::Vec(data),
        depth: 0,
        lineage: Vec::new(),
        entry_name: None,
    }]);
    // Termination detection for the shared work stack: counts items that are
    // either sitting in `stack` or actively being processed by some worker.
    // Starts at 1 for the seed item. A worker increments it BEFORE pushing a
    // popped item's children (so nobody can observe 0 while children are
    // about to appear) and decrements it AFTER it's fully done with an item
    // (extracted + scanned + pushed to `out`). Reaching 0 means the stack is
    // empty AND no worker can produce more work — safe to stop.
    let outstanding = AtomicUsize::new(1);
    let out: Mutex<Vec<Buf>> = Mutex::new(Vec::new());
    let bomb_dets: Mutex<Vec<(String, String, Vec<String>)>> = Mutex::new(Vec::new());
    let total_bytes = AtomicU64::new(0);
    // Count of buffers actually emitted to `out` — used for both the 4096 cap
    // and as each buffer's naming index, without
    // needing to lock `out` just to read its length.
    let emitted = AtomicUsize::new(0);
    // Set once the buffer/byte cap is hit; every worker checks it and winds
    // down rather than pulling more work, even if `outstanding` is nonzero.
    let capped = std::sync::atomic::AtomicBool::new(false);
    // Streaming ClamAV+YARA detections and timing, accumulated per-buffer as
    // extraction proceeds. These are merged into the final result in Phase 3;
    // module_meta is empty during streaming, so module-dependent YARA rules
    // do not match here — they require androguard/hydradragon metadata from
    // Phase 2.
    let streaming_dets: Mutex<Vec<(String, String, Vec<String>)>> = Mutex::new(Vec::new());
    let streaming_timing: Mutex<hydradragonclamav::scanner::TimingBreakdown> = Mutex::new(Default::default());

    // Small, capped pool — collect_buffers already runs inside run_scan's
    // SCAN_SERIAL lock (one file at a time), so it's safe to actually spend
    // the device's cores here without a second file's pool competing for them.
    let workers = worker_count();

    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                // catch_unwind so a single bad buffer can never inflate
                // `outstanding` without ever decrementing it, which would
                // cause every other worker to loop forever (empty stack +
                // outstanding > 0 → yield → repeat) and permanently hang
                // the entire scan.
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    loop {
                        if capped.load(AtomOrdering::Relaxed) {
                            break;
                        }
                        let item = {
                            let mut g = stack.lock().unwrap_or_else(|e| e.into_inner());
                            g.pop()
                        };
                        let item = match item {
                            Some(it) => it,
                            None => {
                                if outstanding.load(AtomOrdering::Acquire) == 0 {
                                    break;
                                }
                                std::thread::yield_now();
                                continue;
                            }
                        };

                        if item.buf.len() <= 12 {
                            outstanding.fetch_sub(1, AtomOrdering::AcqRel);
                            continue;
                        }

                        let idx = emitted.fetch_add(1, AtomOrdering::Relaxed);
                        let prior_total = total_bytes.fetch_add(item.buf.len() as u64, AtomOrdering::Relaxed);
                        if idx >= 4096 || prior_total >= 2_000_000_000 {
                            capped.store(true, AtomOrdering::Relaxed);
                            outstanding.fetch_sub(1, AtomOrdering::AcqRel);
                            break;
                        }

                        let mut lineage = item.lineage;
                        let fmt = hydradragonextractor::detect_format(&item.buf);
                        if item.depth == 0 && SCAN_RELEVANT_ONLY.load(Ordering::Relaxed) && fmt != Some("zip") {
                            // A standalone (loose) EICAR test file is 68 bytes
                            // of text — normally skipped here because it isn't an
                            // APK/zip. Emit it directly as an EICAR detection so
                            // it's still caught, without paying the full
                            // ClamAV/YARA pass. The EICAR category toggle is
                            // applied on the Java side. Everything else standalone
                            // (media, images, unknown binaries, larger text) is
                            // skipped as before.
                            if is_eicar(&item.buf) {
                                if let Ok(mut sd) = streaming_dets.lock() {
                                    sd.push(("Test.EICAR".to_string(), path.to_string(), lineage.clone()));
                                }
                            }
                            outstanding.fetch_sub(1, AtomOrdering::AcqRel);
                            continue;
                        }
                        if fmt == Some("zip") {
                            let h = match top_md5 {
                                Some(md5) if item.depth == 0 => md5.to_string(),
                                _ => md5_hex(&item.buf),
                            };
                            lineage.push(h);
                        }

                        if item.depth < 16 && fmt.is_some() {
                            // Non-zip archives (tar, gz, xz, 7z, rar, cab, iso,
                            // etc.) larger than the user's MAX_ARCHIVE_SIZE_MB
                            // ceiling are not extracted — their contents are
                            // skipped. APKs and plain .zip (fmt == "zip") are
                            // exempt; they stay under MAX_SCAN_SIZE_MB instead.
                            let archive_too_big = fmt != Some("zip") && {
                                let cap = MAX_ARCHIVE_SIZE_MB.load(Ordering::Relaxed) as usize;
                                item.buf.len() > cap.saturating_mul(1024 * 1024)
                            };
                            let relevant_only = SCAN_RELEVANT_ONLY.load(Ordering::Relaxed);
                            match if archive_too_big {
                                Ok(Vec::new())
                            } else {
                                hydradragonextractor::extract_archive_from_bytes(&item.buf, relevant_only)
                            } {
                                Ok(children) => {
                                    let valid_children: Vec<_> = children
                                        .into_iter()
                                        .filter(|entry| {
                                            if entry.name.trim().is_empty()
                                                || entry.name.ends_with('/') // directory entries — no payload
                                            {
                                                return false;
                                            }
                                            let child_lower = entry.name.to_ascii_lowercase();
                                            if is_harmless_resource_extension(&child_lower)
                                                && !entry.data.starts_with(b"dex\n")
                                                && !entry.data.starts_with(b"vdex")
                                                && !entry.data.starts_with(b"\x7fELF")
                                                && !entry.data.starts_with(b"PK\x03\x04")
                                                && !entry.data.starts_with(b"\xca\xfe\xba\xbe")
                                                && !has_polyglot_or_hidden_data(&entry.data)
                                            {
                                                return false;
                                            }
                                            true
                                        })
                                        .collect();

                                    if !valid_children.is_empty() {
                                        let mut g = stack.lock().unwrap_or_else(|e| e.into_inner());
                                        outstanding.fetch_add(valid_children.len(), AtomOrdering::AcqRel);
                                        for entry in valid_children {
                                            let child_name = entry.name.clone();
                                            let entry_name = Some(match &item.entry_name {
                                                Some(parent) => format!("{parent}!/{}", child_name),
                                                None => child_name,
                                            });
                                            g.push(WorkItem {
                                                buf: OwnedBuf::Vec(entry.data),
                                                depth: item.depth + 1,
                                                lineage: lineage.clone(),
                                                entry_name,
                                            });
                                        }
                                    }
                                }
                                Err(e) if hydradragonextractor::is_bomb_error(&e) => {
                                    let obj_path = if idx == 0 {
                                        path.to_string()
                                    } else {
                                        match &item.entry_name {
                                            Some(entry) => format!("{path}!/{entry}"),
                                            None => format!("{path}!/unnamed_{idx}"),
                                        }
                                    };
                                    android_log(&format!(
                                        "collect_buffers: zip-bomb triggered for {obj_path}: {e}"
                                    ));
                                    if let Ok(mut dg) = bomb_dets.lock() {
                                        dg.push(("HDR.Bomb.Decompression".to_string(), obj_path, lineage.clone()));
                                    }
                                }
                                Err(_) => {}
                            }
                        }

                        let relevant = item.entry_name.is_none()
                            || !SCAN_RELEVANT_ONLY.load(Ordering::Relaxed)
                            || is_relevant_buffer(item.entry_name.as_deref(), &item.buf);

                        // Photos and videos are only scanned when the user
                        // opts in via SCAN_MEDIA_ENABLED (default off).
                        // Computed before the clamav block so `media_ok`
                        // can also gate the `out.push` below — otherwise
                        // media files would still enter `buffers` and
                        // waste time in every post-collection phase.
                        let scan_media = SCAN_MEDIA_ENABLED.load(Ordering::Relaxed);
                        let is_img = is_image_buffer(item.entry_name.as_deref(), &item.buf);
                        let is_vid = is_media_file(&item.buf);
                        let media_ok = scan_media || (!is_img && !is_vid);

                        // ClamAV + steganography scanning moved to Phase 3
                        // parallel scope (see run_scan) so extraction is not
                        // blocked by signature matching.  EICAR test files are
                        // still caught here because they are tiny and have no
                        // extractable children.

                        if relevant && media_ok {
                            if let Ok(mut og) = out.lock() {
                                og.push(Buf {
                                    data: item.buf, // OwnedBuf — no copy
                                    apk_lineage: lineage,
                                    entry_name: item.entry_name,
                                    fmt, // reuse the already-computed detect_format result
                                });
                            }
                        }

                        outstanding.fetch_sub(1, AtomOrdering::AcqRel);
                    }
                }));
                // If this worker panicked, outstanding is off (item never
                // decremented) — force-stop ALL workers via `capped` so
                // they don't loop forever waiting for a count that will
                // never reach zero.
                if result.is_err() {
                    android_log(&format!(
                        "collect_buffers: worker PANIC on {path}, aborting remaining extraction: {}",
                        last_panic()
                    ));
                    capped.store(true, AtomOrdering::Release);
                }
            });
        }
    });

    let out = out.into_inner().unwrap_or_default();
    let bomb_dets = bomb_dets.into_inner().unwrap_or_default();
    let streaming_dets = streaming_dets.into_inner().unwrap_or_default();
    let streaming_timing = streaming_timing.into_inner().unwrap_or_default();
    rust_timing_log!(
        "collect_buffers :: extracted {} buffers ({} workers), total {} MB, {} detections",
        out.len(),
        workers,
        total_bytes.load(AtomOrdering::Relaxed) / 1_000_000,
        streaming_dets.len(),
    );

    (out, bomb_dets, streaming_dets, streaming_timing)
}

/// The last captured panic ("message @ file:line"), for diagnostics.
fn last_panic() -> String {
    LAST_PANIC
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_else(|| "?".to_string())
}
