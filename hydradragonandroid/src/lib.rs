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
//!   3. the one-class MinHash/LSH + Isolation Forest model (apk_model.json)

use std::sync::atomic::Ordering;
use std::sync::OnceLock;

use hydradragonclamav::{Engine as ClamavEngine, ScanOptions};
use hydradragonml::Model;
use hydradragonxorfilter::XorFilter;

mod asset_reader;
mod dex_scan;
mod elf;
mod emulate;
mod ip_scan;
mod url_scan;

use jni::errors::LogErrorAndDefault;
use jni::objects::{JClass, JObject, JString};
use jni::sys::{jboolean, jint, jstring, JNI_FALSE, JNI_TRUE};
use jni::EnvUnowned;
use std::fmt::Write;

// Direct FFI into Android's liblog.so (always present in an app process,
// unlike the desktop-only `HDA_PROF`/eprintln! profiling in
// hydradragonclamav's scanner.rs — an env var and stderr writes are both
// invisible on a real device, which is exactly why "which Rust engine is
// slowest" never showed up in logcat before this). No extra crate needed:
// this .so already links against liblog transitively via the NDK toolchain,
// same as every other Android native library.
#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(
        prio: std::os::raw::c_int,
        tag: *const std::os::raw::c_char,
        text: *const std::os::raw::c_char,
    ) -> std::os::raw::c_int;
}
const ANDROID_LOG_INFO: std::os::raw::c_int = 4;

/// Writes one line to logcat under the tag `HydraDragon-RustTiming` — filter
/// with `adb logcat -s HydraDragon-RustTiming` to see which internal stage
/// (dex scan, clamav/YARA, ML model, native-code emulation, ...) is actually
/// slow for a given file, not just "NativeScanner" as one lump sum the way
/// the Java-side FILE_ENGINE_TIMING/SLOWEST_ENGINE logs already do.
fn android_log(msg: &str) {
    use std::ffi::CString;
    let (Ok(tag), Ok(text)) = (
        CString::new("HydraDragon-RustTiming"),
        CString::new(msg),
    ) else {
        return;
    };
    unsafe { __android_log_write(ANDROID_LOG_INFO, tag.as_ptr(), text.as_ptr()) };
}

/// Wraps every `HydraDragon-RustTiming` performance/diagnostic line (per-file
/// init/load timings, `collect_buffers`'s extraction stats, etc.) so it only
/// exists in debug builds. In release (`cfg(debug_assertions)` off) this
/// compiles to nothing — the `format!()` call that builds the message is
/// never evaluated, not just the logcat write skipped — so a production scan
/// doesn't pay any cost for diagnostics nobody in the field will read.
/// Genuine failure/panic reports (`native-init FAILED`, `PANIC`, ...) stay on
/// plain `android_log` calls and keep logging in release, since those matter
/// for diagnosing real crashes on real devices.
#[cfg(debug_assertions)]
macro_rules! rust_timing_log {
    ($($arg:tt)*) => {
        android_log(&format!($($arg)*))
    };
}
#[cfg(not(debug_assertions))]
macro_rules! rust_timing_log {
    ($($arg:tt)*) => {};
}

/// Asset file names expected inside the init directory (static scanner).
const YRC_FILES: &[&str] = &[
    "clean_rules_filtered_verified.yrc",
    "valhalla-rules_filtered_verified.yrc",
    "machine_learning_apk.yrc",
];
/// HIPS / dynamic-analysis rules — loaded lazily on first nativeScanHips call
/// so they don't slow down the static scanner init or consume memory for rules
/// that only match on behavioral/HIPS metadata.
const DYNAMIC_YRC_FILES: &[&str] = &[
    "emerging-all.yrc",
    "hips_rules_filtered_verified.yrc",
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

/// `RwLock` (not a bare `Engine`) so a freshly auto-generated rule can be
/// hot-added to the LIVE engine mid-session (write lock, brief) — see
/// `nativeLearnRule` — instead of only taking effect after the next process
/// restart reloads `generated_rules/*.yar` in `do_init`.
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
static MAX_SCAN_SIZE_MB: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(650);

/// Whether the DYNAMIC_YRC_FILES have been loaded into the live engine (lazy,
/// first nativeScanHips call). Avoids re-loading them on every HIPS scan tick.
static DYNAMIC_RULES_LOADED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Base directory path, set once during do_init(), so lazy dynamic-rule loading
/// in scan_hips() knows where to find the .yrc files without threading a
/// reference through every read-lock acquisition.
static INIT_DIR: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Guards against duplicate calls to `nativeInit` while the first async
/// background thread is still loading the engine (~70 s).
static INIT_STARTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Every bundled asset file read at init time, kept for lazy loading of
/// DYNAMIC_YRC_FILES (HIPS rules) that are read on first scan_hips call
/// rather than at init — no filesystem access needed.
static ASSET_FILES: OnceLock<std::collections::HashMap<String, Vec<u8>>> =
    OnceLock::new();

/// Last panic's "message @ file:line", captured by our hook so we can report
/// WHY a scan panicked (root cause) instead of just swallowing it.
static LAST_PANIC: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Serializes whole-file scan pipelines (`run_scan`). `collect_buffers` and
/// `rescan_buffers_parallel` each spin up their own small worker pool so
/// extraction and scanning overlap WITHIN one file — that parallelism only
/// pays off when it isn't competing with an identical pool from a second
/// file scanned at the same time by another concurrent `nativeScanApk` JNI
/// call. Holding this for the whole of `run_scan` keeps the parallel work
/// confined to one file at a time; a second call simply waits its turn
/// instead of thrashing the same handful of cores alongside the first.
static SCAN_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

fn do_init_from_assets(files: &std::collections::HashMap<String, Vec<u8>>, load_auto_rules: bool) -> Engine {
    let t0 = std::time::Instant::now();

    let (clamav_out, model_out, tlsh_out, whitelist_out, pkg_out, url_out, ip_out) =
        std::thread::scope(|s| {
            let clamav_handle = s.spawn(move || {
                let t_db = std::time::Instant::now();
                let mut report = String::new();
                let clamav = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    hydradragonclamav::Engine::from_bytes_map(files)
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
                            YRC_FILES
                                .iter()
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
                let model_bytes = files.get(MODEL_BIN);
                let model = match model_bytes.and_then(|b| {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Option<Model> {
                        hydradragonml::Model::load_bytes(b).ok()
                    }))
                    .ok()
                    .flatten()
                }) {
                    Some(m) => {
                        let model_ms = t_model.elapsed().as_millis();
                        android_log(&format!("init :: model={model_ms}ms"));
                        report.push_str(&format!(" model=ok({model_ms}ms)"));
                        Some(m)
                    }
                    None => {
                        report.push_str(" model=ERR");
                        None
                    }
                };
                (model, report)
            });

            let tlsh_handle = s.spawn(move || {
                let t_tlsh = std::time::Instant::now();
                let tlsh_db = match files.get(TLSH_DB) {
                    Some(bytes) => {
                        let text = String::from_utf8_lossy(bytes);
                        let mut out = Vec::new();
                        for line in text.lines() {
                            let line = line.trim();
                            if line.is_empty() { continue; }
                            if let Ok(d) = line.parse::<tlsh_rs::TlshDigest>() {
                                out.push(d);
                            }
                        }
                        out
                    }
                    None => Vec::new(),
                };
                let tlsh_ms = t_tlsh.elapsed().as_millis();
                let report = format!(" tlsh={}({tlsh_ms}ms)", tlsh_db.len());
                (tlsh_db, report)
            });

            let whitelist_handle = s.spawn(move || {
                let t_wl = std::time::Instant::now();
                let whitelist = match files.get(WHITELIST_XF) {
                    Some(bytes) => hydradragonxorfilter::XorFilter::from_bytes(bytes),
                    None => None,
                };
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
                    url_scan::UrlScanner::load_from_assets(files)
                })
                .ok()
                .flatten();
                let url_ms = t_url.elapsed().as_millis();
                (url_scanner, format!(" url={url_ms}ms"))
            });

            let ip_handle = s.spawn(move || {
                let t_ip = std::time::Instant::now();
                let ip_scanner = std::panic::catch_unwind(|| {
                    ip_scan::IpScanner::from_bytes_map(files)
                })
                .ok()
                .flatten();
                let ip_ms = t_ip.elapsed().as_millis();
                (ip_scanner, format!(" ip={ip_ms}ms"))
            });

            (
                clamav_handle.join().unwrap_or_else(|_| {
                    (None, format!("clamav=PANIC({})", last_panic()))
                }),
                model_handle.join().unwrap_or_else(|_| {
                    (None, format!(" model=PANIC({})", last_panic()))
                }),
                tlsh_handle.join().unwrap_or_else(|_| {
                    (Vec::new(), format!(" tlsh=PANIC({})", last_panic()))
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
            )
        });

    let (clamav, clamav_report) = clamav_out;
    let (model, model_report) = model_out;
    let (tlsh_db, tlsh_report) = tlsh_out;
    let (whitelist, whitelist_report) = whitelist_out;
    let (package_whitelist, pkg_report) = pkg_out;
    let (url_scanner, url_report) = url_out;
    let (ip_scanner, ip_report) = ip_out;

    let report = format!(
        "{clamav_report}{model_report}{tlsh_report}{whitelist_report}{pkg_report}{url_report}{ip_report}"
    );

    let total_ms = t0.elapsed().as_millis();
    android_log(&format!("init :: TOTAL={total_ms}ms | {report}"));
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

/// Load `key -> md5` from pre-read whitelist_packages.db bytes.
/// Writes to a temp file (rusqlite needs a path) then removes it immediately
/// after reading into the HashMap. One 17 MB write per process lifetime.
fn load_package_whitelist_from_bytes(bytes: &[u8]) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let tmp_dir = std::env::temp_dir();
    let tmp_path = tmp_dir.join("hydra_wl_pkg.db");
    if std::fs::write(&tmp_path, bytes).is_err() {
        return out;
    }
    if let Ok(conn) = rusqlite::Connection::open_with_flags(
        &tmp_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT key, md5 FROM whitelist_package WHERE md5 IS NOT NULL",
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            }) {
                for row in rows.flatten() {
                    out.insert(row.0, row.1.to_lowercase());
                }
            }
        }
    }
    let _ = std::fs::remove_file(&tmp_path);
    out
}

#[allow(dead_code)]
fn do_init(_dir: &str, _load_auto_rules: bool) -> Engine {
    panic!("do_init is dead code; use do_init_from_assets instead");
}

/// Whether `buf` should be skipped by every scan pass: too small (<=12 bytes,
/// can't carry a payload) or over the user's {@link MaxScanFileSize} ceiling.
/// Single shared gate so this rule lives in exactly one place.
fn skip_by_size(buf: &[u8]) -> bool {
    buf.len() <= 12 || buf.len() > (MAX_SCAN_SIZE_MB.load(Ordering::Relaxed) as usize) * 1024 * 1024
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

        // Convert Java AssetManager → native AAssetManager* so the background
        // thread can read files without holding a JNI env reference.
        let mgr = asset_reader::from_java(
            env.get_raw() as *mut std::ffi::c_void,
            asset_manager.into_raw() as *mut std::ffi::c_void,
        );
        // *mut c_void is !Send; cast to usize for thread safety.
        let mgr_addr = mgr as usize;
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
                let mgr = mgr_addr as *mut std::ffi::c_void;
                // Read every bundled asset file into memory via AAssetManager
                asset_reader::init(mgr);
                let files = asset_reader::read_all_assets(&asset_dir);
                if files.is_empty() {
                    android_log("native-init FAILED — no assets read");
                    return;
                }
                let _ = ASSET_FILES.set(files);
                let asset_files = ASSET_FILES.get().unwrap();
                // files_dir is the writable path for generated_rules/
                let _ = INIT_DIR.set(files_dir);
                let engine = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    do_init_from_assets(asset_files, load_auto_rules)
                })) {
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
    let mb = max_mb.max(1) as u32;
    MAX_SCAN_SIZE_MB.store(mb, Ordering::Relaxed);
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

/// `boolean nativeLearnRule(String yarPath)` — hot-load ONE freshly
/// auto-generated `.yar` file (already written to disk by
/// ScanEngine.saveGeneratedRule) into the LIVE engine via a brief write lock,
/// so a family this device just caught is detected by every scan for the
/// REST OF THIS SESSION too — not only after the next process restart, which
/// already reloads every past `generated_rules/*.yar` file from `do_init`.
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

/// Lazy-load HIPS / dynamic YARA rules into the live engine if not already
/// loaded. Called by both scan_hips and scan_text.
fn load_dynamic_rules() {
    if DYNAMIC_RULES_LOADED.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let Some(lock) = ENGINE.get() else { return };
    let Ok(mut guard) = lock.write() else { return };
    let Some(clamav) = &mut guard.clamav else { return };
    let Some(asset_files) = ASSET_FILES.get() else { return };
    for name in DYNAMIC_YRC_FILES {
        let bytes = match asset_files.get(*name) {
            Some(b) => b.clone(),
            None => continue,
        };
        let name_str = name.to_string();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Some(engine) = hydradragonclamav::yara_scan::YaraEngine::from_compiled(&bytes, name_str) {
                clamav.add_compiled_yara(engine);
            }
        }));
    }
    DYNAMIC_RULES_LOADED.store(true, std::sync::atomic::Ordering::Relaxed);
}

fn scan_hips(hips_json: &str) -> String {
    if hips_json.is_empty() {
        return r#"{"malicious":false}"#.to_string();
    }
    // Validate JSON early so we don't bother loading rules for garbage input.
    if serde_json::from_str::<serde_json::Value>(hips_json).is_err() {
        return r#"{"error":"invalid JSON"}"#.to_string();
    }
    // Lazily load DYNAMIC_YRC_FILES on first HIPS/screen-text scan.
    load_dynamic_rules();
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
    load_dynamic_rules();
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
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => return format!(r#"{{"error":"{}"}}"#, json_escape(&e.to_string())),
    };

    // Scan on a big-stack thread (deep clamav/yara recursion) which also catches
    // any panic — so neither a deep stack nor a panic on a malformed/adversarial
    // APK can SIGABRT the whole app process. The read lock is taken INSIDE the
    // spawned thread (not held across the spawn boundary) so a concurrent
    // nativeLearnRule() write lock never blocks scheduling this scan longer
    // than the lock is actually needed.
    let scanned = on_big_stack(move || {
        let guard = match engine_lock.read() {
            Ok(g) => g,
            Err(_) => return r#"{"error":"engine lock poisoned"}"#.to_string(),
        };
        run_scan(&guard, &bytes, &path, hydradragon.as_deref(), file_md5.as_deref(), zero_trust)
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
        if let Some(cat) = scanner.scan(s) {
            out.push(format!("URL.{cat}: {s}"));
            if out.len() >= 16 {
                break;
            }
        }
    }
    out
}

/// Re-scans every extracted buffer with the FULL `module_meta` (androguard +
/// hydradragon metadata) that wasn't available yet when `collect_buffers`
/// ran its own concurrent ClamAV pass during extraction — see the doc
/// comment on `collect_buffers`. Module-gated YARA rules only fire here.
///
/// This used to be a single-threaded `for` loop in `run_scan`, one buffer at
/// a time. On an APK that unpacks into hundreds/thousands of buffers that
/// was the actual "stuck" symptom: logcat would already show
/// `collect_buffers :: extracted N buffers` (and the scanner thread's own
/// "scanned N buffers total" line) — i.e. ClamAV's early pass was long done —
/// and then the scan would sit there for a long time doing the exact same
/// per-buffer ClamAV+YARA work over again, serially, on a single core, with
/// no visible progress in between. Splitting the same work across a small
/// worker pool (bounded by available_parallelism, capped at 4 so a modest
/// phone doesn't get oversubscribed) removes that dead-looking stretch.
///
/// Each worker claims buffer indices off a shared atomic counter (simple
/// work-stealing — buffers vary wildly in size, so static chunking would
/// leave some workers idle while one worker chews a huge nested APK).
/// Results and timing are accumulated per-worker and merged once at the end
/// so there's no lock contention on the hot path, only at merge time.
#[allow(clippy::too_many_arguments)]
fn rescan_buffers_parallel(
    clamav: &ClamavEngine,
    engine: &Engine,
    buffers: &[Buf],
    skip_heavy: &[bool],
    dex_scans: &[Option<dex_scan::DexScan>],
    emulated: &[emulate::EmulationResult],
    emulated_strings: &[Option<Vec<u8>>],
    module_meta: &[(&str, &[u8])],
    path: &str,
    opts: ScanOptions,
    max_dets: usize,
    scan_timing: &mut hydradragonclamav::scanner::TimingBreakdown,
) -> Vec<(String, Vec<String>)> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomOrdering};
    use std::sync::Mutex;

    let next_idx = AtomicUsize::new(0);
    let dets_full = AtomicBool::new(false);
    let results: Mutex<Vec<(String, Vec<String>)>> = Mutex::new(Vec::new());
    let timing: Mutex<hydradragonclamav::scanner::TimingBreakdown> = Mutex::new(Default::default());

    // Small, capped pool — this runs INSIDE the SCAN_SERIAL lock (one file at
    // a time), so it's safe to actually use the device's cores here without
    // worrying about a second file's pool competing for them.
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 4);

    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                // Panic-isolated per worker: one adversarial buffer tripping a
                // panic loses only that worker's remaining share of the work,
                // not every other worker's already-collected detections.
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut local_dets: Vec<(String, Vec<String>)> = Vec::new();
                    let mut local_timing = hydradragonclamav::scanner::TimingBreakdown::default();
                    loop {
                        if dets_full.load(AtomOrdering::Relaxed) {
                            break;
                        }
                        let i = next_idx.fetch_add(1, AtomOrdering::Relaxed);
                        if i >= buffers.len() {
                            break;
                        }
                        if skip_heavy[i] {
                            continue;
                        }
                        let b = &buffers[i];
                        if skip_by_size(&b.data) {
                            continue;
                        }
                        let name = if i == 0 {
                            path.to_string()
                        } else {
                            format!("{path}#extract[{i}]")
                        };
                        let (matches, bt) = clamav
                            .scan_bytes_named_with_breakdown(&b.data, &name, opts, module_meta);
                        for m in matches {
                            local_dets.push((m.name, b.apk_lineage.clone()));
                        }
                        local_timing.accumulate(bt);

                        // Also scan the DEX's decoded string pool (method/class
                        // names contiguous, no MUTF-8/length-prefix noise).
                        if let Some(ds) = &dex_scans[i] {
                            let dname = format!("{name}#dex");
                            let (matches, bt) = clamav.scan_bytes_named_with_breakdown(
                                ds.text.as_bytes(),
                                &dname,
                                opts,
                                module_meta,
                            );
                            for m in matches {
                                local_dets.push((m.name, b.apk_lineage.clone()));
                            }
                            local_timing.accumulate(bt);
                        }

                        // Also scan whatever new strings emulating this ELF
                        // buffer's native code revealed at runtime.
                        if let Some(decoded) = &emulated_strings[i] {
                            let ename = format!("{name}#emulated");
                            let (matches, bt) = clamav
                                .scan_bytes_named_with_breakdown(decoded, &ename, opts, module_meta);
                            for m in matches {
                                local_dets.push((m.name, b.apk_lineage.clone()));
                            }
                            local_timing.accumulate(bt);
                            for url in extract_and_scan_urls(engine, decoded) {
                                local_dets.push((url, b.apk_lineage.clone()));
                            }
                        }

                        // Behavioral signal from emulation.
                        let mut seen_apis = std::collections::HashSet::new();
                        for call in &emulated[i].api_calls {
                            if !seen_apis.insert(call.name.clone()) {
                                continue;
                            }
                            local_dets.push((
                                format!("Behavior.Native: {}", call.name),
                                b.apk_lineage.clone(),
                            ));
                        }

                        if local_dets.len() >= max_dets {
                            dets_full.store(true, AtomOrdering::Relaxed);
                            break;
                        }
                    }
                    (local_dets, local_timing)
                }));
                if let Ok((local_dets, local_timing)) = outcome {
                    if let Ok(mut r) = results.lock() {
                        r.extend(local_dets);
                    }
                    if let Ok(mut t) = timing.lock() {
                        t.accumulate(local_timing);
                    }
                }
                // A panicking worker just contributes nothing further — its
                // in-flight buffer's detections are lost, everyone else's stand.
            });
        }
    });

    if let Ok(t) = timing.into_inner() {
        scan_timing.accumulate(t);
    }
    let mut dets = results.into_inner().unwrap_or_default();
    if dets.len() > max_dets {
        dets.truncate(max_dets);
    }
    dets
}

fn run_scan(
    engine: &Engine,
    bytes: &[u8],
    path: &str,
    hydradragon: Option<&[u8]>,
    file_md5: Option<&str>,
    zero_trust: bool,
) -> String {
    // Only one file's scan pipeline runs at a time: collect_buffers() and
    // rescan_buffers_parallel() below both use their own worker threads
    // internally, and that internal parallelism is what we want — not two
    // files' worth of threads racing each other on the same cores. If a
    // previous scan panicked while holding this (unlikely — the heavy work
    // below is itself panic-guarded), recover the poisoned lock rather than
    // wedging every future scan behind it forever.
    let _scan_serial_guard = SCAN_SERIAL.lock().unwrap_or_else(|e| e.into_inner());

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
    let t_extract = std::time::Instant::now();
    let max_dets = 64;
    let mut early_dets: Vec<(String, Vec<String>)> = Vec::new();
    // `module_meta` is not available yet (androguard JSON etc. is built below
    // from the extracted buffers), so the early-detection scanner thread gets
    // `&[]` at this point. This means YARA rules depending on androguard/
    // hydradragon module data won't match in the early pass — they will be
    // caught when `run_scan` re-scans with the real module_meta below. For
    // rules that don't need module context (most ClamAV signatures), the early
    // pass is fully effective and triggers the `early_hit` fast-path.
    let buffers = collect_buffers(
        bytes, file_md5,
        engine.clamav.as_ref(),
        path, &mut early_dets, max_dets,
        &[],
    );
    let extract_ms = t_extract.elapsed().as_millis();
    let early_hit = !early_dets.is_empty();

    // MD5 of the whole top-level file (its "main hash") — Java builds a
    // VirusTotal lookup link from this (VT accepts md5). Reuses Java's md5.
    // (Moved above the module_meta build since it's needed regardless.)
    let file_hash = match file_md5 {
        Some(md5) => md5.to_string(),
        None => md5_hex(bytes),
    };

    // When the top-level buffer already triggered a detection, skip expensive
    // per-buffer preprocessing (DEX analysis, native emulation, permissions,
    // androguard JSON, whitelist checks) — ClamAV already found the threat.
    let perm_count;
    let packages;
    let hashes;
    let androguard_json;
    let skip_heavy: Vec<bool>;
    let dex_scans: Vec<Option<dex_scan::DexScan>>;
    let dex_ms;
    let hydradragon_meta;
    let mut module_meta: Vec<(&str, &[u8])>;
    let emulated: Vec<emulate::EmulationResult>;
    let emulated_strings: Vec<Option<Vec<u8>>>;
    let emulate_ms;
    if early_hit {
        perm_count = 0;
        packages = Vec::new();
        hashes = Vec::new();
        androguard_json = None::<String>;
        let _ = &androguard_json;
        skip_heavy = vec![false; buffers.len()];
        dex_scans = (0..buffers.len()).map(|_| None).collect();
        dex_ms = 0;
        hydradragon_meta = None::<Vec<u8>>;
        let _ = &hydradragon_meta;
        module_meta = Vec::new();
        emulated = vec![emulate::EmulationResult::default(); buffers.len()];
        emulated_strings = vec![None; buffers.len()];
        emulate_ms = 0;
    } else {
        // Dangerous-permission count from the (in-memory) manifest bytes.
        perm_count = max_dangerous_perms(&buffers);
        // Package name(s) from AndroidManifest.xml.
        packages = collect_packages(&buffers);
        // MD5 of each APK/zip buffer for the hash-keyed whitelist.
        hashes = collect_apk_hashes(&buffers, file_md5);
        // androguard JSON report (manifest + URL sweep).
        androguard_json = build_androguard_json(&buffers);

        // Per-buffer whitelist check.
        skip_heavy = buffers
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

        // DEX static analysis.
        let t_dex = std::time::Instant::now();
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
        dex_ms = t_dex.elapsed().as_millis();

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

        // Native code emulation. Unicorn-based emulation is by far the heaviest
        // pass in this pipeline, and a single APK can legitimately contain
        // dozens of ELF buffers: multi-ABI native libs (arm64-v8a/armeabi-v7a/
        // x86/x86_64 builds of the SAME code, only one of which ever executes
        // on this device) plus nested/repackaged APKs that duplicate identical
        // .so files. Emulating every one of those separately buys no extra
        // detection coverage — identical bytes behave identically under
        // emulation — so buffers are deduped by content hash first, and the
        // per-scan emulation count is capped so one native-lib-heavy APK (e.g.
        // a game engine bundling 4 ABIs) can't blow the scan time budget.
        const MAX_EMULATED_BUFFERS: usize = 8;
        let t_emulate = std::time::Instant::now();
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
                    // Dedupe identical native libs (same code across ABIs or
                    // duplicated inside nested archives) before paying for
                    // emulation.
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
        emulated_strings = emulated
            .iter()
            .map(|r| {
                if r.strings.is_empty() {
                    None
                } else {
                    Some(r.strings.join("\n").into_bytes())
                }
            })
            .collect();
        emulate_ms = t_emulate.elapsed().as_millis();
    }

    // Each detection carries the APK lineage of the buffer it fired on, so Java
    // can suppress it iff one of those ancestor-APK hashes is whitelisted.
    let mut scan_timing = hydradragonclamav::scanner::TimingBreakdown::default();
    let mut yara_dets: Vec<(String, Vec<String>)> = if early_hit {
        // The extraction-time ClamAV pass already found a detection. Treat that as
        // a fast path and avoid rescanning the same buffers here.
        Vec::new()
    } else {
        match &engine.clamav {
            Some(clamav) => {
                let max_dets = 64;
                let opts = ScanOptions::default();
                rescan_buffers_parallel(
                    clamav,
                    engine,
                    &buffers,
                    &skip_heavy,
                    &dex_scans,
                    &emulated,
                    &emulated_strings,
                    &module_meta,
                    path,
                    opts,
                    max_dets,
                    &mut scan_timing,
                )
            }
            None => Vec::new(),
        }
    };
    let clamav_ms = (scan_timing.clamav_ns / 1_000_000) as u128;
    // Aggregate per-YARA-ruleset timing across all buffers.
    let mut yara_agg: std::collections::HashMap<String, u128> = std::collections::HashMap::new();
    for (name, ns) in &scan_timing.yara_per_engine {
        *yara_agg.entry(name.clone()).or_insert(0) += ns;
    }
    let yara_total_ms = (yara_agg.values().sum::<u128>() / 1_000_000) as u128;

    // one-class ML model (independent of clamav's type gate), over the SAME
    // buffers — so an APK nested inside a zip (or any other extracted member)
    // also gets an ML verdict. The strongest signal across all buffers wins.
    let t_ml = std::time::Instant::now();
    let (ml_malicious, ml_jaccard, ml_anomaly, ml_nearest, ml_lineages) = match &engine.model {
        Some(model) => {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut malicious = false;
                let mut best_jaccard = 0.0_f32;
                // hydradragonml flags a buffer malicious when
                // `anomaly_score <= anomaly_threshold` (LOWER = more anomalous —
                // isolation-forest convention). Tracking the MAXIMUM here (as this
                // used to) meant the one buffer that actually tripped `by_iforest`
                // — typically a NEGATIVE score — could never overwrite the 0.0
                // starting value, so the JSON verdict showed "anomaly": 0.0000
                // even when the ML detection genuinely fired on a real anomaly.
                // Track the MINIMUM (most anomalous) instead so the displayed
                // number is always the one that actually caused the flag.
                let mut worst_anomaly = f64::MAX;
                let mut nearest: Option<String> = None;
                // Lineage of every APK/zip buffer the model flagged malicious, so
                // the ML detection is suppressible by a whitelisted ancestor too.
                let mut lineages: Vec<Vec<String>> = Vec::new();
                for (i, b) in buffers.iter().enumerate() {
                    if skip_heavy[i] {
                        continue;
                    }
                    if skip_by_size(&b.data) {
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
                        if r.anomaly_score < worst_anomaly {
                            worst_anomaly = r.anomaly_score;
                        }
                    }
                }
                if worst_anomaly == f64::MAX {
                    worst_anomaly = 0.0; // no buffer was scored — nothing to report
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
    let ml_ms = t_ml.elapsed().as_millis();

    // `matches` stays the clamav/YARA names only (display + PUA classification).
    let hits_json = yara_dets
        .iter()
        .map(|(h, _)| format!("\"{}\"", json_escape(h)))
        .collect::<Vec<_>>()
        .join(",");

    // Unified detection list: early top-level hits first, then full ClamAV/YARA
    // results, then one "ML" detection per ml-flagged APK buffer. Each tagged
    // with its suppressible APK lineage. Duplicates (early hit + full ClamAV
    // re-scan) are harmless — Java deduplicates on the client side.
    let mut detections: Vec<(String, Vec<String>)> = early_dets;
    detections.append(&mut yara_dets);
    for lin in ml_lineages {
        detections.push(("ML".to_string(), lin));
    }

    // DEX static-analysis: only High/Critical findings count as malicious.
    for (i, b) in buffers.iter().enumerate() {
        if let Some(ds) = &dex_scans[i] {
            for f in &ds.findings {
                if dex_scan::is_severe(f.severity) {
                    detections.push((format!("DEX/{:?}: {}", f.severity, f.message), b.apk_lineage.clone()));
                }
            }
        }
    }

    // TLSH fuzzy-similarity to known malware: compare each apk/elf/dex buffer's
    // TLSH against the MalwareBazaar database; a small distance => a likely
    // variant. Tagged with the buffer's APK lineage so a whitelisted APK is
    // still suppressed. Skip when the top-level buffer already triggered a
    // detection — we already have a conclusive verdict.
    let tlsh_ms = if early_hit {
        0
    } else {
        let t_tlsh = std::time::Instant::now();
                for (i, b) in buffers.iter().enumerate() {
                    if skip_heavy[i] {
                        continue;
                    }
                    if skip_by_size(&b.data) {
                        continue;
                    }
            if tlsh_relevant(&b.data) {
                if let Some(dist) = tlsh_nearest(engine, &b.data) {
                    detections.push((format!("TLSH.Malware/dist={}", dist), b.apk_lineage.clone()));
                }
            }
        }
        t_tlsh.elapsed().as_millis()
    };

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

    // Per-stage breakdown for THIS file — filter logcat with
    // `adb logcat -s HydraDragon-RustTiming` to see which Rust-side stage is
    // actually the bottleneck (extraction, dex analysis, native-code
    // emulation, ClamAV, YARA, ML model, or TLSH), not just "NativeScanner" as
    // one lump sum the way the Java-side FILE_ENGINE_TIMING log already does.
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
        android_log(&format!(
            "{path} :: {breakdown} :: slowest={slowest_name}({slowest_ms}ms)"
        ));
    }

    let malicious = !detections.is_empty();
    // yarGen-style auto-generated rule — strings come from this sample's own
    // DEX string pool. References the androguard and hydradragon modules in
    // its condition, not just literal strings, so it also fires on
    // package-name/network reruns of the same family. Built for a malicious
    // verdict OR (Java's) Zero Trust Mode — Zero Trust never treats "nothing
    // matched" as "nothing worth cataloguing"; the rule is then based on the
    // sample's own strings/package rather than a named detection.
    let generated_rule = if malicious || zero_trust {
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
    detections: &[(String, Vec<String>)],
    dex_scans: &[Option<dex_scan::DexScan>],
) -> Option<String> {
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
    out.push_str("    generator = \"hydradragon-autogen (yarGen-style)\"\n");
    out.push_str(&format!("    sample_md5 = \"{}\"\n", file_hash));
    let det_names: Vec<String> = detections.iter().map(|(n, _)| n.replace('"', "'")).collect();
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
    clauses.push("androguard.rootkit_behavior() == 1".to_string());
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
            "{{\"package_name\":{},\"app_name\":{},\"main_activity\":{},",
            "\"activities\":[{}],\"services\":[{}],\"receivers\":[{}],",
            "\"permissions\":[{}],\"new_permissions\":[{}],\"urls\":[{}],",
            "\"min_sdk_version\":{},\"max_sdk_version\":{},\"target_sdk_version\":{},",
            "\"certificate\":{{\"subjectDN\":null,\"IssuerDN\":null,\"sha1\":null}}}}"
        ),
        opt_str(&manifest.package),
        opt_str(&manifest.app_name),
        opt_str(&manifest.main_activity),
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
/// Zip-bomb guard: stops extraction when total decompressed bytes exceed ~2 GB
/// or when the number of extracted buffers exceeds 4096.
///
/// Extraction and scanning are no longer split across a dedicated "main
/// thread extracts, one background thread scans" pipeline — every worker in
/// a small pool does BOTH for whatever buffer it pulls next: extract it,
/// scan it with ClamAV, push any children back onto the shared work stack,
/// repeat. That means scanning genuinely overlaps extraction on however many
/// cores are available (not just two threads handing off through a channel),
/// and a worker that pulls the top-level 162 MB APK scans it while OTHER
/// workers are already extracting/scanning its children concurrently.
/// Scan results accumulate in `early_dets` as they arrive, regardless of
/// whether a match was found.
/// `module_meta` is passed through so YARA rules that depend on androguard/
/// hydradragon module metadata detect correctly in the early pass (previously
/// `&[]` was passed, causing YARA rules with module conditions to never match
/// in the early-detection thread, then re-scanned in `run_scan`).
fn collect_buffers(
    data: &[u8],
    top_md5: Option<&str>,
    engine: Option<&ClamavEngine>,
    path: &str,
    early_dets: &mut Vec<(String, Vec<String>)>,
    max_dets: usize,
    module_meta: &[(&str, &[u8])],
) -> Vec<Buf> {
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomOrdering};
    use std::sync::Mutex;

    /// One unit of pending work: a buffer that still needs extracting+scanning.
    struct WorkItem {
        buf: Vec<u8>,
        depth: usize,
        lineage: Vec<String>,
    }

    let stack: Mutex<Vec<WorkItem>> = Mutex::new(vec![WorkItem {
        buf: data.to_vec(),
        depth: 0,
        lineage: Vec::new(),
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
    let dets: Mutex<Vec<(String, Vec<String>)>> = Mutex::new(Vec::new());
    let total_bytes = AtomicU64::new(0);
    // Count of buffers actually emitted to `out` — used for both the 4096 cap
    // and as each buffer's naming index (`path#extract[idx]`), without
    // needing to lock `out` just to read its length.
    let emitted = AtomicUsize::new(0);
    let dets_full = AtomicBool::new(false);
    // Set once the buffer/byte cap is hit; every worker checks it and winds
    // down rather than pulling more work, even if `outstanding` is nonzero.
    let capped = AtomicBool::new(false);

    let opts = ScanOptions::default();
    // Small, capped pool — collect_buffers already runs inside run_scan's
    // SCAN_SERIAL lock (one file at a time), so it's safe to actually spend
    // the device's cores here without a second file's pool competing for them.
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 4);

    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
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
                            // Nothing to pop right now. If `outstanding` is 0,
                            // no worker is mid-extraction either, so nobody can
                            // ever push more work — done. Otherwise some other
                            // worker may still add children any moment; back
                            // off briefly and check again.
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
                    // Detect format ONCE per buffer (both for lineage and extraction).
                    let fmt = hydradragonextractor::detect_format(&item.buf);
                    if fmt == Some("zip") {
                        // Reuse the caller's top-level MD5 when available — the
                        // 162 MB APK is the only depth-0 zip we ever process, so
                        // this avoids a second full-buffer hash for every APK
                        // scan. Nested zips are small enough that their MD5
                        // cost is negligible.
                        let h = match top_md5 {
                            Some(md5) if item.depth == 0 => md5.to_string(),
                            _ => md5_hex(&item.buf),
                        };
                        lineage.push(h);
                    }

                    // Scan right here, on this same worker — no hand-off to a
                    // separate scanner thread. Other workers are concurrently
                    // doing the same for other buffers, so extraction and
                    // scanning genuinely run at the same time across the pool.
                    if let Some(clamav) = engine {
                        if !dets_full.load(AtomOrdering::Relaxed) && !skip_by_size(&item.buf) {
                            let name = if idx == 0 {
                                path.to_string()
                            } else {
                                format!("{}#extract[{}]", path, idx)
                            };
                            let (matches, _) = clamav.scan_bytes_named_with_breakdown(
                                &item.buf, &name, opts, module_meta,
                            );
                            if !matches.is_empty() {
                                if let Ok(mut dg) = dets.lock() {
                                    for m in matches {
                                        dg.push((m.name, lineage.clone()));
                                    }
                                    if dg.len() >= max_dets {
                                        dets_full.store(true, AtomOrdering::Relaxed);
                                    }
                                }
                            }
                        }
                    }

                    // Extract children (ZIP/tar/gz/… entries) — pushed back
                    // onto the shared stack for this or any other worker to
                    // pick up next.
                    if item.depth < 16 && fmt.is_some() {
                        match hydradragonextractor::extract_archive_from_bytes(&item.buf) {
                            Ok(children) => {
                                if !children.is_empty() {
                                    // Publish BEFORE pushing, so no other
                                    // worker can observe `outstanding == 0`
                                    // while these children are about to land.
                                    outstanding.fetch_add(children.len(), AtomOrdering::AcqRel);
                                    let mut g = stack.lock().unwrap_or_else(|e| e.into_inner());
                                    for child in children {
                                        g.push(WorkItem {
                                            buf: child,
                                            depth: item.depth + 1,
                                            lineage: lineage.clone(),
                                        });
                                    }
                                }
                            }
                            Err(e) if hydradragonextractor::is_bomb_error(&e) => {
                                if let Ok(mut dg) = dets.lock() {
                                    dg.push(("HDR.Bomb.Decompression".to_string(), lineage.clone()));
                                }
                            }
                            Err(_) => {}
                        }
                    }

                    if let Ok(mut og) = out.lock() {
                        og.push(Buf {
                            data: item.buf,
                            apk_lineage: lineage,
                        });
                    }

                    outstanding.fetch_sub(1, AtomOrdering::AcqRel);
                }
            });
        }
    });

    let out = out.into_inner().unwrap_or_default();
    android_log(&format!(
        "collect_buffers :: extracted {} buffers ({} workers), total {} MB",
        out.len(),
        workers,
        total_bytes.load(AtomOrdering::Relaxed) / 1_000_000
    ));

    let dets = dets.into_inner().unwrap_or_default();
    for det in dets {
        early_dets.push(det);
        if early_dets.len() >= max_dets {
            break;
        }
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
