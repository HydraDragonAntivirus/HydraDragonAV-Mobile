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

fn do_init(dir: &str) -> Engine {
    let base = std::path::Path::new(dir);
    // ClamAV engine from the bundled DB, then add the compiled .yrc rulesets
    // (compiled only — never .yar source on-device).
    let clamav = match ClamavEngine::from_database_dir(base) {
        Ok((mut eng, _report)) => {
            for name in YRC_FILES {
                let _ = eng.add_compiled_yara_file(base.join(name));
            }
            Some(eng)
        }
        Err(_) => None,
    };
    let model = Model::load_bin(&base.join(MODEL_BIN)).ok();
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
    // Scan fully through the clamav engine: it detects the file type, applies
    // clamav's supported-type gate (PE/OLE2/mail/Mach-O/Flash/Java-class are
    // skipped), then runs clamav signatures AND all loaded .yrc YARA rulesets,
    // extracting archives along the way. strict_targets enables the type gate.
    // Each engine is isolated: a panic in clamav doesn't lose the ML result (and
    // vice-versa), and `err` names WHICH engine + the panic location so the root
    // cause is pinpointed, not just swallowed.
    let mut err: Option<String> = None;

    let yara_hits: Vec<String> = match &engine.clamav {
        Some(clamav) => {
            let opts = ScanOptions {
                strict_targets: true,
                max_matches: 64,
                ..ScanOptions::default()
            };
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                clamav
                    .scan_bytes_named(bytes, path, opts)
                    .into_iter()
                    .map(|m| m.name)
                    .collect::<Vec<_>>()
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

    // one-class ML model (independent of clamav's type gate).
    let (ml_malicious, ml_jaccard, ml_anomaly, ml_nearest) = match &engine.model {
        Some(model) => {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| model.scan(bytes))) {
                Ok(Some(r)) => (r.malicious, r.best_jaccard, r.anomaly_score, r.nearest),
                Ok(None) => (false, 0.0, 0.0, None),
                Err(_) => {
                    if err.is_none() {
                        err = Some(format!("ml: {}", last_panic()));
                    }
                    (false, 0.0, 0.0, None)
                }
            }
        }
        None => (false, 0.0, 0.0, None),
    };

    let malicious = !yara_hits.is_empty() || ml_malicious;

    let hits_json = yara_hits
        .iter()
        .map(|h| format!("\"{}\"", json_escape(h)))
        .collect::<Vec<_>>()
        .join(",");
    let nearest_json = match ml_nearest {
        Some(n) => format!("\"{}\"", json_escape(&n)),
        None => "null".to_string(),
    };

    let err_json = match err {
        Some(e) => format!(",\"error\":\"{}\"", json_escape(&e)),
        None => String::new(),
    };

    format!(
        r#"{{"malicious":{},"matches":[{}],"ml":{{"malicious":{},"jaccard":{:.4},"anomaly":{:.4},"nearest":{}}}{}}}"#,
        malicious, hits_json, ml_malicious, ml_jaccard, ml_anomaly, nearest_json, err_json
    )
}

/// The last captured panic ("message @ file:line"), for diagnostics.
fn last_panic() -> String {
    LAST_PANIC
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_else(|| "?".to_string())
}
