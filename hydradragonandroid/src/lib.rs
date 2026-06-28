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

use hydradragonclamav::YaraEngine;
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
const MODEL_FILE: &str = "apk_model.json";

struct Engine {
    yara: Vec<(String, YaraEngine)>,
    model: Option<Model>,
}

static ENGINE: OnceLock<Engine> = OnceLock::new();

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
    let mut yara = Vec::new();
    for name in YRC_FILES {
        if let Some(eng) = YaraEngine::from_compiled_file(base.join(name)) {
            yara.push((name.to_string(), eng));
        }
    }
    let model = Model::load_json(&base.join(MODEL_FILE)).ok();
    Engine { yara, model }
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
    let engine = do_init(&dir);
    let ok = !engine.yara.is_empty() || engine.model.is_some();
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

    // 1-3: YARA rulesets.
    let mut yara_hits: Vec<String> = Vec::new();
    for (set, eng) in &engine.yara {
        for m in eng.scan(&bytes, &path) {
            yara_hits.push(format!("{}::{}", set, m.name));
        }
    }

    // 4: one-class ML model.
    let (ml_malicious, ml_jaccard, ml_anomaly, ml_nearest) = match &engine.model {
        Some(model) => match model.scan(&bytes) {
            Some(r) => (r.malicious, r.best_jaccard, r.anomaly_score, r.nearest),
            None => (false, 0.0, 0.0, None),
        },
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

    format!(
        r#"{{"malicious":{},"yara":[{}],"ml":{{"malicious":{},"jaccard":{:.4},"anomaly":{:.4},"nearest":{}}}}}"#,
        malicious, hits_json, ml_malicious, ml_jaccard, ml_anomaly, nearest_json
    )
}
