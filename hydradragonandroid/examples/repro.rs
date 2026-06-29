//! Host reproduction of the on-device native scan crash.
//!
//! Loads the same clamav DB + .yrc rulesets + ML model the app bundles, then
//! scans a directory of APKs exactly like `run_scan`, isolating each engine with
//! catch_unwind. Rust's default panic hook prints "panicked at MSG, file:line"
//! to stderr, so the offending APK + the exact panicking line are revealed.
//!
//! Usage:
//!   cargo run --release --example repro -- <assets_scan_dir> <apk_dir>

use std::path::{Path, PathBuf};

use hydradragonclamav::{Engine as ClamavEngine, ScanOptions};
use hydradragonml::Model;

fn main() {
    // Run on a thread with a HUGE stack to test whether the overflow is
    // deep-but-finite (big stack fixes it) or truly infinite recursion.
    std::thread::Builder::new()
        .stack_size(512 * 1024 * 1024)
        .spawn(run)
        .unwrap()
        .join()
        .unwrap();
}

fn run() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: repro <assets_scan_dir> <apk_dir>");
        std::process::exit(2);
    }
    let base = Path::new(&args[1]);
    let apk_dir = Path::new(&args[2]);

    eprintln!("STEP: from_database_dir");
    let mut clamav = match ClamavEngine::from_database_dir(base) {
        Ok((e, _)) => Some(e),
        Err(e) => {
            eprintln!("clamav DB load failed: {e}");
            None
        }
    };
    if let Some(c) = clamav.as_mut() {
        for name in [
            "clean_rules_filtered_verified.yrc",
            "valhalla-rules_filtered_verified.yrc",
            "AndroidOS_filtered.yrc",
        ] {
            eprintln!("STEP: add_yrc {name}");
            let _ = c.add_compiled_yara_file(base.join(name));
        }
    }
    eprintln!("STEP: load_model");
    let model = Model::load_json(&base.join("apk_model.json")).ok();
    eprintln!("STEP: loaded ok");
    println!("loaded: clamav={} model={}", clamav.is_some(), model.is_some());

    let mut files = Vec::new();
    collect(apk_dir, &mut files);
    println!("scanning {} apks...", files.len());

    let mut clamav_panics = 0u32;
    let mut ml_panics = 0u32;
    for (i, f) in files.iter().enumerate() {
        let bytes = match std::fs::read(f) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let name = f.display().to_string();

        // Stop on the FIRST panic so a slow debug build finds it fast and the
        // culprit file/engine is unambiguous.
        let stop_on_first = std::env::var("REPRO_ALL").is_err();

        if let Some(c) = &clamav {
            eprintln!("[{i}] clamav scanning {name}");
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let opts = ScanOptions {
                    strict_targets: true,
                    max_matches: 64,
                    ..Default::default()
                };
                c.scan_bytes_named(&bytes, &name, opts).len()
            }));
            if r.is_err() {
                clamav_panics += 1;
                println!(">>> CLAMAV PANIC on {name}");
                if stop_on_first {
                    return;
                }
            }
        }

        if let Some(m) = &model {
            eprintln!("[{i}] ml scanning {name}");
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| m.scan(&bytes)));
            if r.is_err() {
                ml_panics += 1;
                println!(">>> ML PANIC on {name}");
                if stop_on_first {
                    return;
                }
            }
        }
    }
    println!("DONE. clamav_panics={clamav_panics} ml_panics={ml_panics}");
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                collect(&p, out);
            } else if p
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("apk"))
                .unwrap_or(false)
            {
                out.push(p);
            }
        }
    }
}
