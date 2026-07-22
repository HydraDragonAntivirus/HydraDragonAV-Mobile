use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use hydradragonclamav::scanner::Engine;
use hydradragonclamav::ScanOptions;

/// How many APKs from each dataset category to sample.
const SAMPLE_SIZE: usize = 10;

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

fn load_real_database() -> (Engine, impl AsRef<Path>) {
    let db_path = workspace_root().join("database");
    assert!(
        db_path.exists(),
        "database directory not found at {}",
        db_path.display()
    );
    let (engine, _) = Engine::from_database_dir(&db_path).expect("failed to load database");
    (engine, db_path)
}

fn scan_and_report_slow(engine: &Engine, data: &[u8], label: &str) -> usize {
    let t0 = Instant::now();
    let matches = engine.scan_bytes(data, ScanOptions::default());
    let ms = t0.elapsed().as_millis();
    eprintln!("[{label}] {ms}ms, {} match(es)", matches.len());
    eprintln!("  ── SLOW-LOG / SLOW-EXT / SIG-DETAIL appear above ──");
    for m in &matches {
        eprintln!("  [{:?}] {} @ {}", m.kind, m.name, m.object_path);
    }
    matches.len()
}

fn load_apk_samples(dir: &Path, max: usize) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    if !dir.exists() {
        eprintln!("  SKIP: dataset dir not found: {}", dir.display());
        return out;
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("apk"))
                .unwrap_or(false)
        })
        .map(|e| e.path())
        .collect();
    entries.sort();
    for p in entries.iter().take(max) {
        match fs::read(p) {
            Ok(bytes) => out.push((p.clone(), bytes)),
            Err(e) => eprintln!("  WARN: cannot read {}: {e}", p.display()),
        }
    }
    out
}

// ─── EICAR baseline ───────────────────────────────────────────

#[test]
fn real_database_detects_eicar() {
    let (engine, _) = load_real_database();
    let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let n = scan_and_report_slow(&engine, eicar, "eicar.com");
    assert!(n > 0, "EICAR must be detected by real signatures");
}

#[test]
fn eicar_scan_stays_under_hard_limit() {
    let (engine, _) = load_real_database();
    let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let t0 = Instant::now();
    engine.scan_bytes(eicar, ScanOptions::default());
    let ms = t0.elapsed().as_millis();
    assert!(ms < 10_000, "EICAR scan took {ms}ms (limit 10s)");
}

#[test]
fn large_file_scan_shows_per_buffer_timing() {
    let (engine, _) = load_real_database();
    let mut buf = vec![b'X'; 512 * 1024];
    buf.extend_from_slice(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
    let n = scan_and_report_slow(&engine, &buf, "512KB+EICAR");
    assert!(n > 0, "EICAR must be detected even in large buffer");
}

// ─── Real APK dataset scans ───────────────────────────────────

fn dataset_benign_dir() -> PathBuf {
    workspace_root().join("dataset/benign/F-Droid/16-07-2026-14.49")
}

fn dataset_malware_dir() -> PathBuf {
    workspace_root().join("dataset/malware/MalwareBazaar/27.06.2026 - 203930_212345/apk")
}

#[test]
fn scan_benign_apk_samples() {
    let (engine, _) = load_real_database();
    let samples = load_apk_samples(&dataset_benign_dir(), SAMPLE_SIZE);
    if samples.is_empty() {
        eprintln!("SKIP: no benign APK samples found");
        return;
    }
    for (path, bytes) in &samples {
        let name = path.file_stem().unwrap().to_string_lossy();
        scan_and_report_slow(&engine, bytes, &name);
    }
}

#[test]
fn scan_malware_apk_samples() {
    let (engine, _) = load_real_database();
    let samples = load_apk_samples(&dataset_malware_dir(), SAMPLE_SIZE);
    if samples.is_empty() {
        eprintln!("SKIP: no malware APK samples found");
        return;
    }
    for (path, bytes) in &samples {
        let name = path.file_stem().unwrap().to_string_lossy();
        scan_and_report_slow(&engine, bytes, &name);
    }
}

#[test]
fn dataset_scan_slow_signatures_collective_report() {
    let (engine, _) = load_real_database();
    let benign = load_apk_samples(&dataset_benign_dir(), SAMPLE_SIZE);
    let malware = load_apk_samples(&dataset_malware_dir(), SAMPLE_SIZE);

    if benign.is_empty() && malware.is_empty() {
        eprintln!("SKIP: no APK samples available (dataset directories missing)");
        return;
    }

    let mut summary: Vec<(String, u128, usize)> = Vec::new();
    for (path, bytes) in benign.iter().chain(malware.iter()) {
        let name = path.file_stem().unwrap().to_string_lossy().to_string();
        let t0 = Instant::now();
        let matches = engine.scan_bytes(bytes, ScanOptions::default());
        let ms = t0.elapsed().as_millis();
        summary.push((name, ms, matches.len()));
    }

    eprintln!("\n═══ DATASET TIMING SUMMARY ═══");
    eprintln!("{:<60} {:>8} {:>6}", "FILE", "TIMEms", "HITS");
    eprintln!("{}", "-".repeat(78));
    let mut total_ms = 0u128;
    for (name, ms, hits) in &summary {
        eprintln!("{:<60} {:>8} {:>6}", name, ms, hits);
        total_ms += ms;
    }
    eprintln!("{}", "-".repeat(78));
    eprintln!("{:<60} {:>8} {:>6}", "TOTAL", total_ms, summary.len());
    eprintln!("═══ END SUMMARY ═══\n");

    // No individual APK should exceed 120s.
    for (name, ms, _) in &summary {
        assert!(
            *ms < 120_000,
            "{name} took {ms}ms — exceeded 120s individual limit"
        );
    }
}

#[test]
fn dataset_scan_no_engine_panic_on_real_apks() {
    let (engine, _) = load_real_database();
    let all: Vec<_> = load_apk_samples(&dataset_benign_dir(), SAMPLE_SIZE)
        .into_iter()
        .chain(load_apk_samples(&dataset_malware_dir(), SAMPLE_SIZE))
        .collect();

    if all.is_empty() {
        eprintln!("SKIP: no APK samples available");
        return;
    }

    let mut panics = 0usize;
    for (path, bytes) in &all {
        let name = path.file_stem().unwrap().to_string_lossy();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            engine.scan_bytes(bytes, ScanOptions::default());
        }));
        if r.is_err() {
            eprintln!(">>> PANIC on {name}");
            panics += 1;
        }
    }
    assert_eq!(panics, 0, "{panics} APK(s) caused engine panic");
}

#[test]
fn signature_timing_appears_in_stderr() {
    let (engine, _) = load_real_database();
    let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    engine.scan_bytes(eicar, ScanOptions::default());
    engine.scan_bytes(eicar, ScanOptions::default());
    // Run with `--nocapture` to see scan_context timing lines.
}
