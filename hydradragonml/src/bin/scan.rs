//! Scan APK(s) against a trained model.
//!
//! Usage:
//!   hydra-ml-scan <model.json> <apk_or_dir> [--json]

use std::path::{Path, PathBuf};

use hydradragonml::Model;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: {} <model.json> <apk_or_dir> [--json]", args[0]);
        std::process::exit(2);
    }
    let json_out = args.iter().any(|a| a == "--json");

    let model = Model::load_bin(Path::new(&args[1])).expect("failed to load model");

    let target = PathBuf::from(&args[2]);
    let mut apks = Vec::new();
    if target.is_dir() {
        walk(&target, &mut apks);
    } else {
        apks.push(target);
    }

    let (mut flagged, mut total) = (0usize, 0usize);
    for p in &apks {
        let Ok(bytes) = std::fs::read(p) else { continue };
        total += 1;
        match model.scan(&bytes) {
            Some(r) => {
                if r.malicious {
                    flagged += 1;
                }
                let _ = json_out;
                println!(
                    "{:<8} jaccard={:.2} anomaly={:.4} {}{} {}",
                    if r.malicious { "MALWARE" } else { "clean" },
                    r.best_jaccard,
                    r.anomaly_score,
                    if r.by_minhash { "[minhash]" } else { "" },
                    if r.by_iforest { "[iforest]" } else { "" },
                    p.file_name().and_then(|s| s.to_str()).unwrap_or("")
                );
                if let Some(n) = &r.nearest {
                    if r.by_minhash {
                        println!("         nearest: {n}");
                    }
                }
            }
            None => eprintln!("skip (not a readable APK): {}", p.display()),
        }
    }
    eprintln!("flagged {flagged} / {total}");
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
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
