//! Train the one-class APK model from a directory of malware APKs.
//!
//! Usage:
//!   hydra-ml-train <apk_dir> <model_out.json> [--jaccard 0.55] [--trees 150]
//!
//! No benign set is required — the corpus is assumed malicious.

use std::path::{Path, PathBuf};

use rayon::prelude::*;

use hydradragonml::{
    features, Model, TrainSample, DEFAULT_ANOMALY_PERCENTILE, DEFAULT_JACCARD_THRESHOLD,
    DEFAULT_N_TREES, DEFAULT_SAMPLE_SIZE,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage: {} <apk_dir> <model_out.json> [--jaccard F] [--trees N]",
            args[0]
        );
        std::process::exit(2);
    }
    let apk_dir = PathBuf::from(&args[1]);
    let out = PathBuf::from(&args[2]);

    let mut jaccard = DEFAULT_JACCARD_THRESHOLD;
    let mut trees = DEFAULT_N_TREES;
    let mut i = 3;
    while i + 1 < args.len() {
        match args[i].as_str() {
            "--jaccard" => jaccard = args[i + 1].parse().unwrap_or(jaccard),
            "--trees" => trees = args[i + 1].parse().unwrap_or(trees),
            other => eprintln!("warning: ignoring unknown arg {other}"),
        }
        i += 2;
    }

    let apks = collect_apks(&apk_dir);
    if apks.is_empty() {
        eprintln!("no .apk files found under {}", apk_dir.display());
        std::process::exit(1);
    }
    eprintln!("found {} APKs, extracting features...", apks.len());

    let samples: Vec<TrainSample> = apks
        .par_iter()
        .filter_map(|p| {
            let bytes = std::fs::read(p).ok()?;
            let feats = features::extract(&bytes)?;
            let label = p
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();
            Some(TrainSample { label, features: feats })
        })
        .collect();

    eprintln!(
        "extracted {} / {} (skipped {} unreadable)",
        samples.len(),
        apks.len(),
        apks.len() - samples.len()
    );
    if samples.is_empty() {
        std::process::exit(1);
    }

    eprintln!("training MinHash + Isolation Forest...");
    // Fixed seed so training is fully reproducible (no RNG drift between runs).
    const SEED: u64 = 0x4844_4D4C_5345_4544; // "HDMLSEED"
    let model = Model::train(
        samples,
        jaccard,
        trees,
        DEFAULT_SAMPLE_SIZE,
        DEFAULT_ANOMALY_PERCENTILE,
        SEED,
    );

    model.save_bin(&out).expect("failed to write model");
    eprintln!(
        "saved model: {} samples, jaccard>={:.2}, anomaly<={:.4} -> {}",
        model.len(),
        model.jaccard_threshold(),
        model.anomaly_threshold(),
        out.display()
    );
}

fn collect_apks(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(dir, &mut out);
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().and_then(|s| s.to_str()).map(|s| s.eq_ignore_ascii_case("apk")).unwrap_or(false) {
                out.push(p);
            }
        }
    }
}
