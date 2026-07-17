use std::path::PathBuf;
use std::time::Instant;

use hydradragonml::{features, Model, DEFAULT_CONFIDENCE_THRESHOLD};
use walkdir::WalkDir;

struct Args {
    dataset: PathBuf,
    model: Option<PathBuf>,
    threshold: f32,
}

fn parse_args() -> Args {
    let mut dataset = None;
    let mut model = None;
    let mut threshold = DEFAULT_CONFIDENCE_THRESHOLD;

    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dataset" | "-d" => {
                dataset = Some(
                    args.next()
                        .map(PathBuf::from)
                        .expect("--dataset requires a path"),
                );
            }
            "--model" | "-m" => {
                model = Some(
                    args.next()
                        .map(PathBuf::from)
                        .expect("--model requires a path"),
                );
            }
            "--threshold" | "-t" => {
                threshold = args
                    .next()
                    .and_then(|s| s.parse().ok())
                    .expect("--threshold requires a float");
            }
            other => {
                eprintln!("Unknown argument: {other}");
                std::process::exit(1);
            }
        }
    }

    Args {
        dataset: dataset.expect("--dataset is required"),
        model,
        threshold,
    }
}

fn find_apks(root: &std::path::Path) -> Vec<PathBuf> {
    let mut apks = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.to_string_lossy().to_ascii_lowercase().contains("invalid") {
            continue;
        }
        if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("apk"))
            .unwrap_or(false)
        {
            apks.push(path.to_path_buf());
        }
    }
    apks.sort();
    apks
}

fn main() {
    let args = parse_args();

    if !args.dataset.exists() {
        eprintln!("ERROR: dataset path does not exist: {}", args.dataset.display());
        std::process::exit(1);
    }

    let model = args.model.as_ref().and_then(|p| {
        if !p.exists() {
            eprintln!("WARN: model path does not exist: {}. ML disabled.", p.display());
            return None;
        }
        match Model::load_bin(p) {
            Ok(mut m) => {
                m.set_threshold(args.threshold);
                eprintln!("OK  model loaded: {} (threshold={})", p.display(), args.threshold);
                Some(m)
            }
            Err(e) => {
                eprintln!("WARN: failed to load model {p:?}: {e}. ML disabled.");
                None
            }
        }
    });

    if model.is_none() {
        eprintln!("WARNING: no model loaded. Only feature extraction will be performed.");
    }

    let apks = find_apks(&args.dataset);
    eprintln!("\nFound {} APK files. Scanning...\n", apks.len());

    if apks.is_empty() {
        return;
    }

    let mut tp = 0u64;
    let mut fp = 0u64;
    let mut tn = 0u64;
    let mut fn_ = 0u64;
    let mut unknown = 0u64;
    let mut errors = 0u64;
    let mut total_ms: u128 = 0;

    for apk_path in &apks {
        let expected = ground_truth(apk_path);

        let apk_bytes = match std::fs::read(apk_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("  ERROR   {} (read: {e})", apk_path.display());
                errors += 1;
                continue;
            }
        };

        let t0 = Instant::now();

        let result = model.as_ref().and_then(|m| {
            let feats = features::extract(&apk_bytes)?;
            Some(m.scan_features(&feats))
        });

        let elapsed = t0.elapsed().as_millis();
        total_ms += elapsed;

        let relative = apk_path
            .strip_prefix(&args.dataset)
            .unwrap_or(apk_path)
            .display();

        let malicious = result.as_ref().map(|r| r.malicious).unwrap_or(false);
        let confidence = result.as_ref().map(|r| r.confidence).unwrap_or(0.0);

        let verdict = if malicious { "MALICIOUS" } else { "BENIGN" };

        println!(
            "  {:<12} {:<50}  [{:.3}s]  confidence={:.4}",
            verdict,
            relative.to_string().chars().take(48).collect::<String>(),
            elapsed as f64 / 1000.0,
            confidence,
        );

        if let Some(exp) = expected {
            match (exp, malicious) {
                (true, true) => tp += 1,
                (true, false) => fn_ += 1,
                (false, true) => fp += 1,
                (false, false) => tn += 1,
            }
        } else {
            unknown += 1;
        }
    }

    println!();
    println!("=== SUMMARY ===");
    println!("Total APKs:       {}", apks.len());
    println!("Errors:           {}", errors);
    println!("Unknown label:    {}", unknown);
    println!("Total time:       {} ms", total_ms);
    if !apks.is_empty() {
        println!("Avg time/APK:     {} ms", total_ms / apks.len() as u128);
    }

    println!();
    println!("=== CLASSIFICATION VS FOLDER LABEL ===");
    println!("True Positives:   {}", tp);
    println!("False Positives:  {}", fp);
    println!("True Negatives:   {}", tn);
    println!("False Negatives:  {}", fn_);
    let total_known = tp + fp + tn + fn_;
    println!("Labeled samples:  {}", total_known);

    if total_known > 0 {
        let accuracy = (tp + tn) as f64 / total_known as f64;
        let precision = if tp + fp > 0 {
            tp as f64 / (tp + fp) as f64
        } else {
            0.0
        };
        let recall = if tp + fn_ > 0 {
            tp as f64 / (tp + fn_) as f64
        } else {
            0.0
        };
        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };
        println!("Accuracy:         {:.4}", accuracy);
        println!("Precision:        {:.4}", precision);
        println!("Recall:           {:.4}", recall);
        println!("F1 Score:         {:.4}", f1);
    }
}

fn ground_truth(path: &std::path::Path) -> Option<bool> {
    let path_str = path.to_string_lossy().to_lowercase();
    if path_str.contains("benign") || path_str.contains("clean") || path_str.contains("f-droid") {
        Some(false)
    } else if path_str.contains("malware")
        || path_str.contains("malicious")
        || path_str.contains("malwarebazaar")
    {
        Some(true)
    } else {
        None
    }
}
