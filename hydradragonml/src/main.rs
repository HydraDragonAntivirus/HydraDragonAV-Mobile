use std::path::PathBuf;
use std::time::Instant;

use hydradragonml::Model;
use walkdir::WalkDir;

struct Args {
    dataset: PathBuf,
    model: PathBuf,
    vocab: PathBuf,
    threshold: f32,
}

fn parse_args() -> Args {
    let mut dataset = None;
    let mut model = None;
    let mut vocab = None;
    let mut threshold = 0.5;

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
            "--vocab" | "-v" => {
                vocab = Some(
                    args.next()
                        .map(PathBuf::from)
                        .expect("--vocab requires a path"),
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
        model: model.expect("--model is required"),
        vocab: vocab.expect("--vocab is required"),
        threshold,
    }
}

fn find_apks(root: &std::path::Path) -> Vec<PathBuf> {
    let mut apks = Vec::new();
    let walker = WalkDir::new(root).into_iter().filter_entry(|e| {
        !e.path()
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains("invalid")
    });
    for entry in walker.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file()
            && path
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
        eprintln!(
            "ERROR: dataset path does not exist: {}",
            args.dataset.display()
        );
        std::process::exit(1);
    }
    if !args.model.exists() {
        eprintln!(
            "ERROR: --model path does not exist: {}",
            args.model.display()
        );
        std::process::exit(1);
    }
    if !args.vocab.exists() {
        eprintln!(
            "ERROR: --vocab path does not exist: {}",
            args.vocab.display()
        );
        std::process::exit(1);
    }

    let model_bytes = std::fs::read(&args.model).expect("cannot read model file");
    let vocab_bytes = std::fs::read(&args.vocab).expect("cannot read vocab file");
    let device = burn::backend::ndarray::NdArrayDevice::default();
    let mut model = Model::load(&model_bytes, &vocab_bytes, device).unwrap_or_else(|e| {
        eprintln!("ERROR: failed to load model: {e}");
        std::process::exit(1);
    });
    model.set_threshold(args.threshold);
    eprintln!(
        "OK  model loaded: {} (threshold={})",
        args.model.display(),
        args.threshold
    );

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
    let mut extract_failed = 0u64;
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

        // Same real content-derived features the on-device engine and
        // training use — so the test-set metrics reflect actual runtime
        // behaviour. Scannable = the APK yields a verdict. APKs the model
        // cannot parse (no DEX/ELF/manifest features, or no tokenizable
        // content) return `None` and are never fed to the model as a
        // zero-feature vector.
        let result = model.scan(&apk_bytes);
        let extraction_ok = result.is_some();

        let elapsed = t0.elapsed().as_millis();
        total_ms += elapsed;

        let relative = apk_path
            .strip_prefix(&args.dataset)
            .unwrap_or(apk_path)
            .display();

        if !extraction_ok {
            extract_failed += 1;
            println!(
                "  {:<12} {:<50}  [{:.3}s]  (tokenization failed, skipped)",
                "EXTRACT-FAIL",
                relative.to_string().chars().take(48).collect::<String>(),
                elapsed as f64 / 1000.0,
            );
            continue;
        }

        let result = result.unwrap();
        let malicious = result.malicious;
        let confidence = result.confidence;
        let verdict = if malicious { "MALICIOUS" } else { "BENIGN" };

        println!(
            "  {:<12} {:<50}  [{:.3}s]  score={:.0}/100",
            verdict,
            relative.to_string().chars().take(48).collect::<String>(),
            elapsed as f64 / 1000.0,
            confidence * 100.0,
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
    println!("Extract failed:   {}", extract_failed);
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