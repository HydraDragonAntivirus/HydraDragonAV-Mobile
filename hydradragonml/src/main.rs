//! `hydradragonml-scan` — scores every APK under `--dataset` with a trained
//! model and reports classification metrics against the benign/malware
//! folder labels.

use hydradragonml::features::{FeaturePercentiles, ENGINE_FEATURE_NAMES};
use hydradragonml::Model;

use std::path::{Path, PathBuf};

use walkdir::WalkDir;

struct Args {
    dataset: PathBuf,
    model: PathBuf,
    vocab: PathBuf,
    features: PathBuf,
    threshold: f32,
    dump_features: bool,
}

fn print_usage_and_exit(msg: &str) -> ! {
    eprintln!("error: {msg}\n");
    eprintln!(
        "usage: hydradragonml-scan --dataset <dir> --model <model.mpk> --vocab <vocab.json> \\\n\
         \x20      --features <features.json> [--threshold 0.5] [--dump-features]"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut dataset: Option<PathBuf> = None;
    let mut model: Option<PathBuf> = None;
    let mut vocab: Option<PathBuf> = None;
    let mut features: Option<PathBuf> = None;
    let mut threshold = 0.5f32;
    let mut dump_features = false;

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        macro_rules! next_val {
            () => {
                args.next()
                    .unwrap_or_else(|| print_usage_and_exit(&format!("`{flag}` needs a value")))
            };
        }
        match flag.as_str() {
            "--dataset" => dataset = Some(PathBuf::from(next_val!())),
            "--model" => model = Some(PathBuf::from(next_val!())),
            "--vocab" => vocab = Some(PathBuf::from(next_val!())),
            "--features" => features = Some(PathBuf::from(next_val!())),
            "--threshold" => {
                let v = next_val!();
                threshold = v.parse().unwrap_or_else(|_| {
                    print_usage_and_exit(&format!("invalid --threshold `{v}`"))
                });
            }
            "--dump-features" => dump_features = true,
            "-h" | "--help" => print_usage_and_exit("help requested"),
            other => print_usage_and_exit(&format!("unknown argument `{other}`")),
        }
    }

    Args {
        dataset: dataset.unwrap_or_else(|| print_usage_and_exit("--dataset <dir> is required")),
        model: model.unwrap_or_else(|| print_usage_and_exit("--model <path> is required")),
        vocab: vocab.unwrap_or_else(|| print_usage_and_exit("--vocab <path> is required")),
        features: features.unwrap_or_else(|| print_usage_and_exit("--features <path> is required")),
        threshold,
        dump_features,
    }
}

/// Ground-truth label inferred from the containing directory path
/// (looks for a `benign` or `malware` path component, case-insensitively).
/// Returns `None` for files that aren't under either — those are scored
/// but excluded from the metrics since we don't know their true label.
fn true_label_from_path(path: &Path) -> Option<bool> {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    let has = |needle: &str| {
        lower
            .split(|c| c == '/' || c == '\\')
            .any(|part| part == needle)
    };
    if has("malware") {
        Some(true)
    } else if has("benign") {
        Some(false)
    } else {
        None
    }
}

fn is_apk_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("apk"))
        .unwrap_or(false)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();

    println!("loading model: {}", args.model.display());
    let model_bytes = std::fs::read(&args.model)?;
    let vocab_bytes = std::fs::read(&args.vocab)?;
    let features_bytes = std::fs::read(&args.features)?;
    let feature_stats = FeaturePercentiles::from_json_bytes(&features_bytes)
        .ok_or_else(|| format!("failed to parse features: {}", args.features.display()))?;
    let device = burn::backend::ndarray::NdArrayDevice::default();
    let mut model = Model::load(&model_bytes, &vocab_bytes, feature_stats, device)?;
    model.set_threshold(args.threshold);

    let (mut tp, mut fp, mut tn, mut fn_) = (0usize, 0usize, 0usize, 0usize);
    let mut unlabeled = 0usize;
    let mut unparseable = 0usize;
    let mut total_labeled = 0usize;

    println!("scanning: {}\n", args.dataset.display());

    for entry in WalkDir::new(&args.dataset).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() || !is_apk_file(entry.path()) {
            continue;
        }
        let path = entry.path();

        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("warning: could not read {}: {e}", path.display());
                continue;
            }
        };

        let result = match model.scan(&bytes) {
            Some(r) => r,
            None => {
                unparseable += 1;
                eprintln!("skip (unparseable): {}", path.display());
                continue;
            }
        };

        let verdict = if result.malicious {
            "MALICIOUS"
        } else if result.suspicious {
            "SUSPICIOUS"
        } else {
            "BENIGN"
        };
        println!("{verdict:>10}  {:.4}  {}", result.confidence, path.display());

        if args.dump_features {
            if let Some(norm) = model.normalized_features(&bytes) {
                let vals: Vec<String> = norm.iter().map(|v| format!("{v:.3}")).collect();
                println!(
                    "      features {}",
                    ENGINE_FEATURE_NAMES
                        .iter()
                        .zip(vals.iter())
                        .map(|(n, v)| format!("{n}={v}"))
                        .collect::<Vec<_>>()
                        .join("  ")
                );
            }
        }

        let Some(true_malware) = true_label_from_path(path) else {
            unlabeled += 1;
            continue;
        };
        let predicted_malware = result.confidence >= args.threshold;
        total_labeled += 1;
        match (predicted_malware, true_malware) {
            (true, true) => tp += 1,
            (true, false) => fp += 1,
            (false, false) => tn += 1,
            (false, true) => fn_ += 1,
        }
    }

    let accuracy = (tp + tn) as f64 / (total_labeled.max(1) as f64);
    let precision = tp as f64 / ((tp + fp).max(1) as f64);
    let recall = tp as f64 / ((tp + fn_).max(1) as f64);
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };

    println!("\n== summary ==");
    println!("labeled files scored: {total_labeled} (unlabeled: {unlabeled}, unparseable: {unparseable})");
    println!("TP={tp} FP={fp} TN={tn} FN={fn_}");
    println!(
        "accuracy={accuracy:.4} precision={precision:.4} recall={recall:.4} f1={f1:.4} (threshold={:.2})",
        args.threshold
    );

    Ok(())
}
