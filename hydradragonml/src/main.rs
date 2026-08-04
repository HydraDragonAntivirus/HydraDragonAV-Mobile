//! `hydradragonml-scan` — CLI tool to scan APK binary file(s) or directory
//! using the trained `hydradragonml` Burn model.

use burn::backend::ndarray::NdArrayDevice;
use hydradragonml::Model;
use std::path::{Path, PathBuf};
use std::process::exit;
use walkdir::WalkDir;

struct ScanArgs {
    model_path: PathBuf,
    vocab_path: PathBuf,
    target_path: PathBuf,
    threshold: Option<f32>,
    json: bool,
}

fn print_usage_and_exit(msg: Option<&str>) -> ! {
    if let Some(err) = msg {
        eprintln!("error: {err}\n");
    }
    eprintln!(
        "usage: hydradragonml-scan [--model model.mpk] [--vocab vocab.json] \\\n\
         \x20                        [--threshold 0.95] [--json] <apk_file_or_dir>"
    );
    exit(2);
}

fn parse_args() -> ScanArgs {
    let mut model_path = PathBuf::from("model.mpk");
    let mut vocab_path = PathBuf::from("vocab.json");
    let mut target_path: Option<PathBuf> = None;
    let mut threshold: Option<f32> = None;
    let mut json = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        macro_rules! next_val {
            () => {
                args.next()
                    .unwrap_or_else(|| print_usage_and_exit(Some(&format!("`{arg}` requires a value"))))
            };
        }
        match arg.as_str() {
            "--model" => model_path = PathBuf::from(next_val!()),
            "--vocab" => vocab_path = PathBuf::from(next_val!()),
            "--threshold" => {
                let v = next_val!();
                let t: f32 = v.parse().unwrap_or_else(|_| {
                    print_usage_and_exit(Some(&format!("invalid threshold `{v}`")))
                });
                threshold = Some(t);
            }
            "--json" => json = true,
            "-h" | "--help" => print_usage_and_exit(None),
            flag if flag.starts_with('-') => {
                print_usage_and_exit(Some(&format!("unknown option `{flag}`")))
            }
            path => {
                if target_path.is_some() {
                    print_usage_and_exit(Some("multiple target paths provided"));
                }
                target_path = Some(PathBuf::from(path));
            }
        }
    }

    let target_path = target_path.unwrap_or_else(|| {
        print_usage_and_exit(Some("target file or directory path is required"))
    });

    ScanArgs {
        model_path,
        vocab_path,
        target_path,
        threshold,
        json,
    }
}

fn is_apk_or_zip(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("apk") || e.eq_ignore_ascii_case("zip"))
        .unwrap_or(false)
}

fn main() {
    let args = parse_args();

    if !args.model_path.exists() {
        eprintln!("error: model file not found at `{}`", args.model_path.display());
        exit(2);
    }
    if !args.vocab_path.exists() {
        eprintln!("error: vocab file not found at `{}`", args.vocab_path.display());
        exit(2);
    }

    let vocab_bytes = match std::fs::read(&args.vocab_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: failed to read vocab file: {e}");
            exit(2);
        }
    };

    let device = NdArrayDevice::default();
    let model_path_str = match args.model_path.to_str() {
        Some(s) => s,
        None => {
            eprintln!("error: model path is not valid UTF-8");
            exit(2);
        }
    };

    let mut model = match Model::load_from_path(model_path_str, &vocab_bytes, device) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: failed to load model: {e}");
            exit(2);
        }
    };

    if let Some(t) = args.threshold {
        model.set_threshold(t);
    }

    let mut targets = Vec::new();
    if args.target_path.is_file() {
        targets.push(args.target_path.clone());
    } else if args.target_path.is_dir() {
        for entry in WalkDir::new(&args.target_path).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            // Skip any path component containing "invalid"
            let has_invalid = path.components().any(|c| {
                c.as_os_str()
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .contains("invalid")
            });
            if has_invalid {
                continue;
            }
            if entry.file_type().is_file() && is_apk_or_zip(path) {
                targets.push(path.to_path_buf());
            }
        }
    } else {
        eprintln!("error: target `{}` does not exist", args.target_path.display());
        exit(2);
    }

    if targets.is_empty() {
        eprintln!("no APK/ZIP files found at `{}`", args.target_path.display());
        exit(0);
    }

    let mut found_malicious = false;

    for path in &targets {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("warning: skipped `{}`: {e}", path.display());
                continue;
            }
        };

        match model.scan(&bytes) {
            Some(res) => {
                if res.malicious || res.suspicious {
                    found_malicious = true;
                }

                if args.json {
                    println!(
                        "{{\"file\":\"{}\",\"malicious\":{},\"suspicious\":{},\"confidence\":{:.4}}}",
                        path.display().to_string().replace('\\', "/"),
                        res.malicious,
                        res.suspicious,
                        res.confidence
                    );
                } else {
                    let status = if res.malicious {
                        "[MALICIOUS]"
                    } else if res.suspicious {
                        "[SUSPICIOUS]"
                    } else {
                        "[CLEAN]"
                    };
                    println!(
                        "{:<13} {:<60} (confidence: {:.2}%)",
                        status,
                        path.display(),
                        res.confidence * 100.0
                    );
                }
            }
            None => {
                if args.json {
                    println!(
                        "{{\"file\":\"{}\",\"error\":\"unable to extract features or tokenize APK\"}}",
                        path.display().to_string().replace('\\', "/")
                    );
                } else {
                    println!("{:<13} {:<60} (unsupported format / no DEX)", "[SKIPPED]", path.display());
                }
            }
        }
    }

    if found_malicious {
        exit(1);
    }
}
