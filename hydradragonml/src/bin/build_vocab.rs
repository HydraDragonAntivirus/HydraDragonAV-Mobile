//! HydraDragonML vocabulary builder.
//!
//! Walks a corpus of `.apk`/`.zip` files, extracts the same subword tokens that
//! `features::Tokenizer` uses at inference (entry names + printable strings
//! from `AndroidManifest.xml`, `resources.arsc`, `*.dex` and `META-INF/*`,
//! split on the standard delimiters and lowercased), counts frequencies and
//! writes the top-K vocabulary as a `vocab.json` mapping token -> id.
//! `0` is reserved for `<UNK>` (out-of-vocab/padding).
//!
//! ```text
//! cargo run --release --bin hydradragonml-vocab -- \
//!     --corpus dataset/benign,dataset/malware --output vocab.json --vocab-size 20000
//! ```

use hydradragonml::features::{self, Tokenizer};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

struct Args {
    corpus: Vec<PathBuf>,
    output: PathBuf,
    vocab_size: usize,
}

fn parse_args() -> Args {
    let mut corpus: Vec<PathBuf> = Vec::new();
    let mut output: Option<PathBuf> = None;
    let mut vocab_size = features::VOCAB_SIZE;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = || it.next().ok_or_else(|| format!("missing value for {arg}"));
        match arg.as_str() {
            "--corpus" | "-c" => {
                for part in val().unwrap().split(',') {
                    corpus.push(PathBuf::from(part));
                }
            }
            "--output" | "-o" => output = Some(PathBuf::from(val().unwrap())),
            "--vocab-size" | "-k" => {
                vocab_size = val().unwrap().parse().expect("invalid --vocab-size")
            }
            other => {
                eprintln!("Unknown argument: {other}");
                std::process::exit(1);
            }
        }
    }

    Args {
        corpus,
        output: output.expect("--output is required"),
        vocab_size,
    }
}

fn collect_apks(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for ent in rd.flatten() {
        let p = ent.path();
        if p.to_string_lossy().to_ascii_lowercase().contains("invalid") {
            continue;
        }
        if p.is_dir() {
            collect_apks(&p, out);
        } else if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
            if ext.eq_ignore_ascii_case("apk") || ext.eq_ignore_ascii_case("zip") {
                out.push(p);
            }
        }
    }
}

fn main() {
    let args = parse_args();

    if args.corpus.is_empty() {
        eprintln!("missing --corpus <dir>[,<dir>...]");
        std::process::exit(2);
    }

    let mut entries: Vec<PathBuf> = Vec::new();
    for dir in &args.corpus {
        eprintln!("Collecting APKs from: {}", dir.display());
        collect_apks(dir, &mut entries);
    }
    entries.sort();
    entries.dedup();
    eprintln!("Total APK/ZIP files: {}", entries.len());

    let mut counts: HashMap<String, usize> = HashMap::new();
    for (i, path) in entries.iter().enumerate() {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        if let Some(tokens) = Tokenizer::raw_tokens(&bytes) {
            for t in tokens {
                *counts.entry(t).or_insert(0) += 1;
            }
        }
        if (i + 1) % 100 == 0 {
            eprintln!("  ... {}/{} ({} unique tokens)", i + 1, entries.len(), counts.len());
        }
    }

    let mut ranked: Vec<(String, usize)> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ranked.truncate(args.vocab_size.saturating_sub(1)); // keep 0 for <UNK>

    let mut map = HashMap::new();
    map.insert("<UNK>".to_string(), 0i64);
    for (i, (token, _)) in ranked.iter().enumerate() {
        map.insert(token.clone(), (i + 1) as i64);
    }

    let json = serde_json::to_string_pretty(&map).expect("serialize vocab");
    std::fs::write(&args.output, json).expect("write vocab.json");
    eprintln!(
        "Wrote {} tokens (+ <UNK>) to {}",
        ranked.len(),
        args.output.display()
    );
}