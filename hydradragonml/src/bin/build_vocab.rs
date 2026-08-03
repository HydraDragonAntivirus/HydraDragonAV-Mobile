//! HydraDragonML vocabulary builder.
//!
//! Counts the lowercase, delimiter-split subword tokens the [`Tokenizer`]
//! extracts from a benign/malware APK corpus and writes the top `VOCAB_SIZE-1`
//! tokens (+`<UNK>`=0) to a `vocab.json` that both training and on-device
//! inference load. This mirrors the `build_vocab` logic of the original
//! (removed) `train_model.py`, reimplemented in Rust so the token stream is
//! guaranteed to match `Tokenizer::raw_tokens`.
//!
//! ```text
//! cargo run --release --bin hydradragonml-vocab -- \
//!     --corpus ./dataset/benign,./dataset/malware --output vocab.json
//! ```

use hydradragonml::features::{Tokenizer, VOCAB_SIZE};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

struct Args {
    corpus: Vec<PathBuf>,
    output: PathBuf,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut corpus = None;
        let mut output = None;
        let mut it = std::env::args().skip(1);
        while let Some(arg) = it.next() {
            let mut val = || it.next().ok_or_else(|| format!("missing value for {arg}"));
            match arg.as_str() {
                "--corpus" => corpus = Some(val()?),
                "--output" => output = Some(PathBuf::from(val()?)),
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        let corpus = corpus.ok_or("missing --corpus <dir1,dir2,...>")?;
        let corpus = corpus
            .split(',')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        if corpus.is_empty() {
            return Err("missing --corpus <dir1,dir2,...>".to_string());
        }
        Ok(Args {
            corpus,
            output: output.ok_or("missing --output vocab.json")?,
        })
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
    let args = match Args::parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            eprintln!(
                "Usage: cargo run --release --bin hydradragonml-vocab -- --corpus <dir1,dir2,...> --output vocab.json"
            );
            std::process::exit(2);
        }
    };

    let mut apks: Vec<PathBuf> = Vec::new();
    for dir in &args.corpus {
        eprintln!("Scanning corpus: {}", dir.display());
        collect_apks(dir, &mut apks);
    }
    apks.sort();
    eprintln!("Total APKs to tokenize: {}", apks.len());

    // Count *distinct* tokens per APK (a token seen 100x in one APK should not
    // dominate: we want corpus coverage, matching the original Counter-over-set
    // behavior), then aggregate the per-APK sets across the corpus.
    let mut counter: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for (n, path) in apks.iter().enumerate() {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Some(tokens) = Tokenizer::raw_tokens(&bytes) else {
            continue;
        };
        let unique: HashSet<&String> = tokens.iter().collect();
        for t in unique {
            *counter.entry(t.clone()).or_insert(0) += 1;
        }
        if (n + 1) % 50 == 0 || n + 1 == apks.len() {
            eprintln!(
                "  ... tokenized {}/{} (unique tokens so far: {})",
                n + 1,
                apks.len(),
                counter.len()
            );
        }
    }

    if counter.is_empty() {
        eprintln!("ERROR: no tokens extracted from the corpus");
        std::process::exit(1);
    }

    let mut ranked: Vec<(&String, &u64)> = counter.iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

    let mut vocab: HashMap<String, i64> = HashMap::with_capacity(VOCAB_SIZE);
    vocab.insert("<UNK>".to_string(), 0);
    for (i, (token, _freq)) in ranked.iter().take(VOCAB_SIZE - 1).enumerate() {
        vocab.insert((*token).clone(), (i + 1) as i64);
    }

    let json = serde_json::to_string(&vocab).expect("serialize vocab");
    if let Err(e) = std::fs::write(&args.output, json) {
        eprintln!("failed to write vocab: {e}");
        std::process::exit(1);
    }
    eprintln!(
        "vocab.json saved: {} tokens (from {} unique in {} APKs) → {}",
        vocab.len(),
        counter.len(),
        apks.len(),
        args.output.display(),
    );
}
