//! `hydradragonml-build-vocab` — scans a labeled APK corpus and writes a
//! `vocab.json` token→id map using exactly the same tokenization rules as
//! `features::Tokenizer`, so the output can be fed to `hydradragonml-train`
//! (and later `hydradragonml-scan`) even when no vocabulary file exists yet.
//!
//! Tokens are ranked by corpus frequency; the top `--size` (default 20000,
//! capped at `VOCAB_SIZE`, minus the reserved `<UNK>` slot at id 0) are kept,
//! and tokens appearing fewer than `--min-count` times are dropped. Ids are
//! assigned deterministically in rank order, so rebuilding on the same corpus
//! produces the same map.

use hydradragonml::features::{harvest_raw_tokens, VOCAB_SIZE};

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

const UNK_TOKEN: &str = "<UNK>";

struct Args {
    benign: PathBuf,
    malware: PathBuf,
    output: PathBuf,
    size: usize,
    min_count: usize,
}

fn print_usage_and_exit(msg: &str) -> ! {
    eprintln!("error: {msg}\n");
    eprintln!(
        "usage: hydradragonml-build-vocab --benign <dir> --malware <dir> \\\n\
         \x20      [--output vocab.json] [--size 20000] [--min-count 2]"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut benign: Option<PathBuf> = None;
    let mut malware: Option<PathBuf> = None;
    let mut output = PathBuf::from("vocab.json");
    let mut size = VOCAB_SIZE;
    let mut min_count = 2usize;

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        macro_rules! next_val {
            () => {
                args.next()
                    .unwrap_or_else(|| print_usage_and_exit(&format!("`{flag}` needs a value")))
            };
        }
        match flag.as_str() {
            "--benign" => benign = Some(PathBuf::from(next_val!())),
            "--malware" => malware = Some(PathBuf::from(next_val!())),
            "--output" => output = PathBuf::from(next_val!()),
            "--size" => {
                let v = next_val!();
                size = v
                    .parse()
                    .unwrap_or_else(|_| print_usage_and_exit(&format!("invalid --size `{v}`")));
            }
            "--min-count" => {
                let v = next_val!();
                min_count = v
                    .parse()
                    .unwrap_or_else(|_| print_usage_and_exit(&format!("invalid --min-count `{v}`")));
            }
            "-h" | "--help" => print_usage_and_exit("help requested"),
            other => print_usage_and_exit(&format!("unknown argument `{other}`")),
        }
    }

    Args {
        benign: benign.unwrap_or_else(|| print_usage_and_exit("--benign <dir> is required")),
        malware: malware.unwrap_or_else(|| print_usage_and_exit("--malware <dir> is required")),
        output,
        size: size.clamp(2, VOCAB_SIZE),
        min_count: min_count.max(1),
    }
}

fn is_archive_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("apk") || e.eq_ignore_ascii_case("zip"))
        .unwrap_or(false)
}

/// Walks `dir` for `.apk`/`.zip` files, harvesting each file's raw tokens
/// into `counts`. Returns how many files contributed tokens.
fn count_tokens(dir: &Path, counts: &mut HashMap<String, usize>) -> usize {
    let mut files = 0usize;
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() || !is_archive_file(entry.path()) {
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
        let Some(tokens) = harvest_raw_tokens(&bytes) else {
            continue;
        };
        files += 1;
        for tok in tokens {
            *counts.entry(tok).or_insert(0) += 1;
        }
    }
    files
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();

    let mut counts: HashMap<String, usize> = HashMap::new();
    println!("scanning benign corpus: {}", args.benign.display());
    let benign_files = count_tokens(&args.benign, &mut counts);
    println!("scanning malware corpus: {}", args.malware.display());
    let malware_files = count_tokens(&args.malware, &mut counts);

    if counts.is_empty() {
        return Err("no tokens harvested from the given corpora".into());
    }

    let keep = args.size - 1; // reserve id 0 for <UNK>
    let distinct = counts.len();
    let mut ranked: Vec<(String, usize)> = counts
        .into_iter()
        .filter(|(_, c)| *c >= args.min_count)
        .collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut vocab: HashMap<String, i64> = HashMap::with_capacity(keep + 1);
    vocab.insert(UNK_TOKEN.to_string(), 0);
    for (tok, _) in ranked.iter().take(keep) {
        vocab.insert(tok.clone(), vocab.len() as i64);
    }

    let json = serde_json::to_string_pretty(&vocab)?;
    std::fs::write(&args.output, json)?;

    println!(
        "harvested tokens from {} benign + {} malware APKs: {} distinct, {} passing min-count, kept {}",
        benign_files,
        malware_files,
        distinct,
        ranked.len(),
        vocab.len()
    );
    println!("wrote vocabulary: {}", args.output.display());
    Ok(())
}
