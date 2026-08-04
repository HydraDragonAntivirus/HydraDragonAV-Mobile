//! `hydradragonml-build-vocab` — scans a labelled APK corpus and produces a
//! `vocab.json` file containing the top-N most frequent string tokens.
//!
//! The resulting vocab.json is consumed by `hydradragonml-train` (via
//! `--vocab`) and at inference time by `hydradragonml-scan` (via `--vocab`).
//!
//! Usage:
//!   hydradragonml-build-vocab --benign <dir> --malware <dir> \
//!       [--output vocab.json] [--vocab-size 20000]

use hydradragonml::features::{for_each_entry, MIN_STR_LEN, VOCAB_SIZE};

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

// ─── CLI ────────────────────────────────────────────────────────────────────

struct Args {
    benign: PathBuf,
    malware: PathBuf,
    output: PathBuf,
    vocab_size: usize,
}

fn print_usage_and_exit(msg: &str) -> ! {
    eprintln!("error: {msg}\n");
    eprintln!(
        "usage: hydradragonml-build-vocab --benign <dir> --malware <dir> \\\n\
         \x20      [--output vocab.json] [--vocab-size 20000]"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut benign: Option<PathBuf> = None;
    let mut malware: Option<PathBuf> = None;
    let mut output = PathBuf::from("vocab.json");
    let mut vocab_size = VOCAB_SIZE;

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
            "--vocab-size" => {
                let v = next_val!();
                vocab_size = v.parse().unwrap_or_else(|_| {
                    print_usage_and_exit(&format!("invalid --vocab-size `{v}`"))
                });
            }
            "-h" | "--help" => print_usage_and_exit("help requested"),
            other => print_usage_and_exit(&format!("unknown argument `{other}`")),
        }
    }

    Args {
        benign: benign.unwrap_or_else(|| print_usage_and_exit("--benign <dir> is required")),
        malware: malware.unwrap_or_else(|| print_usage_and_exit("--malware <dir> is required")),
        output,
        vocab_size,
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn is_archive_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("apk") || e.eq_ignore_ascii_case("zip"))
        .unwrap_or(false)
}

fn is_invalid_path(path: &Path) -> bool {
    path.components().any(|c| {
        c.as_os_str()
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains("invalid")
    })
}

/// Split a text segment (entry name or harvested ASCII string) into tokens and
/// count them into `freq`.
fn count_tokens(text: &str, freq: &mut HashMap<String, u64>) {
    for part in text.split(|c: char| {
        c == '.' || c == '/' || c == ';' || c == ':' || c == '-' || c == '\\' || c == '_'
    }) {
        if part.len() >= MIN_STR_LEN {
            *freq.entry(part.to_ascii_lowercase()).or_insert(0) += 1;
        }
    }
}

/// Harvest printable ASCII strings (≥ MIN_STR_LEN) from raw bytes.
fn harvest_strings(data: &[u8], freq: &mut HashMap<String, u64>) {
    let mut start: Option<usize> = None;
    for (i, &b) in data.iter().enumerate() {
        if b.is_ascii_graphic() || b == b' ' {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            let run = &data[s..i];
            if run.len() >= MIN_STR_LEN {
                if let Ok(text) = std::str::from_utf8(run) {
                    count_tokens(text, freq);
                }
            }
        }
    }
}

/// Accumulate token frequencies for every APK in `dir`.
fn count_dir(dir: &Path, freq: &mut HashMap<String, u64>) -> usize {
    let mut count = 0usize;
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if is_invalid_path(path) || !entry.file_type().is_file() || !is_archive_file(path) {
            continue;
        }
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("warning: cannot read {}: {e}", path.display());
                continue;
            }
        };
        let ok = for_each_entry(&bytes, |name, content| {
            count_tokens(name, freq);
            if !content.is_empty() {
                harvest_strings(content, freq);
            }
        });
        if ok.is_some() {
            count += 1;
        }
    }
    count
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();

    let mut freq: HashMap<String, u64> = HashMap::new();

    println!("scanning benign corpus:  {}", args.benign.display());
    let n_benign = count_dir(&args.benign, &mut freq);
    println!("  → {n_benign} APKs, {} unique tokens so far", freq.len());

    println!("scanning malware corpus: {}", args.malware.display());
    let n_malware = count_dir(&args.malware, &mut freq);
    println!("  → {n_malware} APKs, {} unique tokens total", freq.len());

    if n_benign == 0 && n_malware == 0 {
        return Err("no valid APKs found — check --benign / --malware paths".into());
    }

    // Sort by frequency descending, take top vocab_size, assign IDs 1..=N
    // (ID 0 is reserved for <UNK>).
    let mut sorted: Vec<(String, u64)> = freq.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    sorted.truncate(args.vocab_size);

    let vocab: HashMap<String, i64> = sorted
        .into_iter()
        .enumerate()
        .map(|(i, (tok, _))| (tok, (i + 1) as i64))
        .collect();

    println!(
        "writing {} tokens → {}",
        vocab.len(),
        args.output.display()
    );
    let json = serde_json::to_string(&vocab)?;
    std::fs::write(&args.output, json)?;

    println!("done.");
    Ok(())
}
