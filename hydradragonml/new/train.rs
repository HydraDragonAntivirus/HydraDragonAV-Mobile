//! `hydradragonml-train` — trains `model::ApkClassifier` on a labeled
//! benign/malware APK corpus using Burn's `burn-train` / `burn-dataset`
//! machinery (`SupervisedTraining` + `Learner`), rather than a hand-rolled
//! loop. The `TrainStep`/`InferenceStep` glue lives in
//! `hydradragonml::training` (see that module's doc comment for why).

use burn::backend::{Autodiff, NdArray};
use burn::data::dataloader::DataLoader;
use burn::data::dataloader::DataLoaderBuilder;
use burn::data::dataset::{Dataset, InMemDataset};
use burn::lr_scheduler::step::StepLrSchedulerConfig;
use burn::optim::AdamConfig;
use burn::train::metric::LossMetric;
use burn::train::{Learner, SupervisedTraining};

use hydradragonml::features::{EngineFeatures, Tokenizer};
use hydradragonml::model::ApkClassifier;
use hydradragonml::training::{ApkBatch, ApkBatcher, ApkItem};

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use walkdir::WalkDir;

type TrainBackend = Autodiff<NdArray<f32>>;
type InferBackend = NdArray<f32>;

struct Args {
    benign: PathBuf,
    malware: PathBuf,
    vocab: PathBuf,
    output: PathBuf,
    epochs: usize,
    lr: f64,
    batch_size: usize,
}

fn print_usage_and_exit(msg: &str) -> ! {
    eprintln!("error: {msg}\n");
    eprintln!(
        "usage: hydradragonml-train --benign <dir> --malware <dir> --vocab <vocab.json> \\\n\
         \x20      [--output model.mpk] [--epochs 6] [--lr 0.001] [--batch-size 8]"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut benign: Option<PathBuf> = None;
    let mut malware: Option<PathBuf> = None;
    let mut vocab: Option<PathBuf> = None;
    let mut output = PathBuf::from("model.mpk");
    let mut epochs = 6usize;
    let mut lr = 0.001f64;
    let mut batch_size = 8usize;

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
            "--vocab" => vocab = Some(PathBuf::from(next_val!())),
            "--output" => output = PathBuf::from(next_val!()),
            "--epochs" => {
                let v = next_val!();
                epochs = v
                    .parse()
                    .unwrap_or_else(|_| print_usage_and_exit(&format!("invalid --epochs `{v}`")));
            }
            "--lr" => {
                let v = next_val!();
                lr = v
                    .parse()
                    .unwrap_or_else(|_| print_usage_and_exit(&format!("invalid --lr `{v}`")));
            }
            "--batch-size" => {
                let v = next_val!();
                batch_size = v.parse().unwrap_or_else(|_| {
                    print_usage_and_exit(&format!("invalid --batch-size `{v}`"))
                });
            }
            "-h" | "--help" => print_usage_and_exit("help requested"),
            other => print_usage_and_exit(&format!("unknown argument `{other}`")),
        }
    }

    Args {
        benign: benign.unwrap_or_else(|| print_usage_and_exit("--benign <dir> is required")),
        malware: malware.unwrap_or_else(|| print_usage_and_exit("--malware <dir> is required")),
        vocab: vocab.unwrap_or_else(|| print_usage_and_exit("--vocab <path> is required")),
        output,
        epochs,
        lr,
        batch_size,
    }
}

fn is_archive_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("apk") || e.eq_ignore_ascii_case("zip"))
        .unwrap_or(false)
}

/// Walks `dir` recursively for `.apk`/`.zip` files and builds one `ApkItem`
/// per file that the tokenizer can actually find content in.
fn collect_samples(dir: &Path, label: f32, tokenizer: &Tokenizer) -> Vec<ApkItem> {
    let mut out = Vec::new();
    let mut skipped = 0usize;

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() || !is_archive_file(entry.path()) {
            continue;
        }
        let path = entry.path();
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("warning: could not read {}: {e}", path.display());
                skipped += 1;
                continue;
            }
        };
        let tokens = match tokenizer.tokenize(&bytes) {
            Some(t) => t,
            None => {
                skipped += 1;
                continue;
            }
        };
        let engine = EngineFeatures::extract_from_apk(&bytes)
            .unwrap_or_default()
            .to_vec();

        out.push(ApkItem {
            tokens,
            engine,
            label,
        });
    }

    println!(
        "  {}: {} usable samples, {} skipped (unreadable / no parseable content)",
        dir.display(),
        out.len(),
        skipped
    );
    out
}

/// Prints the mean of each of the 18 normalized engine features per class —
/// a quick way to see whether benign vs. malware differ mostly on
/// "complexity" features (dex/manifest/elf counts) rather than on anything
/// actually malicious. If they do, a feature-rich *benign* app will score
/// close to the malware centroid on those dimensions no matter how well
/// training goes; that's a corpus-composition problem, not something a
/// loss function or architecture change fixes on its own.
fn print_feature_means(label: &str, items: &[ApkItem]) {
    if items.is_empty() {
        return;
    }
    let n = items.len() as f32;
    let mut sums = vec![0f32; items[0].engine.len()];
    for item in items {
        for (s, v) in sums.iter_mut().zip(item.engine.iter()) {
            *s += v;
        }
    }
    let names = [
        "dex_class_count",
        "dex_string_count",
        "dex_api_call_count",
        "dex_finding_high",
        "dex_finding_critical",
        "elf_count",
        "elf_emulated_strings",
        "elf_network_calls",
        "elf_file_calls",
        "elf_exec_calls",
        "elf_anti_debug",
        "manifest_dangerous_permissions",
        "manifest_total_permissions",
        "manifest_activities",
        "manifest_services",
        "manifest_receivers",
        "manifest_min_sdk",
        "manifest_target_sdk",
    ];
    println!("  mean normalized engine features ({label}, n={}):", items.len());
    for (name, sum) in names.iter().zip(sums.iter()) {
        println!("    {name:<32} {:.4}", sum / n);
    }
}

/// Minimal xorshift64* PRNG, used only to shuffle sample order for the
/// train/valid split. Not cryptographic — this is dataset bookkeeping, not
/// a security-relevant use of randomness, so pulling in an external `rand`
/// dependency isn't warranted.
struct SimpleRng(u64);

impl SimpleRng {
    fn seeded() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E3779B97F4A7C15)
            | 1;
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = (self.next_u64() as usize) % (i + 1);
            v.swap(i, j);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();

    println!("loading vocabulary: {}", args.vocab.display());
    let vocab_bytes = std::fs::read(&args.vocab)?;
    let tokenizer = Tokenizer::load_json(&vocab_bytes).ok_or("failed to parse vocab.json")?;

    println!("scanning benign corpus: {}", args.benign.display());
    let benign_samples = collect_samples(&args.benign, 0.0, &tokenizer);
    println!("scanning malware corpus: {}", args.malware.display());
    let malware_samples = collect_samples(&args.malware, 1.0, &tokenizer);

    if benign_samples.is_empty() || malware_samples.is_empty() {
        return Err("need at least one usable sample in both --benign and --malware".into());
    }

    println!();
    print_feature_means("benign", &benign_samples);
    print_feature_means("malware", &malware_samples);
    println!();

    let mut all_samples: Vec<ApkItem> = benign_samples;
    all_samples.extend(malware_samples);

    let mut rng = SimpleRng::seeded();
    rng.shuffle(&mut all_samples);

    let split = ((all_samples.len() as f64) * 0.8) as usize;
    let split = split.clamp(1, all_samples.len().saturating_sub(1).max(1));
    let mut train_items = all_samples;
    let valid_items = train_items.split_off(split);

    println!(
        "dataset: {} train / {} valid ({} total)",
        train_items.len(),
        valid_items.len(),
        train_items.len() + valid_items.len()
    );

    let device = burn::backend::ndarray::NdArrayDevice::default();
    let model: ApkClassifier<TrainBackend> = ApkClassifier::new(&device);
    let optim = AdamConfig::new().init();

    let steps_per_epoch = train_items.len().div_ceil(args.batch_size.max(1)).max(1);
    let lr_scheduler = StepLrSchedulerConfig::new(args.lr, steps_per_epoch)
        .with_gamma(0.5) // halve the learning rate every epoch
        .init()
        .map_err(|e| format!("invalid learning rate schedule: {e}"))?;

    let train_dataset = InMemDataset::new(train_items);
    let valid_dataset = InMemDataset::new(valid_items);
    println!(
        "train dataset size: {}, valid dataset size: {}",
        train_dataset.len(),
        valid_dataset.len()
    );

    let dataloader_train: Arc<dyn DataLoader<TrainBackend, ApkBatch<TrainBackend>>> =
        DataLoaderBuilder::new(ApkBatcher)
            .batch_size(args.batch_size.max(1))
            .shuffle(42)
            .num_workers(2)
            .build(train_dataset);

    let dataloader_valid: Arc<dyn DataLoader<InferBackend, ApkBatch<InferBackend>>> =
        DataLoaderBuilder::new(ApkBatcher)
            .batch_size(args.batch_size.max(1))
            .num_workers(2)
            .build(valid_dataset);

    // Checkpoints/metrics/logs go to a throwaway temp dir; only the final
    // .mpk (written explicitly below via `save_weights`, matching the
    // format `Model::load`/`load_weights` already expect) is kept.
    let artifact_dir = tempfile::tempdir()?;

    let training = SupervisedTraining::new(artifact_dir.path(), dataloader_train, dataloader_valid)
        .metric_train_numeric(LossMetric::new())
        .metric_valid_numeric(LossMetric::new())
        .num_epochs(args.epochs)
        .summary();

    let result = training.launch(Learner::new(model, optim, lr_scheduler));

    let output_str = args
        .output
        .to_str()
        .ok_or("--output path must be valid UTF-8")?;
    result.model.save_weights(output_str)?;
    println!("saved weights: {output_str}");

    if let Some(parent) = args.output.parent().filter(|p| !p.as_os_str().is_empty()) {
        let dest = parent.join("vocab.json");
        if dest != args.vocab {
            std::fs::copy(&args.vocab, &dest)?;
            println!("copied vocab: {}", dest.display());
        }
    }

    Ok(())
}
