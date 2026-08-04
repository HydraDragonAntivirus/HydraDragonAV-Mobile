//! `hydradragonml-train` — trains `model::ApkClassifier` on a labeled
//! benign/malware APK corpus.
//!
//! This uses the high-level `burn-train` / `burn-dataset` `Learner`
//! abstraction (via `SupervisedTraining`) rather than a hand-written training
//! loop: the `TrainStep` / `InferenceStep` traits describe a single step, the
//! batcher turns `Sample`s into `ApkBatch`s, and the `Learner` owns the
//! optimizer + LR scheduler and drives the epochs, validation and checkpointing.

use burn::backend::{Autodiff, NdArray};
use burn::data::dataloader::batcher::Batcher;
use burn::data::dataloader::{DataLoader, DataLoaderBuilder};
use burn::optim::AdamConfig;
use burn::optim::lr_scheduler::exponential::ExponentialLrSchedulerConfig;
use burn::record::CompactRecorder;
use burn::tensor::backend::Backend;
use burn::tensor::{Device, Float, Int, Tensor, TensorData};
use burn::train::metric::{AccuracyMetric, LossMetric};
use burn::train::{Learner, SupervisedTraining};
use burn_dataset::InMemDataset;

use hydradragonml::features::{ENGINE_FEATURE_COUNT, EngineFeatures};
use hydradragonml::model::{ApkBatch, ApkClassifier};

use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use walkdir::WalkDir;

type TrainBackend = Autodiff<NdArray<f32>>;
type InferBackend = NdArray<f32>;

struct Args {
    benign: PathBuf,
    malware: PathBuf,
    output: PathBuf,
    epochs: usize,
    lr: f64,
    batch_size: usize,
}

fn print_usage_and_exit(msg: &str) -> ! {
    eprintln!("error: {msg}\n");
    eprintln!(
        "usage: hydradragonml-train --benign <dir> --malware <dir> \\\n\
         \x20      [--output model.mpk] [--epochs 6] [--lr 0.001] [--batch-size 8]"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut benign: Option<PathBuf> = None;
    let mut malware: Option<PathBuf> = None;
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
        output,
        epochs,
        lr,
        batch_size,
    }
}

/// A single preprocessed training example: the engine-feature vector and the
/// ground-truth label (`1.0` = malware, `0.0` = benign).
#[derive(Clone, Debug)]
struct Sample {
    engine: Vec<f32>,
    label: f32,
}

/// Batches [Sample]s into an [ApkBatch].
#[derive(Clone)]
struct ApkBatcher<B: Backend> {
    _backend: PhantomData<B>,
}

impl<B: Backend> ApkBatcher<B> {
    fn new() -> Self {
        Self {
            _backend: PhantomData,
        }
    }
}

impl<B: Backend> Batcher<B, Sample, ApkBatch<B>> for ApkBatcher<B> {
    fn batch(&self, items: Vec<Sample>, device: &Device<B>) -> ApkBatch<B> {
        let batch_size = items.len().max(1);

        let mut engine_flat = Vec::with_capacity(batch_size * ENGINE_FEATURE_COUNT);
        let mut targets_flat = Vec::with_capacity(batch_size);

        for s in &items {
            engine_flat.extend_from_slice(&s.engine);
            targets_flat.push(s.label.round() as i64);
        }

        ApkBatch {
            engine: Tensor::<B, 2, Float>::from_data(
                TensorData::new(engine_flat, [batch_size, ENGINE_FEATURE_COUNT]),
                device,
            ),
            targets: Tensor::<B, 1, Int>::from_data(
                TensorData::new(targets_flat, [batch_size]),
                device,
            ),
        }
    }
}

fn is_archive_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("apk") || e.eq_ignore_ascii_case("zip"))
        .unwrap_or(false)
}

fn collect_samples(dir: &Path, label: f32) -> Vec<Sample> {
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
        let engine = match EngineFeatures::extract_from_apk(&bytes) {
            Some(f) => f.to_vec(),
            None => {
                skipped += 1;
                continue;
            }
        };

        out.push(Sample { engine, label });
    }

    println!(
        "  {}: {} usable samples, {} skipped (unreadable / no parseable content)",
        dir.display(),
        out.len(),
        skipped
    );
    out
}

/// Minimal xorshift64* PRNG, used only to shuffle the train/valid split order.
/// Not cryptographic — this is dataset bookkeeping, not a security-relevant use
/// of randomness, so an external `rand` dependency isn't warranted.
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

    println!("scanning benign corpus: {}", args.benign.display());
    let benign_samples = collect_samples(&args.benign, 0.0);
    println!("scanning malware corpus: {}", args.malware.display());
    let malware_samples = collect_samples(&args.malware, 1.0);

    if benign_samples.is_empty() || malware_samples.is_empty() {
        return Err("need at least one usable sample in both --benign and --malware".into());
    }

    let mut all_samples: Vec<Sample> = benign_samples;
    all_samples.extend(malware_samples);

    let mut rng = SimpleRng::seeded();
    rng.shuffle(&mut all_samples);

    let split = ((all_samples.len() as f64) * 0.8) as usize;
    let split = split.clamp(1, all_samples.len().saturating_sub(1).max(1));
    let mut train_samples = all_samples;
    let valid_samples = train_samples.split_off(split);

    let train_count = train_samples.len();
    let valid_count = valid_samples.len();

    println!(
        "dataset: {} train / {} valid ({} total)",
        train_count,
        valid_count,
        train_count + valid_count
    );

    let device = burn::backend::ndarray::NdArrayDevice::default();
    let batch_size = args.batch_size.max(1);

    let train_dataset = InMemDataset::new(train_samples);
    let valid_dataset = InMemDataset::new(valid_samples);

    let train_loader: Arc<dyn DataLoader<TrainBackend, ApkBatch<TrainBackend>>> =
        DataLoaderBuilder::new(ApkBatcher::<TrainBackend>::new())
            .batch_size(batch_size)
            .shuffle(0x5EED)
            .num_workers(2)
            .set_device(device.clone())
            .build(train_dataset);

    let valid_loader: Arc<dyn DataLoader<InferBackend, ApkBatch<InferBackend>>> =
        DataLoaderBuilder::new(ApkBatcher::<InferBackend>::new())
            .batch_size(batch_size)
            .num_workers(2)
            .set_device(device.clone())
            .build(valid_dataset);

    // The original HydraDragon trainer used a constant Adam learning rate with
    // no LR schedule; gamma = 1.0 makes the exponential scheduler a no-op so
    // this reproduces that behaviour exactly.
    let gamma = 1.0;
    let model: ApkClassifier<TrainBackend> = ApkClassifier::new(&device);
    let optim = AdamConfig::new().init();
    let lr_scheduler = ExponentialLrSchedulerConfig::new(args.lr, gamma).init()?;
    let learner = Learner::new(model, optim, lr_scheduler);

    let dir = args
        .output
        .parent()
        .map(|p| p.to_path_buf())
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("."));

    let result = SupervisedTraining::new(dir, train_loader, valid_loader)
        .with_file_checkpointer(CompactRecorder::new())
        .metric_train_numeric(LossMetric::new())
        .metric_valid_numeric(LossMetric::new())
        .metric_valid_numeric(AccuracyMetric::new())
        .num_epochs(args.epochs)
        .launch(learner);

    let final_model: ApkClassifier<InferBackend> = result.model;
    let output_str = args
        .output
        .to_str()
        .ok_or("--output path must be valid UTF-8")?;
    final_model.save_weights(output_str)?;
    println!("saved weights: {output_str}");

    Ok(())
}
