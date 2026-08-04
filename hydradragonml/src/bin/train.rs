//! `hydradragonml-train` — trains `model::ApkClassifier` on a labeled
//! benign/malware APK corpus.
//!
//! This uses a manual Burn training loop (see "Custom Training Loop" in the
//! Burn Book) rather than the `burn-train`/`burn-dataset` `Learner`
//! abstraction: the model here is small and the dataset is just two folders
//! of files, so a plain loop over `Tensor`/`Optimizer` primitives keeps the
//! moving parts (and therefore the ways this can break against a future
//! Burn release) to a minimum.

use burn::backend::{Autodiff, NdArray};
use burn::module::AutodiffModule;
use burn::optim::{AdamConfig, GradientsParams, Optimizer};
use burn::tensor::backend::Backend;
use burn::tensor::{Float, Int, Tensor, TensorData};

use hydradragonml::features::{EngineFeatures, Tokenizer, ENGINE_FEATURE_COUNT};
use hydradragonml::model::ApkClassifier;

use std::path::{Path, PathBuf};
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

struct Sample {
    tokens: Vec<i64>,
    engine: Vec<f32>,
    /// 1.0 = malware, 0.0 = benign.
    label: f32,
}

fn is_archive_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("apk") || e.eq_ignore_ascii_case("zip"))
        .unwrap_or(false)
}

fn collect_samples(dir: &Path, label: f32, tokenizer: &Tokenizer) -> Vec<Sample> {
    let mut out = Vec::new();
    let mut skipped = 0usize;

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        // Skip any path component containing "invalid"
        let has_invalid = path.components().any(|c| {
            c.as_os_str()
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains("invalid")
        });
        if has_invalid || !entry.file_type().is_file() || !is_archive_file(path) {
            continue;
        }
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

        out.push(Sample {
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

/// Minimal xorshift64* PRNG, used only to shuffle sample order for the
/// train/valid split and per-epoch batching. Not cryptographic — this is
/// dataset bookkeeping, not a security-relevant use of randomness, so
/// pulling in an external `rand` dependency isn't warranted.
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

/// Builds a padded batch: `tokens` is `[batch, max_len]` (short sequences
/// zero-padded with vocab id `0`, i.e. `<UNK>`), `engine` is
/// `[batch, ENGINE_FEATURE_COUNT]`, `labels` is `[batch, 1]`.
///
/// Note: `ApkClassifier::forward_batch` mean-pools the *entire* padded
/// embedding row with no attention mask, so padding does slightly bias the
/// pooled vector of short sequences toward the `<UNK>` embedding. This
/// matches the (unmasked) pooling already implemented in `model.rs`; fixing
/// it properly would mean adding mask support to `forward_batch` itself.
fn make_batch<B: Backend<FloatElem = f32>>(
    batch: &[&Sample],
    device: &B::Device,
) -> (Tensor<B, 2, Int>, Tensor<B, 2, Float>, Tensor<B, 2, Float>) {
    let max_len = batch.iter().map(|s| s.tokens.len()).max().unwrap_or(1).max(1);

    let mut token_flat = Vec::with_capacity(batch.len() * max_len);
    for s in batch {
        for i in 0..max_len {
            token_flat.push(*s.tokens.get(i).unwrap_or(&0));
        }
    }
    let tokens =
        Tensor::<B, 2, Int>::from_data(TensorData::new(token_flat, [batch.len(), max_len]), device);

    let mut engine_flat = Vec::with_capacity(batch.len() * ENGINE_FEATURE_COUNT);
    for s in batch {
        engine_flat.extend_from_slice(&s.engine);
    }
    let engine = Tensor::<B, 2, Float>::from_data(
        TensorData::new(engine_flat, [batch.len(), ENGINE_FEATURE_COUNT]),
        device,
    );

    let labels: Vec<f32> = batch.iter().map(|s| s.label).collect();
    let labels_t =
        Tensor::<B, 2, Float>::from_data(TensorData::new(labels, [batch.len(), 1]), device);

    (tokens, engine, labels_t)
}

/// Binary cross-entropy over the model's own sigmoid output (the model
/// already ends in `sigmoid`, so this operates on probabilities directly
/// rather than logits).
fn bce_loss<B: Backend<FloatElem = f32>>(pred: Tensor<B, 2, Float>, target: Tensor<B, 2, Float>) -> Tensor<B, 1> {
    let eps = 1e-7;
    let p = pred.clamp(eps, 1.0 - eps);
    let ones = Tensor::ones_like(&p);
    let one_minus_target = ones.clone() - target.clone();
    let one_minus_p = ones - p.clone();
    let per_example = target * p.log() + one_minus_target * one_minus_p.log();
    -per_example.mean()
}

fn evaluate<B: Backend<FloatElem = f32>>(
    model: &ApkClassifier<B>,
    samples: &[Sample],
    device: &B::Device,
) -> (usize, usize) {
    let mut correct = 0;
    for s in samples {
        let (tokens, engine, _labels) = make_batch::<B>(&[s], device);
        let pred: f32 = model.forward_batch(tokens, engine).into_scalar();
        if (pred >= 0.5) == (s.label >= 0.5) {
            correct += 1;
        }
    }
    (correct, samples.len())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();

    let tokenizer = Tokenizer::new();

    println!("scanning benign corpus: {}", args.benign.display());
    let benign_samples = collect_samples(&args.benign, 0.0, &tokenizer);
    println!("scanning malware corpus: {}", args.malware.display());
    let malware_samples = collect_samples(&args.malware, 1.0, &tokenizer);

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

    println!(
        "dataset: {} train / {} valid ({} total)",
        train_samples.len(),
        valid_samples.len(),
        train_samples.len() + valid_samples.len()
    );

    let device = burn::backend::ndarray::NdArrayDevice::default();
    let mut model: ApkClassifier<TrainBackend> = ApkClassifier::new(&device);
    let mut optim = AdamConfig::new().init();

    for epoch in 0..args.epochs {
        let epoch_lr = args.lr / 2f64.powi(epoch as i32);
        rng.shuffle(&mut train_samples);

        let mut total_loss = 0.0f32;
        let mut n_batches = 0usize;

        for batch_slice in train_samples.chunks(args.batch_size.max(1)) {
            let batch_refs: Vec<&Sample> = batch_slice.iter().collect();
            let (tokens, engine, labels) = make_batch::<TrainBackend>(&batch_refs, &device);

            let pred = model.forward_batch(tokens, engine);
            let loss = bce_loss(pred, labels);
            let loss_value: f32 = loss.clone().into_scalar();
            total_loss += loss_value;
            n_batches += 1;

            let grads = loss.backward();
            let grads = GradientsParams::from_grads(grads, &model);
            model = optim.step(epoch_lr, model, grads);
        }

        let valid_model: ApkClassifier<InferBackend> = model.valid();
        let (correct, total) = evaluate(&valid_model, &valid_samples, &device);
        let avg_loss = total_loss / (n_batches.max(1) as f32);
        let valid_acc = correct as f64 / (total.max(1) as f64);
        println!(
            "epoch {:>2}/{}: lr={:.6} loss={:.4} valid_acc={:.4} ({}/{})",
            epoch + 1,
            args.epochs,
            epoch_lr,
            avg_loss,
            valid_acc,
            correct,
            total
        );
    }

    let final_model: ApkClassifier<InferBackend> = model.valid();
    let output_str = args
        .output
        .to_str()
        .ok_or("--output path must be valid UTF-8")?;
    final_model.save_weights(output_str)?;
    println!("saved weights: {output_str}");

    Ok(())
}
