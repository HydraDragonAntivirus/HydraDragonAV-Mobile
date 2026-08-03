//! HydraDragonML training binary.
//!
//! Trains the Burn [`ApkClassifier`] (text tokens + Android engine features)
//! on a benign/malware APK corpus and saves the weights as a `.mpk` file that
//! the Android engine loads at runtime.
//!
//! ```text
//! cargo run --release --bin hydradragonml-train -- \
//!     --benign ./dataset/benign --malware ./dataset/malware \
//!     --vocab vocab.json --output model.mpk [--epochs 6] [--lr 0.001]
//! ```

use burn::backend::NdArray;
use burn::module::AutodiffModule;
use burn::nn::loss::BinaryCrossEntropyLossConfig;
use burn::optim::{AdamConfig, GradientsParams, Optimizer};
use burn::tensor::{Float, Int, Tensor, TensorData};
use burn_autodiff::Autodiff;
use hydradragonml::features::{self, EngineFeatures, Tokenizer};
use hydradragonml::model::ApkClassifier;
use std::path::{Path, PathBuf};

type B = Autodiff<NdArray<f32>>;

struct Args {
    benign: PathBuf,
    malware: PathBuf,
    vocab: PathBuf,
    output: PathBuf,
    epochs: usize,
    lr: f64,
    batch_size: usize,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut benign = None;
        let mut malware = None;
        let mut vocab = None;
        let mut output = None;
        let mut epochs = 6usize;
        let mut lr = 0.001f64;
        let mut batch_size = 8usize;

        let mut it = std::env::args().skip(1);
        while let Some(arg) = it.next() {
            let mut val = || it.next().ok_or_else(|| format!("missing value for {arg}"));
            match arg.as_str() {
                "--benign" => benign = Some(PathBuf::from(val()?)),
                "--malware" => malware = Some(PathBuf::from(val()?)),
                "--vocab" => vocab = Some(PathBuf::from(val()?)),
                "--output" => output = Some(PathBuf::from(val()?)),
                "--epochs" => {
                    epochs = val()?.parse().map_err(|_| "invalid --epochs".to_string())?
                }
                "--lr" => lr = val()?.parse().map_err(|_| "invalid --lr".to_string())?,
                "--batch-size" => {
                    batch_size = val()?
                        .parse()
                        .map_err(|_| "invalid --batch-size".to_string())?
                }
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        Ok(Args {
            benign: benign.ok_or("missing --benign <dir>")?,
            malware: malware.ok_or("missing --malware <dir>")?,
            vocab: vocab.ok_or("missing --vocab vocab.json")?,
            output: output.ok_or("missing --output model.mpk")?,
            epochs,
            lr,
            batch_size,
        })
    }
}

/// One labeled training sample.
struct Sample {
    tokens: Vec<i64>,
    engine_features: EngineFeatures,
    label: i64, // 0 = benign, 1 = malware
}

fn main() {
    let args = match Args::parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            eprintln!(
                "Usage: cargo run --release --bin hydradragonml-train -- --benign <dir> --malware <dir> --vocab vocab.json --output model.mpk [--epochs N] [--lr F] [--batch-size N]"
            );
            std::process::exit(2);
        }
    };

    let vocab_bytes = match std::fs::read(&args.vocab) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to read vocab '{}': {e}", args.vocab.display());
            std::process::exit(2);
        }
    };
    let tokenizer = match Tokenizer::load_json(&vocab_bytes) {
        Some(t) => t,
        None => {
            eprintln!("failed to parse vocab '{}'", args.vocab.display());
            std::process::exit(2);
        }
    };

    eprintln!("Scanning benign corpus: {}", args.benign.display());
    let benign = load_corpus(&args.benign, &tokenizer, 0);
    eprintln!("  loaded {} samples", benign.len());
    eprintln!("Scanning malware corpus: {}", args.malware.display());
    let mut malware = load_corpus(&args.malware, &tokenizer, 1);
    eprintln!("  loaded {} samples", malware.len());

    if benign.is_empty() || malware.is_empty() {
        eprintln!("need at least one benign and one malware APK");
        std::process::exit(1);
    }

    let mut samples = benign;
    samples.append(&mut malware);
    eprintln!("Total training samples: {}", samples.len());

    // Deterministic-ish shuffle (splitmix64 seed).
    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        (z ^ (z >> 31)) as usize
    };
    for i in (1..samples.len()).rev() {
        let j = next() % (i + 1);
        samples.swap(i, j);
    }

    // 80/20 train/validation split.
    let n_valid = (samples.len() / 5).max(1);
    let valid: Vec<Sample> = samples.split_off(samples.len() - n_valid);
    eprintln!("Train: {}, Valid: {}", samples.len(), valid.len());

    let device = burn::backend::ndarray::NdArrayDevice::default();
    let model = ApkClassifier::<B>::new(&device);

    let mut optim = AdamConfig::new().init();
    let loss_fn = BinaryCrossEntropyLossConfig::new().init(&device);

    eprintln!(
        "Training for {} epochs (lr={}, batch_size={})",
        args.epochs, args.lr, args.batch_size
    );
    let start = std::time::Instant::now();
    let mut model = model;

    for epoch in 1..=args.epochs {
        let epoch_lr = args.lr * (0.5f64.powi((epoch - 1) as i32));
        let mut epoch_loss = 0.0f64;
        let mut n_batches = 0usize;

        let mut batch: Vec<&Sample> = Vec::new();
        for sample in &samples {
            if sample.tokens.is_empty() {
                continue;
            }
            batch.push(sample);
            if batch.len() >= args.batch_size {
                let loss = forward_loss(&model, &loss_fn, &device, &batch);
                epoch_loss += loss.clone().into_scalar() as f64;
                n_batches += 1;
                let grads = GradientsParams::from_grads(loss.backward(), &model);
                model = optim.step(epoch_lr, model, grads);
                batch.clear();
            }
        }
        if !batch.is_empty() {
            let loss = forward_loss(&model, &loss_fn, &device, &batch);
            epoch_loss += loss.clone().into_scalar() as f64;
            n_batches += 1;
            let grads = GradientsParams::from_grads(loss.backward(), &model);
            model = optim.step(epoch_lr, model, grads);
        }

        let valid_metrics = evaluate(&model, &loss_fn, &device, &valid);
        eprintln!(
            "epoch {epoch}: train_loss={:.4} valid_loss={:.4} valid_acc={:.2}% ({}/{})  [{:.1}s]",
            epoch_loss / n_batches.max(1) as f64,
            valid_metrics.loss,
            valid_metrics.accuracy * 100.0,
            valid_metrics.correct,
            valid_metrics.total,
            start.elapsed().as_secs_f64(),
        );
    }

    // Save the trained weights (convert from Autodiff to the plain NdArray
    // backend).
    let valid_model = model.valid();
    if let Err(e) = valid_model.save_weights(args.output.to_str().unwrap()) {
        eprintln!("failed to save model: {e}");
        std::process::exit(1);
    }
    eprintln!("Saved model to {}", args.output.display());

    // Also copy the vocab next to the model for deployment convenience.
    if let Ok(vocab_bytes) = std::fs::read(&args.vocab) {
        let out_dir = args.output.parent().unwrap_or(Path::new("."));
        let vocab_out = out_dir.join("vocab.json");
        if std::fs::write(&vocab_out, &vocab_bytes).is_ok() {
            eprintln!("Copied vocab to {}", vocab_out.display());
        }
    }
}

/// Recursively collect all `.apk`/`.zip` files in `dir`, tokenizing each and
/// extracting its engine features. Files that fail to tokenize are skipped.
fn load_corpus(dir: &Path, tokenizer: &Tokenizer, label: i64) -> Vec<Sample> {
    let mut out = Vec::new();
    let mut entries: Vec<PathBuf> = Vec::new();
    collect_apks(dir, &mut entries);
    entries.sort();

    for path in &entries {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Some(tokens) = tokenizer.tokenize(&bytes) else {
            continue;
        };
        let engine_features = EngineFeatures::extract_from_apk(&bytes).unwrap_or_default();
        out.push(Sample {
            tokens,
            engine_features,
            label,
        });
        if out.len() % 50 == 0 {
            eprintln!("  ... {}/{}", out.len(), entries.len());
        }
    }
    out
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

/// Forward the batch and return the mean BCE loss. `rows` is the list of
/// per-sample token sequences; each is padded to the batch `max_len` with
/// UNK (0) tokens so a single embedding + masked mean-pool reproduces the
/// per-sample pooling in `ApkClassifier::forward`.
fn forward_loss(
    model: &ApkClassifier<B>,
    loss_fn: &burn::nn::loss::BinaryCrossEntropyLoss<B>,
    device: &burn::backend::ndarray::NdArrayDevice,
    batch: &[&Sample],
) -> Tensor<B, 1, Float> {
    let n = batch.len();
    let max_len = batch.iter().map(|s| s.tokens.len()).max().unwrap_or(1);
    let mut padded = vec![0i64; n * max_len];
    for (row, sample) in batch.iter().enumerate() {
        for (j, t) in sample.tokens.iter().take(max_len).enumerate() {
            padded[row * max_len + j] = *t;
        }
    }
    let feats: Vec<f32> = batch
        .iter()
        .flat_map(|s| s.engine_features.to_vec())
        .collect();
    let labels: Vec<i64> = batch.iter().map(|s| s.label).collect();

    let token_tensor =
        Tensor::<B, 2, Int>::from_data(TensorData::new(padded, [n, max_len]), device);
    let feat_tensor = Tensor::<B, 2, Float>::from_data(
        TensorData::new(feats, [n, features::ENGINE_FEATURE_COUNT]),
        device,
    );
    let label_tensor = Tensor::<B, 1, Int>::from_data(TensorData::new(labels, [n]), device);

    let output = model.forward_batch(token_tensor, feat_tensor); // [batch, 1]
    loss_fn.forward(output.squeeze_dim::<1>(1), label_tensor)
}

#[derive(Default, Clone, Copy)]
struct ValidMetrics {
    loss: f64,
    correct: usize,
    total: usize,
    accuracy: f32,
}

fn evaluate(
    model: &ApkClassifier<B>,
    loss_fn: &burn::nn::loss::BinaryCrossEntropyLoss<B>,
    device: &burn::backend::ndarray::NdArrayDevice,
    valid: &[Sample],
) -> ValidMetrics {
    let mut m = ValidMetrics::default();
    m.total = valid.len();
    if valid.is_empty() {
        return m;
    }

    let mut total_loss = 0.0f64;
    let mut n_chunks = 0usize;

    for chunk in valid.chunks(16) {
        let n = chunk.len();
        let max_len = chunk.iter().map(|s| s.tokens.len()).max().unwrap_or(1);
        let mut padded = vec![0i64; n * max_len];
        for (row, sample) in chunk.iter().enumerate() {
            for (j, t) in sample.tokens.iter().take(max_len).enumerate() {
                padded[row * max_len + j] = *t;
            }
        }
        let feats: Vec<f32> = chunk.iter().flat_map(|s| s.engine_features.to_vec()).collect();
        let labels: Vec<i64> = chunk.iter().map(|s| s.label).collect();

        // Evaluate on the plain (non-autodiff) backend in mini-batches.
        let token_tensor = Tensor::<NdArray<f32>, 2, Int>::from_data(
            TensorData::new(padded, [n, max_len]),
            device,
        );
        let feat_tensor = Tensor::<NdArray<f32>, 2, Float>::from_data(
            TensorData::new(feats, [n, features::ENGINE_FEATURE_COUNT]),
            device,
        );
        let label_tensor =
            Tensor::<NdArray<f32>, 1, Int>::from_data(TensorData::new(labels.clone(), [n]), device);

        let output = model.valid().forward_batch(token_tensor, feat_tensor);
        let loss = loss_fn
            .valid()
            .forward(output.clone().squeeze_dim::<1>(1), label_tensor);
        total_loss += loss.into_scalar() as f64;
        n_chunks += 1;

        let data = output.into_data();
        let probs = data.to_vec::<f32>().unwrap_or_default();
        for (i, p) in probs.iter().enumerate() {
            let pred = if *p >= 0.5 { 1 } else { 0 };
            if pred == labels[i] {
                m.correct += 1;
            }
        }
    }

    m.loss = total_loss / n_chunks.max(1) as f64;
    m.accuracy = m.correct as f32 / m.total as f32;
    m
}