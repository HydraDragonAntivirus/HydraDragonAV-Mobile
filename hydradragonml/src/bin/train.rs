//! HydraDragonML training binary.
//!
//! Trains the Burn [`ApkClassifier`] (text tokens + Android engine features)
//! on a benign/malware APK corpus and saves the weights as a `.mpk` file that
//! the Android engine loads at runtime.
//!
//! ```text
//! cargo run --release --bin hydradragonml-train -- \
//!     --benign ./benign --malware ./malware \
//!     --vocab vocab.json --output model.mpk [--epochs 6] [--lr 0.001]
//! ```
//!
//! The `--vocab` file is the same `vocab.json` shipped in the Android assets;
//! it must be built over the same corpus so training and inference tokenize
//! identically.

use burn::module::AutodiffModule;
use burn::nn::loss::BinaryCrossEntropyLossConfig;
use burn::optim::{AdamConfig, GradientsParams, Optimizer};
use burn::tensor::{Float, Int, Tensor, TensorData};
use burn::backend::NdArray;
use burn_autodiff::Autodiff;
use hydradragonml::features::{self, EngineFeatures, Tokenizer};
use hydradragonml::model::ApkClassifier;
use std::io::Read;
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
                    batch_size = val()?.parse().map_err(|_| "invalid --batch-size".to_string())?
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

    eprintln!("Training for {} epochs (lr={}, batch_size={})", args.epochs, args.lr, args.batch_size);
    let start = std::time::Instant::now();
    let mut model = model;

    for epoch in 1..=args.epochs {
        let epoch_lr = args.lr * (0.5f64.powi((epoch - 1) as i32));
        let mut epoch_loss = 0.0f64;
        let mut n_batches = 0usize;

        let mut batch_rows: Vec<Vec<i64>> = Vec::new();
        let mut batch_feats: Vec<f32> = Vec::new();
        let mut batch_labels: Vec<i64> = Vec::new();

        for sample in &samples {
            if sample.tokens.is_empty() {
                continue;
            }
            batch_rows.push(sample.tokens.clone());
            batch_feats.extend(sample.engine_features.to_vec());
            batch_labels.push(sample.label);

            if batch_rows.len() >= args.batch_size
                || batch_rows.iter().map(|r| r.len()).sum::<usize>() >= 16_000
            {
                let loss = forward_loss(&model, &loss_fn, &device, &batch_rows, &batch_feats, &batch_labels);
                epoch_loss += loss.clone().into_scalar() as f64;
                n_batches += 1;

                let grads = loss.backward();
                let grads = GradientsParams::from_grads(grads, &model);
                model = optim.step(epoch_lr, model, grads);

                batch_rows.clear();
                batch_feats.clear();
                batch_labels.clear();
            }
        }
        if !batch_rows.is_empty() {
            let loss = forward_loss(&model, &loss_fn, &device, &batch_rows, &batch_feats, &batch_labels);
            epoch_loss += loss.clone().into_scalar() as f64;
            n_batches += 1;
            let grads = loss.backward();
            let grads = GradientsParams::from_grads(grads, &model);
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

    // Save the trained weights (convert from Autodiff to the plain Wgpu backend).
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
        let Ok(bytes) = std::fs::read(path) else { continue };
        let Some(tokens) = tokenizer.tokenize(&bytes) else { continue };
        let engine_features = engine_features_from_apk(&bytes);
        out.push(Sample { tokens, engine_features, label });
        if out.len() % 50 == 0 {
            eprintln!("  ... {}/{}", out.len(), entries.len());
        }
    }
    out
}

fn collect_apks(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
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

/// Build the engine-feature vector from raw APK bytes, mirroring the features
/// the Android engine extracts during a scan (a training-time approximation of
/// the `EngineFeatures` produced by `build_engine_features` in the Android
/// crate — fields the trainer cannot compute (emulation, IP/TLSH/cert lookups,
/// benign-DB) are left at their neutral defaults).
fn engine_features_from_apk(apk: &[u8]) -> EngineFeatures {
    use std::io::Cursor;

    let mut feats = EngineFeatures::default();
    let reader = Cursor::new(apk);
    let Ok(mut archive) = zip::ZipArchive::new(reader) else {
        return feats;
    };

    let mut manifest_bytes: Option<Vec<u8>> = None;
    let mut elf_count = 0usize;

    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.name().to_ascii_lowercase();

        if name == "androidmanifest.xml" {
            let mut buf = Vec::new();
            if entry.by_ref().take(8 * 1024 * 1024).read_to_end(&mut buf).is_ok() {
                manifest_bytes = Some(buf);
            }
        } else if name.ends_with(".so") || name.ends_with(".dylib") {
            elf_count += 1;
        }
    }
    feats.elf_count = elf_count as f32;

    if let Some(manifest) = manifest_bytes {
        let manifest = parse_manifest_minimal(&manifest);
        feats.manifest_total_permissions = manifest.permissions as f32;
        feats.manifest_dangerous_permissions = manifest.dangerous_permissions as f32;
        feats.manifest_activities = manifest.activities as f32;
        feats.manifest_services = manifest.services as f32;
        feats.manifest_receivers = manifest.receivers as f32;
        feats.manifest_min_sdk = manifest.min_sdk.unwrap_or(0) as f32;
        feats.manifest_target_sdk = manifest.target_sdk.unwrap_or(0) as f32;
    }

    feats
}



// ── minimal AXML manifest parsing (subset of the Android crate's parser) ────

struct ManifestMinimal {
    permissions: usize,
    dangerous_permissions: usize,
    activities: usize,
    services: usize,
    receivers: usize,
    min_sdk: Option<i64>,
    target_sdk: Option<i64>,
}

const DANGEROUS_PERMS: &[&str] = &[
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.WRITE_SMS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.BODY_SENSORS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.NEARBY_WIFI_DEVICES",
];

fn parse_manifest_minimal(data: &[u8]) -> ManifestMinimal {
    let mut m = ManifestMinimal {
        permissions: 0,
        dangerous_permissions: 0,
        activities: 0,
        services: 0,
        receivers: 0,
        min_sdk: None,
        target_sdk: None,
    };
    let Some(strings) = axml_strings(data) else { return m };
    // Count uses-permission strings and component element names from the string
    // pool + element chunks.
    for s in &strings {
        if let Some(perm) = s.strip_prefix("android.permission.") {
            if !perm.is_empty() {
                m.permissions += 1;
            }
            if DANGEROUS_PERMS.contains(&s.as_str()) {
                m.dangerous_permissions += 1;
            }
        }
    }
    let pool_size = rd_u32(data, 8 + 4).unwrap_or(0) as usize;
    let mut off = 8 + pool_size;
    let mut guard = 0;
    while off + 8 <= data.len() && guard < 200_000 {
        guard += 1;
        let ctype = rd_u16(data, off).unwrap_or(0);
        let csize = rd_u32(data, off + 4).unwrap_or(0) as usize;
        if csize == 0 {
            break;
        }
        if ctype == 0x0102 {
            let name_idx = rd_u32(data, off + 20).unwrap_or(0) as usize;
            let ename = strings.get(name_idx).map(|s| s.as_str()).unwrap_or("");
            match ename {
                "activity" => m.activities += 1,
                "service" => m.services += 1,
                "receiver" => m.receivers += 1,
                "uses-sdk" => {
                    let attr_start = rd_u16(data, off + 24).unwrap_or(0) as usize;
                    let attr_count = rd_u16(data, off + 28).unwrap_or(0) as usize;
                    let abase = off + 16 + attr_start;
                    for i in 0..attr_count.min(16) {
                        let a = abase + i * 20;
                        let aname = rd_u32(data, a + 4).unwrap_or(0) as usize;
                        let aname = strings.get(aname).map(|s| s.as_str()).unwrap_or("");
                        let ty = rd_u16(data, a + 12).unwrap_or(0);
                        // TYPE_INT_DEC = 0x10, TYPE_INT_HEX = 0x11
                        if ty == 0x10 || ty == 0x11 {
                            let v = rd_u32(data, a + 16).unwrap_or(0) as i64;
                            match aname {
                                "minSdkVersion" => m.min_sdk = Some(v),
                                "targetSdkVersion" => m.target_sdk = Some(v),
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        off = off.checked_add(csize).unwrap_or(data.len());
    }
    m
}

fn rd_u16(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn rd_u32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn axml_strings(data: &[u8]) -> Option<Vec<String>> {
    let pool = 8usize;
    if rd_u16(data, pool)? != 0x0001 {
        return None;
    }
    let count = rd_u32(data, pool + 8)? as usize;
    let flags = rd_u32(data, pool + 16)?;
    let strings_start = rd_u32(data, pool + 20)? as usize;
    let is_utf8 = flags & (1 << 8) != 0;
    let offsets_base = pool + 28;
    let data_base = pool + strings_start;
    let mut out = Vec::with_capacity(count.min(8192));
    for i in 0..count.min(50_000) {
        let off = rd_u32(data, offsets_base + i * 4)? as usize;
        let p = data_base + off;
        let s = if is_utf8 {
            let (q, _) = axml_len8(data, p)?;
            let (q, n) = axml_len8(data, q)?;
            String::from_utf8_lossy(data.get(q..q + n)?).into_owned()
        } else {
            let (q, n) = axml_len16(data, p)?;
            let mut s = String::with_capacity(n);
            for j in 0..n {
                s.push(char::from_u32(rd_u16(data, q + j * 2)? as u32).unwrap_or('\u{FFFD}'));
            }
            s
        };
        out.push(s);
    }
    Some(out)
}

fn axml_len8(d: &[u8], o: usize) -> Option<(usize, usize)> {
    let b0 = *d.get(o)? as usize;
    if b0 & 0x80 != 0 {
        let b1 = *d.get(o + 1)? as usize;
        Some((o + 2, ((b0 & 0x7f) << 8) | b1))
    } else {
        Some((o + 1, b0))
    }
}

fn axml_len16(d: &[u8], o: usize) -> Option<(usize, usize)> {
    let w0 = rd_u16(d, o)? as usize;
    if w0 & 0x8000 != 0 {
        let w1 = rd_u16(d, o + 2)? as usize;
        Some((o + 4, ((w0 & 0x7fff) << 16) | w1))
    } else {
        Some((o + 2, w0))
    }
}

// ── training step ───────────────────────────────────────────────────────────

/// Forward the batch and return the mean BCE loss. `rows` is the list of
/// per-sample token sequences; each is padded to the batch `max_len` so a
/// single 2-D embedding lookup + mean-pool reproduces the per-sample pooling
/// in `ApkClassifier::forward`.
fn forward_loss(
    model: &ApkClassifier<B>,
    loss_fn: &burn::nn::loss::BinaryCrossEntropyLoss<B>,
    device: &burn::backend::ndarray::NdArrayDevice,
    rows: &[Vec<i64>],
    feats: &[f32],
    labels: &[i64],
) -> Tensor<B, 1, Float> {
    let n = rows.len();
    let max_len = rows.iter().map(|r| r.len()).max().unwrap_or(1);
    let mut padded = vec![0i64; n * max_len];
    for (row, seq) in rows.iter().enumerate() {
        for (j, t) in seq.iter().take(max_len).enumerate() {
            padded[row * max_len + j] = *t;
        }
    }

    let token_tensor = Tensor::<B, 2, Int>::from_data(
        TensorData::new(padded, [n, max_len]),
        device,
    );
    let feat_tensor = Tensor::<B, 2, Float>::from_data(
        TensorData::new(feats.to_vec(), [n, features::ENGINE_FEATURE_COUNT]),
        device,
    );
    let label_tensor = Tensor::<B, 1, Int>::from_data(
        TensorData::new(labels.to_vec(), [n]),
        device,
    );

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
        let rows: Vec<Vec<i64>> = chunk.iter().map(|s| s.tokens.clone()).collect();
        let max_len = rows.iter().map(|r| r.len()).max().unwrap_or(1);
        let n = rows.len();
        let mut padded = vec![0i64; n * max_len];
        for (row, seq) in rows.iter().enumerate() {
            for (j, t) in seq.iter().take(max_len).enumerate() {
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
        let label_tensor = Tensor::<NdArray<f32>, 1, Int>::from_data(
            TensorData::new(labels.clone(), [n]),
            device,
        );

        let output = model.valid().forward_batch(token_tensor, feat_tensor);
        let loss = loss_fn.valid().forward(output.clone().squeeze_dim::<1>(1), label_tensor);
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
