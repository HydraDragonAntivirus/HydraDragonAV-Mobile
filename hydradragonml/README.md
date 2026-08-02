# hydradragonml

Pure-Rust [Burn](https://burn.dev) (wgpu) malware/benign APK binary classifier.
Feature extraction from APK strings (manifest, dex, resources) → vocabulary
tokenization → Embedding + mean-pool fused with 26 engine features → MLP →
sigmoid confidence. Training and inference both run in Rust; weights ship as a
`.mpk` file that the Android engine loads at runtime.

## Architecture

1. **Tokenizer** (`features::Tokenizer`) loads `vocab.json` (20K subword tokens,
   `0` = UNK), harvests printable strings from APK entries (entry names,
   `AndroidManifest.xml`, `resources.arsc`, `*.dex`, `META-INF/`), splits on
   delimiters, and maps each fragment to a vocabulary index.
2. **Model** (`model::ApkClassifier`) embeds the token indices and mean-pools
   them, passes the pooled text vector and the 26 normalized engine features
   through a small MLP, and outputs a sigmoid confidence:
   - text branch: `Embedding(20K → 64) → mean-pool → Linear(64 → 32) → ReLU`
   - engine branch: `Linear(26 → 32) → ReLU`
   - fused: `concat → Linear(64 → 32) → ReLU → Linear(32 → 1) → Sigmoid`
3. **Output**: confidence `0.0` (benign) to `1.0` (malware). `>= 0.95`
   malicious, `>= 0.90` suspicious (see `DEFAULT_CONFIDENCE_THRESHOLD` /
   `SUSPICIOUS_THRESHOLD` in `lib.rs`).

The engine features (`EngineFeatures`) mirror the signals the Android engine
extracts during a real scan (DEX/ELF/manifest/URL/IP/cert/benign-DB/media/
HIPS), normalized to `[0, 1]`. The MinHash pipeline (`features::extract_minhash`)
is kept for benign-DB lookups and uses FNV-1a hashing (unchanged).

## Training the model

```powershell
cd hydradragonml
cargo build --release

.\target\release\hydradragonml-train.exe `
    --benign ..\dataset\benign --malware ..\dataset\malware `
    --vocab ..\vocab.json --output model.mpk `
    [--epochs 6] [--lr 0.001] [--batch-size 8]
```

This walks `--benign/` and `--malware/` recursively for `.apk`/`.zip` files,
tokenizes each and extracts its engine features, splits 80/20 into train/valid,
trains `ApkClassifier` with Adam + binary cross-entropy (LR halves each epoch),
and saves the weights as a Burn `.mpk` file (`model.mpk`), copying `vocab.json`
next to it for deployment.

`--vocab` must be the same `vocab.json` shipped in the Android assets; it has to
be built over the same corpus so training and inference tokenize identically.

## Dataset scanner (CLI)

```powershell
cd hydradragonml
cargo build --release

.\target\release\hydradragonml-scan.exe `
    --dataset ..\dataset\ --model model.mpk --vocab vocab.json --threshold 0.5
```

Walks the dataset for `.apk` files, scores each with the model, prints per-file
verdicts (MALICIOUS/BENIGN + confidence), and reports TP/FP/TN/FN,
accuracy/precision/recall/F1 against the benign/malware folder labels.

## Library

```rust
use hydradragonml::Model;

let model_bytes = std::fs::read("model.mpk")?;
let vocab_bytes = std::fs::read("vocab.json")?;
let device = burn_wgpu::WgpuDevice::default();
let model = Model::load(&model_bytes, &vocab_bytes, device)?;
let apk = std::fs::read("sample.apk")?;
let result = model.scan(&apk).unwrap();
println!("malicious={} suspicious={} confidence={}",
         result.malicious, result.suspicious, result.confidence);
```

## On-device (Android)

Ship `model.mpk` + `vocab.json` as app assets. The JNI bridge in
`hydradragonandroid` loads both at init (`hydradragonml::Model::load`) and calls
`Model::scan_with_features` per APK with the live engine features.
