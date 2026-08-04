# HydraDragon ML Engine (`hydradragonml`)

`hydradragonml` is a high-performance, Rust-native malware and benign Android APK binary classifier powered by the [Burn](https://burn.dev) deep learning framework and `ripzip` for ultra-fast, zero-copy APK ZIP parsing.

## Key Features

- **Burn 0.21 Neural Network (`ApkClassifier`)**: Combines embedding bag mean-pooling over APK string tokens with 18 content-derived static analysis features (`EngineFeatures`).
- **Zero-Copy Arhive Processing (`ripzip`)**: Reads APK ZIP entries (`classes*.dex`, `AndroidManifest.xml`, `lib/**/*.so`) directly out of in-memory byte slices without external zip dependencies.
- **Content-Derived Feature Extraction**:
  - **DEX Analysis**: Class counts, string counts, framework API call counts, high & critical severity API usage findings (dynamic code loading, reflection, shell execution, premium SMS).
  - **AXML Analysis**: Binary AndroidManifest parsing for dangerous permissions, total permissions, components (activities, services, receivers), and SDK version targets.
  - **ELF Native Analysis**: Section header parsing for dynamic symbol import classification (network calls, file I/O, process execution, anti-debugging, emulator detection strings).
- **Standalone Scanning CLI (`hydradragonml-scan`)**: Scan single APK files or directories recursively with human-readable or JSON output.
- **Standalone Training Binary (`hydradragonml-train`)**: Train the model on labeled benign and malware APK corpora using a manual Burn training loop with Adam optimizer and binary cross-entropy loss.

---

## ⚡ Quick Reference

```bash
# Build all binaries
cargo build --release

# Run all tests
cargo test

# Scan a single APK
cargo run --release --bin hydradragonml-scan -- --model model.mpk --vocab vocab.json target.apk

# Scan a directory (JSON output)
cargo run --release --bin hydradragonml-scan -- --model model.mpk --vocab vocab.json --json ../dataset/

# Build vocab from corpus (run this first, before training)
cargo run --release --bin hydradragonml-build-vocab -- --benign ../dataset/benign --malware ../dataset/malware --output vocab.json

# Build vocab with custom size
cargo run --release --bin hydradragonml-build-vocab -- --benign ../dataset/benign --malware ../dataset/malware --output vocab.json --vocab-size 20000

# Train a new model
cargo run --release --bin hydradragonml-train -- --benign ../dataset/benign --malware ../dataset/malware --vocab vocab.json --output model.mpk

# Train with custom hyperparameters
cargo run --release --bin hydradragonml-train -- --benign ../dataset/benign --malware ../dataset/malware --vocab vocab.json --output model.mpk --epochs 10 --lr 0.0005 --batch-size 16

# Scan with custom confidence threshold
cargo run --release --bin hydradragonml-scan -- --model model.mpk --vocab vocab.json --threshold 0.90 target.apk
```

> **Note on dataset paths:** If executing commands from inside `hydradragonml/`, use `../dataset/` (since `dataset/` is located at the root of the repository). If running from the root repository, add `--manifest-path hydradragonml/Cargo.toml` and use `./dataset/`.

---

## Workspace Architecture

```
hydradragonml/
├── Cargo.toml
├── src/
│   ├── lib.rs              # High-level Model API & scanner entry points
│   ├── main.rs             # `hydradragonml-scan` CLI tool
│   ├── model.rs            # Burn 0.21 ApkClassifier network module
│   ├── bin/
│   │   └── train.rs        # `hydradragonml-train` binary
│   └── features/
│       ├── mod.rs          # Re-exports feature extraction modules
│       ├── features.rs     # EngineFeatures, Tokenizer & MinHash extraction
│       ├── axml.rs         # Binary AndroidManifest.xml parser
│       ├── dex.rs          # Dalvik Executable (DEX) parser
│       └── elf.rs          # ELF32/64 native shared library parser
```

---

## Dataset & Training Setup

### 1. Dataset Directory Structure

Organize your dataset into two directories containing `.apk` or `.zip` files:

```
dataset/
├── benign/
│   ├── app1.apk
│   ├── app2.apk
│   └── ...
└── malware/
    ├── mal1.apk
    ├── mal2.apk
    └── ...
```

### 2. Vocabulary File (`vocab.json`)

The tokenizer uses a JSON vocabulary mapping string tokens to token IDs (0 reserved for `<UNK>`):

```json
{
  "<UNK>": 0,
  "android": 1,
  "permission": 2,
  "classes": 3,
  "telephony": 4,
  "sms": 5
}
```

### 3. Training the Model (`hydradragonml-train`)

Run `hydradragonml-train` to train the classifier:

```bash
cargo run --bin hydradragonml-train -- \
    --benign path/to/benign/ \
    --malware path/to/malware/ \
    --vocab path/to/vocab.json \
    --output model.mpk \
    --epochs 10 \
    --lr 0.001 \
    --batch-size 16
```

#### Training Arguments

| Argument | Description | Default |
|---|---|---|
| `--benign <dir>` | Directory containing clean/benign APKs (**Required**) | - |
| `--malware <dir>` | Directory containing malware APKs (**Required**) | - |
| `--vocab <path>` | Path to `vocab.json` (**Required**) | - |
| `--output <path>` | Output weights file path | `model.mpk` |
| `--epochs <n>` | Number of training epochs | `6` |
| `--lr <float>` | Initial learning rate | `0.001` |
| `--batch-size <n>` | Training batch size | `8` |

The training process shuffles samples, splits into an 80/20 train/validation split, prints epoch loss & accuracy metrics, and saves the final weights (`model.mpk`) along with copying `vocab.json` to the output directory.

---

## Running Scans (`hydradragonml-scan`)

Use `hydradragonml-scan` to evaluate APK files or entire directories against a trained model:

```bash
cargo run --bin hydradragonml-scan -- \
    --model model.mpk \
    --vocab vocab.json \
    --threshold 0.95 \
    path/to/apk_or_directory
```

### Options

- `--model <file>`: Path to model weights (default: `model.mpk`).
- `--vocab <file>`: Path to vocabulary JSON (default: `vocab.json`).
- `--threshold <f32>`: Confidence threshold for malicious verdicts (default: `0.95`).
- `--json`: Output verdicts in JSON lines format.

### Example JSON Output

```json
{"file":"samples/suspicious_app.apk","malicious":true,"suspicious":false,"confidence":0.9874}
```

---

## Using `hydradragonml` as a Rust Library

Add `hydradragonml` to your `Cargo.toml`:

```toml
[dependencies]
hydradragonml = { path = "../hydradragonml" }
burn = { version = "0.21", default-features = false, features = ["ndarray"] }
```

### Loading and Scanning in Code

```rust
use hydradragonml::{Model, DEFAULT_CONFIDENCE_THRESHOLD};
use burn::backend::ndarray::NdArrayDevice;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device = NdArrayDevice::default();
    let model_bytes = std::fs::read("model.mpk")?;
    let vocab_bytes = std::fs::read("vocab.json")?;

    let model = Model::load(&model_bytes, &vocab_bytes, device)?;

    let apk_bytes = std::fs::read("target_sample.apk")?;
    if let Some(result) = model.scan(&apk_bytes) {
        println!("Malicious: {}", result.malicious);
        println!("Suspicious: {}", result.suspicious);
        println!("Confidence: {:.2}%", result.confidence * 100.0);
    }

    Ok(())
}
```
