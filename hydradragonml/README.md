# hydradragonml

Pure-Rust [Burn](https://burn.dev) (NdArray) malware/benign APK binary
classifier. Real, content-derived features are parsed straight from the APK
(DEX structure, native ELF libraries and `AndroidManifest.xml`) with the same
parsers used by the Android engine, then fed through an Embedding + mean-pool
text branch fused with the engine features in an MLP → sigmoid confidence.
Training and inference both run in Rust; weights ship as a `.mpk` file that the
Android engine loads at runtime.

## A note on the model architecture

The classifier is deliberately a **simple, classic architecture** — a mean-pooled
token embedding (a "bag of subwords" text branch, with no positional or
sequential modeling) fused with a shallow MLP over the engine features. This is
not a modern sequence model (no attention, no RNN/CNN over the token stream);
it's closer to a 2015-era text-classification baseline. That's an intentional
trade-off for this use case, not an oversight:

- **On-device budget**: the whole model (embedding table + a handful of small
  `Linear` layers) is a few MB and runs inference in single-digit milliseconds
  on a phone CPU, with no GPU/accelerator dependency.
- **Interpretability**: a shallow MLP over 18 named, human-checkable engine
  features (`dump-apk-features`) is much easier to audit and debug than a deep
  sequence model's internals.
- **Bare-APK data budget**: subword mean-pooling degrades gracefully with the
  amount of realistic labeled training data available for a niche
  binary-classification task; a large transformer would likely overfit or
  need far more data to earn its extra capacity.

The trade-off is real, though: mean-pooling discards token order, so the text
branch can't learn phrase-level or call-sequence patterns — it's essentially a
weighted vocabulary-presence signal. If false-negative rate on
order-sensitive obfuscation patterns becomes a problem, the natural upgrade
path is a small 1D-CNN or single-layer Transformer over the token embeddings
in place of the mean-pool, without touching the engine-feature branch or the
DEX/ELF/manifest parsers.

## Architecture

1. **Parsers** (`features::dex`, `features::elf`, `features::axml`) extract real
   content from APK entries: DEX class/string/API-call counts, ELF
   emulator/network/file/exec strings and anti-debug markers, and manifest
   permissions (dangerous/total), activities, services, receivers and
   min/target SDK. This is the **single source of truth** for both training and
   on-device inference (`EngineFeatures::extract_from_apk`). Archive reading
   itself goes through `ripzip` (parsing the ZIP central directory straight
   from the in-memory APK bytes) with `flate2` handling DEFLATE decompression
   for individual entries.
2. **Tokenizer** (`features::Tokenizer`) loads `vocab.json` (20K subword tokens,
   `0` = UNK), harvests printable strings from APK entries (entry names,
   `AndroidManifest.xml`, `resources.arsc`, `*.dex`, `META-INF/`), splits on
   delimiters, and maps each fragment to a vocabulary index.
3. **Model** (`model::ApkClassifier`) embeds the token indices and mean-pools
   them, passes the pooled text vector and the 18 normalized engine features
   through a small MLP, and outputs a sigmoid confidence:
   - text branch: `Embedding(20K → 64) → mean-pool → Linear(64 → 32) → ReLU`
   - engine branch: `Linear(18 → 32) → ReLU`
   - fused: `concat → Linear(64 → 32) → ReLU → Linear(32 → 1) → Sigmoid`
4. **Output**: confidence `0.0` (benign) to `1.0` (malware). `>= 0.95`
   malicious, `>= 0.90` suspicious (see `DEFAULT_CONFIDENCE_THRESHOLD` /
   `SUSPICIOUS_THRESHOLD` in `lib.rs`).

The engine features (`EngineFeatures`) are 18 content-derived values that the
Android engine can compute from a bare APK: 5 DEX structure counts, 6 native
ELF library signals and 7 manifest fields — all normalized to `[0, 1]`.
External/reputation-style signals (URL/IP blocklists, certificate test-key
flags, benign-DB similarity, media steganography, runtime HIPS findings) are
deliberately NOT part of the learned representation: they are neither available
at training time from a bare APK nor comparable between training and on-device
inference. The MinHash pipeline (`features::extract_minhash`) is kept for
benign-DB lookups and uses FNV-1a hashing (unchanged).

> ⚠️ **`.mpk` weight compatibility**: the engine-feature vector width is a
> fixed constant (`features::ENGINE_FEATURE_COUNT`, currently 19) baked into
> `ApkClassifier`'s `fc_engine` layer shape. Any change to that constant means
> previously trained `.mpk` weights will fail to load (`load_record` shape
> mismatch) and the model must be retrained from scratch.

## Building the vocabulary

The `vocab.json` token vocabulary is built over the same corpus that trains the
model, so training and inference tokenize identically.

```powershell
cargo build --release; .\target\release\hydradragonml-vocab.exe --corpus ..\dataset\benign,..\dataset\malware --output vocab.json
```

## Training the model

```powershell
cargo build --release; .\target\release\hydradragonml-train.exe --benign ..\dataset\benign --malware ..\dataset\malware --vocab vocab.json --output model.mpk --epochs 6 --lr 0.001 --batch-size 8
```

This walks `--benign/` and `--malware/` recursively for `.apk`/`.zip` files,
extracts each file's engine features (`EngineFeatures::extract_from_apk`) and
tokenizes it, splits 80/20 into train/valid, trains `ApkClassifier` with Adam +
binary cross-entropy (LR halves each epoch), and saves the weights as a Burn
`.mpk` file (`model.mpk`), copying `vocab.json` next to it for deployment.

`--vocab` must be the same `vocab.json` shipped in the Android assets; it has to
be built over the same corpus so training and inference tokenize identically.

## Dataset scanner (CLI)

```powershell
cargo build --release; .\target\release\hydradragonml-scan.exe --dataset ..\dataset\ --model model.mpk --vocab vocab.json --threshold 0.5
```

Walks the dataset for `.apk` files, scores each with the model, prints per-file
verdicts (MALICIOUS/BENIGN + confidence), and reports TP/FP/TN/FN,
accuracy/precision/recall/F1 against the benign/malware folder labels. The scan
binary builds the real engine features with `EngineFeatures::extract_from_apk`,
so CLI metrics reflect actual on-device runtime behaviour.

## Inspecting extracted features

```powershell
cargo build --release; .\target\release\dump-apk-features.exe ..\com.ttech.android.onlineislem_base.apk
```

Prints the raw DEX/ELF/manifest feature values for a single APK — useful to
verify the parsers and understand what a particular verdict is based on.

## Library

```rust
use hydradragonml::Model;

let model_bytes = std::fs::read("model.mpk")?;
let vocab_bytes = std::fs::read("vocab.json")?;
let device = burn::backend::ndarray::NdArrayDevice::default();
let model = Model::load(&model_bytes, &vocab_bytes, device)?;
let apk = std::fs::read("sample.apk")?;
let result = model.scan_with_features(&apk, &hydradragonml::features::EngineFeatures::extract_from_apk(&apk).unwrap_or_default());
println!("malicious={} suspicious={} confidence={}",
         result.malicious, result.suspicious, result.confidence);
```

## On-device (Android)

Ship `model.mpk` + `vocab.json` as app assets. The JNI bridge in
`hydradragonandroid` loads both at init (`hydradragonml::Model::load`) and calls
`Model::scan_with_features` per APK with the live engine features built by
`hydradragonandroid::build_engine_features` (DEX/ELF/manifest content only).
