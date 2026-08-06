# hydradragonml

Pure-Rust [Burn](https://burn.dev) (NdArray) malware/benign APK binary classifier.
Real, content-derived features are parsed straight from the APK — DEX structure,
native ELF libraries and `AndroidManifest.xml` — with the same parsers the
Android engine uses. Tokenized APK text and the engine features are fused in a
small MLP that outputs a `[0, 1]` sigmoid confidence. Training and inference
both run in Rust; weights ship as a `.mpk` file the Android engine loads at
runtime.

## Architecture

1. **Parsers** (`features::dex`, `features::elf`, `features::axml`) extract real
   content from APK entries:
   - DEX: class count, string count, method reference count (raw `method_ids`
     table size — no framework-prefix filter, no curated API lists).
   - ELF: number of structurally valid native libraries (`lib/**/*.so`).
   - AXML: manifest total permissions, activities, services, receivers,
     min/target SDK.
   Plus one Shannon-entropy feature over the decompressed code-bearing entries
   (DEX/ELF/manifest content). There are **no hardcoded lists or caps** anywhere
   in this crate — every feature is a plain count/size derived from the file.
   This is the **single source of truth** for both training and on-device
   inference (`EngineFeatures::extract_from_apk`). Archive reading goes through
   `ripzip` (ZIP central directory parsed straight from the in-memory APK bytes)
   with `flate2` for DEFLATE decompression.
2. **Tokenizer** (`features::Tokenizer`) loads a `vocab.json` subword vocabulary
   (`0` = UNK), harvests printable ASCII / UTF-16LE strings from APK entry names
   and the contents of `AndroidManifest.xml`, `resources.arsc`, `*.dex` and
   `META-INF/*`, splits on delimiters and maps fragments to vocabulary ids
   (capped at `MAX_TOKENS`).
3. **Normalization** (`features::FeaturePercentiles`) is corpus-derived, never
   hardcoded: at train time the raw per-feature values over the whole corpus are
   sorted column-wise and persisted to `features.json`; each value is mapped to
   its interpolated rank percentile in `[0, 1]`. Inference loads the same
   `features.json`, so an out-of-distribution giant APK lands *at the top of the
   training distribution* instead of being clipped by an arbitrary cap.
4. **Model** (`model::ApkClassifier`):
   - text branch: `Embedding(20K -> 64) -> mean-pool over sequence ->
     Linear(64 -> 32) -> ReLU`
   - engine branch: `Linear(11 -> 32) -> ReLU`
   - fused head: `cat([text, engine]) -> Linear(64 -> 32) -> ReLU ->
     Linear(32 -> 1) -> Sigmoid`
   The output is a single malware probability; `forward_batch(tokens, engine)`
   serves training/validation and `forward(tokens, engine)` serves the
   single-sample scan path. Both operate on token id tensors and the 11
   percentile-normalized engine features.
5. **Output**: confidence `0.0` (benign) to `1.0` (malware). `>= 0.95`
   malicious, `>= 0.90` suspicious (`DEFAULT_CONFIDENCE_THRESHOLD` /
   `SUSPICIOUS_THRESHOLD` in `lib.rs`).

The 11 `EngineFeatures` are content-derived values the Android engine can
compute from a bare APK: 3 DEX structure counts, 1 native ELF count, 6 manifest
fields and 1 content-entropy value — all raw, normalized only by the
corpus-derived percentile stats (`features::FeaturePercentiles`).
External/reputation-style signals (URL blocklists, certificate flags,
benign-DB similarity, HIPS findings) are not part of the learned
representation: they are neither available at training time from a bare APK nor
comparable between training and on-device inference.

> ⚠️ **`.mpk` weight compatibility**: the engine-feature vector width
> (`features::ENGINE_FEATURE_COUNT`, 11) and vocabulary size
> (`features::VOCAB_SIZE`) are baked into `ApkClassifier` layer shapes. Changing
> either invalidates previously trained `.mpk` weights (`load_record` shape
> mismatch) and requires retraining from scratch. The `features.json` percentile
> stats must also come from the same training run that produced the `.mpk`.

### Generalization, not memorization

The classifier learns a decision boundary over *patterns*; it is **not** a
lookup table of the training samples. A direct consequence:

- It can score a malware APK **below the malicious threshold even when that
  sample came from its own training corpus** — the model never stores a copy of
  any APK, so it can fail to re-flag samples it was literally trained on.
- Conversely, it can flag an *unseen* sample that shares malware-like structure.

That trade-off is intentional: a model that merely memorized its corpus would be
useless against novel, mutated or packed malware — it would only ever re-flag
exactly what it had already seen, which is not detection. Treat the ML confidence
as one corroborating signal alongside the YARA-X/ClamAV signatures and the other
engines, never as an exact-match database. The thresholds are deliberately
conservative (`>= 0.95` malicious, `>= 0.90` suspicious), and the ML layer is
designed to generalize rather than recite.

## Building the vocabulary

If no `vocab.json` exists, build one over the same corpus that trains the
model (same tokenization rules as `features::Tokenizer`, so training and
inference tokenize identically):

```powershell
cargo run --release --bin hydradragonml-build-vocab -- --benign ..\dataset\benign --malware ..\dataset\malware --output vocab.json --size 20000 --min-count 2
```

Tokens are ranked by corpus frequency; id `0` is `<UNK>`, and `--size` is
capped at `VOCAB_SIZE` (20000).

## Training

```powershell
cargo build --release; .\target\release\hydradragonml-train.exe --benign ..\dataset\benign --malware ..\dataset\malware --vocab vocab.json --output model.mpk --epochs 6 --lr 0.001 --batch-size 8
```

Walks `--benign/` and `--malware/` recursively for `.apk`/`.zip` files, extracts
each file's engine features and token ids, derives the corpus percentile stats,
normalizes every sample, splits 80/20 into train/valid, trains
`ApkClassifier` with Adam + binary cross-entropy (LR halves every epoch via a
step scheduler), prints mean normalized engine features per class for a quick
corpus audit, and saves weights as a Burn `.mpk`, writing `features.json`
(percentile stats) and copying `vocab.json` next to it for deployment.

`--vocab` must be the same `vocab.json` shipped in the Android assets, and the
produced `features.json` must ship alongside the `.mpk`.

## Dataset scanner (CLI)

```powershell
cargo build --release; .\target\release\hydradragonml-scan.exe --dataset ..\dataset\ --model model.mpk --vocab vocab.json --features features.json --threshold 0.5
```

Walks the dataset for `.apk` files, scores each with the model, prints per-file
verdicts (MALICIOUS / SUSPICIOUS / BENIGN + confidence) and reports
TP/FP/TN/FN, accuracy/precision/recall/F1 against the benign/malware folder
labels. The scan binary builds the real engine features with
`EngineFeatures::extract_from_apk` and normalizes them with the shipped
`features.json`, so CLI metrics reflect actual on-device runtime behaviour.

## Library

```rust
use hydradragonml::features::FeaturePercentiles;
use hydradragonml::Model;

let model_bytes = std::fs::read("model.mpk")?;
let vocab_bytes = std::fs::read("vocab.json")?;
let features_bytes = std::fs::read("features.json")?;
let feature_stats = FeaturePercentiles::from_json_bytes(&features_bytes)?;
let device = burn::backend::ndarray::NdArrayDevice::default();
let model = Model::load(&model_bytes, &vocab_bytes, feature_stats, device)?;
let apk = std::fs::read("sample.apk")?;
let result = model.scan_with_features(&apk, &hydradragonml::features::EngineFeatures::extract_from_apk(&apk).unwrap_or_default());
println!("malicious={} suspicious={} confidence={}",
         result.malicious, result.suspicious, result.confidence);
```

## On-device (Android)

Ship `model.mpk` + `vocab.json` + `features.json` as app assets. The JNI bridge
loads all three at init (`Model::load`) and calls `Model::scan_with_features`
per APK with live engine features built by the Android side (DEX/ELF/manifest
content only).
