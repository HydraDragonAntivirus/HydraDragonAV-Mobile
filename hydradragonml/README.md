# hydradragonml

Pure-Rust ONNX-based APK malware binary classifier. Feature extraction from
APK strings (manifest, dex, resources) → 256-d vector → tract-onnx inference.

## Feature Engineering

Feature set is intentionally minimal: printable strings from
`AndroidManifest.xml`, `resources.arsc`, `classes*.dex`, and `META-INF/*`
are harvested, hashed into 256 bins, and L2-normalized.

Why not add opcode n-grams, ELF analysis, CFG features, etc.?

- **Curse of dimensionality**: more features than training samples causes
  the model to memorize noise instead of learning patterns.
- **Overfitting**: each new feature is another axis the model can exploit
  to separate training data by accident. On unseen malware the extra
  features degrade detection.
- **Feature decay**: opcodes, API call graphs, ELF structures change
  rapidly across Android versions. String-based features (permissions,
  URLs, class names) are more stable across malware families and versions.
- **Model size**: more features means a larger ONNX graph, more RAM on
  the device, and slower inference. 256-d is a proven trade-off.

## Dataset scanner (CLI)

```powershell
# Build
cd hydradragonml
cargo build --release

# Feature extraction only (no model)
.\target\release\hydradragonml-scan.exe --dataset ..\dataset\

# Full scan with ML model (--model is required for actual inference)
.\target\release\hydradragonml-scan.exe --dataset ..\dataset\ --model ..\app\src\main\assets\scan\model.onnx --threshold 0.5
```

Without `--model`, inference is skipped — every APK shows `BENIGN` with
`confidence=0.0000` and `total time = 0 ms`. Always pass `--model` for
real detection. Scan pipeline per APK:

1. **ML model** (`model.onnx`) → `BENIGN` / `MALICIOUS` with confidence

Output includes per-file verdict, confidence score, and a summary with
accuracy / precision / recall / F1 vs folder labels.

## Library

```rust
use hydradragonml::Model;

let model = Model::load_bin("model.onnx")?;
let apk = std::fs::read("sample.apk")?;
let result = model.scan(&apk);
println!("malicious={} confidence={}", result.malicious, result.confidence);
```

## On-device (Android)

Ship `model.onnx` as an app asset. The JNI bridge in `hydradragonandroid`
loads it once at init and calls `Model::scan` per APK buffer as part of
the full scan pipeline (ClamAV + YARA-X + ML + TLSH).
