# hydradragonml

Pure-Rust ONNX-based APK malware binary classifier. Feature extraction from
APK strings (manifest, dex, resources) → 256-d vector → tract-onnx inference.

## Dataset scanner (CLI)

```powershell
# Build
cd hydradragonml
cargo build --release

# Feature extraction only (no model)
.\target\release\hydradragonml-scan.exe --dataset ..\dataset\

# Full scan with ML model
.\target\release\hydradragonml-scan.exe --dataset ..\dataset\ --model ..\app\src\main\assets\scan\model.onnx --threshold 0.5
```

Scan pipeline per APK:

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
