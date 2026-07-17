# hydradragonml

Pure-Rust ONNX-based APK malware binary classifier. Feature extraction from
APK strings (manifest, dex, resources) → 256-d vector → tract-onnx inference.

## Dataset scanner (CLI)

```powershell
# Build
cd hydradragonml
cargo build --release

# Feature extraction only (no model / whitelist)
.\target\release\hydradragonml-scan.exe --dataset ..\dataset\

# Full scan: NSRL whitelist + package whitelist + ML model
.\target\release\hydradragonml-scan.exe --dataset ..\dataset\ --model ..\app\src\main\assets\scan\model.onnx --whitelist ..\app\src\main\assets\scan\whitelist.xf --packages ..\app\src\main\assets\scan\whitelist_packages.db --threshold 0.5
```

Scan pipeline per APK:

1. **NSRL hash whitelist** (`whitelist.xf`) → `NSRL.Whitelist` (stats only)
2. **Package whitelist** (`whitelist_packages.db`) → `Package.Whitelist` (stats only)
3. **ML model** (`model.onnx`) → `ML.Benign` / `ML.Malware` with confidence (always runs)

Output includes per-file verdict, matching signatures, package name, MD5,
and a summary with accuracy / precision / recall / F1 vs folder labels.

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
