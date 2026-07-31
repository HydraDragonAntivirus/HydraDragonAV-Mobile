# hydradragonml

Pure-Rust ONNX-based APK malware binary classifier. Feature extraction from
APK strings (manifest, dex, resources) → vocabulary tokenization →
EmbeddingBag → ONNX inference.

## Architecture

1. **Tokenizer** (`features::Tokenizer`) loads `vocab.json` (20K subword tokens),
   harvests printable strings from APK entries, splits on delimiters, and
   maps each fragment to a vocabulary index (0 = UNK).
2. **Model** (`Model`) runs the tokenized indices through an ONNX graph:
   `Gather → ReduceMean → Linear(64→32) → ReLU → Linear(32→1) → Sigmoid`.
3. **Output**: confidence `0.0` (benign) to `1.0` (malware).

The MinHash pipeline (`features::extract_minhash`) is kept for benign-DB
lookups and uses FNV-1a hashing (unchanged).

## Dataset scanner (CLI)

```powershell
cd hydradragonml
cargo build --release

.\target\release\hydradragonml-scan.exe --dataset ..\dataset\ --model model.onnx --vocab vocab.json --threshold 0.5
```

## Training the model

```powershell
pip install torch numpy
python ..\train_model.py ..\dataset\
```

This walks `dataset/benign/` and `dataset/malware/`, builds a 20K-token
vocabulary, trains an EmbeddingBag + MLP classifier, and exports
`model.onnx` + `vocab.json`.

## Library

```rust
use hydradragonml::Model;

let model_bytes = std::fs::read("model.onnx")?;
let vocab_bytes = std::fs::read("vocab.json")?;
let model = Model::load(&model_bytes, &vocab_bytes)?;
let apk = std::fs::read("sample.apk")?;
let result = model.scan(&apk).unwrap();
println!("malicious={} confidence={}", result.malicious, result.confidence);
```

## On-device (Android)

Ship `model.onnx` + `vocab.json` as app assets. The JNI bridge in
`hydradragonandroid` loads both at init and calls `Model::scan` per APK.
