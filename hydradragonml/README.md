# hydradragonml

Pure-Rust **one-class** APK malware detector. Trained on malware only — **no benign
set required**. It is the generalising successor to the per-file YARA set in
`yara-x/machine_learning_apk.yar`: instead of exact strings, it matches APKs by
similarity and anomaly.

## How it works

1. **Feature extraction** (`features.rs`) — an APK is a ZIP. We harvest printable
   ASCII + UTF-16LE strings from `AndroidManifest.xml`, `resources.arsc`, every
   `classes*.dex`, and `META-INF/*`, plus all entry names. Permissions, API
   descriptors (`Landroid/...`), URLs, and native lib names survive as tokens.
   Produces a token set (for MinHash) and a 256-d feature-hashed vector (for the
   forest).
2. **MinHash + LSH** (`minhash.rs`) — 128-permutation MinHash signature per APK,
   LSH-banded for fast candidate lookup. Estimates Jaccard similarity to every
   known sample → catches repacks / variants the exact YARA rules miss.
3. **Isolation Forest** (`iforest.rs`) — one-class anomaly score over the dense
   vector. APKs resembling the malware corpus score LOW; outliers score HIGH.

A scan is flagged when **either** signal fires:
`jaccard >= 0.55` **or** `anomaly <= <learned 97th-percentile of training scores>`.
Thresholds favour recall (deployment whitelists known-good apps upstream).

Training is deterministic (fixed RNG seed) — same corpus ⇒ identical model.

## Usage

```sh
# Train (offline, on desktop)
cargo run --release --bin hydra-ml-train -- <apk_dir> apk_model.json

# Scan a file or a directory
cargo run --release --bin hydra-ml-scan -- apk_model.json <apk_or_dir>
cargo run --release --bin hydra-ml-scan -- apk_model.json <apk_or_dir> --json
```

Tuning: `--jaccard 0.5` (lower = more recall), `--trees 200`.

## On-device (Android)

Keep training **offline**. Ship `apk_model.json` as an app asset and call
`Model::load_json` + `Model::scan` from a thin JNI wrapper next to YARA-X. The
model loads once; scanning is a feature pass + 128 hashes + ~150 short tree
walks — cheap enough for on-device use.

## Getting to a *real* supervised classifier

The moment you add a benign APK set (F-Droid + top Play apps), the same
`features.rs` vectors feed a proper binary classifier (logistic regression or a
small MLP) that will beat one-class methods. The feature layer is already shared.
