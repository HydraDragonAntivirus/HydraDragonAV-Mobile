# hydradragonandroid

JNI bridge that scans APKs on-device by combining:

1. **`hydradragonclamav`** YARA engine over three compiled rulesets:
   - `clean_rules_filtered_verified.yrc`
   - `valhalla-rules_filtered_verified.yrc`
   - `AndroidOS_filtered.yrc`
2. **`hydradragonml`** ONNX malware/benign binary classifier (`model.onnx`).

An APK is flagged **malicious** if any YARA ruleset matches **or** the ML model
flags it (confidence >= 0.5). (Whitelisting happens upstream, so recall is
favoured.)

## Native methods

Bound to `com.hydradragon.antivirus.engine.NativeScanner`:

| Java | Native |
|------|--------|
| `boolean nativeInit(String dir)` | load `.yrc` rulesets + `model.onnx` from `dir` |
| `String nativeScanApk(String path)` | scan one APK → JSON verdict |

Verdict JSON:
```json
{"malicious":true,
 "yara":["AndroidOS_filtered.yrc::YARA.Some_Rule"],
 "ml":{"malicious":true,"jaccard":0.87,"anomaly":0.87,"nearest":null}}
```

## Prerequisites

- [Android NDK](https://developer.android.com/ndk/downloads) (tested with r27)
- Rust Android targets:
  ```sh
  rustup target add aarch64-linux-android armv7-linux-androideabi \
                    x86_64-linux-android i686-linux-android
  ```
- `cargo-ndk`:
  ```sh
  cargo install cargo-ndk
  ```
- [Unicorn Engine](https://github.com/unicorn-engine/unicorn) must be built
  separately with the NDK (see [Cross build with NDK](#cross-build-with-ndk)).

## Build the .so

```cmd
build-android.cmd
```

The script auto-detects the NDK path, builds Unicorn Engine (one-time cache),
builds all four ABIs via `cargo ndk`, and copies the `.so` files into
`app/src/main/jniLibs/<abi>/`.

## Cross build with NDK

Unicorn Engine's cmake build requires the NDK toolchain. Build it once:

```sh
git clone https://github.com/unicorn-engine/unicorn /tmp/unicorn
cd /tmp/unicorn && mkdir build && cd build
cmake .. \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_NATIVE_API_LEVEL=21 \
  -DCMAKE_INSTALL_PREFIX=$PWD/install
make -j$(nproc)
make install
export PKG_CONFIG_PATH=/tmp/unicorn/build/install/lib/pkgconfig
export PKG_CONFIG_ALLOW_CROSS=1
cargo ndk -t arm64-v8a build --release
```

Gradle bundles `jniLibs/` and `app/src/main/assets/*.yrc|model.onnx`
automatically — no `build.gradle` changes needed.

## Use from the app

`ScanEngine` already calls `NativeScanner.init(context)` in its constructor and
exposes `nativeScanApk(String)`. Direct use:

```java
NativeScanner.init(context);                          // once
String verdict = NativeScanner.scanApk(apkFilePath);  // per APK
```

## Refreshing rules / model

1. Re-run `yara_filter.py` → regenerate `*_filtered_verified.yar`.
2. Recompile to `.yrc` with `hydradragon_yara_x_compile`.
3. Train a new ONNX model in Python with your malware + benign dataset.
4. Copy the `.yrc` + `model.onnx` into `app/src/main/assets/`.
   (Bump a version so `NativeScanner.init` re-copies — currently it re-copies
   only when an asset is missing or zero-length.)
