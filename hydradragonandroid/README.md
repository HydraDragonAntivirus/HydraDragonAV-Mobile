# hydradragonandroid

JNI bridge that scans APKs on-device by combining:

1. **`hydradragonclamav`** YARA engine over three compiled rulesets:
   - `clean_rules_filtered_verified.yrc`
   - `valhalla-rules_filtered_verified.yrc`
   - `AndroidOS_filtered.yrc`
2. **`hydradragonml`** one-class model (`apk_model.json`) — MinHash/LSH +
   Isolation Forest.

An APK is flagged **malicious** if any YARA ruleset matches **or** the ML model
flags it. (Whitelisting happens upstream, so recall is favoured.)

## Native methods

Bound to `com.hydradragon.antivirus.engine.NativeScanner`:

| Java | Native |
|------|--------|
| `boolean nativeInit(String dir)` | load `.yrc` rulesets + `apk_model.json` from `dir` |
| `String nativeScanApk(String path)` | scan one APK → JSON verdict |

Verdict JSON:
```json
{"malicious":true,
 "yara":["AndroidOS_filtered.yrc::YARA.Some_Rule"],
 "ml":{"malicious":false,"jaccard":0.61,"anomaly":0.42,"nearest":"<sha>"}}
```

## Build the .so

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi \
                  x86_64-linux-android i686-linux-android
cargo install cargo-ndk            # needs Android NDK + ANDROID_NDK_HOME
./build-android.sh                 # -> app/src/main/jniLibs/<abi>/libhydradragonandroid.so
```

Gradle bundles `jniLibs/` and `app/src/main/assets/*.yrc|apk_model.json`
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
3. Retrain the model with `hydra-ml-train` if needed.
4. Copy the `.yrc` + `apk_model.json` into `app/src/main/assets/`.
   (Bump a version so `NativeScanner.init` re-copies — currently it re-copies
   only when an asset is missing or zero-length.)
