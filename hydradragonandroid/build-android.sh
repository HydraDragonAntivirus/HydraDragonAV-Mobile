#!/usr/bin/env bash
# Cross-compile libhydradragonandroid.so for Android and place it under the
# app's jniLibs so gradle bundles it into the APK automatically.
#
# Prerequisites (one-time):
#   rustup target add aarch64-linux-android armv7-linux-androideabi \
#                     x86_64-linux-android i686-linux-android
#   cargo install cargo-ndk
#   # Android NDK installed; set ANDROID_NDK_HOME (e.g. ~/Android/Sdk/ndk/26.x)
#
# Usage:
#   ./build-android.sh            # builds all 4 ABIs, release
set -euo pipefail

cd "$(dirname "$0")"

JNILIBS="../app/src/main/jniLibs"
# minSdk in app/build.gradle is 26.
API=26

# arm64-v8a, armeabi-v7a, x86_64, x86 — covers phones + emulators.
# NOTE: cargo-ndk 4.x renamed the API-level flag — it is now `--platform`
# (the old short `-p` is forwarded to cargo as `--package`, which fails).
cargo ndk \
  -t arm64-v8a \
  -t armeabi-v7a \
  -t x86_64 \
  -t x86 \
  --platform "$API" \
  -o "$JNILIBS" \
  build --release

echo "Built .so into $JNILIBS:"
find "$JNILIBS" -name 'libhydradragonandroid.so' -exec ls -lh {} \;
