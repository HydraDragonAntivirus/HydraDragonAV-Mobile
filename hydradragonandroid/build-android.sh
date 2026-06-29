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

# --- NDK r27+ pthread/rt stub fix -------------------------------------------
# On Android, pthread/rt symbols live inside libc; there is no standalone
# libpthread/librt. Older NDKs shipped empty libpthread.a / librt.a compat
# stubs, but NDK r27 removed them. Some native C deps pulled in by
# hydradragonextractor (zstd-sys, bzip2, unrar_sys, lzma) still emit
# `-lpthread`, so the link fails on r27 with "unable to find library -lpthread".
# Recreate the empty stubs (idempotent) next to every libc.so in the sysroot.
if [ -n "${ANDROID_NDK_HOME:-}" ]; then
  _prebuilt=$(echo "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/)
  _ar="${_prebuilt}bin/llvm-ar"
  _sys="${_prebuilt}sysroot/usr/lib"
  if [ -x "$_ar" ] && [ -d "$_sys" ]; then
    # mktemp -u: a NAME only, not an existing empty file — otherwise llvm-ar
    # tries to load the 0-byte file as an archive and fails ("too small").
    _stub=$(mktemp -u)
    "$_ar" rcs "$_stub"            # creates a valid (empty) static archive
    while IFS= read -r _libc; do
      _d=$(dirname "$_libc")
      # Always overwrite: ensures any previously-written 0-byte/bad stub is
      # replaced by the valid empty archive.
      cp -f "$_stub" "$_d/libpthread.a"
      cp -f "$_stub" "$_d/librt.a"
    done < <(find "$_sys" -name 'libc.so')
    rm -f "$_stub"
    echo "Ensured libpthread.a / librt.a stubs in NDK sysroot."
  fi
fi
# ----------------------------------------------------------------------------

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
