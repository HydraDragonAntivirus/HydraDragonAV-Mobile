use std::env;
use std::path::{Path, PathBuf};

// unicorn-engine's vendored QEMU/TCG JIT emits __builtin___clear_cache() after
// writing translated code (qemu/tcg/*/tcg-target.h). On Android that builtin
// lowers to an external call to `__clear_cache`, which bionic's libc.so does
// NOT export -- it must come from the NDK's compiler-rt builtins archive.
// cargo-ndk's linker invocation doesn't pull that archive in for symbols
// referenced only by cmake-built C objects, so the final .so ships an
// undefined `__clear_cache` and dlopen() fails at runtime with
// "cannot locate symbol \"__clear_cache\"". Force-link the archive here so
// the symbol is resolved statically at build time instead.
fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    if !target.contains("android") {
        return;
    }

    let arch = match target.as_str() {
        t if t.contains("aarch64") => "aarch64",
        t if t.contains("armv7") => "arm",
        t if t.contains("x86_64") => "x86_64",
        t if t.contains("i686") => "i686",
        _ => return,
    };

    let Some(lib_dir) = find_compiler_rt_dir(arch) else {
        println!(
            "cargo:warning=hydradragonandroid: could not locate libclang_rt.builtins-{arch}-android.a under ANDROID_NDK_HOME; __clear_cache may be left unresolved"
        );
        return;
    };

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    // Plain `-lstatic=` only pulls object files the linker already has a
    // pending undefined symbol for *at the point it consults this archive*
    // on the command line; ordering relative to unicorn's static lib isn't
    // guaranteed, which left __clear_cache unresolved in practice. Force the
    // whole archive in so its symbols (incl. __clear_cache) are always
    // defined, regardless of link order.
    println!("cargo:rustc-link-lib=static:+whole-archive=clang_rt.builtins-{arch}-android");
}

fn find_compiler_rt_dir(arch: &str) -> Option<PathBuf> {
    let ndk_home = env::var("ANDROID_NDK_HOME")
        .or_else(|_| env::var("ANDROID_NDK_ROOT"))
        .or_else(|_| env::var("NDK_HOME"))
        .ok()?;
    let prebuilt = Path::new(&ndk_home).join("toolchains/llvm/prebuilt");
    let host_dir = std::fs::read_dir(&prebuilt)
        .ok()?
        .filter_map(Result::ok)
        .find(|e| e.path().is_dir())?
        .path();

    let clang_dir = host_dir.join("lib/clang");
    let clang_ver_dir = std::fs::read_dir(&clang_dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .max()?; // pick the highest clang version directory present

    let lib_dir = clang_ver_dir.join("lib/linux");
    let archive = lib_dir.join(format!("libclang_rt.builtins-{arch}-android.a"));
    if archive.is_file() {
        Some(lib_dir)
    } else {
        None
    }
}
