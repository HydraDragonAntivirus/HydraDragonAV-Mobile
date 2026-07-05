param(
    [string]$Abi = "arm64-v8a,armeabi-v7a,x86_64,x86",
    [string]$NdkHome = "",
    [string]$Configuration = "release"
)

$ErrorActionPreference = "Stop"

# ---------- NDK ----------
$sdkRoot = "${env:LOCALAPPDATA}\Android\Sdk"
if (-not $NdkHome) {
    $ndkDir = "$sdkRoot\ndk"
    if (Test-Path $ndkDir) {
        $latest = Get-ChildItem $ndkDir -Directory | Sort-Object Name -Descending | Select-Object -First 1
        if ($latest) { $NdkHome = $latest.FullName }
    }
}
if (-not $NdkHome -or -not (Test-Path "$NdkHome\build\cmake\android.toolchain.cmake")) {
    Write-Error "NDK not found at $sdkRoot\ndk\. Install NDK via Android Studio: SDK Manager > SDK Tools > NDK"
    exit 1
}
$env:ANDROID_NDK_HOME = $NdkHome
$env:ANDROID_HOME = $sdkRoot
$env:ANDROID_SDK_ROOT = $sdkRoot

# Tell cmake-rs / cmake where the NDK toolchain file lives (needed by
# unicorn-engine-sys and similar crates that use cmake-rs for Android).
$env:CMAKE_TOOLCHAIN_FILE = "$NdkHome\build\cmake\android.toolchain.cmake"

# Add Git Bash's usr/bin to PATH so cmake can run `sh` (needed by unicorn's
# QEMU configure scripts to generate config-host.h and config-target.h).
$gitBin = "C:\Program Files\Git\usr\bin"
if (Test-Path "$gitBin\sh.exe") { $env:PATH = "$gitBin;$env:PATH" }

Write-Host "NDK: $NdkHome"

# ---------- Rust targets ----------
$targetMap = @{
    "arm64-v8a"   = "aarch64-linux-android"
    "armeabi-v7a" = "armv7-linux-androideabi"
    "x86_64"      = "x86_64-linux-android"
    "x86"         = "i686-linux-android"
}
$abiList = $Abi -split ","
$origEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
foreach ($a in $abiList) {
    $t = $targetMap[$a.Trim()]
    Write-Host "rustup target add $t..."
    rustup target add $t 2>&1 | Out-Null
}
$ErrorActionPreference = $origEap

# ---------- cargo-ndk ----------
if (-not (Get-Command "cargo-ndk" -ErrorAction SilentlyContinue)) {
    Write-Host "Installing cargo-ndk..."
    cargo install cargo-ndk
}

# ---------- Pre-fetch crate sources so the registry source is available ------
Write-Host "Fetching crate sources..."
Push-Location $PSScriptRoot
cargo fetch --quiet 2>&1 | Out-Null
Pop-Location

# ---------- Unicorn per-ABI build (pkg-config bypass) ----------
# Build unicorn from the registry's bundled source with NDK cmake per-ABI,
# then set PKG_CONFIG_PATH so unicorn-engine-sys build.rs finds the .pc file
# and skips its own broken cmake-rs cross-compile step.
$unicornRoot = "$env:LOCALAPPDATA\unicorn-android"
$env:PKG_CONFIG_ALLOW_CROSS = "1"

$registrySrc = "$env:USERPROFILE\.cargo\registry\src"
$unicornDir = Get-ChildItem "$registrySrc\index.crates.io-*\unicorn-engine-sys-2.1.5" -Directory `
    | Select-Object -First 1
if (-not $unicornDir) {
    Write-Warning "unicorn-engine-sys source not found in registry; falling back to cmake-rs path"
}

foreach ($a in $abiList) {
    $abi = $a.Trim()
    $triple = $targetMap[$abi]
    $installDir = "$unicornRoot\$abi"
    $pcDir = "$installDir\lib\pkgconfig"

    if ($unicornDir -and -not (Test-Path "$pcDir\unicorn.pc")) {
        Write-Host "Building Unicorn for $abi from $($unicornDir.Name)..."
        $buildDir = "$env:TEMP\unicorn-$abi"
        New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

        # Patch unicorn source for NDK r27 compatibility
        $int128 = Join-Path $unicornDir.FullName "qemu/include/qemu/int128.h"
        $osdep  = Join-Path $unicornDir.FullName "qemu/util/osdep.c"
        if (-not ((Get-Content $int128 -Raw) -match "__SIZEOF_INT128__")) {
            Write-Host "Patching int128.h for NDK r27..."
            $ic = Get-Content $int128 -Raw
            $rep = "#ifndef __SIZEOF_INT128__`ntypedef Int128 __int128_t;`n#endif"
            $ic = $ic.Replace("typedef Int128 __int128_t;", $rep)
            Set-Content -Path $int128 -Value $ic -NoNewline
        }
        if (-not ((Get-Content $osdep -Raw) -match "sys/mman.h")) {
            Write-Host "Patching osdep.c for NDK r27..."
            $oc = Get-Content $osdep -Raw
            $oc = $oc.Replace('#include "qemu/cutils.h"', '#include "qemu/cutils.h"`n#include <sys/mman.h>')
            Set-Content -Path $osdep -Value $oc -NoNewline
        }
        # Also patch oslib-posix.c which uses mmap/munmap family
        $oslib = Join-Path $unicornDir.FullName "qemu/util/oslib-posix.c"
        if (-not ((Get-Content $oslib -Raw) -match "sys/mman.h")) {
            Write-Host "Patching oslib-posix.c for NDK r27..."
            $ol = Get-Content $oslib -Raw
            $ol = $ol.Replace('#include "qemu/osdep.h"', '#include "qemu/osdep.h"`n#include <sys/mman.h>')
            Set-Content -Path $oslib -Value $ol -NoNewline
        }

        Push-Location $buildDir
        cmake "$($unicornDir.FullName)" -G "Ninja" `
            -DCMAKE_TOOLCHAIN_FILE="$NdkHome\build\cmake\android.toolchain.cmake" `
            -DANDROID_ABI="$abi" -DANDROID_NATIVE_API_LEVEL=21 `
            -DCMAKE_INSTALL_PREFIX="$installDir" `
            -DUNICORN_BUILD_TESTS=OFF
        if ($LASTEXITCODE -ne 0) { throw "cmake configure failed for $abi" }

        # If config-host.h is empty/stub (cmake's sh-based qemu configure
        # scripts fail on Windows without Git Bash in PATH), create minimal
        # config files so compilation can proceed.
        $ch = "$buildDir\config-host.h"
        if ((Get-Item $ch -ErrorAction SilentlyContinue).Length -eq 0) {
            Write-Host "config-host.h empty; creating stubs for NDK r27..."
            Set-Content -Path $ch -Value "#define CONFIG_POSIX 1`n#define CONFIG_LINUX 1`n"
            foreach ($td in @("x86_64-softmmu","arm-softmmu","aarch64-softmmu","mips-softmmu","mipsel-softmmu","mips64-softmmu","mips64el-softmmu","sparc-softmmu","sparc64-softmmu","ppc-softmmu","ppc64-softmmu","riscv32-softmmu","riscv64-softmmu","s390x-softmmu","tricore-softmmu","m68k-softmmu")) {
                $tdir = "$buildDir\$td"
                New-Item -ItemType Directory -Force -Path $tdir | Out-Null
                Set-Content -Path "$tdir\config-target.h" -Value "/* stub */`n"
            }
        }
        cmake --build . --target install
        if ($LASTEXITCODE -ne 0) { throw "cmake build failed for $abi" }
        Pop-Location
        Write-Host "Unicorn $abi built and installed"
    }

    if ($unicornDir) { $env:PKG_CONFIG_PATH = $pcDir }

    $cfg = if ($Configuration -eq "release") { "--release" } else { "" }
    Write-Host "Building hydradragonandroid for $abi ($triple)..."
    Push-Location $PSScriptRoot
    cargo ndk -t $triple build $cfg
    if ($LASTEXITCODE -ne 0) { throw "cargo ndk failed for $abi" }
    Pop-Location
}

# ---------- Copy to jniLibs ----------
$jniRoot = Join-Path (Split-Path $PSScriptRoot -Parent) "app\src\main\jniLibs"
foreach ($a in $abiList) {
    $abi = $a.Trim()
    $triple = $targetMap[$abi]
    $src = Join-Path $PSScriptRoot "target\$triple\$Configuration\libhydradragonandroid.so"
    $dstDir = Join-Path $jniRoot $abi
    New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
    if (Test-Path $src) {
        Copy-Item -Force $src (Join-Path $dstDir "libhydradragonandroid.so")
        Write-Host "$abi OK"
    } else {
        Write-Error "Missing $src"
    }
}
Write-Host "Done"
