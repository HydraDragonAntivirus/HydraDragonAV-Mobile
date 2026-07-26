param(
    [string]$Abi = "arm64-v8a,armeabi-v7a,x86_64,x86",
    [string]$NdkHome = "",
    # "release" -> optimized, stripped, LTO (shipped build)
    # "debug"   -> plain `cargo ndk build`, full debug_assertions, unoptimized
    # Falls back to $env:HYDRADRAGON_BUILD_CONFIGURATION when -Configuration
    # isn't passed, so you can `setx HYDRADRAGON_BUILD_CONFIGURATION debug`
    # once and just run build-android.cmd with no args from then on.
    [ValidateSet("release", "debug")]
    [string]$Configuration = $(if ($env:HYDRADRAGON_BUILD_CONFIGURATION) { $env:HYDRADRAGON_BUILD_CONFIGURATION } else { "release" }),
    [Alias("t")]
    [switch]$Test,
    [Alias("h", "?")]
    [switch]$Help
)

if ($Help) {
    Write-Host @"
build-android.ps1 - Build libhydradragonandroid.so per ABI and copy into app/src/main/jniLibs

USAGE:
  build-android.cmd [-Abi <list>] [-NdkHome <path>] [-Configuration <release|debug>]
  build-android.ps1 [-Abi <list>] [-NdkHome <path>] [-Configuration <release|debug>]

PARAMETERS:
  -Abi <list>            Comma-separated ABIs to build. Default:
                          arm64-v8a,armeabi-v7a,x86_64,x86
  -NdkHome <path>        Path to the Android NDK. Auto-detected from
                          %LOCALAPPDATA%\Android\Sdk\ndk if not given.
  -Configuration <mode>  release  Optimized, stripped, LTO (shipped build).
                          debug    Plain `cargo ndk build`: full debug_assertions,
                                   unoptimized.
                          Default: release, or `$env:HYDRADRAGON_BUILD_CONFIGURATION`
                          if that environment variable is set.
  -Help, -h, -?          Show this help and exit.

EXAMPLES:
  build-android.cmd
  build-android.cmd -Configuration debug
  build-android.cmd -Abi arm64-v8a -Configuration debug
"@
    exit 0
}

$ErrorActionPreference = "Stop"

# ---------- Test mode (skips NDK build) ----------
if ($Test) {
    Push-Location $PSScriptRoot
    cargo test --lib suricata_scan 2>&1
    $ok = $LASTEXITCODE
    Pop-Location
    exit $ok
}

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

# Add Git Bash's usr/bin to PATH so cmake (via cmake-rs in unicorn-engine-sys
# build.rs) can run `sh` for QEMU configure scripts (config-host.h).
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

# ---------- per-ABI cargo-ndk build ----------
# unicorn-engine-sys is now a git dependency whose build.rs defines
# ANDROID_ABI so cmake-rs cross-compiles correctly with the NDK
# toolchain (CMAKE_TOOLCHAIN_FILE set above). No manual unicorn
# C-source build or pkg-config bypass needed.
$env:PKG_CONFIG_ALLOW_CROSS = "1"

foreach ($a in $abiList) {
    $abi = $a.Trim()
    $triple = $targetMap[$abi]

    $buildArgs = @()
    if ($Configuration -eq "release") { $buildArgs = @("--release") }
    Write-Host "Building hydradragonandroid for $abi ($triple) [$Configuration]..."
    Push-Location $PSScriptRoot
    cargo ndk -t $triple build @buildArgs
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
