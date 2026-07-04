param(
    [string]$Abi = "arm64-v8a,armeabi-v7a,x86_64,x86",
    [string]$NdkHome = "",
    [string]$Configuration = "release"
)

$ErrorActionPreference = "Stop"

# ---------- NDK ----------
if (-not $NdkHome) {
    $candidates = @(
        "${env:LOCALAPPDATA}\Android\Sdk\ndk",
        "${env:USERPROFILE}\AppData\Local\Android\Sdk\ndk",
        "C:\Android\Sdk\ndk"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) {
            $latest = Get-ChildItem $c -Directory | Sort-Object Name -Descending | Select-Object -First 1
            if ($latest) { $NdkHome = $latest.FullName; break }
        }
    }
}
if (-not $NdkHome -or -not (Test-Path "$NdkHome\build\cmake\android.toolchain.cmake")) {
    Write-Error "NDK not found. Set -NdkHome or install Android NDK."
    exit 1
}
$env:ANDROID_NDK_HOME = $NdkHome

# ---------- Rust targets ----------
$targetMap = @{
    "arm64-v8a"   = "aarch64-linux-android"
    "armeabi-v7a" = "armv7-linux-androideabi"
    "x86_64"      = "x86_64-linux-android"
    "x86"         = "i686-linux-android"
}
$abiList = $Abi -split ","
foreach ($a in $abiList) {
    rustup target add $targetMap[$a.Trim()]
}

# ---------- cargo-ndk ----------
if (-not (Get-Command "cargo-ndk" -ErrorAction SilentlyContinue)) {
    cargo install cargo-ndk
}

# ---------- Unicorn bypass ----------
$unicornInstall = "$env:LOCALAPPDATA\unicorn-android"
$unicornPcDir = "$unicornInstall\lib\pkgconfig"
$unicornSrc = Join-Path (Split-Path $PSScriptRoot -Parent) "third_party\unicorn"

if (-not (Test-Path "$unicornPcDir\unicorn.pc")) {
    Write-Host "Building Unicorn Engine..."
    if (-not (Test-Path "$unicornSrc\CMakeLists.txt")) {
        git clone --depth 1 https://github.com/unicorn-engine/unicorn $unicornSrc
    }
    foreach ($a in $abiList) {
        $abi = $a.Trim()
        $buildDir = "$env:TEMP\unicorn-$abi"
        New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
        Push-Location $buildDir
        cmake $unicornSrc -G "Ninja" `
            -DCMAKE_TOOLCHAIN_FILE="$NdkHome\build\cmake\android.toolchain.cmake" `
            -DANDROID_ABI="$abi" -DANDROID_NATIVE_API_LEVEL=21 `
            -DCMAKE_INSTALL_PREFIX="$unicornInstall" `
            -DUNICORN_BUILD_TESTS=OFF -DUNICORN_BUILD_FUZZ=OFF | Out-Null
        cmake --build . --target install | Out-Null
        Pop-Location
    }
}
$env:PKG_CONFIG_PATH = $unicornPcDir
$env:PKG_CONFIG_ALLOW_CROSS = "1"

# ---------- cargo ndk ----------
$cfg = if ($Configuration -eq "release") { "--release" } else { "" }
$targetList = ($abiList | ForEach-Object { $targetMap[$_.Trim()] }) -join ","
cargo ndk -t $targetList build $cfg

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
    }
}
