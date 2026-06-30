@echo off
setlocal enabledelayedexpansion

:: Run from this script's own directory so relative paths resolve correctly
:: regardless of the caller's working directory.
cd /d "%~dp0"

set GUAVA_VERSION=33.0.0-android
set GUAVA_JAR=guava-%GUAVA_VERSION%.jar
set GUAVA_URL=https://repo1.maven.org/maven2/com/google/guava/guava/%GUAVA_VERSION%/guava-%GUAVA_VERSION%.jar

:: Download Guava if not present
if not exist "%GUAVA_JAR%" (
    echo Downloading Guava %GUAVA_VERSION%...
    powershell -Command "Invoke-WebRequest -Uri '%GUAVA_URL%' -OutFile '%GUAVA_JAR%'"
    if !ERRORLEVEL! neq 0 (
        echo Failed to download Guava
        exit /b 1
    )
)

set ASSETS=..\..\app\src\main\assets

if not exist "%ASSETS%\malicious_domains.txt" (
    echo %ASSETS%\malicious_domains.txt not found - run gen_domain_bloom.py first
    exit /b 1
)

:: Compile once
echo Compiling BloomWriter.java...
javac -cp "%GUAVA_JAR%" -source 17 -target 17 BloomWriter.java
if !ERRORLEVEL! neq 0 (
    echo Compilation failed
    exit /b 1
)

:: Every domain/URL bloom is checked against each browsed domain, and (because
:: fpp is per-bloom, not per-entry) each one at 1e-4 contributes ~1e-4 to the
:: stacked false-positive rate. To drive the per-domain FP to ~1e-6 they ALL
:: use the tight 1e-6 fpp. malicious is the union of every category, so it's the
:: largest, but every bloom uses the same target.
set FPP=0.000001
set FPP_MALICIOUS=0.000001

:: Generate one .bloom per "<name>_domains.txt" file. This covers every
:: category written by gen_domain_bloom.py (phishing, malwareurl, malware,
:: abuse, mining, spam, malicious_mail, phishing_urls) plus the combined
:: "malicious_domains.txt" -> malicious.bloom. Each filter is sized to its
:: own entry count so small categories stay small.
for %%F in ("%ASSETS%\*_domains.txt") do (
    set "TXT=%%~fF"
    set "BASE=%%~nF"
    set "NAME=!BASE:_domains=!"
    set "OUT=%ASSETS%\!NAME!.bloom"

    set "COUNT=0"
    for /f %%C in ('find /v /c "" ^< "!TXT!"') do set "COUNT=%%C"
    if !COUNT! lss 1 set "COUNT=1"

    set "THIS_FPP=%FPP%"
    if /i "!NAME!"=="malicious" set "THIS_FPP=%FPP_MALICIOUS%"

    echo Generating !NAME!.bloom from !COUNT! entries (fpp=!THIS_FPP!)...
    java -Xmx6g -cp ".;%GUAVA_JAR%" BloomWriter "!TXT!" "!OUT!" !COUNT! !THIS_FPP!
    if !ERRORLEVEL! neq 0 (
        echo Bloom generation failed for !NAME!
        exit /b 1
    )
)

echo Done.
