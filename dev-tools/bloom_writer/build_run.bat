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

set FPP=0.0001

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

    echo Generating !NAME!.bloom from !COUNT! entries...
    java -cp ".;%GUAVA_JAR%" BloomWriter "!TXT!" "!OUT!" !COUNT! %FPP%
    if !ERRORLEVEL! neq 0 (
        echo Bloom generation failed for !NAME!
        exit /b 1
    )
)

echo Done.
