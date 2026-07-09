@echo off
REM Build every website Binary-Fuse (xor) filter (.xf) the native URL/domain
REM scanner loads. Windows cmd port of build_xfilters.sh.
REM
REM   website (domain/url) filters -> fpp 1e-4   (these run on live DNS + APK URLs)
REM   whitelist (md5 hashes)       -> fpp 1e-4   (built SEPARATELY from all_md5.txt;
REM                                               see the whitelist command at the end)
REM
REM Pipeline:
REM   1. gen_domain_xfilter.py    -> xf_build\<stem>.txt  (phishing, abuse, spam,
REM                                  mining, malicious_mail, malwareurl, phishingurl,
REM                                  malicious[combined])
REM   2. build_url_xfilters.py    -> overwrites xf_build\{malwareurl,phishingurl}.txt
REM                                  with the whitelist-FILTERED versions
REM   3. xorfilter_writer per stem -> app\src\main\assets\scan\<stem>.xf

setlocal enabledelayedexpansion
cd /d "%~dp0"

set WRITER=dev-tools\xorfilter_writer\target\release\xorfilter_writer.exe
set SCAN=app\src\main\assets\scan
set STAGE=xf_build
set WEB_FPP=0.0001

if not exist "%WRITER%" (
    echo building xorfilter_writer...
    pushd dev-tools\xorfilter_writer
    cargo build --release || exit /b 1
    popd
)

if not exist "%SCAN%" mkdir "%SCAN%"

echo === 1/3 extracting category lists ===
python gen_domain_xfilter.py || exit /b 1

echo === 2/3 whitelist-filtering URL lists ===
python build_url_xfilters.py || exit /b 1

echo === 3/3 building website .xf (fpp %WEB_FPP%) ===
REM Stems MUST match the CATS table in hydradragonandroid\src\url_scan.rs.
for %%S in (malwareurl phishingurl phishing malicious malicious_mail abuse spam mining) do (
    set "SRC=%STAGE%\%%S.txt"
    if exist "!SRC!" (
        for %%F in ("!SRC!") do if %%~zF gtr 0 (
            "%WRITER%" "!SRC!" "%SCAN%\%%S.xf" %WEB_FPP%
        ) else (
            echo   [SKIP] %%S: !SRC! empty
        )
    ) else (
        echo   [SKIP] %%S: !SRC! missing
    )
)

echo === 3b/3 building malicious-IP .xf from allips (non-CIDR only) ===
REM Stems MUST match the CATS table in hydradragonandroid\src\ip_scan.rs.
call :buildip ipmalware IPv4Malware
call :buildip ipspam IPv4Spam
call :buildip ipbruteforce IPv4BruteForce
call :buildip ipddos IPv4DDoS
call :buildip ipphishing IPv4PhishingActive

echo === 4/4 building whitelist.xf from all_md5.txt (fpp %WEB_FPP%) ===
if exist "all_md5.txt" (
    for %%F in ("all_md5.txt") do if %%~zF gtr 0 (
        "%WRITER%" all_md5.txt "%SCAN%\whitelist.xf" %WEB_FPP%
    ) else (
        echo   [SKIP] whitelist: all_md5.txt empty
    )
) else (
    echo   [SKIP] whitelist: all_md5.txt missing
)

echo.
echo Done. All .xf written to %SCAN%\.
goto :eof

:buildip
set "STEM=%~1"
set "CSV=allips\%~2.optimized.csv"
if exist "%CSV%" (
    for %%F in ("%CSV%") do if %%~zF gtr 0 (
        set "OUT=%STAGE%\%STEM%.txt"
        python extract_ip_csv.py "%CSV%" "!OUT!" || exit /b 1
        "%WRITER%" "!OUT!" "%SCAN%\%STEM%.xf" %WEB_FPP%
    ) else (
        echo   [SKIP] %STEM%: %CSV% empty
    )
) else (
    echo   [SKIP] %STEM%: %CSV% missing
)
goto :eof
