@echo off
setlocal

set REPO=HydraDragonAntivirus/BenignAPKDataset
set LOCALDIR=dataset\benign
set MAXTRIES=50
set /a TRY=0

:retry
set /a TRY+=1
echo.
echo === Attempt %TRY% of %MAXTRIES% ===
hf upload %REPO% %LOCALDIR% --repo-type=dataset

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Upload complete after %TRY% attempt(s).
    goto :eof
)

if %TRY% GEQ %MAXTRIES% (
    echo.
    echo Gave up after %MAXTRIES% attempts. Run again later or try HF_HUB_DISABLE_XET=1.
    goto :eof
)

echo Upload failed, retrying in 20s...
timeout /t 20 /nobreak >nul
goto retry
