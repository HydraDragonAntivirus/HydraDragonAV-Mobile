@echo off
powershell -ExecutionPolicy Bypass -File "%~dp0build-android.ps1" %*
