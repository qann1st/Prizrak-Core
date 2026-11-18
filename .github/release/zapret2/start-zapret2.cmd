@echo off
setlocal
pushd "%~dp0" || exit /b 1
set "WINWS2=zapret2-v1.0.7\binaries\windows-x86_64\winws2.exe"
if not exist "%WINWS2%" (
    >&2 echo Run setup-zapret2.ps1 to install zapret2 v1.0.7 first.
    popd
    exit /b 1
)
"%WINWS2%" @youtube-winws2.txt
set "RESULT=%ERRORLEVEL%"
popd
exit /b %RESULT%
