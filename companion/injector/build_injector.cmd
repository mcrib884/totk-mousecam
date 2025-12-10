@echo off
setlocal
cd /d "%~dp0"

echo Attempting to find Visual Studio...

set "VS_PATH=D:\Microsoft Visual Studio"
set "VCVARS="

if exist "%VS_PATH%\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=%VS_PATH%\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    goto :Found
)
if exist "%VS_PATH%\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=%VS_PATH%\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    goto :Found
)
if exist "%VS_PATH%\2019\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=%VS_PATH%\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
    goto :Found
)

:Found
if defined VCVARS (
    echo Found VS environment: "%VCVARS%"
    call "%VCVARS%"
) else (
    echo WARNING: Could not find vcvars64.bat automatically.
)

echo.
echo Building Injector DLL with CL...
rem /LD = Create DLL
rem /O2 = Maximize Speed
rem /EHsc = Enable C++ Exceptions
cl injector.cpp /LD /O2 /EHa /Fe:MouseCamInjector.dll /link /MACHINE:X64 Advapi32.lib user32.lib
if %errorlevel% neq 0 (
    echo Build failed!
    exit /b %errorlevel%
)

echo.
echo Build Successful!
if exist "MouseCamInjector.dll" (
    echo DLL created: MouseCamInjector.dll
)
