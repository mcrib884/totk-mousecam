@echo off

set DEVKITPRO_PATH=C:\devkitpro

echo ======================================
echo TOTK MouseCam Final - Windows Builder
echo ======================================
echo.

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: Python not found. Please install Python 3.8+ and add to PATH.
    pause
    exit /b 1
)

if exist "%DEVKITPRO_PATH%" (
    set DEVKITPRO=%DEVKITPRO_PATH%
) else if exist "%SCRIPT_DIR%..\devkitpro" (
    set DEVKITPRO=%SCRIPT_DIR%..\devkitpro
) else if defined DEVKITPRO (
    echo Using system DEVKITPRO: %DEVKITPRO%
) else (
    echo WARNING: devkitPro not found.
    echo Set DEVKITPRO_PATH at the top of this script.
    echo Skipping mod build...
    set SKIP_MOD=1
    goto :python_deps
)

set DEVKITA64=%DEVKITPRO%\devkitA64
set PATH=%DEVKITPRO%\tools\bin;%DEVKITA64%\bin;%PATH%
set SKIP_MOD=0
echo Using DEVKITPRO: %DEVKITPRO%

:python_deps
echo [1/4] Installing Python dependencies...
pip install -r companion\requirements.txt -q
pip install pyinstaller -q
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to install Python dependencies.
    pause
    exit /b 1
)
echo Done.
echo.

if "%SKIP_MOD%"=="1" (
    echo [2/4] Skipping mod build - devkitPro not found.
    echo.
    goto :companion_build
)

echo [2/4] Building mod...
cd mod
make clean
make
if %ERRORLEVEL% neq 0 (
    echo WARNING: Mod build had errors but may have succeeded. Check output above.
)
cd ..
echo Done.
echo.

:companion_build
echo [3/4] Building companion app...
cd companion

echo   - Building Injector DLL...
call injector\build_injector.cmd
if %ERRORLEVEL% neq 0 (
    echo ERROR: Injector build failed.
    pause
    exit /b 1
)

if not exist "dist\windows" mkdir dist\windows
pyinstaller --onefile --noconsole --uac-admin --add-binary "injector/MouseCamInjector.dll;." --name MouseCamCompanion --distpath dist\windows mousecam_companion.py
if %ERRORLEVEL% neq 0 (
    echo ERROR: Companion build failed.
    cd ..
    pause
    exit /b 1
)
cd ..
echo Done.
echo.

echo [4/4] Build complete!
echo.
echo Output locations:
if "%SKIP_MOD%"=="0" (
    echo   Mod:       %SCRIPT_DIR%mod\deploy\
)
echo   Companion: %SCRIPT_DIR%companion\dist\windows\MouseCamCompanion.exe
echo.
echo Installation:
echo   1. Copy mod\deploy\atmosphere folder to your emulator's sdmc folder
echo   2. Run companion\dist\windows\MouseCamCompanion.exe
echo   3. Start TOTK in emulator, click "Scan Memory" in companion
echo   4. Press F3 to toggle mouse capture
echo.
pause

