#!/bin/bash

DEVKITPRO_PATH="/opt/devkitpro"

set -e

echo "======================================"
echo "TOTK MouseCam Final - Linux Builder"
echo "======================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

SKIP_MOD=0

if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 not found. Please install Python 3.8+"
    exit 1
fi

if [ -z "$DEVKITPRO" ]; then
    if [ -d "$DEVKITPRO_PATH" ]; then
        export DEVKITPRO="$DEVKITPRO_PATH"
    elif [ -d "$SCRIPT_DIR/../devkitpro" ]; then
        export DEVKITPRO="$SCRIPT_DIR/../devkitpro"
    elif [ -d "/opt/devkitpro" ]; then
        export DEVKITPRO="/opt/devkitpro"
    else
        echo "WARNING: DEVKITPRO not found."
        echo "Set DEVKITPRO_PATH at the top of this script."
        echo "Skipping mod build..."
        SKIP_MOD=1
    fi
fi

if [ $SKIP_MOD -eq 0 ]; then
    export DEVKITA64="$DEVKITPRO/devkitA64"
    export PATH="$DEVKITPRO/tools/bin:$DEVKITA64/bin:$PATH"
    echo "Using DEVKITPRO: $DEVKITPRO"
fi

echo "[1/4] Installing Python dependencies..."
pip3 install -r companion/requirements.txt -q
pip3 install pyinstaller -q
echo "Done."
echo ""

if [ $SKIP_MOD -eq 0 ]; then
    echo "[2/4] Building mod..."
    cd mod
    make clean
    make || echo "WARNING: Mod build had errors but may have succeeded"
    cd ..
    echo "Done."
    echo ""
else
    echo "[2/4] Skipping mod build - devkitPro not found."
    echo ""
fi

echo "[3/4] Building companion app..."
cd companion
mkdir -p dist/linux
pyinstaller --onefile --name MouseCamCompanion \
    --hidden-import=pynput.keyboard._xorg \
    --hidden-import=pynput.mouse._xorg \
    --hidden-import=tkinter \
    --distpath dist/linux mousecam_companion.py
cd ..
echo "Done."
echo ""

echo "[4/4] Build complete!"
echo ""
echo "Output locations:"
if [ $SKIP_MOD -eq 0 ]; then
    echo "  Mod:       $SCRIPT_DIR/mod/deploy/"
fi
echo "  Companion: $SCRIPT_DIR/companion/dist/linux/MouseCamCompanion"
echo ""
echo "Installation:"
echo "  1. Copy mod/deploy/atmosphere folder to your emulator's sdmc folder"
echo "  2. Run companion/dist/linux/MouseCamCompanion (may need sudo for /dev/input/mice)"
echo "  3. Start TOTK in emulator, click 'Scan Memory' in companion"
echo "  4. Press F3 to toggle mouse capture"
echo ""
echo "Optional dependencies for cursor locking/hiding:"
echo "  sudo apt install xdotool unclutter  # Debian/Ubuntu"
echo "  sudo pacman -S xdotool unclutter    # Arch"
echo ""
echo "Note: For raw mouse input on Linux without sudo, add yourself to the input group:"
echo "  sudo usermod -aG input \$USER"
echo "  (then log out and back in)"
