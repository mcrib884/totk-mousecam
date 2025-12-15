# TOTK MouseCam

Mouse-controlled camera for The Legend of Zelda: Tears of the Kingdom on Nintendo Switch emulators.

## Features

- Mouse control for camera rotation with adjustable sensitivity
- Scroll wheel zoom
- Mouse button to gamepad button mapping
- Cross-platform companion app (Windows/Linux)
- Works with Ryujinx and Yuzu emulators

## Installation (From Release)

### Windows

1. Download the latest release from [Releases](../../releases)
2. Extract and copy `totk-mousecam/` to your emulator's mod folder
3. Run `MouseCamCompanion.exe` wherever you want
4. Start TOTK and click "**Scan Memory**"
5. Press F3 to toggle mouse capture once the companion says ready

### Linux

1. Download the latest Linux release
2. Copy `atmosphere/` folder to your emulator's mod folder
3. Run `./MouseCamCompanion` (may require `sudo` for input capture)
4. Start TOTK and click "**Scan Memory**"
5. Press F3 to toggle mouse capture once its ready 

## Building From Source

### Requirements

**Mod:**
- [devkitPro](https://devkitpro.org/wiki/Getting_Started) with switch-dev package

**Companion (Windows):**
- Python 3.8+
- Administrator privileges may be required (for reading/writing emulator memory)

**Companion (Linux):**
- Python 3.8+
- Root privileges for input capture (or add user to `input` group)

### Build Commands

**Windows:**
```cmd
build_windows.cmd
```

**Linux:**
```bash
chmod +x build_linux.sh
./build_linux.sh
```

Output:
- Mod: `mod/deploy/atmosphere/`
- Windows Companion: `companion/dist/windows/MouseCamCompanion.exe`
- Linux Companion: `companion/dist/linux/MouseCamCompanion`

## Configuration

Settings are saved automatically to:
- Windows: `%APPDATA%/mousecam/config.json`
- Linux: `~/.config/mousecam/config.json`

## Project Structure

```
totk-mousecam-final/
├── mod/                    # Switch mod (exlaunch)
├── companion/              # Desktop companion app
│   ├── mousecam_companion.py
│   └── requirements.txt
├── build_windows.cmd
├── build_linux.sh
└── README.md
```

## License

GPL v2

mod by mcrib884