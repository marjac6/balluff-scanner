# ProtocolHarbor

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![License](https://img.shields.io/badge/license-GPL--3.0-green)

A network scanning tool for detecting industrial field devices without prior knowledge of the subnet. Designed for engineers and system integrators working with industrial hardware.

> **Current version:** `v1.0.0` — multi-protocol industrial device discovery

---

## Features

- Detects industrial devices via **ARP** (passive + active probe)
- Detects Profinet devices via **DCP Identify** multicast
- Scans all network adapters simultaneously or a single selected adapter
- Continuous scan — devices are added to the list as they respond
- Displays IP, MAC, device name, protocol, VendorID, DeviceID and adapter
- Resizable GUI with live log, version bar and changelog popup

---

## Screenshot

![Screenshot](screenshot.png)

---

## Requirements

| Requirement | Version |
|---|---|
| Windows | 10 / 11 |
| Python | 3.10+ |
| [Npcap](https://npcap.com) | latest — required for packet capture |

> Install Npcap with **"WinPcap API-compatible mode"** enabled.

---

## Installation

```powershell
# 1. Clone the repository
git clone https://github.com/<twoj-login>/ProtocolHarbor.git
cd ProtocolHarbor

# 2. Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt
```

### Run from source

```powershell
python main.py
```

### Vendor filter mode

By default the scanner reports only devices matching known OUIs/keywords (`SCANNER_VENDOR_FILTER=1`).
To scan all ARP devices in the network:

```powershell
$env:SCANNER_VENDOR_FILTER="0"
python main.py
```

Restore default:

```powershell
Remove-Item Env:SCANNER_VENDOR_FILTER -ErrorAction SilentlyContinue
```

### Advanced debug mode (for tests before commit)

Enable detailed logs only for local test runs:

```powershell
$env:SCANNER_DEBUG="1"
$env:SCANNER_DEBUG_FILE=".logs\\debug.log"   # optional
python main.py
```

Disable again:

```powershell
Remove-Item Env:SCANNER_DEBUG -ErrorAction SilentlyContinue
Remove-Item Env:SCANNER_DEBUG_FILE -ErrorAction SilentlyContinue
```

---

## Building the EXE

```powershell
pyinstaller ProtocolHarbor.spec
```

Output: `dist\ProtocolHarbor-v<version>.exe`

The spec file reads the version from `version.py` at build time — the EXE filename is versioned automatically.

> **Note:** `icon.ico` and `github.svg` must be present in the project root before building.

---

## Project Structure

```
scanner/
├── main.py               # Entry point
├── gui.py                # Tkinter UI
├── scanner.py            # ARP scan (passive + active probe)
├── ethercat_scanner.py   # EtherCAT scan
├── profinet_scanner.py   # Profinet DCP scan
├── version.py            # Single source of truth for version
├── CHANGELOG.md          # Release history
├── ProtocolHarbor.spec   # PyInstaller build config
├── requirements.txt      # Python dependencies
├── icon.ico              # App icon
└── github.svg            # GitHub logo for UI
```

---

## Protocol Roadmap

The goal is to support all major industrial network protocols. Version `1.0.0` will be released when all planned protocols and features are implemented.

| Protocol | Status |
|---|---|
| EtherNet/IP (ARP) | ✅ v1.0.0 |
| Modbus TCP (ARP) | ✅ v1.0.0 |
| EtherCAT | ✅ v1.0.0 |
| Profinet DCP | ✅ v1.0.0 |

---

## Contributing

External contributions are welcome — please open an issue before submitting a pull request.

---

## License

This project is licensed under the **GNU General Public License v3.0**.  
See [LICENSE](LICENSE) for details.
