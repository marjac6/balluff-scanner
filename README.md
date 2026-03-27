# Balluff Device Scanner

![Version](https://img.shields.io/badge/version-0.3.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![License](https://img.shields.io/badge/license-GPL--3.0-green)

A network scanning tool for detecting **Balluff** and **BNI** devices without prior knowledge of the subnet. Designed for Balluff engineers and external system integrators working with Balluff hardware.

> **Current version:** `v0.3.0` — ARP passive/active scan + Profinet DCP discovery

---

## Features

- Detects Balluff/BNI devices via **ARP** (passive + active probe)
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
git clone https://github.com/marjac6/balluff-scanner.git
cd balluff-scanner

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

---

## Building the EXE

```powershell
pyinstaller BalluffScanner.spec
```

Output: `dist\BalluffScanner-v0.3.0.exe`

The spec file reads the version from `version.py` at build time — the EXE filename is versioned automatically.

> **Note:** `icon.ico` and `github.svg` must be present in the project root before building.

---

## Project Structure

```
balluff-scanner/
├── main.py               # Entry point
├── gui.py                # Tkinter UI
├── scanner.py            # ARP scan (passive + active probe)
├── profinet_scanner.py   # Profinet DCP scan
├── version.py            # Single source of truth for version
├── CHANGELOG.md          # Release history
├── BalluffScanner.spec   # PyInstaller build config
├── requirements.txt      # Python dependencies
├── icon.ico              # App icon
└── github.svg            # GitHub logo for UI
```

---

## Protocol Roadmap

The goal is to support all major protocols used by Balluff network devices. Version `1.0.0` will be released when all planned protocols and features are implemented.

| Protocol | Status |
|---|---|
| EtherNet/IP (ARP) | ✅ v0.3.0 |
| Modbus TCP (ARP) | ✅ v0.3.0 |
| EtherCAT | ✅ v0.3.0 |
| Profinet DCP | ✅ v0.3.0 |

---

## Contributing

External contributions are welcome — please open an issue before submitting a pull request.

---

## License

This project is licensed under the **GNU General Public License v3.0**.  
See [LICENSE](LICENSE) for details.
