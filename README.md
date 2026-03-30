# ProtocolHarbor

![Version](https://img.shields.io/badge/version-1.0.1-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![License](https://img.shields.io/badge/license-GPL--3.0-green)

A network scanning tool for detecting industrial field devices without prior knowledge of the subnet. Designed for engineers and system integrators working with industrial hardware.

> **Current version:** `v1.0.1` — multi-protocol industrial device discovery

---

## Features

- Multi-protocol discovery: **ARP**, **Profinet DCP**, **EtherNet/IP**, **Modbus TCP**, **EtherCAT**, **LLDP**
- Scans all network adapters simultaneously or a single selected adapter
- Continuous scan with in-place updates when device protocol changes
- Unified device list (single row per physical device; EtherCAT entries remain separate)
- Displays IP, MAC, producer, module name, device description, protocol, VendorID, DeviceID, version and adapter
- Visual row highlighting for duplicate IP conflicts and subnet match/mismatch
- Vendor fallback resolution from MAC OUI (IEEE database)
- Extended Profinet DCP metadata extraction (includes additional firmware/device-family fields when advertised)
- LLDP-based enrichment for missing metadata (for example firmware)
- Resizable GUI with live log, version bar and changelog popup

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
git clone https://github.com/marjac6/ProtocolHarbor.git
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

---

## Building the EXE

```powershell
pyinstaller ProtocolHarbor.spec
```

Output: `dist\ProtocolHarbor.exe`

The spec file reads the version from `version.py` at build time, writes it into the Windows EXE metadata, and embeds an application manifest.

> **Note:** `icon.ico` and `github.svg` must be present in the project root before building.

Release and SmartScreen publication guidance is documented in `RELEASE_CHECKLIST.md`.

### Packaging a Release ZIP

```powershell
.\scripts\package-release.ps1
```

Output:

- `release\<version>\ProtocolHarbor-<version>-win64.zip`
- `release\<version>\ProtocolHarbor-<version>-win64.sha256.txt`

The ZIP contains `ProtocolHarbor.exe`, `README.md`, `LICENSE`, and `CHANGELOG.md` inside a versioned folder.

---

## Project Structure

```
ProtocolHarbor/
├── main.py               # Entry point
├── gui.py                # Tkinter UI
├── scanner.py            # ARP scan (passive + active probe)
├── ethercat_scanner.py   # EtherCAT scan
├── profinet_scanner.py   # Profinet DCP scan
├── ethernetip_scanner.py # EtherNet/IP identity probe
├── modbus_scanner.py     # Modbus TCP identity probe
├── lldp_scanner.py       # LLDP listener/enrichment
├── vendor_registry.py    # Vendor/OUI/VendorID registry
├── debug_utils.py        # Logging and debug controls
├── version.py            # Single source of truth for version
├── CHANGELOG.md          # Release history
├── ProtocolHarbor.spec   # PyInstaller build config
├── requirements.txt      # Python dependencies
├── icon.ico              # App icon
└── github.svg            # GitHub logo for UI
```

---

## Supported Protocols

| Protocol | Status |
|---|---|
| ARP | ✅ v1.0.1 |
| LLDP | ✅ v1.0.1 |
| EtherNet/IP | ✅ v1.0.1 |
| Modbus TCP | ✅ v1.0.1 |
| EtherCAT | ✅ v1.0.1 |
| Profinet DCP | ✅ v1.0.1 |

---

## Roadmap

- Profinet DCP: IP address change for selected devices from the GUI
- Protocol change for selected devices: EtherCAT -> Profinet

Implementation note:
EtherCAT -> Profinet protocol switching will be available only for devices that support this transition and provide the required configuration mechanism.

---

## Contributing

External contributions are welcome — please open an issue before submitting a pull request.

---

## License

This project is licensed under the **GNU General Public License v3.0**.  
See [LICENSE](LICENSE) for details.
