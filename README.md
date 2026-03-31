# ProtocolHarbor

Industrial network discovery tool for Windows.

## Key Features

- Multi-protocol discovery: ARP, Profinet DCP, EtherNet/IP, Modbus TCP, EtherCAT, LLDP.
- One unified device table with live updates during scanning.
- Protocol switch for supported Balluff BNI XG devices: EtherCAT -> Profinet / Modbus TCP / Ethernet IP.
- Profinet configuration from GUI (IP and station name).
- Full PL/EN interface with automatic OS language detection and manual flag switch.

## Requirements

- Windows 10/11
- Python 3.10+
- Npcap (WinPcap API-compatible mode)

## Quick Start

```powershell
git clone https://github.com/marjac6/ProtocolHarbor.git
cd ProtocolHarbor
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

## Build EXE

```powershell
pyinstaller ProtocolHarbor.spec
```

Output: `dist\ProtocolHarbor.exe`

## Package Release

```powershell
.\scripts\package-release.ps1
```

Output:

- `release\<version>\ProtocolHarbor-<version>-win64.zip`
- `release\<version>\ProtocolHarbor-<version>-win64.sha256.txt`

## License

GNU GPL v3.0. See `LICENSE`.
