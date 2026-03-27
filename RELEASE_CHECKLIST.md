# Release Checklist

## Build Hygiene

- Build from a clean virtual environment and a clean working tree.
- Keep the executable name stable as `ProtocolHarbor.exe`.
- Do not enable UPX or any other executable packer.
- Verify that `version.py` contains the release version before building.

## Pre-Release Validation

- Run `pyinstaller --noconfirm ProtocolHarbor.spec`.
- Verify Windows metadata on `dist\ProtocolHarbor.exe`.
- Start the EXE on a clean Windows machine or VM.
- Confirm the application works with and without Npcap already installed.
- Scan the EXE with Microsoft Defender and VirusTotal before publishing.

## Publish Artifacts

- Publish the EXE from GitHub Releases over HTTPS.
- Attach `LICENSE`, `README.md`, and the release notes.
- Publish SHA256 checksums for the EXE and ZIP package.
- Prefer shipping the EXE inside a ZIP archive with a versioned ZIP filename, for example `ProtocolHarbor-1.0.0-win64.zip`.
- Generate the ZIP and checksum with `./scripts/package-release.ps1`.

## If Defender Or SmartScreen Triggers

- Submit the EXE to Microsoft Security Intelligence as a false positive.
- Avoid changing the product name and executable filename between releases unless necessary.
- Keep publishing from the same repository and account to build reputation over time.
- Re-test the exact uploaded artifact after Microsoft clears it.