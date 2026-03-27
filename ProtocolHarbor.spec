# -*- mode: python ; coding: utf-8 -*-
import importlib.util
from pathlib import Path

# Read version at build time
_spec = importlib.util.spec_from_file_location("version", "version.py")
_mod  = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
VERSION = _mod.__version__


def _windows_version_tuple(version):
    parts = [int(part) for part in version.split('.')[:4]]
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts)


WINDOWS_VERSION = _windows_version_tuple(VERSION)
VERSION_FILE = Path("build") / "file_version_info.txt"
MANIFEST_FILE = Path("build") / "app.manifest"
VERSION_FILE.parent.mkdir(parents=True, exist_ok=True)
VERSION_FILE.write_text(
    f"""VSVersionInfo(
    ffi=FixedFileInfo(
        filevers={WINDOWS_VERSION},
        prodvers={WINDOWS_VERSION},
        mask=0x3f,
        flags=0x0,
        OS=0x40004,
        fileType=0x1,
        subtype=0x0,
        date=(0, 0)
    ),
    kids=[
        StringFileInfo([
            StringTable(
                '040904B0',
                [
                    StringStruct('CompanyName', 'marjac6'),
                    StringStruct('FileDescription', 'Industrial network protocol scanner'),
                    StringStruct('FileVersion', '{VERSION}'),
                    StringStruct('InternalName', 'ProtocolHarbor'),
                    StringStruct('OriginalFilename', 'ProtocolHarbor.exe'),
                    StringStruct('ProductName', 'ProtocolHarbor'),
                    StringStruct('ProductVersion', '{VERSION}')
                ]
            )
        ]),
        VarFileInfo([VarStruct('Translation', [1033, 1200])])
    ]
)
""",
        encoding="utf-8",
)
MANIFEST_FILE.write_text(
        f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
    <assemblyIdentity version="{VERSION}.0" processorArchitecture="*" name="ProtocolHarbor" type="win32"/>
    <description>Industrial network protocol scanner</description>
    <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
        <security>
            <requestedPrivileges>
                <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
            </requestedPrivileges>
        </security>
    </trustInfo>
    <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
        <application>
            <supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}"/>
            <supportedOS Id="{{1f676c76-80e1-4239-95bb-83d0f6d0da78}}"/>
        </application>
    </compatibility>
    <application xmlns="urn:schemas-microsoft-com:asm.v3">
        <windowsSettings>
            <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
            <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
        </windowsSettings>
    </application>
</assembly>
""",
        encoding="utf-8",
)

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('gui.py',              '.'),
        ('scanner.py',          '.'),
        ('profinet_scanner.py', '.'),
        ('version.py',          '.'),
        ('CHANGELOG.md',        '.'),
        ('github.svg',          '.'),
        ('icon.ico',            '.'),
    ],
    hiddenimports=['scapy.all', 'tkinter', 'svglib', 'reportlab', 'PIL'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ProtocolHarbor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    manifest=str(MANIFEST_FILE),
    version=str(VERSION_FILE),
    codesign_identity=None,
    entitlements_file=None,
    icon=['icon.ico'],
)
