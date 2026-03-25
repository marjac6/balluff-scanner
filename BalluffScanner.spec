# -*- mode: python ; coding: utf-8 -*-
import importlib.util

# Read version at build time
_spec = importlib.util.spec_from_file_location("version", "version.py")
_mod  = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
VERSION = _mod.__version__

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('gui.py',             '.'),
        ('scanner.py',         '.'),
        ('profinet_scanner.py','.'),
        ('version.py',         '.'),
        ('CHANGELOG.md',       '.'),
        ('github.svg',         '.'),
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
    name=f'BalluffScanner-v{VERSION}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['icon.ico'],
)
