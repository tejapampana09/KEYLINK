# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for KeyLink Companion
# Bundles companion.py + all WinRT/PyWin32 dependencies into a single EXE

from PyInstaller.utils.hooks import collect_submodules, collect_data_files, collect_dynamic_libs

block_cipher = None

winrt_hidden = collect_submodules('winrt')
winrt_datas = collect_data_files('winrt')
winrt_binaries = collect_dynamic_libs('winrt')

all_datas = [('config.py', '.')] + winrt_datas
all_binaries = winrt_binaries

all_hidden = [
    'win32pipe',
    'win32file',
    'pywintypes',
    'win32security',
    'win32con',
    'win32api',
    'cryptography',
    'cryptography.hazmat.primitives.asymmetric.ec',
    'cryptography.hazmat.primitives.hashes',
    'cryptography.hazmat.primitives.serialization',
    'cryptography.exceptions',
    'asyncio',
    'socket',
] + winrt_hidden

a = Analysis(
    ['companion.py'],
    pathex=['.'],
    binaries=all_binaries,
    datas=all_datas,
    hiddenimports=all_hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='KeyLinkCompanion',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # Built with console for easy live logging & debugging
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
