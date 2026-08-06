# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for LGI.

    pyinstaller lgi.spec --noconfirm

Produces:
    Linux    dist/lgi                one file, needs Tk present at build time
    Windows  dist/lgi.exe            one file, no console window
    macOS    dist/LGI.app            bundle, plus dist/lgi for the command line

The GUI entry point forwards subcommands to the headless side, so the single
binary does both jobs: `lgi` opens the window, `lgi scan 192.168.1.50` does not.
"""

import sys
from pathlib import Path

IS_MAC = sys.platform == "darwin"
IS_WINDOWS = sys.platform == "win32"

SPECDIR = Path(__file__).resolve().parent if "__file__" in globals() else Path.cwd()
if str(SPECDIR) not in sys.path:
    sys.path.insert(0, str(SPECDIR))
from lgi_core import VERSION
NAME = "lgi"
BUNDLE_NAME = "LGI"

a = Analysis(
    ["lgi.py"],
    pathex=[],
    binaries=[],
    datas=[],
    # lgi_core imports lgi_testcontroller inside a function; name both so the
    # analysis cannot miss them however the call graph is walked.
    hiddenimports=["lgi_core", "lgi_testcontroller"],
    hookspath=[],
    runtime_hooks=[],
    # Nothing here needs the scientific stack or a web server. Excluding them
    # keeps the binary small and stops PyInstaller pulling in a stray numpy.
    excludes=[
        "numpy", "pandas", "matplotlib", "scipy", "PIL", "pytest",
        "setuptools", "pip", "distutils", "unittest", "pydoc_data",
        "test", "lib2to3", "multiprocessing",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                      # UPX trips antivirus heuristics on Windows
    console=not IS_WINDOWS,         # Windows gets a separate console build below
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,               # set by the workflow for macOS slices
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

# A windowed Windows executable has no stdout at all, so `lgi.exe scan ...`
# would run and print nothing. Ship a second console build for the command
# line; both come from the same analysis and behave identically otherwise.
if IS_WINDOWS:
    exe_cli = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name=f"{NAME}-cli",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=True,
        disable_windowed_traceback=False,
        icon=None,
    )

if IS_MAC:
    app = BUNDLE(
        exe,
        name=f"{BUNDLE_NAME}.app",
        icon=None,
        bundle_identifier="dk.lygte.lgi",
        version=VERSION,
        info_plist={
            "CFBundleName": BUNDLE_NAME,
            "CFBundleDisplayName": "LAN GPIB Inventory",
            "CFBundleShortVersionString": VERSION,
            "CFBundleVersion": VERSION,
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "11.0",
            # macOS 14 and later refuse local network traffic without this, and
            # the prompt it drives never appears for an app that lacks it. The
            # whole program is local network discovery, so it is mandatory.
            "NSLocalNetworkUsageDescription":
                "LGI searches the local network for GPIB gateways and talks to "
                "the instruments connected to them.",
        },
    )
