#!/usr/bin/env python3
"""
lgi_testcontroller — match inventoried instruments to TestController drivers.

TestController keeps each instrument as a plain text device definition file in
a Devices folder. The tags that matter here are at the top of every file:

    #idString KEITHLEY INSTRUMENTS INC.,MODEL 2001,
    #name     Keithley 2001
    #handle   K2001
    #port     GPIB

#idString is the first two comma-separated fields of the instrument's *idn?
reply, and TestController's SCPI driver refuses to connect unless it matches.
That makes it exactly the right key: the inventory already stores the full IDN
string read off the bus, so matching is a comparison between two things that
both came from the instrument itself rather than a guess based on model names.

Where files live:
  * The install folder that holds TestController.jar has the bundled definitions.
  * Your own definitions go in the working folder TestController creates —
    Documents\\TestController\\Devices on Windows, ~/TestController/Devices on
    Linux. Either can be given as the base; the scanner searches below it.

Case handling, which is the awkward part:
  * The folder may be Devices, devices or DEVICES depending on how it was made,
    so directories are found case-insensitively.
  * File names are matched case-insensitively too, since the same definition
    gets called Keithley2001.txt on one machine and keithley2001.txt on another.
  * Two files whose names differ only in case are reported as a collision. They
    coexist on Linux but collapse into one file on Windows and macOS, so a set
    of definitions carrying such a pair loses one of them when it moves.

Nothing here writes to the TestController installation. It is read-only.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

DEVICE_DIR_NAMES = {"devices"}
DEVICE_SUFFIXES = {".txt"}
MAX_FILE_BYTES = 512 * 1024
MAX_DEPTH = 4

TAG_RE = re.compile(r"^\s*#(?P<tag>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<rest>.*?)\s*$")
WS_RE = re.compile(r"[ \t]+")

# Tags whose last value in a block describes the device it defines.
HEADER_TAGS = ("idstring", "name", "handle", "port", "driver", "subdriver",
               "baudrate", "help", "interfacetype")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

@dataclass
class DriverDef:
    """One device that TestController can offer, from one definition file."""
    path: str
    filename: str
    index: int = 0                  # 0 is the file's own definition
    name: str = ""
    handle: str = ""
    idstring: str = ""
    port: str = ""
    driver: str = ""
    interface_type: str = ""
    is_meta: bool = False           # a template, never offered as a device
    line: int = 1

    @property
    def stem(self) -> str:
        return Path(self.filename).stem

    @property
    def label(self) -> str:
        return self.name or self.handle or self.stem

    @property
    def ports(self) -> list[str]:
        return [p for p in WS_RE.split(self.port.strip()) if p]

    @property
    def supports_gpib(self) -> bool:
        return any(p.lower() == "gpib" for p in self.ports)


def normalize_idn(text: str) -> str:
    """Collapse whitespace and case so two IDN strings can be compared."""
    return WS_RE.sub(" ", (text or "").strip()).strip(",").upper()


def idn_prefix(idn: str, fields: int = 2) -> str:
    """The manufacturer and model fields — what #idString is built from."""
    parts = [p.strip() for p in (idn or "").split(",")]
    return ",".join(parts[:fields])


def parse_definition_file(path: Path) -> tuple[list[DriverDef], Optional[str]]:
    """Read one definition file into the devices it declares.

    A file usually declares one device. It can declare several: a #meta block
    acts as a template and each following #metadef block makes another device
    from it, overriding tags such as #idString and #name. Blocks inherit any
    tag they do not override, which mirrors how TestController resolves them.
    """
    try:
        raw = path.read_bytes()[:MAX_FILE_BYTES]
    except OSError as exc:
        return [], f"{path}: {exc}"
    text = raw.decode("utf-8", "replace") if b"\x00" not in raw[:64] else ""
    if not text:
        return [], f"{path}: not a text file"

    blocks: list[dict] = [{"_line": 1}]
    is_meta = False
    for number, line in enumerate(text.splitlines(), 1):
        match = TAG_RE.match(line)
        if not match:
            continue
        tag = match["tag"].lower()
        rest = match["rest"]
        if tag == "meta" and not rest:
            is_meta = True
            continue
        if tag == "metadef":
            blocks.append({"_line": number, "_metadef": rest})
            continue
        if tag in HEADER_TAGS:
            blocks[-1].setdefault(tag, rest)      # first value in a block wins

    base = blocks[0]
    defs: list[DriverDef] = []
    for index, block in enumerate(blocks):
        merged = dict(base) | block if index else block
        if index == 0 and not (merged.get("idstring") or merged.get("name")):
            continue                              # a pure template header
        definition = DriverDef(
            path=str(path), filename=path.name, index=index,
            name=merged.get("name", ""), handle=merged.get("handle", ""),
            idstring=merged.get("idstring", ""), port=merged.get("port", ""),
            driver=merged.get("driver", ""),
            interface_type=merged.get("interfacetype", ""),
            is_meta=(is_meta and index == 0), line=block["_line"])
        defs.append(definition)
    return defs, None


# --------------------------------------------------------------------------
# Catalog
# --------------------------------------------------------------------------

@dataclass
class Catalog:
    base: str = ""
    directories: list[str] = field(default_factory=list)
    definitions: list[DriverDef] = field(default_factory=list)
    files: int = 0
    collisions: list[tuple[str, list[str]]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scanned_at: str = ""

    @property
    def usable(self) -> list[DriverDef]:
        return [d for d in self.definitions if not d.is_meta]

    def summary(self) -> str:
        if not self.directories:
            return "No Devices folder found under that path."
        bits = [f"{len(self.usable)} device definition(s)",
                f"{self.files} file(s)",
                f"{len(self.directories)} folder(s)"]
        if self.collisions:
            bits.append(f"{len(self.collisions)} name collision(s)")
        if self.errors:
            bits.append(f"{len(self.errors)} unreadable")
        return " · ".join(bits)


def find_device_dirs(base: Path, max_depth: int = MAX_DEPTH) -> list[Path]:
    """Every Devices folder under base, whatever case it is spelled in.

    If the base is itself a Devices folder, that counts.
    """
    found: list[Path] = []
    base = base.expanduser()
    if not base.is_dir():
        return found
    if base.name.lower() in DEVICE_DIR_NAMES:
        found.append(base)
    base_depth = len(base.parts)
    for root, dirs, _files in os.walk(base):
        here = Path(root)
        if len(here.parts) - base_depth >= max_depth:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for name in list(dirs):
            if name.lower() in DEVICE_DIR_NAMES:
                found.append(here / name)
    # A folder reachable by two routes should still only be scanned once.
    unique: dict[str, Path] = {}
    for directory in found:
        unique.setdefault(str(directory.resolve()), directory)
    return sorted(unique.values(), key=lambda p: str(p).lower())


def scan_install(base: str | Path, on_log=None) -> Catalog:
    """Read every definition file below an install or working folder."""
    def log(message: str) -> None:
        if on_log:
            on_log(message)

    base_path = Path(base).expanduser()
    catalog = Catalog(base=str(base_path), scanned_at=utcnow())
    if not base_path.exists():
        catalog.errors.append(f"{base_path} does not exist")
        return catalog

    directories = find_device_dirs(base_path)
    catalog.directories = [str(d) for d in directories]
    if not directories:
        log(f"No Devices folder under {base_path}.")
        return catalog

    lowered: dict[str, list[str]] = {}
    for directory in directories:
        log(f"Reading {directory}")
        try:
            entries = sorted(directory.iterdir(), key=lambda p: p.name.lower())
        except OSError as exc:
            catalog.errors.append(f"{directory}: {exc}")
            continue
        for entry in entries:
            if not entry.is_file() or entry.suffix.lower() not in DEVICE_SUFFIXES:
                continue
            catalog.files += 1
            lowered.setdefault(entry.name.lower(), []).append(str(entry))
            defs, error = parse_definition_file(entry)
            if error:
                catalog.errors.append(error)
                continue
            catalog.definitions.extend(defs)

    for name, paths in sorted(lowered.items()):
        distinct = {Path(p).name for p in paths}
        if len(distinct) > 1:
            catalog.collisions.append((name, sorted(paths)))

    log(catalog.summary())
    for name, paths in catalog.collisions:
        log(f"  name collision on {name}: " +
            ", ".join(Path(p).name for p in paths) +
            " — these are one file on Windows and macOS")
    return catalog


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------

CONFIDENCE_ORDER = {"idstring": 0, "idstring-case": 1, "name": 2, "filename": 3}
CONFIDENCE_TEXT = {
    "idstring": "exact",
    "idstring-case": "case differs",
    "name": "likely",
    "filename": "possible",
}


@dataclass
class Match:
    definition: DriverDef
    confidence: str
    reason: str

    @property
    def rank(self) -> int:
        return CONFIDENCE_ORDER.get(self.confidence, 9)

    @property
    def confidence_text(self) -> str:
        return CONFIDENCE_TEXT.get(self.confidence, self.confidence)


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^A-Za-z0-9]+", (text or "").upper()) if len(t) > 1}


def match_instrument(catalog: Catalog, idn: str = "", manufacturer: str = "",
                     model: str = "") -> list[Match]:
    """Rank the definitions that could drive this instrument.

    An #idString hit is authoritative — TestController itself would accept the
    connection. Everything below that is a suggestion for the user to confirm.
    """
    matches: list[Match] = []
    idn_norm = normalize_idn(idn)
    prefix_norm = normalize_idn(idn_prefix(idn))
    model_tokens = _tokens(model)
    mfr_tokens = _tokens(manufacturer)

    for definition in catalog.usable:
        confidence = reason = ""
        if definition.idstring and idn_norm:
            declared = normalize_idn(definition.idstring)
            if idn.strip().upper().replace(" ", "").startswith(
                    definition.idstring.strip().upper().replace(" ", "")):
                # Compare the raw strings too: TestController matches literally,
                # so a difference that is only case is worth calling out.
                exact = idn.strip().replace(" ", "").startswith(
                    definition.idstring.strip().replace(" ", ""))
                confidence = "idstring" if exact else "idstring-case"
                reason = f"#idString {definition.idstring.strip()}"
            elif declared and declared == prefix_norm:
                confidence = "idstring-case"
                reason = f"#idString {definition.idstring.strip()}"

        if not confidence and model_tokens:
            name_tokens = _tokens(definition.name) | _tokens(definition.handle)
            file_tokens = _tokens(definition.stem)
            if model_tokens <= name_tokens and (not mfr_tokens or mfr_tokens & name_tokens):
                confidence, reason = "name", f"#name {definition.name}"
            elif model_tokens <= (name_tokens | file_tokens):
                confidence, reason = "filename", f"file name {definition.filename}"

        if confidence:
            matches.append(Match(definition, confidence, reason))

    matches.sort(key=lambda m: (m.rank, m.definition.filename.lower(), m.definition.index))
    return matches


def best_match(matches: Iterable[Match]) -> Optional[Match]:
    """The single match worth recording without asking, or None."""
    ranked = sorted(matches, key=lambda m: m.rank)
    if not ranked:
        return None
    top = ranked[0]
    if top.rank > CONFIDENCE_ORDER["idstring-case"]:
        return None                       # a guess: let the user decide
    contenders = [m for m in ranked if m.rank == top.rank]
    if len(contenders) > 1:
        return None                       # ambiguous: let the user decide
    return top


def default_bases() -> list[str]:
    """Where TestController usually keeps its working folder."""
    home = Path.home()
    candidates = [home / "Documents" / "TestController", home / "TestController"]
    return [str(p) for p in candidates if p.is_dir()] or [str(candidates[0])]
