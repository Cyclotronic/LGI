#!/usr/bin/env python3
"""
lgi_core — LAN GPIB Inventory: protocol, discovery and database layer.

Pure standard library. No pyvisa, no python-vxi11, no external deps.

Contains:
  * A minimal ONC RPC (SunRPC) client, over TCP and UDP.
  * A portmapper client, including a broadcast GETPORT for discovery.
  * A VXI-11 Core channel client (create_link / write / read / readstb / ...).
  * Gateway identification over HTTP (LXI identification XML, then page scrape).
  * Two-phase GPIB bus scanning: serial poll first, then *IDN? on responders.
  * A SQLite inventory store with first-seen / last-seen tracking.
  * A headless CLI so the same code can be scripted without the GUI.

Tested against Agilent/Keysight E5810A/B style LAN-GPIB gateways, and any
other VXI-11 instrument server that exports a "gpib0,<addr>" device namespace
(E2050, HP/Agilent E5810, and the various clones).

CLI:
    python3 lgi_core.py discover --cidr 192.168.1.0/24
    python3 lgi_core.py scan 192.168.1.50
    python3 lgi_core.py list
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import random
import re
import socket
import sqlite3
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional

APP_NAME = "LGI"
APP_TITLE = "LAN GPIB Inventory"
VERSION = "1.0.0"

DEFAULT_DB_PATH = Path.home() / ".lgi" / "inventory.sqlite3"

# --------------------------------------------------------------------------
# ONC RPC / XDR
# --------------------------------------------------------------------------

PMAP_PORT = 111
PMAP_PROG = 100000
PMAP_VERS = 2
PMAP_GETPORT = 3

PROTO_TCP = 6
PROTO_UDP = 17

VXI11_CORE_PROG = 0x0607AF          # 395183
VXI11_CORE_VERS = 1

CREATE_LINK = 10
DEVICE_WRITE = 11
DEVICE_READ = 12
DEVICE_READSTB = 13
DEVICE_TRIGGER = 14
DEVICE_CLEAR = 15
DEVICE_REMOTE = 16
DEVICE_LOCAL = 17
DEVICE_LOCK = 18
DEVICE_UNLOCK = 19
DESTROY_LINK = 23

FLAG_WAITLOCK = 0x01
FLAG_END = 0x08
FLAG_TERMCHRSET = 0x80

REASON_REQCNT = 0x01
REASON_CHR = 0x02
REASON_END = 0x04

VXI11_ERRORS = {
    0: "no error",
    1: "syntax error",
    3: "device not accessible",
    4: "invalid link identifier",
    5: "parameter error",
    6: "channel not established",
    8: "operation not supported",
    9: "out of resources",
    11: "device locked by another link",
    12: "no lock held by this link",
    15: "I/O timeout",
    17: "I/O error",
    21: "invalid address",
    23: "abort",
    29: "channel already established",
}


class RpcError(Exception):
    """Transport- or RPC-level failure (bad reply, refused program, ...)."""


class Vxi11Error(Exception):
    """A VXI-11 device error code returned by the gateway."""

    def __init__(self, code: int, context: str = ""):
        self.code = code
        self.context = context
        text = VXI11_ERRORS.get(code, f"error {code}")
        super().__init__(f"{context}: {text}" if context else text)

    @property
    def is_timeout(self) -> bool:
        return self.code in (15, 3, 21)


def p_int(v: int) -> bytes:
    return struct.pack(">i", v)


def p_uint(v: int) -> bytes:
    return struct.pack(">I", v & 0xFFFFFFFF)


def p_bytes(b: bytes) -> bytes:
    pad = (-len(b)) % 4
    return struct.pack(">I", len(b)) + b + b"\x00" * pad


def p_str(s: str) -> bytes:
    return p_bytes(s.encode("ascii", "replace"))


class Unpacker:
    def __init__(self, data: bytes):
        self.d = data
        self.i = 0

    def uint(self) -> int:
        if self.i + 4 > len(self.d):
            raise RpcError("short RPC reply")
        v = struct.unpack_from(">I", self.d, self.i)[0]
        self.i += 4
        return v

    def int(self) -> int:
        if self.i + 4 > len(self.d):
            raise RpcError("short RPC reply")
        v = struct.unpack_from(">i", self.d, self.i)[0]
        self.i += 4
        return v

    def bytes(self) -> bytes:
        n = self.uint()
        if self.i + n > len(self.d):
            raise RpcError("short opaque field in RPC reply")
        v = self.d[self.i:self.i + n]
        self.i += n + ((-n) % 4)
        return v


def rpc_call_body(xid: int, prog: int, vers: int, proc: int, payload: bytes) -> bytes:
    """An RPC CALL message body (no TCP record marker)."""
    return (
        struct.pack(">IIIIII", xid, 0, 2, prog, vers, proc)
        + b"\x00" * 16                       # null cred + null verf
        + payload
    )


def rpc_parse_reply(data: bytes, xid: int) -> Unpacker:
    u = Unpacker(data)
    if u.uint() != xid:
        raise RpcError("RPC reply xid mismatch")
    if u.uint() != 1:
        raise RpcError("not an RPC reply")
    reply_stat = u.uint()
    if reply_stat != 0:
        raise RpcError(f"RPC call denied (stat {reply_stat})")
    u.uint()                      # verifier flavor
    n = u.uint()                  # verifier body length
    u.i += n + ((-n) % 4)         # skip the verifier body
    accept_stat = u.uint()
    if accept_stat != 0:
        raise RpcError(f"RPC program error (accept stat {accept_stat})")
    return u


class RpcTcpClient:
    """One TCP connection to an RPC program, with record marking."""

    def __init__(self, host: str, port: int, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = socket.create_connection((host, port), timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.xid = random.randint(1, 0x7FFFFFF0)

    def call(self, prog: int, vers: int, proc: int, payload: bytes,
             timeout: Optional[float] = None) -> Unpacker:
        self.sock.settimeout(timeout if timeout is not None else self.timeout)
        self.xid = (self.xid + 1) & 0x7FFFFFFF
        body = rpc_call_body(self.xid, prog, vers, proc, payload)
        self.sock.sendall(struct.pack(">I", 0x80000000 | len(body)) + body)
        return rpc_parse_reply(self._recv_record(), self.xid)

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise RpcError("connection closed by peer")
            buf += chunk
        return bytes(buf)

    def _recv_record(self) -> bytes:
        out = bytearray()
        while True:
            head = struct.unpack(">I", self._recv_exact(4))[0]
            last = bool(head & 0x80000000)
            out += self._recv_exact(head & 0x7FFFFFFF)
            if last:
                return bytes(out)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def portmap_getport(host: str, prog: int, vers: int, proto: int = PROTO_TCP,
                    timeout: float = 2.0, pmap_port: int = PMAP_PORT) -> int:
    """Ask host's portmapper which port serves prog/vers. 0 = not registered."""
    c = RpcTcpClient(host, pmap_port, timeout)
    try:
        u = c.call(PMAP_PROG, PMAP_VERS, PMAP_GETPORT,
                   p_uint(prog) + p_uint(vers) + p_uint(proto) + p_uint(0))
        return u.uint()
    finally:
        c.close()


# --------------------------------------------------------------------------
# VXI-11 core channel
# --------------------------------------------------------------------------

class Vxi11Client:
    """A VXI-11 Core channel. One TCP session, many links."""

    def __init__(self, host: str, core_port: Optional[int] = None,
                 timeout: float = 5.0, client_id: Optional[int] = None):
        self.host = host
        self.core_port = core_port
        self.timeout = timeout
        self.client_id = client_id if client_id is not None else random.randint(1, 0x7FFFFFF0)
        self.rpc: Optional[RpcTcpClient] = None
        self.max_recv = 4096

    # -- session -----------------------------------------------------------
    def connect(self) -> None:
        if self.core_port is None:
            port = portmap_getport(self.host, VXI11_CORE_PROG, VXI11_CORE_VERS,
                                   PROTO_TCP, self.timeout)
            if not port:
                raise RpcError("portmapper reports no VXI-11 core channel")
            self.core_port = port
        self.rpc = RpcTcpClient(self.host, self.core_port, self.timeout)

    def reconnect(self) -> None:
        self.close()
        self.rpc = RpcTcpClient(self.host, self.core_port, self.timeout)

    def close(self) -> None:
        if self.rpc:
            self.rpc.close()
            self.rpc = None

    def __enter__(self) -> "Vxi11Client":
        if self.rpc is None:
            self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _call(self, proc: int, payload: bytes, timeout: Optional[float] = None) -> Unpacker:
        if self.rpc is None:
            raise RpcError("not connected")
        return self.rpc.call(VXI11_CORE_PROG, VXI11_CORE_VERS, proc, payload, timeout)

    @staticmethod
    def _sock_timeout(io_timeout_ms: int) -> float:
        return max(2.0, io_timeout_ms / 1000.0 + 2.0)

    # -- procedures --------------------------------------------------------
    def create_link(self, device: str, lock: bool = False, lock_timeout: int = 0) -> int:
        u = self._call(CREATE_LINK,
                       p_int(self.client_id) + p_uint(1 if lock else 0)
                       + p_uint(lock_timeout) + p_str(device))
        err = u.int()
        if err:
            raise Vxi11Error(err, f"create_link({device})")
        lid = u.int()
        u.uint()                     # abort port
        self.max_recv = max(256, u.uint() or 4096)
        return lid

    def destroy_link(self, lid: int) -> None:
        u = self._call(DESTROY_LINK, p_int(lid))
        err = u.int()
        if err:
            raise Vxi11Error(err, "destroy_link")

    def write(self, lid: int, data: bytes, io_timeout: int = 3000,
              lock_timeout: int = 0) -> int:
        sent = 0
        view = memoryview(data)
        while sent < len(data):
            chunk = view[sent:sent + self.max_recv]
            last = sent + len(chunk) >= len(data)
            flags = FLAG_END if last else 0
            u = self._call(DEVICE_WRITE,
                           p_int(lid) + p_uint(io_timeout) + p_uint(lock_timeout)
                           + p_uint(flags) + p_bytes(bytes(chunk)),
                           self._sock_timeout(io_timeout))
            err = u.int()
            n = u.uint()
            if err:
                raise Vxi11Error(err, "device_write")
            sent += n if n else len(chunk)
        return sent

    def read(self, lid: int, count: int = 8192, io_timeout: int = 3000,
             lock_timeout: int = 0, term: Optional[bytes] = b"\n") -> bytes:
        out = bytearray()
        flags = FLAG_TERMCHRSET if term else 0
        termchar = term[0] if term else 0
        while True:
            req = min(self.max_recv, max(1, count - len(out)))
            u = self._call(DEVICE_READ,
                           p_int(lid) + p_uint(req) + p_uint(io_timeout)
                           + p_uint(lock_timeout) + p_uint(flags) + p_uint(termchar),
                           self._sock_timeout(io_timeout))
            err = u.int()
            reason = u.uint()
            data = u.bytes()
            if err:
                raise Vxi11Error(err, "device_read")
            out += data
            if reason & (REASON_END | REASON_CHR):
                break
            if len(out) >= count or not data:
                break
        return bytes(out)

    def readstb(self, lid: int, io_timeout: int = 500, lock_timeout: int = 0) -> int:
        u = self._call(DEVICE_READSTB,
                       p_int(lid) + p_uint(0) + p_uint(lock_timeout) + p_uint(io_timeout),
                       self._sock_timeout(io_timeout))
        err = u.int()
        stb = u.uint()
        if err:
            raise Vxi11Error(err, "device_readstb")
        return stb & 0xFF

    def _generic(self, proc: int, lid: int, io_timeout: int, name: str,
                 lock_timeout: int = 0) -> None:
        u = self._call(proc,
                       p_int(lid) + p_uint(0) + p_uint(lock_timeout) + p_uint(io_timeout),
                       self._sock_timeout(io_timeout))
        err = u.int()
        if err:
            raise Vxi11Error(err, name)

    def clear(self, lid: int, io_timeout: int = 2000) -> None:
        self._generic(DEVICE_CLEAR, lid, io_timeout, "device_clear")

    def trigger(self, lid: int, io_timeout: int = 2000) -> None:
        self._generic(DEVICE_TRIGGER, lid, io_timeout, "device_trigger")

    def local(self, lid: int, io_timeout: int = 2000) -> None:
        self._generic(DEVICE_LOCAL, lid, io_timeout, "device_local")

    def query(self, device: str, command: str, io_timeout: int = 3000) -> str:
        """One-shot convenience: link, write, read, unlink."""
        lid = self.create_link(device)
        try:
            self.write(lid, command.encode() + b"\n", io_timeout)
            return self.read(lid, io_timeout=io_timeout).decode("latin-1").strip()
        finally:
            try:
                self.destroy_link(lid)
            except Exception:
                pass


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

@dataclass
class GatewayInfo:
    ip: str
    hostname: str = ""
    manufacturer: str = ""
    model: str = ""
    serial: str = ""
    firmware: str = ""
    description: str = ""
    core_port: Optional[int] = None
    source: str = ""

    def label(self) -> str:
        bits = [b for b in (self.model, self.hostname or self.ip) if b]
        return " — ".join(bits) if bits else self.ip


def local_ipv4_addresses() -> list[str]:
    addrs: set[str] = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        addrs.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addrs.add(info[4][0])
    except OSError:
        pass
    return sorted(a for a in addrs if not a.startswith("127."))


def default_cidr() -> str:
    for a in local_ipv4_addresses():
        try:
            return str(ipaddress.ip_network(a + "/24", strict=False))
        except ValueError:
            continue
    return "192.168.1.0/24"


def broadcast_addresses() -> list[str]:
    out = ["255.255.255.255"]
    for a in local_ipv4_addresses():
        try:
            out.append(str(ipaddress.ip_network(a + "/24", strict=False).broadcast_address))
        except ValueError:
            pass
    return list(dict.fromkeys(out))


def discover_broadcast(timeout: float = 2.0,
                       targets: Optional[Iterable[str]] = None) -> dict[str, int]:
    """Broadcast a portmap GETPORT for the VXI-11 core program.

    Every VXI-11 instrument server on the wire answers with its core port.
    This is the same mechanism a VISA "TCPIP?*::INSTR" search uses.
    """
    found: dict[str, int] = {}
    xid = random.randint(1, 0x7FFFFFF0)
    msg = rpc_call_body(xid, PMAP_PROG, PMAP_VERS, PMAP_GETPORT,
                        p_uint(VXI11_CORE_PROG) + p_uint(VXI11_CORE_VERS)
                        + p_uint(PROTO_TCP) + p_uint(0))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(("", 0))
        s.settimeout(0.25)
        for target in (targets if targets is not None else broadcast_addresses()):
            for _ in range(2):                  # UDP; a lost probe costs a whole scan
                try:
                    s.sendto(msg, (target, PMAP_PORT))
                except OSError:
                    break
                time.sleep(0.01)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                port = rpc_parse_reply(data, xid).uint()
            except (RpcError, struct.error):
                continue
            if port:
                found[addr[0]] = port
    finally:
        s.close()
    return found


def discover_sweep(cidr: str, timeout: float = 0.6, workers: int = 64,
                   stop: Optional[threading.Event] = None,
                   progress: Optional[Callable[[int, int], None]] = None) -> dict[str, int]:
    """Unicast portmap sweep. Slower than broadcast but crosses routers and
    survives switches that eat directed broadcasts."""
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses > 4096:
        raise ValueError(f"{cidr} is too large to sweep ({net.num_addresses} addresses)")
    hosts = [str(h) for h in (net.hosts() if net.num_addresses > 1 else [net.network_address])]
    found: dict[str, int] = {}
    done = 0
    lock = threading.Lock()

    def probe(ip: str) -> None:
        nonlocal done
        port = 0
        if not (stop and stop.is_set()):
            try:
                port = portmap_getport(ip, VXI11_CORE_PROG, VXI11_CORE_VERS,
                                       PROTO_TCP, timeout)
            except (OSError, RpcError):
                port = 0
        with lock:
            done += 1
            if port:
                found[ip] = port
            if progress:
                progress(done, len(hosts))

    with ThreadPoolExecutor(max_workers=max(4, workers)) as pool:
        list(pool.map(probe, hosts))
    return found


# --------------------------------------------------------------------------
# Gateway identification
# --------------------------------------------------------------------------

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t\r\n\xa0]+")


def _http_get(ip: str, path: str, timeout: float = 2.0, limit: int = 65536,
              port: int = 80) -> str:
    """Small hand-rolled HTTP/1.0 GET. The E5810A's web server is ancient and
    urllib's keep-alive handling is more trouble than it is worth here."""
    try:
        with socket.create_connection((ip, port), timeout) as s:
            s.settimeout(timeout)
            s.sendall(
                f"GET {path} HTTP/1.0\r\nHost: {ip}\r\n"
                f"User-Agent: {APP_NAME}/{VERSION}\r\nConnection: close\r\n\r\n".encode()
            )
            buf = bytearray()
            while len(buf) < limit:
                chunk = s.recv(8192)
                if not chunk:
                    break
                buf += chunk
    except OSError:
        return ""
    text = bytes(buf).decode("latin-1", "replace")
    head, _, body = text.partition("\r\n\r\n")
    if " 200" not in head.split("\r\n")[0]:
        return ""
    return body


def _first(pattern: str, text: str) -> str:
    m = re.search(pattern, text, re.I)
    return m.group(1).strip() if m else ""


def identify_gateway(ip: str, timeout: float = 2.0, http_port: int = 80) -> GatewayInfo:
    info = GatewayInfo(ip=ip)
    try:
        info.hostname = socket.gethostbyaddr(ip)[0]
    except OSError:
        info.hostname = ""

    # LXI devices (E5810B and friends) publish a clean identification document.
    xml = _http_get(ip, "/lxi/identification", timeout, port=http_port)
    if "<" in xml:
        info.manufacturer = _first(r"<Manufacturer>([^<]+)</Manufacturer>", xml)
        info.model = _first(r"<Model>([^<]+)</Model>", xml)
        info.serial = _first(r"<SerialNumber>([^<]+)</SerialNumber>", xml)
        info.firmware = _first(r"<FirmwareRevision>([^<]+)</FirmwareRevision>", xml)
        info.description = _first(r"<Description>([^<]+)</Description>", xml)

    if not info.model:
        html = _http_get(ip, "/", timeout, port=http_port)
        flat = _WS_RE.sub(" ", _TAG_RE.sub(" ", html)).strip()
        m = re.search(r"(E5810[A-Z]?|E2050[A-Z]?|E5813[A-Z]?)", flat, re.I)
        if m:
            info.model = m.group(1).upper()
        if not info.manufacturer:
            info.manufacturer = _first(r"\b(Agilent|Keysight|Hewlett[- ]Packard|HP)\b", flat)
        info.serial = info.serial or _first(r"Serial\s*Number\s*:?\s*([A-Za-z0-9\-]{4,})", flat)
        info.firmware = info.firmware or _first(
            r"Firmware\s*(?:Revision|Version)\s*:?\s*([A-Za-z0-9._\-]+)", flat)
        info.description = info.description or _first(
            r"Description\s*:?\s*([^:]{3,60}?)\s+(?:Hostname|IP Address|Serial)", flat)
        info.hostname = info.hostname or _first(r"Host\s*name\s*:?\s*([A-Za-z0-9._\-]+)", flat)

    if not info.model:
        info.model = "VXI-11 device"
    return info


# --------------------------------------------------------------------------
# GPIB bus scanning
# --------------------------------------------------------------------------

@dataclass
class DeviceRecord:
    address: int
    present: bool = False
    stb: Optional[int] = None
    idn: str = ""
    manufacturer: str = ""
    model: str = ""
    serial: str = ""
    firmware: str = ""
    error: str = ""
    responded_idn: bool = False
    queried: bool = False          # phase 2 has run for this address

    def as_dict(self) -> dict:
        return dict(address=self.address, present=self.present, stb=self.stb,
                    idn=self.idn, manufacturer=self.manufacturer, model=self.model,
                    serial=self.serial, firmware=self.firmware, error=self.error,
                    responded_idn=self.responded_idn, queried=self.queried)


def parse_idn(idn: str) -> tuple[str, str, str, str]:
    """Split a *IDN? response into manufacturer, model, serial, firmware."""
    clean = (idn or "").strip().strip("\x00").strip()
    if not clean:
        return "", "", "", ""
    parts = [p.strip() for p in clean.split(",", 3)]
    while len(parts) < 4:
        parts.append("")
    mfr, model, serial, fw = parts
    if model.upper().startswith("MODEL "):
        model = model[6:].strip()
    return mfr, model, serial, fw


def decode_stb(stb: Optional[int]) -> str:
    """Human-readable IEEE 488.2 status byte."""
    if stb is None:
        return ""
    names = [(0x40, "RQS/MSS"), (0x20, "ESB"), (0x10, "MAV"),
             (0x08, "QSB"), (0x04, "EAV"), (0x02, "b1"), (0x01, "b0")]
    hits = [n for bit, n in names if stb & bit]
    return f"0x{stb:02X}" + (f" ({', '.join(hits)})" if hits else "")


def scan_bus(host: str,
             core_port: Optional[int] = None,
             interface: str = "gpib0",
             addresses: Iterable[int] = range(0, 31),
             skip: Iterable[int] = (21,),
             spoll_ms: int = 500,
             idn_ms: int = 3000,
             deep: bool = False,
             send_clear: bool = False,
             connect_timeout: float = 5.0,
             on_event: Optional[Callable[..., None]] = None,
             stop: Optional[threading.Event] = None) -> list[DeviceRecord]:
    """Two-phase bus scan.

    Phase 1 serial-polls every address, which is fast and does not disturb
    instrument state. Phase 2 asks the responders for *IDN?. With deep=True
    phase 2 also tries the silent addresses, which catches devices that ignore
    serial poll (older listen-only gear).
    """
    def emit(kind: str, *args) -> None:
        if on_event:
            on_event(kind, *args)

    skip_set = set(skip)
    addrs = [a for a in addresses if a not in skip_set]
    total = len(addrs) * 2
    records: dict[int, DeviceRecord] = {}

    client = Vxi11Client(host, core_port=core_port, timeout=connect_timeout)
    client.connect()
    emit("log", f"Core channel open on {host}:{client.core_port}")

    def with_link(addr: int, body: Callable[[int], None]) -> Optional[Vxi11Error]:
        """Create a link, run body, always destroy. Reconnects once on a
        transport drop, which E5810A firmware occasionally needs."""
        name = f"{interface},{addr}"
        for attempt in (0, 1):
            lid = None
            try:
                lid = client.create_link(name)
                body(lid)
                return None
            except Vxi11Error as e:
                return e
            except (OSError, RpcError) as e:
                if attempt == 0:
                    emit("log", f"Transport reset at {name} ({e}); reconnecting")
                    try:
                        client.reconnect()
                    except OSError as e2:
                        raise RpcError(f"reconnect failed: {e2}") from e2
                    continue
                raise
            finally:
                if lid is not None:
                    try:
                        client.destroy_link(lid)
                    except Exception:
                        pass
        return None

    try:
        # ---- phase 1: serial poll --------------------------------------
        for i, addr in enumerate(addrs):
            if stop and stop.is_set():
                emit("log", "Scan stopped")
                break
            emit("progress", i, total, f"Serial polling {interface},{addr}")
            rec = DeviceRecord(addr)
            records[addr] = rec

            def poll(lid: int, rec=rec) -> None:
                rec.stb = client.readstb(lid, spoll_ms)
                rec.present = True

            err = with_link(addr, poll)
            if err is not None:
                rec.present = False
                rec.stb = None
                if not err.is_timeout:
                    rec.error = str(err)
            emit("row", rec)

        # ---- phase 2: identify -----------------------------------------
        targets = [a for a in addrs if records.get(a) and (records[a].present or deep)]
        for j, addr in enumerate(targets):
            if stop and stop.is_set():
                break
            rec = records[addr]
            rec.queried = True
            emit("progress", len(addrs) + j, total, f"Querying *IDN? at {interface},{addr}")

            def ident(lid: int, rec=rec) -> None:
                if send_clear:
                    client.clear(lid, idn_ms)
                client.write(lid, b"*IDN?\n", idn_ms)
                raw = client.read(lid, io_timeout=idn_ms)
                text = raw.decode("latin-1").strip().strip("\x00").strip()
                if text:
                    rec.idn = text
                    rec.responded_idn = True
                    rec.present = True
                    (rec.manufacturer, rec.model, rec.serial, rec.firmware) = parse_idn(text)

            err = with_link(addr, ident)
            if err is not None and not rec.responded_idn:
                rec.error = rec.error or str(err)
            emit("row", rec)

        emit("progress", total, total, "Scan complete")
    finally:
        client.close()

    return [records[a] for a in sorted(records)]


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS gateways (
    id           INTEGER PRIMARY KEY,
    ip           TEXT NOT NULL UNIQUE,
    hostname     TEXT DEFAULT '',
    manufacturer TEXT DEFAULT '',
    model        TEXT DEFAULT '',
    serial       TEXT DEFAULT '',
    firmware     TEXT DEFAULT '',
    description  TEXT DEFAULT '',
    core_port    INTEGER,
    interface    TEXT DEFAULT 'gpib0',
    ctrl_address INTEGER DEFAULT 21,
    notes        TEXT DEFAULT '',
    first_seen   TEXT,
    last_seen    TEXT
);

CREATE TABLE IF NOT EXISTS instruments (
    id            INTEGER PRIMARY KEY,
    gateway_id    INTEGER NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    gpib_address  INTEGER NOT NULL,
    idn           TEXT DEFAULT '',
    manufacturer  TEXT DEFAULT '',
    model         TEXT DEFAULT '',
    serial        TEXT DEFAULT '',
    firmware      TEXT DEFAULT '',
    stb           INTEGER,
    responded_idn INTEGER DEFAULT 0,
    nickname      TEXT DEFAULT '',
    notes         TEXT DEFAULT '',
    first_seen    TEXT,
    last_seen     TEXT,
    UNIQUE (gateway_id, gpib_address, idn)
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id         INTEGER PRIMARY KEY,
    gateway_id INTEGER NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    started    TEXT,
    finished   TEXT,
    interface  TEXT,
    scanned    INTEGER,
    found      INTEGER,
    mode       TEXT
);

CREATE TABLE IF NOT EXISTS scan_hits (
    id           INTEGER PRIMARY KEY,
    run_id       INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    gpib_address INTEGER,
    present      INTEGER,
    stb          INTEGER,
    idn          TEXT,
    error        TEXT
);

CREATE TABLE IF NOT EXISTS app_settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS tc_links (
    id            INTEGER PRIMARY KEY,
    instrument_id INTEGER NOT NULL UNIQUE REFERENCES instruments(id) ON DELETE CASCADE,
    path          TEXT,
    filename      TEXT,
    definition    TEXT,
    handle        TEXT,
    idstring      TEXT,
    port          TEXT,
    confidence    TEXT,
    reason        TEXT,
    chosen_by     TEXT DEFAULT 'auto',
    linked_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_instruments_gw ON instruments(gateway_id);
CREATE INDEX IF NOT EXISTS idx_hits_run ON scan_hits(run_id);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fmt_ts(ts: Optional[str]) -> str:
    """ISO UTC in the database, local wall-clock on screen."""
    if not ts:
        return ""
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return ts
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")


class Database:
    """Thread-safe enough for this app: one connection behind one lock."""

    def __init__(self, path: Path | str = DEFAULT_DB_PATH):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            self.conn.execute("PRAGMA foreign_keys = ON")
            self.conn.execute("PRAGMA journal_mode = WAL")
            self.conn.executescript(SCHEMA)
            self.conn.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(SCHEMA_VERSION),))
            self.conn.commit()

    def close(self) -> None:
        with self.lock:
            self.conn.close()

    # -- gateways ----------------------------------------------------------
    def upsert_gateway(self, info: GatewayInfo, seen: bool = True) -> int:
        now = utcnow()
        with self.lock:
            cur = self.conn.execute("SELECT * FROM gateways WHERE ip = ?", (info.ip,))
            row = cur.fetchone()
            if row is None:
                cur = self.conn.execute(
                    "INSERT INTO gateways (ip, hostname, manufacturer, model, serial, "
                    "firmware, description, core_port, first_seen, last_seen) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (info.ip, info.hostname, info.manufacturer, info.model, info.serial,
                     info.firmware, info.description, info.core_port, now, now))
                self.conn.commit()
                return int(cur.lastrowid)

            def keep(new: str, old: str) -> str:
                return new if new else (old or "")

            self.conn.execute(
                "UPDATE gateways SET hostname=?, manufacturer=?, model=?, serial=?, "
                "firmware=?, description=?, core_port=?, last_seen=? WHERE id=?",
                (keep(info.hostname, row["hostname"]),
                 keep(info.manufacturer, row["manufacturer"]),
                 keep(info.model, row["model"]) if info.model != "VXI-11 device" or not row["model"]
                 else row["model"],
                 keep(info.serial, row["serial"]),
                 keep(info.firmware, row["firmware"]),
                 keep(info.description, row["description"]),
                 info.core_port if info.core_port else row["core_port"],
                 now if seen else row["last_seen"], row["id"]))
            self.conn.commit()
            return int(row["id"])

    def gateways(self) -> list[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(
                "SELECT * FROM gateways ORDER BY last_seen DESC").fetchall()

    def gateway(self, gid: int) -> Optional[sqlite3.Row]:
        with self.lock:
            return self.conn.execute("SELECT * FROM gateways WHERE id = ?", (gid,)).fetchone()

    def gateway_by_ip(self, ip: str) -> Optional[sqlite3.Row]:
        with self.lock:
            return self.conn.execute("SELECT * FROM gateways WHERE ip = ?", (ip,)).fetchone()

    def update_gateway_settings(self, gid: int, interface: str, ctrl_address: int,
                                core_port: Optional[int] = None) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE gateways SET interface=?, ctrl_address=?, core_port=COALESCE(?, core_port) "
                "WHERE id=?", (interface, ctrl_address, core_port, gid))
            self.conn.commit()

    def set_gateway_notes(self, gid: int, notes: str) -> None:
        with self.lock:
            self.conn.execute("UPDATE gateways SET notes=? WHERE id=?", (notes, gid))
            self.conn.commit()

    def delete_gateway(self, gid: int) -> None:
        with self.lock:
            self.conn.execute("DELETE FROM gateways WHERE id=?", (gid,))
            self.conn.commit()

    # -- instruments -------------------------------------------------------
    def record_scan(self, gateway_id: int, interface: str, records: list[DeviceRecord],
                    started: str, mode: str = "two-phase") -> int:
        now = utcnow()
        found = sum(1 for r in records if r.present)
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO scan_runs (gateway_id, started, finished, interface, "
                "scanned, found, mode) VALUES (?,?,?,?,?,?,?)",
                (gateway_id, started, now, interface, len(records), found, mode))
            run_id = int(cur.lastrowid)
            for r in records:
                self.conn.execute(
                    "INSERT INTO scan_hits (run_id, gpib_address, present, stb, idn, error) "
                    "VALUES (?,?,?,?,?,?)",
                    (run_id, r.address, int(r.present), r.stb, r.idn, r.error))
                if not r.present:
                    continue
                key = (gateway_id, r.address, r.idn or "")
                row = self.conn.execute(
                    "SELECT id FROM instruments WHERE gateway_id=? AND gpib_address=? AND idn=?",
                    key).fetchone()
                if row:
                    self.conn.execute(
                        "UPDATE instruments SET manufacturer=?, model=?, serial=?, firmware=?, "
                        "stb=?, responded_idn=?, last_seen=? WHERE id=?",
                        (r.manufacturer, r.model, r.serial, r.firmware, r.stb,
                         int(r.responded_idn), now, row["id"]))
                else:
                    self.conn.execute(
                        "INSERT INTO instruments (gateway_id, gpib_address, idn, manufacturer, "
                        "model, serial, firmware, stb, responded_idn, first_seen, last_seen) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (gateway_id, r.address, r.idn or "", r.manufacturer, r.model,
                         r.serial, r.firmware, r.stb, int(r.responded_idn), now, now))
            self.conn.execute("UPDATE gateways SET last_seen=? WHERE id=?", (now, gateway_id))
            self.conn.commit()
        return run_id

    def instruments(self, gateway_id: Optional[int] = None) -> list[sqlite3.Row]:
        sql = ("SELECT i.*, g.ip AS gw_ip, g.hostname AS gw_hostname, g.model AS gw_model, "
               "t.filename AS tc_filename, t.definition AS tc_definition, "
               "t.handle AS tc_handle, t.path AS tc_path, t.port AS tc_port, "
               "t.confidence AS tc_confidence, t.chosen_by AS tc_chosen_by "
               "FROM instruments i JOIN gateways g ON g.id = i.gateway_id "
               "LEFT JOIN tc_links t ON t.instrument_id = i.id")
        args: tuple = ()
        if gateway_id is not None:
            sql += " WHERE i.gateway_id = ?"
            args = (gateway_id,)
        sql += " ORDER BY g.ip, i.gpib_address, i.last_seen DESC"
        with self.lock:
            return self.conn.execute(sql, args).fetchall()

    def set_instrument_fields(self, iid: int, nickname: str, notes: str) -> None:
        with self.lock:
            self.conn.execute("UPDATE instruments SET nickname=?, notes=? WHERE id=?",
                              (nickname, notes, iid))
            self.conn.commit()

    def delete_instrument(self, iid: int) -> None:
        with self.lock:
            self.conn.execute("DELETE FROM instruments WHERE id=?", (iid,))
            self.conn.commit()

    def scan_runs(self, gateway_id: int, limit: int = 50) -> list[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(
                "SELECT * FROM scan_runs WHERE gateway_id=? ORDER BY id DESC LIMIT ?",
                (gateway_id, limit)).fetchall()

    def scan_hits(self, run_id: int) -> list[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(
                "SELECT * FROM scan_hits WHERE run_id=? ORDER BY gpib_address",
                (run_id,)).fetchall()

    # -- settings ----------------------------------------------------------
    def setting(self, key: str, default: str = "") -> str:
        with self.lock:
            row = self.conn.execute("SELECT value FROM app_settings WHERE key=?",
                                    (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO app_settings(key, value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
            self.conn.commit()

    # -- TestController links ----------------------------------------------
    def set_tc_link(self, instrument_id: int, match, chosen_by: str = "auto") -> None:
        """Record which TestController definition drives an instrument."""
        d = match.definition
        with self.lock:
            self.conn.execute(
                "INSERT INTO tc_links (instrument_id, path, filename, definition, handle, "
                "idstring, port, confidence, reason, chosen_by, linked_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(instrument_id) DO UPDATE SET path=excluded.path, "
                "filename=excluded.filename, definition=excluded.definition, "
                "handle=excluded.handle, idstring=excluded.idstring, port=excluded.port, "
                "confidence=excluded.confidence, reason=excluded.reason, "
                "chosen_by=excluded.chosen_by, linked_at=excluded.linked_at",
                (instrument_id, d.path, d.filename, d.label, d.handle, d.idstring,
                 d.port, match.confidence, match.reason, chosen_by, utcnow()))
            self.conn.commit()

    def clear_tc_link(self, instrument_id: int) -> None:
        with self.lock:
            self.conn.execute("DELETE FROM tc_links WHERE instrument_id=?", (instrument_id,))
            self.conn.commit()

    def clear_auto_tc_links(self) -> None:
        """Drop links this program chose, keeping the ones the user picked."""
        with self.lock:
            self.conn.execute("DELETE FROM tc_links WHERE chosen_by='auto'")
            self.conn.commit()

    def tc_links(self) -> dict[int, sqlite3.Row]:
        with self.lock:
            rows = self.conn.execute("SELECT * FROM tc_links").fetchall()
        return {int(r["instrument_id"]): r for r in rows}

    # -- export ------------------------------------------------------------
    def export_dict(self) -> dict:
        with self.lock:
            gws = [dict(r) for r in self.conn.execute("SELECT * FROM gateways").fetchall()]
            for g in gws:
                g["instruments"] = [dict(r) for r in self.conn.execute(
                    "SELECT i.*, t.filename AS tc_filename, t.definition AS tc_definition, "
                    "t.handle AS tc_handle, t.confidence AS tc_confidence "
                    "FROM instruments i LEFT JOIN tc_links t ON t.instrument_id = i.id "
                    "WHERE i.gateway_id=? ORDER BY i.gpib_address", (g["id"],)).fetchall()]
        return {"application": APP_NAME, "version": VERSION,
                "exported": utcnow(), "gateways": gws}


# --------------------------------------------------------------------------
# Headless CLI
# --------------------------------------------------------------------------

def parse_host_port(text: str) -> tuple[str, Optional[int]]:
    """Accept "10.0.0.5" or "10.0.0.5:1024" (explicit VXI-11 core port)."""
    text = text.strip()
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        if port.isdigit():
            return host.strip(), int(port)
    return text, None


def _cli_discover(args) -> int:
    hits: dict[str, int] = {}
    if not args.no_broadcast:
        hits.update(discover_broadcast(args.timeout))
        print(f"broadcast: {len(hits)} responder(s)")
    if args.cidr:
        swept = discover_sweep(args.cidr, timeout=args.probe_timeout, workers=args.workers)
        print(f"sweep {args.cidr}: {len(swept)} responder(s)")
        hits.update(swept)
    db = Database(args.db)
    for ip, port in sorted(hits.items()):
        info = identify_gateway(ip)
        info.core_port = port
        db.upsert_gateway(info)
        print(f"  {ip:<16} port {port:<6} {info.model:<14} {info.serial:<14} {info.hostname}")
    if not hits:
        print("No VXI-11 gateways answered.")
    db.close()
    return 0


def _cli_scan(args) -> int:
    host, port = parse_host_port(args.host)
    db = Database(args.db)
    info = identify_gateway(host)
    info.core_port = port
    gid = db.upsert_gateway(info)
    started = utcnow()
    print(f"{info.model} at {host} ({info.hostname or 'no reverse DNS'})")
    skip = () if args.include_controller else (args.ctrl_address,)
    recs = scan_bus(host, core_port=port, interface=args.interface,
                    addresses=range(args.first, args.last + 1), skip=skip,
                    spoll_ms=args.spoll_ms, idn_ms=args.idn_ms, deep=args.deep,
                    on_event=lambda kind, *a: (
                        print(f"  {a[0]}") if kind == "log" else None))
    db.update_gateway_settings(gid, args.interface, args.ctrl_address, port)
    db.record_scan(gid, args.interface, recs, started,
                   "deep" if args.deep else "two-phase")
    print(f"{'Addr':<5} {'STB':<20} Identification")
    for r in recs:
        if not r.present:
            continue
        print(f"{r.address:<5} {decode_stb(r.stb):<20} {r.idn or '(no *IDN? response)'}")
    print(f"\n{sum(1 for r in recs if r.present)} device(s) recorded in {db.path}")
    db.close()
    return 0


def _cli_tc(args) -> int:
    import lgi_testcontroller as tc
    db = Database(args.db)
    base = args.base or db.setting("tc_base")
    if not base:
        print("No TestController folder set. Pass --base, or set one in the app.")
        return 1
    catalog = tc.scan_install(base, on_log=lambda m: print(m))
    db.set_setting("tc_base", base)
    for name, paths in catalog.collisions:
        print(f"  collision: {' and '.join(Path(p).name for p in paths)} differ only by case")
    print()
    linked = 0
    for row in db.instruments():
        matches = tc.match_instrument(catalog, row["idn"] or "", row["manufacturer"] or "",
                                      row["model"] or "")
        best = tc.best_match(matches)
        label = f"{row['gw_ip']} @{row['gpib_address']:<3} {row['model'] or '(no IDN)':<12}"
        if best is not None:
            note = "" if best.definition.supports_gpib else "   [#port does not list GPIB]"
            print(f"{label} {best.definition.filename:<28} {best.confidence_text}{note}")
            if args.link:
                db.set_tc_link(row["id"], best, chosen_by="auto")
                linked += 1
        elif matches:
            print(f"{label} {len(matches)} candidates, none decisive: "
                  + ", ".join(m.definition.filename for m in matches[:4]))
        else:
            print(f"{label} no definition found")
    if args.link:
        print(f"\nRecorded {linked} link(s) in {db.path}")
    db.close()
    return 0


def _cli_list(args) -> int:
    db = Database(args.db)
    for g in db.gateways():
        print(f"{g['ip']:<16} {g['model']:<14} {g['serial']:<14} last seen {fmt_ts(g['last_seen'])}")
        for i in db.instruments(g["id"]):
            nick = f"  [{i['nickname']}]" if i["nickname"] else ""
            driver = f"  <{i['tc_filename']}>" if i["tc_filename"] else ""
            print(f"   {i['gpib_address']:>3}  {i['manufacturer']:<24} {i['model']:<14} "
                  f"{i['serial']:<12} {fmt_ts(i['last_seen'])}{nick}{driver}")
    db.close()
    return 0


def _cli_export(args) -> int:
    db = Database(args.db)
    text = json.dumps(db.export_dict(), indent=2)
    if args.out:
        Path(args.out).write_text(text)
        print(f"Wrote {args.out}")
    else:
        print(text)
    db.close()
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="lgi_core", description=f"{APP_TITLE} {VERSION} — headless interface")
    p.add_argument("--db", default=str(DEFAULT_DB_PATH), help="SQLite inventory file")
    # Repeat --db on every subcommand so it works either side of it. SUPPRESS
    # stops the subparser default from overwriting a value given up front.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--db", default=argparse.SUPPRESS, help="SQLite inventory file")
    sub = p.add_subparsers(dest="cmd", required=True, parser_class=(
        lambda **kw: argparse.ArgumentParser(parents=[common], **kw)))

    d = sub.add_parser("discover", help="find VXI-11 / GPIB gateways")
    d.add_argument("--cidr", default=None, help="also sweep this subnet, e.g. 192.168.1.0/24")
    d.add_argument("--timeout", type=float, default=2.0, help="broadcast listen time (s)")
    d.add_argument("--probe-timeout", type=float, default=0.6, help="per-host sweep timeout (s)")
    d.add_argument("--workers", type=int, default=64)
    d.add_argument("--no-broadcast", action="store_true")
    d.set_defaults(func=_cli_discover)

    s = sub.add_parser("scan", help="inventory the GPIB bus behind a gateway")
    s.add_argument("host", help="gateway address, optionally IP:coreport")
    s.add_argument("--interface", default="gpib0")
    s.add_argument("--first", type=int, default=0)
    s.add_argument("--last", type=int, default=30)
    s.add_argument("--ctrl-address", type=int, default=21)
    s.add_argument("--include-controller", action="store_true")
    s.add_argument("--spoll-ms", type=int, default=500)
    s.add_argument("--idn-ms", type=int, default=3000)
    s.add_argument("--deep", action="store_true",
                   help="also try *IDN? on addresses that ignored serial poll")
    s.set_defaults(func=_cli_scan)

    t = sub.add_parser("tc", help="match the inventory against TestController definitions")
    t.add_argument("--base", default=None,
                   help="TestController install or working folder (remembered between runs)")
    t.add_argument("--link", action="store_true", help="record the matches in the database")
    t.set_defaults(func=_cli_tc)

    l = sub.add_parser("list", help="print the recorded inventory")
    l.set_defaults(func=_cli_list)

    e = sub.add_parser("export", help="dump the inventory as JSON")
    e.add_argument("--out", default=None)
    e.set_defaults(func=_cli_export)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
