#!/usr/bin/env python3
"""
fake_gateway — a pretend Agilent E5810A on localhost.

Serves just enough of the portmapper and the VXI-11 core channel to exercise
the scanner end to end: discovery, link creation, serial poll, *IDN? and a few
common SCPI queries. Handy for working on the GUI on a train.

    sudo python3 fake_gateway.py                 # real ports: 111 + web on 80
    python3 fake_gateway.py --pmap-port 11111 --core-port 9010 --no-http

Virtual bus (mirrors a plausible bench):
    2   Keithley 2001
    9   Keithley 2002
    16  Tektronix TDS 460A
    23  present, but mute to *IDN? (an old listen-only device)
"""

from __future__ import annotations

import argparse
import socket
import socketserver
import struct
import sys
import threading
import time

PMAP_PROG, PMAP_VERS, PMAP_GETPORT = 100000, 2, 3
CORE_PROG, CORE_VERS = 0x0607AF, 1

CREATE_LINK, DEV_WRITE, DEV_READ, DEV_READSTB = 10, 11, 12, 13
DEV_TRIGGER, DEV_CLEAR, DEV_REMOTE, DEV_LOCAL = 14, 15, 16, 17
DESTROY_LINK = 23

ERR_IO_TIMEOUT = 15
ERR_INVALID_LINK = 4
ERR_INVALID_ADDR = 21

DEVICES = {
    2:  {"idn": "KEITHLEY INSTRUMENTS INC.,MODEL 2001,0912345,A09  /A02", "stb": 0x40, "talks": True},
    9:  {"idn": "KEITHLEY INSTRUMENTS INC.,MODEL 2002,1234567,B06  /A02", "stb": 0x00, "talks": True},
    16: {"idn": "TEKTRONIX,TDS 460A,B010101,CF:91.1CT FV:v1.0.2e", "stb": 0x10, "talks": True},
    23: {"idn": "", "stb": 0x00, "talks": False},
}

WEB_PAGE = """<html><head><title>Agilent E5810A LAN/GPIB Gateway</title></head>
<body><h1>Welcome Page</h1><table>
<tr><td>Description</td><td>Bench gateway (simulated)</td></tr>
<tr><td>Hostname</td><td>fake-e5810a</td></tr>
<tr><td>Serial Number</td><td>MY44001234</td></tr>
<tr><td>Firmware Revision</td><td>A.03.06</td></tr>
</table></body></html>"""


def p_uint(v):
    return struct.pack(">I", v & 0xFFFFFFFF)


def p_int(v):
    return struct.pack(">i", v)


def p_bytes(b):
    return struct.pack(">I", len(b)) + b + b"\x00" * ((-len(b)) % 4)


class U:
    def __init__(self, d):
        self.d, self.i = d, 0

    def uint(self):
        v = struct.unpack_from(">I", self.d, self.i)[0]
        self.i += 4
        return v

    def int(self):
        v = struct.unpack_from(">i", self.d, self.i)[0]
        self.i += 4
        return v

    def bytes(self):
        n = self.uint()
        v = self.d[self.i:self.i + n]
        self.i += n + ((-n) % 4)
        return v


def parse_call(msg):
    u = U(msg)
    xid, mtype, rpcvers, prog, vers, proc = (u.uint() for _ in range(6))
    if mtype != 0 or rpcvers != 2:
        raise ValueError("not an RPC call")
    u.i += 16                                   # cred + verf (assumed AUTH_NULL)
    return xid, prog, vers, proc, u


def accept_reply(xid, payload=b""):
    return (p_uint(xid) + p_uint(1) + p_uint(0)
            + p_uint(0) + p_uint(0) + p_uint(0) + payload)


class Bus:
    """Link table shared by every core-channel connection."""

    def __init__(self, interface="gpib0", latency=0.0):
        self.interface = interface
        self.latency = latency
        self.links = {}
        self.next_lid = 1
        self.lock = threading.Lock()

    def create(self, device):
        name = device.strip().lower()
        if not name.startswith(self.interface):
            return None, ERR_INVALID_ADDR
        tail = name[len(self.interface):].lstrip(",")
        if not tail.isdigit():
            return None, ERR_INVALID_ADDR
        addr = int(tail)
        if not 0 <= addr <= 30:
            return None, ERR_INVALID_ADDR
        with self.lock:
            lid = self.next_lid
            self.next_lid += 1
            self.links[lid] = {"addr": addr, "pending": b""}
        return lid, 0


class CoreHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(60)
        while True:
            try:
                head = self._recv(4)
                if not head:
                    return
                n = struct.unpack(">I", head)[0] & 0x7FFFFFFF
                msg = self._recv(n)
            except (OSError, struct.error):
                return
            if not msg:
                return
            try:
                reply = self.dispatch(msg)
            except Exception as e:                       # keep the sim alive
                print("core error:", e, file=sys.stderr)
                return
            if reply is None:
                return
            try:
                sock.sendall(struct.pack(">I", 0x80000000 | len(reply)) + reply)
            except OSError:
                return

    def _recv(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                return b""
            buf += chunk
        return buf

    def dispatch(self, msg):
        xid, prog, vers, proc, u = parse_call(msg)
        bus = self.server.bus
        if prog == PMAP_PROG and proc == PMAP_GETPORT:
            want_prog, _wv, _proto, _p = u.uint(), u.uint(), u.uint(), u.uint()
            port = self.server.core_port if want_prog == CORE_PROG else 0
            return accept_reply(xid, p_uint(port))
        if prog != CORE_PROG:
            return accept_reply(xid, p_uint(0))

        if proc == CREATE_LINK:
            u.int(); u.uint(); u.uint()
            device = u.bytes().decode("latin-1")
            lid, err = bus.create(device)
            if err:
                return accept_reply(xid, p_int(err) + p_int(0) + p_uint(0) + p_uint(0))
            return accept_reply(xid, p_int(0) + p_int(lid) + p_uint(0) + p_uint(4096))

        if proc == DESTROY_LINK:
            lid = u.int()
            bus.links.pop(lid, None)
            return accept_reply(xid, p_int(0))

        if proc == DEV_WRITE:
            lid = u.int(); io_to = u.uint(); u.uint(); u.uint()
            data = u.bytes()
            link = bus.links.get(lid)
            if link is None:
                return accept_reply(xid, p_int(ERR_INVALID_LINK) + p_uint(0))
            dev = DEVICES.get(link["addr"])
            if dev is None or not dev["talks"]:
                time.sleep(min(io_to, 300) / 1000.0)
                return accept_reply(xid, p_int(ERR_IO_TIMEOUT) + p_uint(0))
            link["pending"] = self.respond(dev, data)
            return accept_reply(xid, p_int(0) + p_uint(len(data)))

        if proc == DEV_READ:
            lid = u.int(); u.uint(); io_to = u.uint(); u.uint(); u.uint(); u.uint()
            link = bus.links.get(lid)
            if link is None:
                return accept_reply(xid, p_int(ERR_INVALID_LINK) + p_uint(0) + p_bytes(b""))
            data = link.get("pending") or b""
            if not data:
                time.sleep(min(io_to, 300) / 1000.0)
                return accept_reply(xid, p_int(ERR_IO_TIMEOUT) + p_uint(0) + p_bytes(b""))
            link["pending"] = b""
            time.sleep(bus.latency)
            return accept_reply(xid, p_int(0) + p_uint(4) + p_bytes(data))

        if proc == DEV_READSTB:
            lid = u.int(); u.uint(); u.uint(); io_to = u.uint()
            link = bus.links.get(lid)
            if link is None:
                return accept_reply(xid, p_int(ERR_INVALID_LINK) + p_uint(0))
            dev = DEVICES.get(link["addr"])
            if dev is None:
                time.sleep(min(io_to, 200) / 1000.0)   # empty address: bus timeout
                return accept_reply(xid, p_int(ERR_IO_TIMEOUT) + p_uint(0))
            time.sleep(bus.latency)
            return accept_reply(xid, p_int(0) + p_uint(dev["stb"]))

        if proc in (DEV_TRIGGER, DEV_CLEAR, DEV_REMOTE, DEV_LOCAL):
            lid = u.int()
            link = bus.links.get(lid)
            return accept_reply(xid, p_int(0 if link else ERR_INVALID_LINK))

        return accept_reply(xid, p_int(8))                 # not supported

    @staticmethod
    def respond(dev, data):
        cmd = data.decode("latin-1").strip().upper()
        if cmd.startswith("*IDN?"):
            return dev["idn"].encode() + b"\n"
        if cmd.startswith("*OPC?"):
            return b"1\n"
        if cmd.startswith("*ESR?") or cmd.startswith("*STB?"):
            return b"0\n"
        if cmd.startswith(":READ?") or cmd.startswith("READ?"):
            return b"+1.00042000E+00VDC,+1234.567SECS,+00001RDNG#\n"
        if cmd.endswith("?"):
            return b"0\n"
        return b""


class CoreServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class PmapUdpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            xid, prog, vers, proc, u = parse_call(data)
        except Exception:
            return
        if prog != PMAP_PROG or proc != PMAP_GETPORT:
            return
        want_prog = u.uint()
        port = self.server.core_port if want_prog == CORE_PROG else 0
        sock.sendto(accept_reply(xid, p_uint(port)), self.client_address)


class PmapUdpServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class WebHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(2)
            self.request.recv(4096)
            body = WEB_PAGE.encode()
            self.request.sendall(
                b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        except OSError:
            pass


class WebServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(bind="127.0.0.1", pmap_port=111, core_port=9010, http_port=80,
          latency=0.0, block=True):
    bus = Bus(latency=latency)
    servers = []

    core = CoreServer((bind, core_port), CoreHandler)
    core.bus, core.core_port = bus, core_port
    servers.append(core)

    try:
        pmap_tcp = CoreServer((bind, pmap_port), CoreHandler)
        pmap_tcp.bus, pmap_tcp.core_port = bus, core_port
        servers.append(pmap_tcp)
        pmap_udp = PmapUdpServer((bind, pmap_port), PmapUdpHandler)
        pmap_udp.core_port = core_port
        servers.append(pmap_udp)
    except OSError as e:
        print(f"portmapper on {pmap_port} unavailable ({e}); core port only", file=sys.stderr)

    if http_port:
        try:
            servers.append(WebServer((bind, http_port), WebHandler))
        except OSError as e:
            print(f"web server on {http_port} unavailable ({e})", file=sys.stderr)

    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
    for t in threads:
        t.start()
    print(f"fake gateway on {bind}: portmap {pmap_port}, core {core_port}, "
          f"devices at {sorted(DEVICES)}")
    if not block:
        return servers
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        for s in servers:
            s.shutdown()
    return servers


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--pmap-port", type=int, default=111)
    ap.add_argument("--core-port", type=int, default=9010)
    ap.add_argument("--http-port", type=int, default=80)
    ap.add_argument("--no-http", action="store_true")
    ap.add_argument("--latency", type=float, default=0.0)
    a = ap.parse_args()
    serve(a.bind, a.pmap_port, a.core_port, 0 if a.no_http else a.http_port, a.latency)
