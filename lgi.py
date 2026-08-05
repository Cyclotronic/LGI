#!/usr/bin/env python3
"""
LGI — LAN GPIB Inventory

A desktop front end for Agilent/Keysight E5810A-class LAN/GPIB gateways.
Finds gateways on the network, opens a tab per gateway, walks the GPIB bus
behind it, and keeps a SQLite record of every instrument it has ever seen,
with first-seen and last-seen timestamps.

Standard library only: tkinter + sqlite3 + sockets. The protocol work lives in
lgi_core.py, which also runs headless if you want to script a scan.

    python3 lgi.py [--db path/to/inventory.sqlite3]
"""

from __future__ import annotations

import argparse
import csv
import json
import queue
import socket
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Optional

import lgi_testcontroller as tc
from lgi_core import (
    APP_NAME, APP_TITLE, DEFAULT_DB_PATH, VERSION, Database, DeviceRecord,
    GatewayInfo, RpcError, Vxi11Client, Vxi11Error, decode_stb, default_cidr,
    discover_broadcast, discover_sweep, fmt_ts, identify_gateway, parse_host_port,
    scan_bus, utcnow,
)

PAD = 6


# --------------------------------------------------------------------------
# Small shared helpers
# --------------------------------------------------------------------------

class QueuedFrame(ttk.Frame):
    """A frame whose background workers post events to a queue that the Tk
    main loop drains. Workers never touch a widget directly."""

    def __init__(self, master, **kw):
        super().__init__(master, **kw)
        self.q: queue.Queue = queue.Queue()
        self._pump_id: Optional[str] = None
        self._alive = True
        self._pump()

    def _pump(self) -> None:
        if not self._alive:
            return
        try:
            while True:
                event = self.q.get_nowait()
                try:
                    self.on_event(*event)
                except Exception as exc:            # a bad event must not stop the pump
                    print(f"event error: {exc}")
        except queue.Empty:
            pass
        self._pump_id = self.after(80, self._pump)

    def on_event(self, kind: str, *args) -> None:
        raise NotImplementedError

    def shutdown(self) -> None:
        self._alive = False
        if self._pump_id:
            try:
                self.after_cancel(self._pump_id)
            except tk.TclError:
                pass


class LogPane(ttk.Frame):
    def __init__(self, master, height: int = 6):
        super().__init__(master)
        self.text = tk.Text(self, height=height, wrap="none", state="disabled",
                            font=("TkFixedFont", 9))
        bar = ttk.Scrollbar(self, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=bar.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        bar.grid(row=0, column=1, sticky="ns")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

    def write(self, line: str) -> None:
        self.text.configure(state="normal")
        self.text.insert("end", line.rstrip() + "\n")
        self.text.see("end")
        self.text.configure(state="disabled")

    def clear(self) -> None:
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")


class FieldDialog(tk.Toplevel):
    """Modal editor for a handful of single-line fields."""

    def __init__(self, master, title: str, fields: dict[str, str]):
        super().__init__(master)
        self.title(title)
        self.transient(master)
        self.resizable(False, False)
        self.result: Optional[dict[str, str]] = None
        self.vars: dict[str, tk.StringVar] = {}
        body = ttk.Frame(self, padding=PAD * 2)
        body.pack(fill="both", expand=True)
        for row, (label, value) in enumerate(fields.items()):
            ttk.Label(body, text=label).grid(row=row, column=0, sticky="w", pady=3, padx=(0, PAD))
            var = tk.StringVar(value=value)
            self.vars[label] = var
            entry = ttk.Entry(body, textvariable=var, width=48)
            entry.grid(row=row, column=1, sticky="ew", pady=3)
            if row == 0:
                entry.focus_set()
        buttons = ttk.Frame(body)
        buttons.grid(row=len(fields), column=0, columnspan=2, sticky="e", pady=(PAD * 2, 0))
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right", padx=(PAD, 0))
        ttk.Button(buttons, text="Save", command=self._save).pack(side="right")
        self.bind("<Return>", lambda _e: self._save())
        self.bind("<Escape>", lambda _e: self.destroy())
        self.grab_set()
        self.wait_window(self)

    def _save(self) -> None:
        self.result = {k: v.get().strip() for k, v in self.vars.items()}
        self.destroy()


def sortable(tree: ttk.Treeview, columns: tuple[str, ...], numeric: tuple[str, ...] = ()) -> None:
    """Click a heading to sort by it."""
    state = {"col": None, "reverse": False}

    def sort_by(col: str) -> None:
        reverse = state["reverse"] if state["col"] == col else False
        reverse = not reverse if state["col"] == col else False
        state.update(col=col, reverse=reverse)
        rows = [(tree.set(k, col), k) for k in tree.get_children("")]

        def key(pair):
            value = pair[0]
            if col in numeric:
                try:
                    return (0, float(value))
                except ValueError:
                    return (1, 0.0)
            return (0, value.lower())

        rows.sort(key=key, reverse=reverse)
        for index, (_v, k) in enumerate(rows):
            tree.move(k, "", index)

    for col in columns:
        tree.heading(col, command=lambda c=col: sort_by(c))


# --------------------------------------------------------------------------
# Discovery tab
# --------------------------------------------------------------------------

DISCOVERY_COLUMNS = (
    ("ip", "Address", 130), ("hostname", "Host name", 170), ("model", "Model", 110),
    ("serial", "Serial", 120), ("firmware", "Firmware", 90), ("port", "VXI-11 port", 105),
    ("state", "State", 90), ("last_seen", "Last seen", 150),
)


class DiscoveryTab(QueuedFrame):
    def __init__(self, app: "App"):
        super().__init__(app.notebook, padding=PAD)
        self.app = app
        self.db = app.db
        self.stop_event = threading.Event()
        self.worker: Optional[threading.Thread] = None
        self.live: set[str] = set()

        controls = ttk.LabelFrame(self, text="Find gateways", padding=PAD)
        controls.grid(row=0, column=0, sticky="ew")
        controls.columnconfigure(9, weight=1)

        self.broadcast_var = tk.BooleanVar(value=True)
        self.sweep_var = tk.BooleanVar(value=True)
        self.cidr_var = tk.StringVar(value=default_cidr())
        self.timeout_var = tk.DoubleVar(value=2.0)
        self.probe_var = tk.DoubleVar(value=0.6)
        self.workers_var = tk.IntVar(value=64)

        ttk.Checkbutton(controls, text="Broadcast", variable=self.broadcast_var).grid(
            row=0, column=0, sticky="w")
        ttk.Checkbutton(controls, text="Sweep subnet", variable=self.sweep_var).grid(
            row=0, column=1, sticky="w", padx=(PAD, 2))
        ttk.Entry(controls, textvariable=self.cidr_var, width=18).grid(row=0, column=2)
        ttk.Label(controls, text="Listen (s)").grid(row=0, column=3, padx=(PAD * 2, 2))
        ttk.Spinbox(controls, from_=0.5, to=15, increment=0.5, width=5,
                    textvariable=self.timeout_var).grid(row=0, column=4)
        ttk.Label(controls, text="Per host (s)").grid(row=0, column=5, padx=(PAD, 2))
        ttk.Spinbox(controls, from_=0.1, to=5, increment=0.1, width=5,
                    textvariable=self.probe_var).grid(row=0, column=6)
        ttk.Label(controls, text="Threads").grid(row=0, column=7, padx=(PAD, 2))
        ttk.Spinbox(controls, from_=4, to=256, increment=4, width=5,
                    textvariable=self.workers_var).grid(row=0, column=8)

        buttons = ttk.Frame(controls)
        buttons.grid(row=0, column=10, sticky="e")
        self.find_btn = ttk.Button(buttons, text="Find gateways", command=self.start)
        self.find_btn.pack(side="left")
        self.stop_btn = ttk.Button(buttons, text="Stop", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=(PAD, 0))
        ttk.Button(buttons, text="Add by address…", command=self.add_manual).pack(
            side="left", padx=(PAD, 0))

        self.progress = ttk.Progressbar(self, mode="determinate")
        self.progress.grid(row=1, column=0, sticky="ew", pady=(PAD, 0))

        table = ttk.Frame(self)
        table.grid(row=2, column=0, sticky="nsew", pady=PAD)
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        cols = tuple(c[0] for c in DISCOVERY_COLUMNS)
        self.tree = ttk.Treeview(table, columns=cols, show="headings", selectmode="browse")
        for key, title, width in DISCOVERY_COLUMNS:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor="w",
                             stretch=(key in ("hostname", "last_seen")))
        vbar = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        self.tree.tag_configure("live", foreground="#0b6b2f")
        self.tree.tag_configure("stale", foreground="#666666")
        self.tree.bind("<Double-1>", lambda _e: self.open_selected())
        sortable(self.tree, cols, numeric=("port",))

        actions = ttk.Frame(self)
        actions.grid(row=3, column=0, sticky="ew")
        ttk.Button(actions, text="Open inventory", command=self.open_selected).pack(side="left")
        ttk.Button(actions, text="Edit settings…", command=self.edit_selected).pack(
            side="left", padx=(PAD, 0))
        ttk.Button(actions, text="Forget gateway", command=self.forget_selected).pack(
            side="left", padx=(PAD, 0))
        ttk.Label(actions, text="Double-click a gateway to inventory its bus.").pack(
            side="right")

        self.log = LogPane(self, height=7)
        self.log.grid(row=4, column=0, sticky="nsew", pady=(PAD, 0))

        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=3)
        self.rowconfigure(4, weight=1)

        self.refresh()
        if not self.tree.get_children(""):
            self.log.write("No gateways recorded yet. Press Find gateways to search the network.")

    # -- table -------------------------------------------------------------
    def refresh(self) -> None:
        selected = self.tree.selection()
        keep = selected[0] if selected else None
        self.tree.delete(*self.tree.get_children(""))
        for row in self.db.gateways():
            tag = "live" if row["ip"] in self.live else "stale"
            self.tree.insert(
                "", "end", iid=str(row["id"]), tags=(tag,),
                values=(row["ip"], row["hostname"] or "", row["model"] or "",
                        row["serial"] or "", row["firmware"] or "",
                        row["core_port"] or "", "responding" if tag == "live" else "recorded",
                        fmt_ts(row["last_seen"])))
        if keep and self.tree.exists(keep):
            self.tree.selection_set(keep)

    def selected_gateway_id(self) -> Optional[int]:
        selection = self.tree.selection()
        return int(selection[0]) if selection else None

    # -- discovery ---------------------------------------------------------
    def start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        if not (self.broadcast_var.get() or self.sweep_var.get()):
            messagebox.showinfo(APP_NAME, "Choose broadcast, subnet sweep, or both.")
            return
        self.stop_event.clear()
        self.find_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.progress.configure(value=0, maximum=100)
        self.log.write("─" * 60)
        params = dict(broadcast=self.broadcast_var.get(), sweep=self.sweep_var.get(),
                      cidr=self.cidr_var.get().strip(), timeout=self.timeout_var.get(),
                      probe=self.probe_var.get(), workers=self.workers_var.get())
        self.worker = threading.Thread(target=self._work, kwargs=params, daemon=True)
        self.worker.start()
        self.app.set_status("Searching for gateways…")

    def stop(self) -> None:
        self.stop_event.set()
        self.log.write("Stopping…")

    def _work(self, broadcast: bool, sweep: bool, cidr: str, timeout: float,
              probe: float, workers: int) -> None:
        found: dict[str, int] = {}
        try:
            if broadcast and not self.stop_event.is_set():
                self.q.put(("log", "Broadcasting portmap GETPORT for the VXI-11 core program…"))
                hits = discover_broadcast(timeout)
                self.q.put(("log", f"Broadcast: {len(hits)} responder(s)"))
                found.update(hits)
            if sweep and cidr and not self.stop_event.is_set():
                self.q.put(("log", f"Sweeping {cidr} on TCP/111…"))
                hits = discover_sweep(
                    cidr, timeout=probe, workers=workers, stop=self.stop_event,
                    progress=lambda done, total: self.q.put(("progress", done, total)))
                self.q.put(("log", f"Sweep: {len(hits)} responder(s)"))
                found.update(hits)
        except ValueError as exc:
            self.q.put(("log", f"Cannot sweep: {exc}"))
        except OSError as exc:
            self.q.put(("log", f"Network error: {exc}"))

        for ip, port in sorted(found.items()):
            if self.stop_event.is_set():
                break
            info = identify_gateway(ip)
            info.core_port = port
            info.source = "discovery"
            self.q.put(("gateway", info))
        self.q.put(("done", len(found)))

    def on_event(self, kind: str, *args) -> None:
        if kind == "log":
            self.log.write(args[0])
        elif kind == "progress":
            done, total = args
            self.progress.configure(maximum=max(1, total), value=done)
        elif kind == "gateway":
            info: GatewayInfo = args[0]
            self.db.upsert_gateway(info)
            self.live.add(info.ip)
            self.log.write(f"  {info.ip:<16} port {info.core_port:<6} "
                           f"{info.model:<14} {info.serial:<14} {info.hostname}")
            self.refresh()
        elif kind == "done":
            self.progress.configure(value=0)
            self.find_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            count = args[0]
            self.log.write(f"Search finished: {count} gateway(s) responding.")
            if not count:
                self.log.write("Nothing answered. Some switches drop directed broadcasts — "
                               "try the subnet sweep, or add the gateway by address.")
            self.app.set_status(f"{count} gateway(s) responding")
            self.app.refresh_inventory()
        elif kind == "manual":
            info, open_tab = args
            gid = self.db.upsert_gateway(info)
            self.live.add(info.ip)
            self.refresh()
            self.log.write(f"Added {info.ip} ({info.model}).")
            if open_tab:
                self.app.open_gateway(gid)

    # -- actions -----------------------------------------------------------
    def add_manual(self) -> None:
        dialog = FieldDialog(self, "Add gateway", {
            "Address": "",
            "VXI-11 core port (blank = ask the portmapper)": "",
            "GPIB interface name": "gpib0",
        })
        if not dialog.result:
            return
        raw = dialog.result["Address"]
        if not raw:
            return
        host, port = parse_host_port(raw)
        port_text = dialog.result["VXI-11 core port (blank = ask the portmapper)"]
        if port_text.isdigit():
            port = int(port_text)
        iface = dialog.result["GPIB interface name"] or "gpib0"
        self.log.write(f"Probing {host}…")

        def work() -> None:
            try:
                socket.gethostbyname(host)
            except OSError as exc:
                self.q.put(("log", f"Cannot resolve {host}: {exc}"))
                return
            info = identify_gateway(host)
            info.core_port = port
            info.source = "manual"
            self.q.put(("manual", info, True))
            gid_row = self.db.gateway_by_ip(host)
            if gid_row:
                self.db.update_gateway_settings(gid_row["id"], iface,
                                                gid_row["ctrl_address"], port)

        threading.Thread(target=work, daemon=True).start()

    def open_selected(self) -> None:
        gid = self.selected_gateway_id()
        if gid is None:
            messagebox.showinfo(APP_NAME, "Select a gateway first.")
            return
        self.app.open_gateway(gid)

    def edit_selected(self) -> None:
        gid = self.selected_gateway_id()
        if gid is None:
            return
        row = self.db.gateway(gid)
        dialog = FieldDialog(self, f"Settings for {row['ip']}", {
            "GPIB interface name": row["interface"] or "gpib0",
            "Controller GPIB address": str(row["ctrl_address"] if row["ctrl_address"] is not None else 21),
            "VXI-11 core port": str(row["core_port"] or ""),
            "Notes": row["notes"] or "",
        })
        if not dialog.result:
            return
        try:
            ctrl = int(dialog.result["Controller GPIB address"] or 21)
        except ValueError:
            ctrl = 21
        port_text = dialog.result["VXI-11 core port"]
        self.db.update_gateway_settings(
            gid, dialog.result["GPIB interface name"] or "gpib0", ctrl,
            int(port_text) if port_text.isdigit() else None)
        self.db.set_gateway_notes(gid, dialog.result["Notes"])
        self.refresh()
        self.log.write(f"Updated settings for {row['ip']}.")

    def forget_selected(self) -> None:
        gid = self.selected_gateway_id()
        if gid is None:
            return
        row = self.db.gateway(gid)
        count = len(self.db.instruments(gid))
        if not messagebox.askyesno(
                APP_NAME,
                f"Delete {row['ip']} and its {count} recorded instrument(s) from the database?\n\n"
                "Scan history for this gateway goes too. This cannot be undone."):
            return
        self.app.close_gateway_tab(gid)
        self.db.delete_gateway(gid)
        self.live.discard(row["ip"])
        self.refresh()
        self.app.refresh_inventory()
        self.log.write(f"Removed {row['ip']} from the database.")


# --------------------------------------------------------------------------
# Gateway tab
# --------------------------------------------------------------------------

BUS_COLUMNS = (
    ("addr", "Addr", 55), ("state", "State", 125), ("stb", "Status byte", 150),
    ("manufacturer", "Manufacturer", 215), ("model", "Model", 110),
    ("serial", "Serial", 120), ("firmware", "Firmware", 130),
    ("nickname", "Nickname", 120), ("first_seen", "First seen", 158),
    ("last_seen", "Last seen", 158), ("idn", "*IDN? response", 420),
)


class GatewayTab(QueuedFrame):
    def __init__(self, app: "App", gateway_id: int):
        super().__init__(app.notebook, padding=PAD)
        self.app = app
        self.db = app.db
        self.gateway_id = gateway_id
        row = self.db.gateway(gateway_id)
        self.ip = row["ip"]
        self.stop_event = threading.Event()
        self.worker: Optional[threading.Thread] = None
        self.records: dict[int, DeviceRecord] = {}
        self.instrument_ids: dict[int, int] = {}
        self.console_client: Optional[Vxi11Client] = None
        self.console_lid: Optional[int] = None
        self.console_addr: Optional[int] = None
        self.history: list[str] = []
        self.history_pos = 0

        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)
        title = f"{row['model'] or 'VXI-11 gateway'} at {row['ip']}"
        subtitle_bits = [b for b in (row["hostname"], f"serial {row['serial']}" if row["serial"] else "",
                                     f"firmware {row['firmware']}" if row["firmware"] else "",
                                     row["description"]) if b]
        ttk.Label(header, text=title, font=("TkDefaultFont", 11, "bold")).grid(
            row=0, column=0, sticky="w")
        ttk.Label(header, text="   " + " · ".join(subtitle_bits), foreground="#555555").grid(
            row=0, column=1, sticky="w")
        ttk.Button(header, text="Close tab",
                   command=lambda: self.app.close_gateway_tab(self.gateway_id)).grid(
            row=0, column=2, sticky="e")

        self.inner = ttk.Notebook(self)
        self.inner.grid(row=1, column=0, sticky="nsew", pady=(PAD, 0))
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self._build_bus_pane(row)
        self._build_console_pane()
        self._build_history_pane()

        self.load_from_db()
        self.refresh_history()

    # -- layout ------------------------------------------------------------
    def _build_bus_pane(self, row) -> None:
        pane = ttk.Frame(self.inner, padding=PAD)
        self.inner.add(pane, text="Bus inventory")
        pane.columnconfigure(0, weight=1)
        pane.rowconfigure(2, weight=3)
        pane.rowconfigure(4, weight=1)

        controls = ttk.LabelFrame(pane, text="Scan", padding=PAD)
        controls.grid(row=0, column=0, sticky="ew")
        controls.columnconfigure(14, weight=1)

        self.iface_var = tk.StringVar(value=row["interface"] or "gpib0")
        self.first_var = tk.IntVar(value=0)
        self.last_var = tk.IntVar(value=30)
        self.ctrl_var = tk.IntVar(value=row["ctrl_address"] if row["ctrl_address"] is not None else 21)
        self.skip_ctrl_var = tk.BooleanVar(value=True)
        self.spoll_var = tk.IntVar(value=500)
        self.idn_var = tk.IntVar(value=3000)
        self.deep_var = tk.BooleanVar(value=False)
        self.clear_var = tk.BooleanVar(value=False)

        ttk.Label(controls, text="Interface").grid(row=0, column=0, sticky="w")
        ttk.Entry(controls, textvariable=self.iface_var, width=8).grid(row=0, column=1, padx=(2, PAD))
        ttk.Label(controls, text="Addresses").grid(row=0, column=2, sticky="w")
        ttk.Spinbox(controls, from_=0, to=30, width=4, textvariable=self.first_var).grid(row=0, column=3)
        ttk.Label(controls, text="to").grid(row=0, column=4, padx=2)
        ttk.Spinbox(controls, from_=0, to=30, width=4, textvariable=self.last_var).grid(row=0, column=5)
        ttk.Label(controls, text="Controller at").grid(row=0, column=6, padx=(PAD, 2))
        ttk.Spinbox(controls, from_=0, to=30, width=4, textvariable=self.ctrl_var).grid(row=0, column=7)
        ttk.Checkbutton(controls, text="skip it", variable=self.skip_ctrl_var).grid(
            row=0, column=8, padx=(2, PAD))
        ttk.Label(controls, text="Poll ms").grid(row=0, column=9)
        ttk.Spinbox(controls, from_=100, to=10000, increment=100, width=6,
                    textvariable=self.spoll_var).grid(row=0, column=10, padx=(2, PAD))
        ttk.Label(controls, text="*IDN? ms").grid(row=0, column=11)
        ttk.Spinbox(controls, from_=200, to=30000, increment=250, width=6,
                    textvariable=self.idn_var).grid(row=0, column=12, padx=(2, PAD))

        options = ttk.Frame(controls)
        options.grid(row=1, column=0, columnspan=13, sticky="w", pady=(PAD, 0))
        ttk.Checkbutton(options, text="Also query addresses that ignore serial poll",
                        variable=self.deep_var).pack(side="left")
        ttk.Checkbutton(options, text="Send device clear before *IDN?",
                        variable=self.clear_var).pack(side="left", padx=(PAD * 2, 0))

        buttons = ttk.Frame(controls)
        buttons.grid(row=0, column=15, rowspan=2, sticky="e")
        self.scan_btn = ttk.Button(buttons, text="Scan bus", command=self.start_scan)
        self.scan_btn.pack(side="left")
        self.stop_btn = ttk.Button(buttons, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=(PAD, 0))

        self.progress = ttk.Progressbar(pane, mode="determinate")
        self.progress.grid(row=1, column=0, sticky="ew", pady=(PAD, 0))

        table = ttk.Frame(pane)
        table.grid(row=2, column=0, sticky="nsew", pady=PAD)
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        cols = tuple(c[0] for c in BUS_COLUMNS)
        self.tree = ttk.Treeview(table, columns=cols, show="headings", selectmode="browse")
        for key, title, width in BUS_COLUMNS:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor="w", stretch=(key == "idn"))
        vbar = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        hbar = ttk.Scrollbar(table, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        hbar.grid(row=1, column=0, sticky="ew")
        self.tree.tag_configure("present", foreground="#0b6b2f")
        self.tree.tag_configure("silent", foreground="#8a6d00")
        self.tree.tag_configure("absent", foreground="#999999")
        self.tree.tag_configure("failed", foreground="#a11")
        self.tree.bind("<Double-1>", lambda _e: self.edit_instrument())
        sortable(self.tree, cols, numeric=("addr",))

        actions = ttk.Frame(pane)
        actions.grid(row=3, column=0, sticky="ew")
        ttk.Button(actions, text="Query this address", command=self.query_selected).pack(side="left")
        ttk.Button(actions, text="Edit nickname and notes…", command=self.edit_instrument).pack(
            side="left", padx=(PAD, 0))
        ttk.Button(actions, text="Open in console", command=self.send_to_console).pack(
            side="left", padx=(PAD, 0))
        ttk.Button(actions, text="Export this bus…", command=self.export_bus).pack(
            side="left", padx=(PAD, 0))
        self.summary = ttk.Label(actions, text="")
        self.summary.pack(side="right")

        self.log = LogPane(pane, height=7)
        self.log.grid(row=4, column=0, sticky="nsew", pady=(PAD, 0))

    def _build_console_pane(self) -> None:
        pane = ttk.Frame(self.inner, padding=PAD)
        self.inner.add(pane, text="Console")
        pane.columnconfigure(0, weight=1)
        pane.rowconfigure(1, weight=1)

        bar = ttk.Frame(pane)
        bar.grid(row=0, column=0, sticky="ew")
        ttk.Label(bar, text="GPIB address").pack(side="left")
        self.console_addr_var = tk.StringVar()
        self.console_addr_box = ttk.Combobox(bar, textvariable=self.console_addr_var,
                                             width=6, values=[str(a) for a in range(31)])
        self.console_addr_box.pack(side="left", padx=(2, PAD))
        ttk.Button(bar, text="Serial poll", command=lambda: self.console_action("stb")).pack(side="left")
        ttk.Button(bar, text="Read", command=lambda: self.console_action("read")).pack(
            side="left", padx=(PAD, 0))
        ttk.Button(bar, text="Device clear", command=lambda: self.console_action("clear")).pack(
            side="left", padx=(PAD, 0))
        ttk.Button(bar, text="Go to local", command=lambda: self.console_action("local")).pack(
            side="left", padx=(PAD, 0))
        ttk.Button(bar, text="Drop link", command=lambda: self.console_action("unlink")).pack(
            side="left", padx=(PAD, 0))
        ttk.Label(bar, text="A link stays open until you change address or drop it.",
                  foreground="#555555").pack(side="right")

        self.console_out = LogPane(pane, height=18)
        self.console_out.grid(row=1, column=0, sticky="nsew", pady=PAD)

        entry_row = ttk.Frame(pane)
        entry_row.grid(row=2, column=0, sticky="ew")
        entry_row.columnconfigure(0, weight=1)
        self.command_var = tk.StringVar()
        self.command_entry = ttk.Entry(entry_row, textvariable=self.command_var,
                                       font=("TkFixedFont", 10))
        self.command_entry.grid(row=0, column=0, sticky="ew")
        self.command_entry.bind("<Return>", lambda _e: self.console_action("auto"))
        self.command_entry.bind("<Up>", self._history_back)
        self.command_entry.bind("<Down>", self._history_forward)
        ttk.Button(entry_row, text="Send", command=lambda: self.console_action("auto")).grid(
            row=0, column=1, padx=(PAD, 0))
        ttk.Label(pane, text="A command ending in ? is written and then read back; "
                             "anything else is write-only.",
                  foreground="#555555").grid(row=3, column=0, sticky="w", pady=(2, 0))


    def _build_history_pane(self) -> None:
        pane = ttk.Frame(self.inner, padding=PAD)
        self.inner.add(pane, text="Scan history")
        pane.columnconfigure(0, weight=1)
        pane.columnconfigure(1, weight=2)
        pane.rowconfigure(0, weight=1)

        left = ttk.Frame(pane)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, PAD))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(0, weight=1)
        self.runs_tree = ttk.Treeview(
            left, columns=("when", "found", "scanned", "mode"), show="headings", selectmode="browse")
        for key, title, width in (("when", "Finished", 150), ("found", "Found", 60),
                                  ("scanned", "Scanned", 70), ("mode", "Mode", 90)):
            self.runs_tree.heading(key, text=title)
            self.runs_tree.column(key, width=width, anchor="w")
        self.runs_tree.grid(row=0, column=0, sticky="nsew")
        self.runs_tree.bind("<<TreeviewSelect>>", lambda _e: self.show_run())

        right = ttk.Frame(pane)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)
        self.hits_tree = ttk.Treeview(
            right, columns=("addr", "present", "stb", "idn", "error"),
            show="headings", selectmode="browse")
        for key, title, width in (("addr", "Addr", 50), ("present", "Present", 70),
                                  ("stb", "Status byte", 130), ("idn", "*IDN? response", 380),
                                  ("error", "Note", 160)):
            self.hits_tree.heading(key, text=title)
            self.hits_tree.column(key, width=width, anchor="w", stretch=(key == "idn"))
        self.hits_tree.grid(row=0, column=0, sticky="nsew")

    # -- inventory table ---------------------------------------------------
    def load_from_db(self) -> None:
        """Show the latest recorded instrument for each address."""
        self.tree.delete(*self.tree.get_children(""))
        self.instrument_ids.clear()
        latest: dict[int, dict] = {}
        for row in self.db.instruments(self.gateway_id):
            addr = row["gpib_address"]
            if addr not in latest or (row["last_seen"] or "") > (latest[addr]["last_seen"] or ""):
                latest[addr] = dict(row)
        for addr in sorted(latest):
            row = latest[addr]
            self.instrument_ids[addr] = row["id"]
            state = "recorded" if row["responded_idn"] else "recorded (mute)"
            self.tree.insert("", "end", iid=str(addr), tags=("absent",), values=(
                addr, state, decode_stb(row["stb"]), row["manufacturer"], row["model"],
                row["serial"], row["firmware"], row["nickname"],
                fmt_ts(row["first_seen"]), fmt_ts(row["last_seen"]), row["idn"]))
        for rec in self.records.values():          # live scan state wins over history
            self.upsert_row(rec, scroll=False)
        first = next((k for k in self.tree.get_children("")
                      if self.tree.tag_has("present", k) or self.tree.tag_has("silent", k)), None)
        self.tree.see(first or (self.tree.get_children("") or [None])[0] or "")
        self.update_summary()
        self.console_addr_box.configure(
            values=[str(a) for a in sorted(latest)] or [str(a) for a in range(31)])

    def upsert_row(self, rec: DeviceRecord, scroll: bool = True) -> None:
        iid = str(rec.address)
        if rec.responded_idn:
            state, tag = "responding", "present"
        elif rec.present and rec.queried:
            state, tag = "present (mute)", "silent"
        elif rec.present:
            state, tag = "polled", "silent"
        elif rec.error:
            state, tag = "error", "failed"
        else:
            state, tag = "empty", "absent"
        values = (rec.address, state, decode_stb(rec.stb), rec.manufacturer, rec.model,
                  rec.serial, rec.firmware,
                  self.tree.set(iid, "nickname") if self.tree.exists(iid) else "",
                  self.tree.set(iid, "first_seen") if self.tree.exists(iid) else "",
                  self.tree.set(iid, "last_seen") if self.tree.exists(iid) else "",
                  rec.idn or rec.error)
        if self.tree.exists(iid):
            self.tree.item(iid, values=values, tags=(tag,))
        else:
            index = sum(1 for k in self.tree.get_children("") if int(k) < rec.address)
            self.tree.insert("", index, iid=iid, values=values, tags=(tag,))
        if scroll:
            self.tree.see(iid)

    def update_summary(self) -> None:
        present = sum(1 for r in self.records.values() if r.present)
        if self.records:
            self.summary.configure(
                text=f"{present} device(s) on the bus · {len(self.records)} address(es) probed")
        else:
            self.summary.configure(text=f"{len(self.tree.get_children(''))} address(es) on record")

    # -- scanning ----------------------------------------------------------
    def start_scan(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        first, last = self.first_var.get(), self.last_var.get()
        if first > last:
            messagebox.showinfo(APP_NAME, "The first address must not be above the last.")
            return
        row = self.db.gateway(self.gateway_id)
        iface = self.iface_var.get().strip() or "gpib0"
        self.db.update_gateway_settings(self.gateway_id, iface, self.ctrl_var.get())
        self.records.clear()
        self.stop_event.clear()
        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.log.write("─" * 60)
        self.log.write(f"Scanning {iface} addresses {first}–{last} on {self.ip}")
        self.close_console_link(quiet=True)
        params = dict(host=self.ip, core_port=row["core_port"], interface=iface,
                      first=first, last=last,
                      skip=(self.ctrl_var.get(),) if self.skip_ctrl_var.get() else (),
                      spoll=self.spoll_var.get(), idn=self.idn_var.get(),
                      deep=self.deep_var.get(), clear=self.clear_var.get())
        self.worker = threading.Thread(target=self._scan_work, kwargs=params, daemon=True)
        self.worker.start()
        self.app.set_status(f"Scanning {self.ip}…")

    def stop_scan(self) -> None:
        self.stop_event.set()
        self.log.write("Stopping after the current address…")

    def _scan_work(self, host, core_port, interface, first, last, skip,
                   spoll, idn, deep, clear) -> None:
        started = utcnow()
        try:
            records = scan_bus(
                host, core_port=core_port, interface=interface,
                addresses=range(first, last + 1), skip=skip, spoll_ms=spoll,
                idn_ms=idn, deep=deep, send_clear=clear,
                on_event=lambda kind, *a: self.q.put((kind,) + a),
                stop=self.stop_event)
        except (OSError, RpcError, Vxi11Error) as exc:
            self.q.put(("log", f"Scan failed: {exc}"))
            self.q.put(("scan_done", None, started))
            return
        self.q.put(("scan_done", records, started))

    def on_event(self, kind: str, *args) -> None:
        if kind == "log":
            self.log.write(args[0])
        elif kind == "progress":
            done, total, message = args
            self.progress.configure(maximum=max(1, total), value=done)
            self.app.set_status(message)
        elif kind == "row":
            rec: DeviceRecord = args[0]
            self.records[rec.address] = rec
            self.upsert_row(rec)
            if rec.responded_idn:
                self.log.write(f"  {rec.address:>3}  {rec.idn}")
            elif rec.present and rec.queried:
                self.log.write(f"  {rec.address:>3}  answers serial poll "
                               f"({decode_stb(rec.stb)}) but not *IDN?")
            elif rec.present:
                self.log.write(f"  {rec.address:>3}  answers serial poll ({decode_stb(rec.stb)})")
            elif rec.error:
                self.log.write(f"  {rec.address:>3}  {rec.error}")
            self.update_summary()
        elif kind == "scan_done":
            records, started = args
            self.progress.configure(value=0)
            self.scan_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            if records:
                mode = "deep" if self.deep_var.get() else "two-phase"
                self.db.record_scan(self.gateway_id, self.iface_var.get() or "gpib0",
                                    records, started, mode)
                found = sum(1 for r in records if r.present)
                self.log.write(f"Recorded {found} device(s) in {self.db.path.name}.")
                self.app.set_status(f"{self.ip}: {found} device(s) found")
                for rec in records:
                    self.records[rec.address] = rec
                self.load_from_db()
                self.refresh_history()
                self.app.refresh_inventory()
                self.app.discovery.refresh()
            else:
                self.app.set_status("Scan finished with no result")
        elif kind == "console":
            self.console_out.write(args[0])
        elif kind == "console_state":
            self.console_addr = args[0]

    # -- per-address actions -----------------------------------------------
    def selected_address(self) -> Optional[int]:
        selection = self.tree.selection()
        if not selection:
            return None
        try:
            return int(selection[0])
        except ValueError:
            return None

    def query_selected(self) -> None:
        addr = self.selected_address()
        if addr is None:
            messagebox.showinfo(APP_NAME, "Select an address first.")
            return
        if self.worker and self.worker.is_alive():
            messagebox.showinfo(APP_NAME, "A scan is already running.")
            return
        row = self.db.gateway(self.gateway_id)
        iface = self.iface_var.get().strip() or "gpib0"
        self.log.write(f"Querying {iface},{addr}…")
        started = utcnow()
        spoll_ms, idn_ms = self.spoll_var.get(), self.idn_var.get()
        send_clear, core_port = self.clear_var.get(), row["core_port"]

        def work() -> None:
            try:
                records = scan_bus(
                    self.ip, core_port=core_port, interface=iface,
                    addresses=[addr], skip=(), spoll_ms=spoll_ms,
                    idn_ms=idn_ms, deep=True, send_clear=send_clear,
                    on_event=lambda kind, *a: self.q.put((kind,) + a))
            except (OSError, RpcError, Vxi11Error) as exc:
                self.q.put(("log", f"Query failed: {exc}"))
                return
            self.q.put(("scan_done", records, started))

        self.scan_btn.configure(state="disabled")
        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def edit_instrument(self) -> None:
        addr = self.selected_address()
        if addr is None:
            return
        iid = self.instrument_ids.get(addr)
        if iid is None:
            messagebox.showinfo(APP_NAME, "Scan the bus first so there is a record to annotate.")
            return
        current = next((r for r in self.db.instruments(self.gateway_id) if r["id"] == iid), None)
        if current is None:
            return
        dialog = FieldDialog(self, f"Address {addr}", {
            "Nickname": current["nickname"] or "",
            "Notes": current["notes"] or "",
        })
        if not dialog.result:
            return
        self.db.set_instrument_fields(iid, dialog.result["Nickname"], dialog.result["Notes"])
        if self.tree.exists(str(addr)):
            self.tree.set(str(addr), "nickname", dialog.result["Nickname"])
        self.app.refresh_inventory()
        self.log.write(f"Saved notes for address {addr}.")

    def send_to_console(self) -> None:
        addr = self.selected_address()
        if addr is None:
            return
        self.console_addr_var.set(str(addr))
        self.inner.select(1)
        self.command_entry.focus_set()

    def export_bus(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export this bus", defaultextension=".json",
            initialfile=f"{self.ip.replace('.', '-')}-inventory.json",
            filetypes=[("JSON", "*.json"), ("CSV", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        rows = [dict(r) for r in self.db.instruments(self.gateway_id)]
        try:
            if path.lower().endswith(".csv"):
                with open(path, "w", newline="") as fh:
                    writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else
                                            ["gpib_address"])
                    writer.writeheader()
                    writer.writerows(rows)
            else:
                gateway = dict(self.db.gateway(self.gateway_id))
                gateway["instruments"] = rows
                Path(path).write_text(json.dumps(
                    {"application": APP_NAME, "version": VERSION, "exported": utcnow(),
                     "gateways": [gateway]}, indent=2))
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"Could not write {path}:\n{exc}")
            return
        self.log.write(f"Exported {len(rows)} record(s) to {path}")

    # -- console -----------------------------------------------------------
    def ensure_console_link(self, addr: int, iface: str, core_port: Optional[int]) -> None:
        """Called from a worker thread, so it must not touch Tk variables."""
        if self.console_client and self.console_addr == addr and self.console_lid is not None:
            return
        self.close_console_link(quiet=True)
        client = Vxi11Client(self.ip, core_port=core_port, timeout=5.0)
        client.connect()
        self.console_lid = client.create_link(f"{iface},{addr}")
        self.console_client = client
        self.console_addr = addr
        self.q.put(("console", f"— link open on {iface},{addr} —"))

    def close_console_link(self, quiet: bool = False) -> None:
        if self.console_client:
            try:
                if self.console_lid is not None:
                    self.console_client.destroy_link(self.console_lid)
            except Exception:
                pass
            self.console_client.close()
            if not quiet:
                self.console_out.write("— link closed —")
        self.console_client = None
        self.console_lid = None
        self.console_addr = None

    def console_action(self, action: str) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showinfo(APP_NAME, "Wait for the scan to finish before using the console.")
            return
        if action == "unlink":
            self.close_console_link()
            return
        text = self.console_addr_var.get().strip()
        if not text.isdigit():
            messagebox.showinfo(APP_NAME, "Enter the GPIB address to talk to.")
            return
        addr = int(text)
        command = self.command_var.get().strip()
        if action == "auto":
            if not command:
                return
            self.history.append(command)
            self.history_pos = len(self.history)
            self.command_var.set("")
        timeout = self.idn_var.get()
        spoll_ms = self.spoll_var.get()
        iface = self.iface_var.get().strip() or "gpib0"
        core_port = self.db.gateway(self.gateway_id)["core_port"]

        def work() -> None:
            try:
                self.ensure_console_link(addr, iface, core_port)
                client, lid = self.console_client, self.console_lid
                if client is None or lid is None:
                    return
                if action == "stb":
                    stb = client.readstb(lid, spoll_ms)
                    self.q.put(("console", f"< serial poll {decode_stb(stb)}"))
                elif action == "clear":
                    client.clear(lid, timeout)
                    self.q.put(("console", "< device clear sent"))
                elif action == "local":
                    client.local(lid, timeout)
                    self.q.put(("console", "< returned to local control"))
                elif action == "read":
                    data = client.read(lid, io_timeout=timeout)
                    self.q.put(("console", f"< {data.decode('latin-1').strip()}"))
                elif action == "auto":
                    self.q.put(("console", f"> {command}"))
                    client.write(lid, command.encode() + b"\n", timeout)
                    if command.rstrip().endswith("?"):
                        data = client.read(lid, io_timeout=timeout)
                        self.q.put(("console", f"< {data.decode('latin-1').strip()}"))
            except Vxi11Error as exc:
                self.q.put(("console", f"! {exc}"))
            except (OSError, RpcError) as exc:
                self.q.put(("console", f"! transport error: {exc}"))
                self.close_console_link(quiet=True)

        threading.Thread(target=work, daemon=True).start()

    def _history_back(self, _event) -> str:
        if self.history and self.history_pos > 0:
            self.history_pos -= 1
            self.command_var.set(self.history[self.history_pos])
        return "break"

    def _history_forward(self, _event) -> str:
        if self.history_pos < len(self.history) - 1:
            self.history_pos += 1
            self.command_var.set(self.history[self.history_pos])
        else:
            self.history_pos = len(self.history)
            self.command_var.set("")
        return "break"

    # -- history -----------------------------------------------------------
    def refresh_history(self) -> None:
        self.runs_tree.delete(*self.runs_tree.get_children(""))
        for run in self.db.scan_runs(self.gateway_id):
            self.runs_tree.insert("", "end", iid=str(run["id"]), values=(
                fmt_ts(run["finished"]), run["found"], run["scanned"], run["mode"]))

    def show_run(self) -> None:
        selection = self.runs_tree.selection()
        self.hits_tree.delete(*self.hits_tree.get_children(""))
        if not selection:
            return
        for hit in self.db.scan_hits(int(selection[0])):
            self.hits_tree.insert("", "end", values=(
                hit["gpib_address"], "yes" if hit["present"] else "no",
                decode_stb(hit["stb"]), hit["idn"] or "", hit["error"] or ""))

    def shutdown(self) -> None:
        self.stop_event.set()
        self.close_console_link(quiet=True)
        super().shutdown()


# --------------------------------------------------------------------------
# Inventory tab
# --------------------------------------------------------------------------

INVENTORY_COLUMNS = (
    ("gateway", "Gateway", 150), ("addr", "Addr", 50), ("manufacturer", "Manufacturer", 190),
    ("model", "Model", 110), ("serial", "Serial", 120), ("firmware", "Firmware", 130),
    ("driver", "TestController driver", 215), ("match", "Match", 95),
    ("nickname", "Nickname", 120), ("first_seen", "First seen", 158),
    ("last_seen", "Last seen", 158), ("notes", "Notes", 220),
)
TC_COLUMNS = ("driver", "match")


class DriverChooser(tk.Toplevel):
    """Pick which TestController definition drives an instrument."""

    def __init__(self, master, title: str, matches, current: str = ""):
        super().__init__(master)
        self.title(title)
        self.transient(master)
        self.result: Optional[object] = None
        self.cleared = False
        body = ttk.Frame(self, padding=PAD * 2)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(1, weight=1)

        heading = (f"{len(matches)} candidate definition(s). "
                   "An exact match is one TestController itself would accept."
                   if matches else
                   "No definition in the catalogue mentions this instrument.")
        ttk.Label(body, text=heading).grid(row=0, column=0, sticky="w", pady=(0, PAD))

        columns = ("definition", "file", "confidence", "port", "reason")
        self.tree = ttk.Treeview(body, columns=columns, show="headings",
                                 selectmode="browse", height=10)
        for key, label, width in (("definition", "Definition", 190), ("file", "File", 175),
                                  ("confidence", "Match", 95), ("port", "Ports", 110),
                                  ("reason", "Matched on", 300)):
            self.tree.heading(key, text=label)
            self.tree.column(key, width=width, anchor="w", stretch=(key == "reason"))
        bar = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=bar.set)
        self.tree.grid(row=1, column=0, sticky="nsew")
        bar.grid(row=1, column=1, sticky="ns")
        self.tree.tag_configure("noport", foreground="#8a6d00")

        self.matches = list(matches)
        for index, match in enumerate(self.matches):
            definition = match.definition
            tags = () if definition.supports_gpib else ("noport",)
            self.tree.insert("", "end", iid=str(index), tags=tags, values=(
                definition.label, definition.filename, match.confidence_text,
                definition.port or "not stated", match.reason))
            if definition.filename == current:
                self.tree.selection_set(str(index))
        if self.matches and not self.tree.selection():
            self.tree.selection_set("0")

        note = ("Amber rows do not list GPIB in #port, so TestController will not "
                "offer them for a GPIB connection as they stand.")
        ttk.Label(body, text=note, foreground="#555555").grid(
            row=2, column=0, sticky="w", pady=(PAD, 0))

        buttons = ttk.Frame(body)
        buttons.grid(row=3, column=0, columnspan=2, sticky="e", pady=(PAD * 2, 0))
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right", padx=(PAD, 0))
        ttk.Button(buttons, text="Use this one", command=self._choose).pack(side="right")
        ttk.Button(buttons, text="No driver", command=self._clear).pack(side="right", padx=(0, PAD))
        self.tree.bind("<Double-1>", lambda _e: self._choose())
        self.bind("<Escape>", lambda _e: self.destroy())
        self.grab_set()
        self.wait_window(self)

    def _choose(self) -> None:
        selection = self.tree.selection()
        if selection:
            self.result = self.matches[int(selection[0])]
        self.destroy()

    def _clear(self) -> None:
        self.cleared = True
        self.destroy()


class InventoryTab(QueuedFrame):
    """Two panes: the instrument records, and the TestController integration
    that annotates them. The integration is optional, so it gets its own sub-tab
    rather than crowding the records with settings most people never touch."""

    def __init__(self, app: "App"):
        super().__init__(app.notebook, padding=PAD)
        self.app = app
        self.db = app.db
        self.catalog: Optional[tc.Catalog] = None
        self.tc_busy = False
        self.tc_enabled_var = tk.BooleanVar(value=self.db.setting("tc_enabled") == "1")
        self.tc_base_var = tk.StringVar(
            value=self.db.setting("tc_base") or tc.default_bases()[0])

        self.inner = ttk.Notebook(self)
        self.inner.grid(row=0, column=0, sticky="nsew")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        self._build_records_pane()
        self._build_testcontroller_pane()

        self.apply_tc_visibility()
        self.refresh()
        if self.tc_enabled_var.get():
            self.scan_testcontroller()

    # -- instrument records ------------------------------------------------
    def _build_records_pane(self) -> None:
        pane = ttk.Frame(self.inner, padding=PAD)
        self.inner.add(pane, text="Instruments")
        pane.columnconfigure(0, weight=1)
        pane.rowconfigure(1, weight=1)

        bar = ttk.Frame(pane)
        bar.grid(row=0, column=0, sticky="ew")
        ttk.Label(bar, text="Filter").pack(side="left")
        self.filter_var = tk.StringVar()
        entry = ttk.Entry(bar, textvariable=self.filter_var, width=32)
        entry.pack(side="left", padx=(4, PAD))
        entry.bind("<KeyRelease>", lambda _e: self.refresh())
        ttk.Button(bar, text="Refresh", command=self.refresh).pack(side="left")
        ttk.Button(bar, text="Edit nickname and notes…", command=self.edit_selected).pack(
            side="left", padx=(PAD, 0))
        ttk.Button(bar, text="Delete record", command=self.delete_selected).pack(
            side="left", padx=(PAD, 0))
        ttk.Button(bar, text="Export JSON…", command=self.app.export_json).pack(side="right")
        ttk.Button(bar, text="Export CSV…", command=self.app.export_csv).pack(
            side="right", padx=(0, PAD))

        table = ttk.Frame(pane)
        table.grid(row=1, column=0, sticky="nsew", pady=PAD)
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        cols = tuple(c[0] for c in INVENTORY_COLUMNS)
        self.tree = ttk.Treeview(table, columns=cols, show="headings", selectmode="browse")
        for key, title, width in INVENTORY_COLUMNS:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor="w", stretch=(key == "notes"))
        vbar = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        hbar = ttk.Scrollbar(table, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        hbar.grid(row=1, column=0, sticky="ew")
        self.tree.tag_configure("nodriver", foreground="#8a6d00")
        self.tree.bind("<Double-1>", lambda _e: self.edit_selected())
        sortable(self.tree, cols, numeric=("addr",))

        self.count = ttk.Label(pane, text="")
        self.count.grid(row=2, column=0, sticky="w")

    # -- TestController ----------------------------------------------------
    def _build_testcontroller_pane(self) -> None:
        pane = ttk.Frame(self.inner, padding=PAD)
        self.inner.add(pane, text="TestController")
        pane.columnconfigure(0, weight=1)
        pane.rowconfigure(1, weight=1)

        settings = ttk.LabelFrame(pane, text="Device definitions", padding=PAD)
        settings.grid(row=0, column=0, sticky="ew")
        settings.columnconfigure(2, weight=1)
        ttk.Checkbutton(settings, text="Match instruments to device definitions",
                        variable=self.tc_enabled_var,
                        command=self.toggle_testcontroller).grid(row=0, column=0, sticky="w")
        ttk.Label(settings, text="Install or working folder").grid(
            row=0, column=1, sticky="w", padx=(PAD * 2, 4))
        ttk.Entry(settings, textvariable=self.tc_base_var).grid(row=0, column=2, sticky="ew")
        ttk.Button(settings, text="Browse…", command=self.browse_tc_base).grid(
            row=0, column=3, padx=(4, 0))
        self.tc_scan_btn = ttk.Button(settings, text="Scan definitions",
                                      command=self.scan_testcontroller)
        self.tc_scan_btn.grid(row=0, column=4, padx=(PAD, 0))
        ttk.Label(settings, text="Nothing is written to the TestController folder. "
                                 "Definitions are matched on #idString, which is the first "
                                 "two fields of the instrument's *IDN? reply.",
                  foreground="#555555").grid(row=1, column=0, columnspan=5,
                                             sticky="w", pady=(4, 0))
        self.tc_status = ttk.Label(settings, text="", wraplength=1150, justify="left")
        self.tc_status.grid(row=2, column=0, columnspan=5, sticky="w", pady=(4, 0))

        split = ttk.PanedWindow(pane, orient="horizontal")
        split.grid(row=1, column=0, sticky="nsew", pady=PAD)

        left = ttk.Frame(split)
        left.columnconfigure(0, weight=1)
        left.rowconfigure(1, weight=1)
        ttk.Label(left, text="Inventoried instruments and their drivers").grid(
            row=0, column=0, sticky="w")
        link_cols = ("gateway", "addr", "instrument", "driver", "match")
        self.tc_tree = ttk.Treeview(left, columns=link_cols, show="headings",
                                    selectmode="browse")
        for key, title, width in (("gateway", "Gateway", 110), ("addr", "Addr", 50),
                                  ("instrument", "Instrument", 200),
                                  ("driver", "Definition file", 200), ("match", "Match", 105)):
            self.tc_tree.heading(key, text=title)
            self.tc_tree.column(key, width=width, anchor="w", stretch=(key == "driver"))
        lbar = ttk.Scrollbar(left, orient="vertical", command=self.tc_tree.yview)
        self.tc_tree.configure(yscrollcommand=lbar.set)
        self.tc_tree.grid(row=1, column=0, sticky="nsew")
        lbar.grid(row=1, column=1, sticky="ns")
        self.tc_tree.tag_configure("linked", foreground="#0b6b2f")
        self.tc_tree.tag_configure("needs", foreground="#8a6d00")
        self.tc_tree.tag_configure("none", foreground="#777777")
        self.tc_tree.bind("<Double-1>", lambda _e: self.choose_driver())
        sortable(self.tc_tree, link_cols, numeric=("addr",))

        buttons = ttk.Frame(left)
        buttons.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(4, 0))
        ttk.Button(buttons, text="Choose driver…", command=self.choose_driver).pack(side="left")
        ttk.Button(buttons, text="Clear driver", command=self.clear_driver).pack(
            side="left", padx=(4, 0))
        ttk.Label(buttons, text="Double-click a row to see every candidate.",
                  foreground="#555555").pack(side="right")
        split.add(left, weight=3)

        right = ttk.Frame(split)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)
        self.defs_label = ttk.Label(right, text="Definitions found")
        self.defs_label.grid(row=0, column=0, sticky="w")
        def_cols = ("file", "definition", "handle", "port")
        self.defs_tree = ttk.Treeview(right, columns=def_cols, show="headings",
                                      selectmode="browse")
        for key, title, width in (("file", "File", 175), ("definition", "Definition", 175),
                                  ("handle", "Handle", 85), ("port", "Ports", 110)):
            self.defs_tree.heading(key, text=title)
            self.defs_tree.column(key, width=width, anchor="w", stretch=(key == "definition"))
        rbar = ttk.Scrollbar(right, orient="vertical", command=self.defs_tree.yview)
        self.defs_tree.configure(yscrollcommand=rbar.set)
        self.defs_tree.grid(row=1, column=0, sticky="nsew")
        rbar.grid(row=1, column=1, sticky="ns")
        self.defs_tree.tag_configure("collision", foreground="#a11")
        self.defs_tree.tag_configure("noport", foreground="#8a6d00")
        sortable(self.defs_tree, def_cols)
        ttk.Label(right, text="Red: two file names differing only by case. "
                             "Amber: #port does not list GPIB.",
                  foreground="#555555").grid(row=2, column=0, columnspan=2,
                                             sticky="w", pady=(4, 0))
        split.add(right, weight=2)

        self.tc_log = LogPane(pane, height=6)
        self.tc_log.grid(row=2, column=0, sticky="nsew")

    def apply_tc_visibility(self) -> None:
        """Hide the driver columns in the records table when the feature is off."""
        columns = [c[0] for c in INVENTORY_COLUMNS]
        if not self.tc_enabled_var.get():
            columns = [c for c in columns if c not in TC_COLUMNS]
        self.tree.configure(displaycolumns=columns)
        state = "normal" if self.tc_enabled_var.get() else "disabled"
        self.tc_scan_btn.configure(state="disabled" if self.tc_busy else state)

    def toggle_testcontroller(self) -> None:
        enabled = self.tc_enabled_var.get()
        self.db.set_setting("tc_enabled", "1" if enabled else "0")
        self.apply_tc_visibility()
        if enabled:
            self.scan_testcontroller()
        else:
            self.catalog = None
            self.tc_status.configure(text="")
            self.defs_tree.delete(*self.defs_tree.get_children(""))
            self.defs_label.configure(text="Definitions found")
            self.tc_log.write("TestController matching turned off. "
                              "Existing links stay in the database.")
            self.refresh()

    def browse_tc_base(self) -> None:
        start = self.tc_base_var.get() or tc.default_bases()[0]
        chosen = filedialog.askdirectory(
            title="Where is TestController installed?",
            initialdir=start if Path(start).is_dir() else str(Path.home()))
        if not chosen:
            return
        self.tc_base_var.set(chosen)
        self.db.set_setting("tc_base", chosen)
        if self.tc_enabled_var.get():
            self.scan_testcontroller()

    def scan_testcontroller(self) -> None:
        if self.tc_busy or not self.tc_enabled_var.get():
            return
        base = self.tc_base_var.get().strip()
        if not base:
            self.tc_status.configure(text="Set the folder TestController is installed in.")
            return
        self.db.set_setting("tc_base", base)
        self.tc_busy = True
        self.tc_scan_btn.configure(state="disabled")
        self.tc_log.write("─" * 60)
        self.tc_log.write(f"Reading definitions under {base}…")

        def work() -> None:
            catalog = tc.scan_install(base, on_log=lambda m: self.q.put(("tc_log", m)))
            linked = 0
            ambiguous = 0
            existing = self.db.tc_links()
            self.db.clear_auto_tc_links()          # keep the user's own choices
            for row in self.db.instruments():
                if row["id"] in existing and existing[row["id"]]["chosen_by"] == "user":
                    continue
                matches = tc.match_instrument(catalog, row["idn"] or "",
                                              row["manufacturer"] or "", row["model"] or "")
                best = tc.best_match(matches)
                if best is not None:
                    self.db.set_tc_link(row["id"], best, chosen_by="auto")
                    linked += 1
                elif matches:
                    ambiguous += 1
            self.q.put(("tc_scanned", catalog, linked, ambiguous))

        threading.Thread(target=work, daemon=True).start()

    def on_event(self, kind: str, *args) -> None:
        if kind == "tc_log":
            self.tc_log.write(args[0])
            return
        if kind != "tc_scanned":
            return
        catalog, linked, ambiguous = args
        self.catalog = catalog
        self.tc_busy = False
        self.apply_tc_visibility()

        status = f"{catalog.summary()}   ·   {linked} instrument(s) linked automatically"
        if ambiguous:
            status += f"   ·   {ambiguous} need a choice"
        self.tc_status.configure(
            text=status, foreground="#a11" if catalog.collisions or catalog.errors else "#555555")
        for name, paths in catalog.collisions:
            self.tc_log.write(
                f"Name collision: {' and '.join(Path(p).name for p in paths)} differ only by "
                "case, so they are one file on Windows and macOS")
        for error in catalog.errors:
            self.tc_log.write(error)
        self.tc_log.write(f"{linked} linked automatically, {ambiguous} awaiting a choice.")
        self.fill_definitions()
        self.refresh()

    def fill_definitions(self) -> None:
        self.defs_tree.delete(*self.defs_tree.get_children(""))
        if self.catalog is None:
            return
        colliding = {Path(p).name for _n, paths in self.catalog.collisions for p in paths}
        for index, definition in enumerate(sorted(
                self.catalog.usable, key=lambda d: (d.filename.lower(), d.index))):
            tags = []
            if definition.filename in colliding:
                tags.append("collision")
            elif not definition.supports_gpib:
                tags.append("noport")
            self.defs_tree.insert("", "end", iid=str(index), tags=tuple(tags), values=(
                definition.filename, definition.label, definition.handle,
                definition.port or "not stated"))
        self.defs_label.configure(
            text=f"Definitions found — {len(self.catalog.usable)} in "
                 f"{len(self.catalog.directories)} folder(s)")

    def fill_links(self) -> None:
        selected = self.tc_tree.selection()
        keep = selected[0] if selected else None
        self.tc_tree.delete(*self.tc_tree.get_children(""))
        if not self.tc_enabled_var.get():
            return
        for row in self.db.instruments():
            instrument = " ".join(b for b in (row["manufacturer"], row["model"]) if b)
            if row["nickname"]:
                instrument = f"{row['nickname']} — {instrument}" if instrument else row["nickname"]
            driver = row["tc_filename"] or ""
            if row["tc_confidence"]:
                match = tc.CONFIDENCE_TEXT.get(row["tc_confidence"], row["tc_confidence"])
                if row["tc_chosen_by"] == "user":
                    match += ", chosen"
                tag = "linked"
            elif self.catalog is None:
                match, tag = "", "none"
            else:
                match, tag = "none", "none"
            self.tc_tree.insert("", "end", iid=str(row["id"]), tags=(tag,), values=(
                row["gw_hostname"] or row["gw_ip"], row["gpib_address"],
                instrument or "(no identification)", driver, match))
        if keep and self.tc_tree.exists(keep):
            self.tc_tree.selection_set(keep)

    def selected_instrument_id(self) -> Optional[int]:
        """Whichever table the user is looking at."""
        if str(self.inner.select()) == str(self.inner.tabs()[1]):
            selection = self.tc_tree.selection()
        else:
            selection = self.tree.selection()
        return int(selection[0]) if selection else None

    def choose_driver(self) -> None:
        if not self.tc_enabled_var.get():
            messagebox.showinfo(APP_NAME, "Turn on the TestController integration first.")
            return
        if self.catalog is None:
            messagebox.showinfo(APP_NAME, "Scan the definitions first.")
            return
        iid = self.selected_instrument_id()
        if iid is None:
            messagebox.showinfo(APP_NAME, "Select an instrument first.")
            return
        row = next((r for r in self.db.instruments() if r["id"] == iid), None)
        if row is None:
            return
        matches = tc.match_instrument(self.catalog, row["idn"] or "",
                                      row["manufacturer"] or "", row["model"] or "")
        title = f"{row['manufacturer']} {row['model']} at address {row['gpib_address']}"
        dialog = DriverChooser(self, title, matches, row["tc_filename"] or "")
        if dialog.cleared:
            self.db.clear_tc_link(iid)
            self.tc_log.write(f"Cleared the driver for address {row['gpib_address']}.")
        elif dialog.result is not None:
            self.db.set_tc_link(iid, dialog.result, chosen_by="user")
            self.tc_log.write(f"Address {row['gpib_address']} linked to "
                              f"{dialog.result.definition.filename} by hand.")
        else:
            return
        self.refresh()

    def clear_driver(self) -> None:
        iid = self.selected_instrument_id()
        if iid is None:
            messagebox.showinfo(APP_NAME, "Select an instrument first.")
            return
        self.db.clear_tc_link(iid)
        self.tc_log.write("Driver link cleared.")
        self.refresh()

    # -- records -----------------------------------------------------------
    def refresh(self) -> None:
        needle = self.filter_var.get().strip().lower()
        self.tree.delete(*self.tree.get_children(""))
        shown = 0
        unmatched = 0
        for row in self.db.instruments():
            gateway = row["gw_hostname"] or row["gw_ip"]
            blob = " ".join(str(row[k] or "") for k in (
                "manufacturer", "model", "serial", "firmware", "nickname", "notes", "idn",
                "tc_filename", "tc_definition", "tc_handle")).lower()
            if needle and needle not in blob and needle not in gateway.lower():
                continue
            shown += 1
            driver = row["tc_filename"] or ""
            if driver and row["tc_definition"]:
                driver = f"{row['tc_definition']} ({driver})"
            match = ""
            if row["tc_confidence"]:
                match = tc.CONFIDENCE_TEXT.get(row["tc_confidence"], row["tc_confidence"])
                if row["tc_chosen_by"] == "user":
                    match += ", chosen"
            elif self.tc_enabled_var.get() and self.catalog is not None:
                match = "none"
            tags = ("nodriver",) if match == "none" else ()
            if match == "none":
                unmatched += 1
            self.tree.insert("", "end", iid=str(row["id"]), tags=tags, values=(
                gateway, row["gpib_address"], row["manufacturer"], row["model"],
                row["serial"], row["firmware"], driver, match, row["nickname"],
                fmt_ts(row["first_seen"]), fmt_ts(row["last_seen"]), row["notes"]))
        summary = f"{shown} instrument record(s) · database {self.db.path}"
        if unmatched and self.tc_enabled_var.get():
            summary += f" · {unmatched} without a TestController driver"
        self.count.configure(text=summary)
        self.fill_links()

    def selected_id(self) -> Optional[int]:
        selection = self.tree.selection()
        return int(selection[0]) if selection else None

    def edit_selected(self) -> None:
        iid = self.selected_instrument_id()
        if iid is None:
            return
        row = next((r for r in self.db.instruments() if r["id"] == iid), None)
        if row is None:
            return
        dialog = FieldDialog(self, f"{row['model'] or 'Instrument'} at address {row['gpib_address']}", {
            "Nickname": row["nickname"] or "",
            "Notes": row["notes"] or "",
        })
        if not dialog.result:
            return
        self.db.set_instrument_fields(iid, dialog.result["Nickname"], dialog.result["Notes"])
        self.refresh()
        tab = self.app.gateway_tabs.get(row["gateway_id"])
        if tab:
            tab.load_from_db()

    def delete_selected(self) -> None:
        iid = self.selected_instrument_id()
        if iid is None:
            return
        if not messagebox.askyesno(APP_NAME, "Delete this instrument record?"):
            return
        self.db.delete_instrument(iid)
        self.refresh()


class App(tk.Tk):
    def __init__(self, db_path: Path):
        super().__init__()
        self.title(f"{APP_NAME} — {APP_TITLE} {VERSION}")
        self.geometry("1280x800")
        self.minsize(980, 600)
        self.db = Database(db_path)
        self.gateway_tabs: dict[int, GatewayTab] = {}

        try:
            style = ttk.Style(self)
            for preferred in ("clam", "vista", "aqua"):
                if preferred in style.theme_names():
                    style.theme_use(preferred)
                    break
            style.configure("Treeview", rowheight=22)
        except tk.TclError:
            pass

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=PAD, pady=(PAD, 0))

        self.discovery = DiscoveryTab(self)
        self.notebook.add(self.discovery, text="Gateways")
        self.inventory = InventoryTab(self)
        self.notebook.add(self.inventory, text="Inventory")

        self.status = ttk.Label(self, text=f"Database: {self.db.path}", anchor="w",
                                relief="sunken", padding=(PAD, 2))
        self.status.pack(fill="x", side="bottom")

        self._build_menu()
        self.protocol("WM_DELETE_WINDOW", self.quit_app)
        self.bind("<Control-w>", lambda _e: self.close_current_tab())
        self.bind("<F5>", lambda _e: self.discovery.start())

    def _build_menu(self) -> None:
        menu = tk.Menu(self)
        file_menu = tk.Menu(menu, tearoff=0)
        file_menu.add_command(label="Open database…", command=self.open_database)
        file_menu.add_separator()
        file_menu.add_command(label="Export JSON…", command=self.export_json)
        file_menu.add_command(label="Export CSV…", command=self.export_csv)
        file_menu.add_separator()
        file_menu.add_command(label="Quit", command=self.quit_app)
        menu.add_cascade(label="File", menu=file_menu)

        scan_menu = tk.Menu(menu, tearoff=0)
        scan_menu.add_command(label="Find gateways", accelerator="F5",
                              command=lambda: self.discovery.start())
        scan_menu.add_command(label="Add gateway by address…",
                              command=lambda: self.discovery.add_manual())
        scan_menu.add_separator()
        scan_menu.add_command(label="Close this tab", accelerator="Ctrl+W",
                              command=self.close_current_tab)
        menu.add_cascade(label="Scan", menu=scan_menu)

        help_menu = tk.Menu(menu, tearoff=0)
        help_menu.add_command(label="About", command=self.about)
        menu.add_cascade(label="Help", menu=help_menu)
        self.configure(menu=menu)

    # -- tabs --------------------------------------------------------------
    def open_gateway(self, gateway_id: int) -> None:
        tab = self.gateway_tabs.get(gateway_id)
        if tab is not None:
            self.notebook.select(tab)
            return
        row = self.db.gateway(gateway_id)
        if row is None:
            return
        tab = GatewayTab(self, gateway_id)
        self.gateway_tabs[gateway_id] = tab
        label = row["hostname"].split(".")[0] if row["hostname"] else row["ip"]
        self.notebook.add(tab, text=label)
        self.notebook.select(tab)
        self.set_status(f"Opened {row['ip']}")

    def close_gateway_tab(self, gateway_id: int) -> None:
        tab = self.gateway_tabs.pop(gateway_id, None)
        if tab is None:
            return
        tab.shutdown()
        self.notebook.forget(tab)
        tab.destroy()

    def close_current_tab(self) -> None:
        current = self.notebook.nametowidget(self.notebook.select())
        for gid, tab in list(self.gateway_tabs.items()):
            if tab is current:
                self.close_gateway_tab(gid)
                return

    def refresh_inventory(self) -> None:
        self.inventory.refresh()

    def set_status(self, text: str) -> None:
        self.status.configure(text=f"{text}   ·   {self.db.path}")

    # -- files -------------------------------------------------------------
    def open_database(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Open or create an inventory database", defaultextension=".sqlite3",
            initialfile="inventory.sqlite3", confirmoverwrite=False,
            filetypes=[("SQLite", "*.sqlite3 *.db *.sqlite"), ("All files", "*.*")])
        if not path:
            return
        for gid in list(self.gateway_tabs):
            self.close_gateway_tab(gid)
        self.db.close()
        self.db = Database(Path(path))
        self.discovery.db = self.db
        self.discovery.live.clear()
        self.discovery.refresh()
        self.inventory.db = self.db
        self.inventory.refresh()
        self.set_status("Database opened")

    def export_json(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export inventory as JSON", defaultextension=".json",
            initialfile="gpib-inventory.json", filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            Path(path).write_text(json.dumps(self.db.export_dict(), indent=2))
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"Could not write {path}:\n{exc}")
            return
        self.set_status(f"Exported {path}")

    def export_csv(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export inventory as CSV", defaultextension=".csv",
            initialfile="gpib-inventory.csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        rows = self.db.instruments()
        fields = ["gw_ip", "gw_hostname", "gw_model", "gpib_address", "manufacturer",
                  "model", "serial", "firmware", "nickname", "notes", "idn",
                  "first_seen", "last_seen"]
        try:
            with open(path, "w", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=fields)
                writer.writeheader()
                for row in rows:
                    writer.writerow({k: row[k] for k in fields})
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"Could not write {path}:\n{exc}")
            return
        self.set_status(f"Exported {len(rows)} record(s) to {path}")

    def about(self) -> None:
        messagebox.showinfo(
            f"About {APP_NAME}",
            f"{APP_NAME} {VERSION} — {APP_TITLE}\n\n"
            "Finds VXI-11 LAN/GPIB gateways such as the Agilent E5810A, walks the\n"
            "GPIB bus behind each one, and keeps a SQLite record of what was found\n"
            "and when.\n\n"
            "Discovery broadcasts a portmap GETPORT for the VXI-11 core program and\n"
            "can also sweep a subnet directly. Bus scans serial-poll every address\n"
            "first, then ask the responders for *IDN?.\n\n"
            "Standard library only: no VISA runtime required.")

    def quit_app(self) -> None:
        for gid in list(self.gateway_tabs):
            self.close_gateway_tab(gid)
        self.discovery.shutdown()
        self.inventory.shutdown()
        try:
            self.db.close()
        except Exception:
            pass
        self.destroy()


# Subcommands handled by the headless side. A frozen build is a single
# executable, so the GUI entry point has to hand these straight through or the
# command line interface becomes unreachable once packaged.
CLI_COMMANDS = ("discover", "scan", "tc", "list", "export")


def first_positional(argv: list[str]) -> str:
    """The first bare word, skipping options and the values they consume.

    Needed so that `lgi --db bench.sqlite3 scan 10.0.0.5` still recognises
    "scan", while a database file that happens to be called scan does not
    masquerade as a subcommand.
    """
    takes_value = {"--db"}
    skip_next = False
    for arg in argv:
        if skip_next:
            skip_next = False
            continue
        if arg == "--":
            continue
        if arg.startswith("-"):
            skip_next = arg in takes_value
            continue
        return arg
    return ""


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if first_positional(argv) in CLI_COMMANDS:
        import lgi_core
        return lgi_core.main(argv)

    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} — {APP_TITLE}",
        epilog="Run with a subcommand (" + ", ".join(CLI_COMMANDS) +
               ") for the headless interface; see `--help` after the subcommand.")
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH),
                        help=f"SQLite inventory file (default {DEFAULT_DB_PATH})")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    args = parser.parse_args(argv)

    try:
        app = App(Path(args.db))
    except tk.TclError as exc:
        print(f"{APP_NAME}: no display available ({exc}).\n"
              f"Use a subcommand for headless work: {', '.join(CLI_COMMANDS)}",
              file=sys.stderr)
        return 2
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
