# LGI - LAN GPIB Inventory

Finds Agilent/Keysight E5810A-class LAN/GPIB gateways on the network, walks the
GPIB bus behind each one, and keeps a SQLite record of every instrument it has
ever seen - gateway, GPIB address, instrument identity, and first/last seen.

Standard library only. No VISA runtime, no `pyvisa`, no `python-vxi11`.
Python 3.9+ with Tk (`python3-tk` on Debian/Ubuntu, bundled on macOS/Windows).

```
python3 lgi.py                       # default DB at ~/.lgi/inventory.sqlite3
python3 lgi.py --db bench.sqlite3
```

## Files

| File | Purpose |
|---|---|
| `lgi.py` | Tkinter GUI. Gateways tab, one tab per gateway, inventory browser. |
| `lgi_core.py` | ONC RPC + VXI-11 client, discovery, scanning, SQLite layer, headless CLI. |
| `lgi_testcontroller.py` | Optional: reads TestController device definitions and matches them to the inventory. |
| `fake_gateway.py` | A simulated E5810A with four virtual instruments, for testing without hardware. |

## How discovery works

Two independent mechanisms, both selectable:

1. **Broadcast** - a portmap `GETPORT` for the VXI-11 core program (`0x0607AF`,
   version 1) sent to UDP/111 on each subnet broadcast address. Every VXI-11
   instrument server answers with its core channel port. Same mechanism VISA
   uses for `TCPIP?*::INSTR`.
2. **Subnet sweep** - a threaded unicast `GETPORT` over TCP/111 across a CIDR.
   Slower, but crosses routers and survives switches that drop directed
   broadcasts. Capped at 4096 addresses.

Responders are then identified over HTTP: `/lxi/identification` first (E5810B
and other LXI devices give clean XML), falling back to scraping the welcome page
for model, serial, firmware and hostname. Anything that answers on the VXI-11
program is listed even if identification fails - the tool works with E2050s and
clones, not just the E5810A.

If neither finds your gateway, **Add by address…** takes an IP or hostname, and
optionally an explicit VXI-11 core port to bypass the portmapper entirely
(`10.0.0.50:1024` also works in the address field).

## How the bus scan works

Two-phase, and it does not disturb instrument state:

1. **Serial poll every address.** Create a link to `gpib0,<addr>`, `device_readstb`
   with a short timeout, destroy the link. Fast, and an empty address just times
   out at the bus level.
2. **`*IDN?` the responders.** Write, read, parse into manufacturer / model /
   serial / firmware.

The status byte is decoded (RQS/MSS, ESB, MAV, QSB, EAV) and kept, so an
instrument sitting with SRQ asserted is visible at a glance.

Options worth knowing:

- **Also query addresses that ignore serial poll** - catches older listen-mostly
  gear that never answers a poll but does answer `*IDN?`. Slower: every empty
  address costs a full `*IDN?` timeout.
- **Send device clear before `*IDN?`** - off by default, since DCL will abort
  whatever the instrument is doing. Useful for something wedged mid-transfer.
- **Controller at / skip it** - the E5810A's own GPIB address, default 21.
- **Interface** - `gpib0` for the E5810A. Editable for gateways using other
  logical names.

Anything the gateway reports as present gets a row; addresses that answer serial
poll but stay mute to `*IDN?` are recorded too, marked "present (mute)", so you
can annotate them by hand.

## Console

Per-gateway terminal against a single address. A link stays open until you
change address or drop it, so multi-step sequences work. A command ending in `?`
is written then read back; anything else is write-only. Up/Down walks history.
Buttons for serial poll, bare read, device clear, and go-to-local.

## TestController integration (optional)

Off by default, and it lives on its own sub-tab so it stays out of the way when
unused: **Inventory → TestController**. Turn it on there, point it at your
TestController install or working folder, and press **Scan definitions**.

That sub-tab shows two tables side by side - your inventoried instruments with
the definition file matched to each, and every definition the scan found, with
its handle and the ports it declares. A log below records what was read. Over on
the **Instruments** sub-tab, two extra columns appear on the records themselves
so the match is visible alongside everything else known about the instrument.
Nothing is ever written to the TestController installation.

Matching is on `#idString`, which is the first two comma-separated fields of the
instrument's `*idn?` reply, and which TestController's SCPI driver requires to
match before it will connect. Since the inventory already stores the full IDN
read off the bus, both sides of the comparison came from the instrument itself
rather than from a guess about model names.

| Match | Meaning |
|---|---|
| exact | `#idString` matches the recorded IDN. TestController would accept this. |
| case differs | Matches only when case is ignored - worth checking, as the comparison is literal. |
| likely / possible | No IDN to compare, so the model name was matched against `#name` or the file name. Confirm it yourself. |
| none | No definition in the catalogue mentions this instrument. |

An unambiguous `#idString` hit is linked automatically. Anything ambiguous -
two files claiming the same instrument, or only a name-based guess - is left
alone and marked, because a wrong link is worse than no link. Select the row
and press **Choose driver…** (or double-click it) to see every candidate with
the reason it matched, and pick one. A choice you make by hand is marked "chosen" and survives later
rescans; automatic links are recalculated each time.

Case handling, which is the fiddly part:

- The folder is found whether it is spelled `Devices`, `devices` or `DEVICES`,
  and both the install folder and the working folder under
  `Documents/TestController` are searched.
- File names are matched case-insensitively, so `Keithley2001.txt` and
  `keithley2001.txt` are the same definition as far as matching goes.
- Two files whose names differ **only** by case are reported as a collision.
  They coexist happily on Linux but collapse into one file on Windows and
  macOS, so a definition set carrying such a pair silently loses one when it
  moves between machines.

A `#meta` block is a template rather than a device, so it is never offered.
Devices built from it with `#metadef` are, inheriting any tag they don't
override. If a matched definition's `#port` doesn't list GPIB, that's flagged -
TestController won't offer it for a GPIB connection as written.

## Database

`gateways` → `instruments`, plus `scan_runs` / `scan_hits` for scan history and
diffing, `tc_links` for TestController associations, and `app_settings` for
preferences. Timestamps are ISO-8601 UTC in the file, shown as local time.

Instruments are keyed on `(gateway_id, gpib_address, idn)`. Swap the instrument
at address 16 and you get a second row rather than a clobbered one - the old
instrument keeps its `last_seen`, so the record shows what was on that address
and when. `first_seen` never moves once set.

`nickname` and `notes` are yours to fill in and survive rescans. Export is JSON
or CSV, per-bus or whole-database.

## Testing without hardware

```
sudo python3 fake_gateway.py                     # portmapper on 111, web on 80
python3 lgi.py                                   # sweep 127.0.0.1/32
```

Or without root:

```
python3 fake_gateway.py --pmap-port 11111 --core-port 9010 --no-http
```
then add `127.0.0.1:9010` by address. The simulator presents a Keithley 2001 at
2, a 2002 at 9, a TDS 460A at 16, and a deliberately mute device at 23.

## Headless

The core module runs without Tk:

```
python3 lgi_core.py discover --cidr 192.168.1.0/24
python3 lgi_core.py scan 192.168.1.50 --deep
python3 lgi_core.py list
python3 lgi_core.py export --out inventory.json

python3 lgi_core.py tc --base ~/TestController          # report matches
python3 lgi_core.py tc --link                           # and record them
```

Same database, so a cron scan and the GUI share one inventory.

The gateway's own settings are not touched by this tool - configure the E5810A
from its web interface.

## Notes on E5810A behaviour

- Link creation usually succeeds regardless of whether a device is actually at
  that address; the failure surfaces at the first I/O as error 15 (I/O timeout).
  That is why presence detection is serial-poll based rather than link-based.
- Concurrent links are limited. Every scan link is destroyed immediately after
  use, and the console link is dropped before a scan starts.
- The core channel occasionally drops on older firmware. The scanner reconnects
  once per address and carries on rather than aborting the pass.
- Scan time is roughly `addresses × poll timeout` for the empty ones. 500 ms
  across 0–30 is about 15 s worst case; drop to 200–300 ms on a healthy bus.
