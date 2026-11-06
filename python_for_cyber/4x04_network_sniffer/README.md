# PySniffer 🕵️‍♂️

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Scapy](https://img.shields.io/badge/powered%20by-Scapy-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

A lightweight, extensible network packet sniffer built on top of
[Scapy](https://scapy.net/). PySniffer captures live traffic, identifies
TCP/UDP/ICMP packets, optionally searches payloads for a string, prints
per-packet details, dumps hex output in verbose mode, writes traffic to a
pcap file, and reports end-of-capture statistics.

---

## Description

PySniffer is a small command-line tool that:

- Captures live packets on a chosen interface (or all interfaces by default).
- Applies optional BPF filters (`tcp port 80`, `udp`, etc.).
- Dispatches packets to protocol-specific processors (TCP, UDP, ICMP).
- Optionally searches packet payloads for a user-supplied substring and
  prints an alert on a match.
- Optionally writes captured traffic to a `.pcap` file for later analysis
  (e.g. with Wireshark).
- Prints a summary of TCP/UDP/ICMP counts when the capture stops.
- Supports verbose mode with a hexdump of each packet.

It is designed to be readable and easy to extend: adding a new protocol
is as simple as subclassing `PacketProcessor` and registering it in
`Sniffer.processors`.

---

## Installation

### Requirements

- Python 3.8+
- [Scapy](https://scapy.readthedocs.io/)

### Install Scapy

```bash
pip install scapy
```

### Get the script

Save the source as `pysniffer.py` and make it executable:

```bash
chmod +x pysniffer.py
```

### Platform notes

- **Linux/macOS:** live capture typically requires elevated privileges
  (root or `CAP_NET_RAW`).
- **Windows:** install [Npcap](https://npcap.com/) and run the terminal
  as Administrator.

---

## Usage

```bash
./pysniffer.py [options]
```

### Options

| Flag | Long form | Description | Default |
|------|-----------|-------------|---------|
| `-i` | `--interface` | Interface to sniff on | all interfaces |
| `-f` | `--filter` | BPF capture filter (e.g. `"tcp port 80"`) | none |
| `-w` | `--write` | Write captured packets to a pcap file | none |
| `-v` | `--verbose` | Print a hexdump of each packet | off |
| `-s` | `--search` | Search payloads for this string and alert on match | none |

### Examples

Capture all traffic and print per-packet summaries:

```bash
sudo ./pysniffer.py
```

Capture only HTTP traffic on `eth0`:

```bash
sudo ./pysniffer.py -i eth0 -f "tcp port 80"
```

Search payloads for a keyword and alert on matches:

```bash
sudo ./pysniffer.py -i eth0 -f "tcp" -s "password"
```

Save capture to a pcap file for later inspection in Wireshark:

```bash
sudo ./pysniffer.py -i eth0 -w capture.pcap
```

Verbose mode with hexdump plus a search string, writing to disk:

```bash
sudo ./pysniffer.py -i eth0 -v -s "admin" -w out.pcap
```

Press `Ctrl+C` to stop the capture; a statistics summary is printed on exit.

### Sample output

```
[INFO] PySniffer initialized.
[TCP] 192.168.1.10:54321 -> 93.184.216.34:80 | Flags: S
[UDP] 192.168.1.10 -> 8.8.8.8
[ICMP] 192.168.1.10 -> 8.8.8.8
[ALERT] Payload Match found!

[INFO] Stopping capture...

========== PACKET STATISTICS ==========
TCP: 12
UDP: 4
ICMP: 1
TOTAL: 17
=======================================
```

---

## Architecture

PySniffer is organized around three cooperating pieces: a **capture
source**, a **dispatcher**, and a set of **protocol processors**.

### Components

- **`Sniffer`** — the orchestrator. Holds configuration, statistics,
  the pcap writer, and the list of processors. Its `start()` method
  resolves Scapy's `sniff()` at call time (so tests can monkeypatch it)
  and registers `_process_packet` as the per-packet callback.
- **`PacketProcessor`** — base class for protocol handlers. Subclasses
  declare a `layer_name`, `requires`, and `excludes`, implement
  `matches()` and `process()`, and inherit shared payload-search helpers
  (`_payload_bytes`, `_check_search`).
- **`TCPProcessor`, `UDPProcessor`, `ICMPProcessor`** — concrete
  processors for the three built-in protocols.
- **`packet_handler` / `_global_search`** — module-level compatibility
  shims allowing a caller to feed a packet through the pipeline without
  starting a live capture (useful for tests and embedding).

### Thread / Queue design

PySniffer deliberately uses Scapy's callback model rather than a custom
producer/consumer pipeline:

1. **Capture thread** — Scapy's `sniff()` runs in the foreground and owns
   the capture loop. It reads packets from the interface and invokes the
   callback (`Sniffer._process_packet`) **synchronously** for each packet.
   There is no separate user-created capture thread and no explicit
   `queue.Queue` in this tool.
2. **Callback = implicit work queue** — Each packet is processed
   immediately in the capture thread: dispatch → processor → optional
   search → optional hexdump → optional pcap write. Because processing is
   synchronous, ordering is preserved and no locking is required, but a
   slow processor will slow the capture loop.
3. **Dispatch stage** — `_dispatch()` first runs the payload search (if a
   search string is configured), then iterates over processors, calling
   `matches()` and, on success, `process()`. The first processor whose
   `matches()` returns `True` wins, and the matched protocol is recorded
   for statistics.
4. **Output stage** — After dispatch, the callback optionally prints a
   hexdump (verbose mode) and writes the raw packet to the pcap writer.

If you need real concurrency (e.g. heavy analysis), the intended extension
point is to hand each packet off to a worker `queue.Queue` inside
`_process_packet` and consume it from a pool of worker threads — the
processor classes are already stateless with respect to one another, so
they can be reused across threads.

### Extending

To add a new protocol, define a subclass of `PacketProcessor`, set
`protocol` and `layer_name`, implement `process()`, and register an
instance in `Sniffer.__init__`'s `self.processors` list:

```python
class DNSProcessor(PacketProcessor):
    protocol = "DNS"
    layer_name = "DNS"

    def process(self, packet):
        print(f"[DNS] {packet.src} -> {packet.dst}")
```

---

## License

MIT License. See the source for details.
