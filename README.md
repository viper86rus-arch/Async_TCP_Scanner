# ⚡ Async TCP Port Scanner

A **high-performance, production-grade TCP port scanner** built in pure Python using `asyncio`. Designed for speed, safety, and clean output — an ideal showcase of asynchronous systems programming.

---

## ✨ Features

| Feature | Details |
|---|---|
| **Asynchronous I/O** | Built entirely on `asyncio` — thousands of probes run concurrently in a single thread |
| **Semaphore control** | `asyncio.Semaphore` enforces a hard cap on simultaneous connections (default: 500) |
| **Hard timeouts** | `asyncio.wait_for` guarantees each probe is killed after N seconds — no hangs |
| **Clean CLI** | `argparse`-powered interface; specify target, port range, concurrency, timeout, and output |
| **Levelled logging** | `INFO` by default (strategic output only); `--verbose` enables per-port `DEBUG` traces |
| **JSON export** | Full scan metadata and open port list written to structured JSON |
| **Type-annotated** | PEP 8 compliant, fully typed with `dataclasses` and `typing` hints |
| **Graceful shutdown** | `KeyboardInterrupt` is caught cleanly — no tracebacks on Ctrl+C |

---

## 🏗️ Project Structure

```
Async_TCP_Scanner/
├── scanner.py       # Main scanner — all logic lives here
├── README.md        # This file
└── results/         # Auto-created when -o is used
    └── *.json       # Exported scan reports
```

---

## 🚀 Quick Start

**Requirements:** Python 3.11+ (no third-party dependencies — stdlib only)

```bash
# Clone / navigate to the project
cd Async_TCP_Scanner

# Basic scan of the top 1024 ports
python scanner.py 192.168.1.1

# Scan a hostname with a custom port range
python scanner.py scanme.nmap.org -p 1-1024

# Full options: custom range, concurrency, timeout, and JSON export
python scanner.py example.com -p 20-9000 -c 300 -t 1.5 -o results/scan.json

# Full internet scan with high concurrency and verbose per-port output
python scanner.py 10.0.0.1 -p 1-65535 -c 1000 --verbose
```

---

## 📋 CLI Reference

```
usage: scanner [-h] [-p START-END] [-c N] [-t SECS] [-o FILE] [-v] target

positional arguments:
  target                Target hostname or IP address to scan.

options:
  -h, --help            Show this help message and exit.
  -p, --ports START-END Port range in START-END format (default: 1-1024).
  -c, --concurrency N   Maximum simultaneous connections (default: 500).
  -t, --timeout SECS    Per-connection timeout in seconds (default: 1.0).
  -o, --output FILE     Path to write JSON results (optional).
  -v, --verbose         Enable DEBUG-level logging (shows every port probe).
```

---

## 🖥️ Sample Output

```
20:41:02  INFO      Scanning scanme.nmap.org (45.33.32.156) | ports 1-1024 | 1024 ports | concurrency 500 | timeout 1.0s
20:41:05  INFO      ------------------------------------------------------------
20:41:05  INFO      Scan complete in 3.142s
20:41:05  INFO      Open ports found : 3
20:41:05  INFO      Open ports       : [22, 80, 9929]
20:41:05  INFO      ------------------------------------------------------------
20:41:05  INFO      Results exported -> D:\AI_Server\Async_TCP_Scanner\results\scan.json
```

---

## 📄 JSON Export Format

When `--output` is specified, a structured report is written to disk:

```json
{
  "target": "scanme.nmap.org",
  "resolved_ip": "45.33.32.156",
  "port_range": [1, 1024],
  "concurrency": 500,
  "timeout": 1.0,
  "open_ports": [22, 80, 9929],
  "scan_duration_seconds": 3.142,
  "timestamp": "2026-10-11T15:41:05.123456+00:00"
}
```

---

## ⚙️ Architecture & Design Decisions

### Why `asyncio` instead of threads?
TCP connection probing is **I/O-bound**, not CPU-bound. `asyncio` coroutines have negligible overhead compared to OS threads, allowing tens of thousands of concurrent probes without exhausting system resources.

### Why `asyncio.Semaphore`?
Raw `asyncio.gather` with thousands of tasks would spawn thousands of OS-level TCP connections simultaneously — risking:
- **File descriptor exhaustion** (`OSError: [Errno 24] Too many open files`)
- **Network stack overload** on the host
- **Rate limiting / blacklisting** on the target

The semaphore acts as a **token bucket** — at most N probes run at any moment.

### Why `asyncio.wait_for` instead of `asyncio.open_connection` timeout?
`asyncio.open_connection` does not natively support a timeout parameter. Wrapping it in `asyncio.wait_for` guarantees the coroutine is **cancelled** (not just abandoned) after the deadline, preventing resource leaks.

### Single DNS resolution
The target hostname is resolved **once** via `socket.gethostbyname()` before any probes begin. This prevents hammering DNS servers and ensures all probes target a consistent IP throughout the scan.

---

## ⚠️ Legal & Ethical Notice

> **Only scan systems you own or have explicit written permission to test.**
> Unauthorized port scanning may be illegal under computer misuse laws in your jurisdiction.
> This tool is provided for **educational and authorized security testing purposes only**.

---

## 📜 License

MIT License — free to use, modify, and distribute with attribution.
