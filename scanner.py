#!/usr/bin/env python3
"""
Async TCP Port Scanner
======================
A high-performance, asynchronous TCP port scanner built on Python's asyncio.
Uses a semaphore to enforce a strict concurrency ceiling and asyncio.wait_for
for hard connection timeouts — giving you full resource control at scale.

Supports passive banner grabbing: after a successful connection the scanner
waits up to 1 s for a server-initiated response; if the server is silent an
HTTP GET trigger is sent and the reply is captured.  The first line of each
banner is stored per-port in the ScanResult and written to the JSON export.

Author  : Portfolio Project
License : MIT
"""

import asyncio
import argparse
import json
import logging
import socket
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------

def configure_logging(verbose: bool = False) -> None:
    """
    Configure a clean, levelled logging format.

    Args:
        verbose: When True, sets level to DEBUG; otherwise INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s  %(levelname)-8s  %(message)s"
    date_fmt = "%H:%M:%S"
    logging.basicConfig(level=level, format=fmt, datefmt=date_fmt)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Holds the aggregated output of a completed scan."""

    target: str
    resolved_ip: str
    port_range: tuple[int, int]
    concurrency: int
    timeout: float
    open_ports: list[int] = field(default_factory=list)
    banners: dict[int, str] = field(default_factory=dict)
    scan_duration_seconds: float = 0.0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        """Serialize to a plain dictionary suitable for JSON export."""
        data = asdict(self)
        data["port_range"] = list(self.port_range)   # tuples aren't JSON-native
        # JSON keys must be strings; convert int port keys.
        data["banners"] = {str(k): v for k, v in self.banners.items()}
        return data


# ---------------------------------------------------------------------------
# Core Scanner
# ---------------------------------------------------------------------------

class AsyncPortScanner:
    """
    Asynchronous TCP port scanner.

    Attributes:
        target      : Hostname or IP address to scan.
        concurrency : Maximum number of simultaneous TCP probes.
        timeout     : Per-connection timeout in seconds.
    """

    def __init__(
        self,
        target: str,
        concurrency: int = 500,
        timeout: float = 1.0,
    ) -> None:
        self.target = target
        self.concurrency = concurrency
        self.timeout = timeout
        self._semaphore: asyncio.Semaphore  # initialised in scan()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> str:
        """
        Attempt to retrieve a service banner from an already-open connection.

        Strategy:
          1. Wait up to 1 s for a server-initiated greeting.
          2. If the server is silent, send an HTTP GET trigger and wait again.
          3. Decode the raw bytes, strip control characters, and return only
             the first non-empty line as the banner.

        Args:
            reader : Stream reader for the established connection.
            writer : Stream writer (used to send the HTTP trigger if needed).

        Returns:
            A single-line string with the banner, or an empty string if none.
        """
        raw = b""
        try:
            raw = await asyncio.wait_for(reader.read(1024), timeout=1.0)
        except asyncio.TimeoutError:
            pass

        if not raw:
            # Server didn't send anything — try an HTTP GET trigger.
            try:
                writer.write(b"GET / HTTP/1.1\r\n\r\n")
                await writer.drain()
                raw = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            except (asyncio.TimeoutError, OSError):
                pass

        if not raw:
            return ""

        decoded = raw.decode(errors="replace")
        first_line = decoded.split("\n")[0].strip()
        return first_line

    async def _probe_port(self, port: int) -> Optional[tuple[int, str]]:
        """
        Attempt a TCP connection to *port* on self.target and grab its banner.

        Uses asyncio.wait_for to enforce a hard timeout, and the shared
        semaphore to cap simultaneous connections.

        Args:
            port: The TCP port number to probe.

        Returns:
            A (port, banner) tuple if the port is open, otherwise None.
        """
        async with self._semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target, port),
                    timeout=self.timeout,
                )

                banner = await self._grab_banner(reader, writer)

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                if banner:
                    logger.debug("Port %d  ->  OPEN  |  banner: %s", port, banner)
                else:
                    logger.debug("Port %d  ->  OPEN", port)
                return port, banner

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                logger.debug("Port %d  ->  closed / filtered", port)
                return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(self, start_port: int, end_port: int) -> ScanResult:
        """
        Scan all TCP ports in the inclusive range [start_port, end_port].

        Args:
            start_port : First port in the range.
            end_port   : Last port in the range (inclusive).

        Returns:
            A populated ScanResult instance.
        """
        # Resolve the target once so every probe uses a stable IP.
        try:
            resolved_ip = socket.gethostbyname(self.target)
        except socket.gaierror as exc:
            logger.error("DNS resolution failed for '%s': %s", self.target, exc)
            sys.exit(1)

        total_ports = end_port - start_port + 1
        logger.info(
            "Scanning %s (%s) | ports %d-%d | %d ports | "
            "concurrency %d | timeout %.1fs",
            self.target,
            resolved_ip,
            start_port,
            end_port,
            total_ports,
            self.concurrency,
            self.timeout,
        )

        self._semaphore = asyncio.Semaphore(self.concurrency)

        t0 = time.perf_counter()

        tasks = [
            asyncio.create_task(self._probe_port(port))
            for port in range(start_port, end_port + 1)
        ]

        # Gather with return_exceptions=False; individual exceptions are
        # already caught inside _probe_port, so this won't mask errors.
        raw_results: list[Optional[tuple[int, str]]] = await asyncio.gather(
            *tasks, return_exceptions=False
        )

        elapsed = time.perf_counter() - t0

        open_entries = sorted(
            (port, banner) for port, banner in (r for r in raw_results if r is not None)
        )
        open_ports = [port for port, _ in open_entries]
        banners: dict[int, str] = {
            port: banner for port, banner in open_entries if banner
        }

        result = ScanResult(
            target=self.target,
            resolved_ip=resolved_ip,
            port_range=(start_port, end_port),
            concurrency=self.concurrency,
            timeout=self.timeout,
            open_ports=open_ports,
            banners=banners,
            scan_duration_seconds=round(elapsed, 3),
        )

        self._log_summary(result)
        return result

    @staticmethod
    def _log_summary(result: ScanResult) -> None:
        """Emit a structured summary once scanning is complete."""
        logger.info("-" * 60)
        logger.info("Scan complete in %.3fs", result.scan_duration_seconds)
        logger.info("Open ports found : %d", len(result.open_ports))
        if result.open_ports:
            logger.info("Open ports       : %s", result.open_ports)
            if result.banners:
                logger.info("Banners captured : %d", len(result.banners))
                for port in result.open_ports:
                    banner = result.banners.get(port, "")
                    if banner:
                        logger.info("  %-6d  %s", port, banner)
        else:
            logger.info("No open ports detected in the specified range.")
        logger.info("-" * 60)


# ---------------------------------------------------------------------------
# JSON Export
# ---------------------------------------------------------------------------

def export_json(result: ScanResult, output_path: Path) -> None:
    """
    Write a ScanResult to disk as a formatted JSON file.

    Args:
        result      : The completed scan result.
        output_path : Destination file path (created/overwritten).
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, indent=2)
    logger.info("Results exported -> %s", output_path.resolve())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Construct and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="scanner",
        description=(
            "Async TCP Port Scanner -- high-performance port scanning "
            "with strict concurrency control and JSON export."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py 192.168.1.1
  python scanner.py scanme.nmap.org -p 1-1024
  python scanner.py example.com -p 20-9000 -c 300 -t 1.5 -o results.json
  python scanner.py 10.0.0.1 -p 1-65535 -c 1000 --verbose
        """,
    )

    parser.add_argument(
        "target",
        type=str,
        help="Target hostname or IP address to scan.",
    )
    parser.add_argument(
        "-p", "--ports",
        type=str,
        default="1-1024",
        metavar="START-END",
        help="Port range in START-END format (default: 1-1024).",
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=500,
        metavar="N",
        help="Maximum simultaneous connections (default: 500).",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        metavar="SECS",
        help="Per-connection timeout in seconds (default: 1.0).",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        metavar="FILE",
        help="Path to write JSON results (optional).",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging (shows every port probe).",
    )

    return parser


def parse_port_range(port_str: str) -> tuple[int, int]:
    """
    Parse a 'START-END' string into a validated (start, end) tuple.

    Args:
        port_str: Port range string, e.g. '20-1024'.

    Returns:
        (start_port, end_port) integers.

    Raises:
        SystemExit: If the format is invalid or values are out of range.
    """
    try:
        parts = port_str.split("-")
        if len(parts) != 2:
            raise ValueError
        start, end = int(parts[0]), int(parts[1])
    except ValueError:
        logger.error(
            "Invalid port range '%s'. Expected format: START-END (e.g. 1-1024).",
            port_str,
        )
        sys.exit(1)

    if not (1 <= start <= 65535 and 1 <= end <= 65535):
        logger.error("Ports must be in the range 1-65535.")
        sys.exit(1)

    if start > end:
        logger.error("Start port (%d) must be <= end port (%d).", start, end)
        sys.exit(1)

    return start, end


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

async def main() -> None:
    """Async entry point: parse args, run scan, optionally export."""
    parser = build_parser()
    args = parser.parse_args()

    configure_logging(verbose=args.verbose)

    start_port, end_port = parse_port_range(args.ports)

    scanner = AsyncPortScanner(
        target=args.target,
        concurrency=args.concurrency,
        timeout=args.timeout,
    )

    result = await scanner.scan(start_port, end_port)

    if args.output:
        export_json(result, Path(args.output))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
        sys.exit(130)
