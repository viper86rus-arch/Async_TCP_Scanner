"""
==============================================================================
Тестовый комплекс: Async_TCP_Scanner Test Suite
==============================================================================
Автор: V1PER (viper86rus-arch)
GitHub: https://github.com/viper86rus-arch/Async_TCP_Scanner
Лицензия: MIT License (2026)
Назначение: Автоматизированное тестирование парсинга портов, сетевых сокетов и экспорта.
==============================================================================
"""

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Добавление корня проекта в sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import scanner
from scanner import AsyncPortScanner, ScanResult, export_json, parse_port_range


class TestAsyncTCPScanner(unittest.TestCase):
    """Набор тестов для асинхронного сканера портов."""

    def test_parse_single_port(self):
        """Проверка парсинга одиночного порта."""
        start, end = parse_port_range("80")
        self.assertEqual(start, 80)
        self.assertEqual(end, 80)

    def test_parse_port_range(self):
        """Проверка парсинга диапазона портов."""
        start, end = parse_port_range("80-443")
        self.assertEqual(start, 80)
        self.assertEqual(end, 443)

    def test_parse_invalid_port_range(self):
        """Проверка обработки невалидных диапазонов портов."""
        with self.assertRaises(SystemExit):
            parse_port_range("443-80")
        with self.assertRaises(SystemExit):
            parse_port_range("70000")
        with self.assertRaises(SystemExit):
            parse_port_range("abc")
        with self.assertRaises(SystemExit):
            parse_port_range("1-2-3")

    def test_scan_result_model(self):
        """Проверка модели данных ScanResult и сериализации в словарь."""
        res = ScanResult(
            target="127.0.0.1",
            resolved_ip="127.0.0.1",
            port_range=(80, 81),
            concurrency=100,
            timeout=1.0,
            open_ports=[80],
            banners={80: "HTTP/1.1 200 OK"},
            scan_duration_seconds=0.15,
        )
        d = res.to_dict()
        self.assertEqual(d["target"], "127.0.0.1")
        self.assertEqual(d["open_ports"], [80])
        self.assertEqual(d["port_range"], [80, 81])
        self.assertEqual(d["banners"]["80"], "HTTP/1.1 200 OK")
        self.assertEqual(d["scan_duration_seconds"], 0.15)

    def test_export_json(self):
        """Проверка корректности экспорта результатов сканирования в JSON."""
        res = ScanResult(
            target="localhost",
            resolved_ip="127.0.0.1",
            port_range=(22, 22),
            concurrency=50,
            timeout=0.5,
            open_ports=[22],
            banners={22: "SSH-2.0-OpenSSH"},
            scan_duration_seconds=0.05,
        )
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            temp_path = Path(tf.name)

        try:
            export_json(res, temp_path)
            self.assertTrue(temp_path.exists())
            import json
            with open(temp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["target"], "localhost")
            self.assertIn("open_ports", data)
            self.assertEqual(data["banners"]["22"], "SSH-2.0-OpenSSH")
            self.assertEqual(data["port_range"], [22, 22])
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_async_scanner_initialization(self):
        """Проверка инициализации сканера и параметров сокетов."""
        s = AsyncPortScanner(
            target="127.0.0.1",
            concurrency=20,
            timeout=1.0,
        )
        self.assertEqual(s.target, "127.0.0.1")
        self.assertEqual(s.concurrency, 20)
        self.assertEqual(s.timeout, 1.0)

    def test_async_probe_closed_port(self):
        """Проверка асинхронного зондирования заведомо закрытого порта."""
        async def run_probe():
            s = AsyncPortScanner(target="127.0.0.1", concurrency=10, timeout=0.2)
            s._semaphore = asyncio.Semaphore(10)
            # Неиспользуемый порт (высокий порт 59999)
            result = await s._probe_port(59999)
            return result

        probe_res = asyncio.run(run_probe())
        self.assertIsNone(probe_res)


if __name__ == "__main__":
    unittest.main()
