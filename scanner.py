#!/usr/bin/env python3
"""
⚡ Async TCP Port Scanner (scanner.py)
=====================================
Высокопроизводительный асинхронный сканер TCP-портов на базе Python asyncio.
Использует asyncio.Semaphore для строгого контроля параллелизма и asyncio.wait_for
для жестких таймаутов соединений при масштабном сканировании.

Поддерживает гибридный захват баннеров сервисов (Active/Passive Banner Grabbing):
1. Ожидание серверного приветствия (SSH, FTP, SMTP).
2. При молчании — отправка триггерного HTTP GET запроса.
Результаты структурируются и экспортируются в JSON.

Автор: V1PER (viper86rus-arch)
Лицензия: MIT
"""

import argparse
import asyncio
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import socket
import sys
import time
from typing import Optional


# ==============================================================================
# 1. НАСТРОЙКА ЛОГИРОВАНИЯ
# ==============================================================================

def configure_logging(verbose: bool = False) -> None:
    """
    Настройка формата и уровня логирования сканера.

    Args:
        verbose: При True устанавливает уровень DEBUG; иначе INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s  %(levelname)-8s  %(message)s"
    date_fmt = "%H:%M:%S"
    logging.basicConfig(level=level, format=fmt, datefmt=date_fmt)


logger = logging.getLogger(__name__)


# ==============================================================================
# 2. МОДЕЛИ ДАННЫХ
# ==============================================================================

@dataclass
class ScanResult:
    """Хранит агрегированные результаты завершенного сетевого сканирования."""

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
        """Сериализация результатов в словарь для чистого JSON-экспорта."""
        data = asdict(self)
        data["port_range"] = list(self.port_range)
        # Ключи в JSON должны быть строками: преобразуем целочисленные порты
        data["banners"] = {str(k): v for k, v in self.banners.items()}
        return data


# ==============================================================================
# 3. АСИНХРОННЫЙ ДВИЖОК СКАНИРОВАНИЯ
# ==============================================================================

class AsyncPortScanner:
    """
    Высокопроизводительный асинхронный сканер TCP-портов.

    Attributes:
        target: Имя хоста или IP-адрес цели сканирования.
        concurrency: Максимальное количество одновременных сетевых соединений (семафор).
        timeout: Таймаут на одно соединение в секундах.
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
        self._semaphore: asyncio.Semaphore

    # --------------------------------------------------------------------------
    # Внутренние методы сканирования и анализа
    # --------------------------------------------------------------------------

    async def _grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> str:
        """
        Захват сервисного баннера (Banner Grabbing) из установленного соединения.

        Алгоритм работы:
          1. Ожидание до 1 сек ответа от сервера (пассивный режим: SSH, FTP, SMTP).
          2. Если сервер молчит — отправка HTTP GET триггера и повторное ожидание (активный режим).
          3. Очистка байтов от управляющих символов и извлечение первой непустой строки.

        Args:
            reader: Поток чтения установленного TCP-сокета.
            writer: Поток записи для отправки триггерного запроса при необходимости.

        Returns:
            Строка с первой строкой баннера сервиса или пустая строка.
        """
        raw = b""
        try:
            raw = await asyncio.wait_for(reader.read(1024), timeout=1.0)
        except asyncio.TimeoutError:
            pass

        if not raw:
            # Сервер не прислал приветствие пассивно — отправляем HTTP GET триггер
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
        Проверка одного TCP-порта на цели с захватом баннера сервиса.

        Использует asyncio.wait_for для обеспечения жесткого таймаута
        и общий семафор для ограничения параллельных соединений.

        Args:
            port: Номер целевого TCP-порта.

        Returns:
            Кортеж (порт, баннер), если порт открыт, иначе None.
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
                    logger.debug("Порт %d  ->  ОТКРЫТ  |  баннер: %s", port, banner)
                else:
                    logger.debug("Порт %d  ->  ОТКРЫТ", port)
                return port, banner

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                logger.debug("Порт %d  ->  закрыт / фильтруется", port)
                return None

    # --------------------------------------------------------------------------
    # Публичный интерфейс сканирования
    # --------------------------------------------------------------------------

    async def scan(self, start_port: int, end_port: int) -> ScanResult:
        """
        Асинхронное сканирование диапазона TCP-портов [start_port, end_port] включительно.

        Args:
            start_port: Начальный порт диапазона.
            end_port: Конечный порт диапазона (включительно).

        Returns:
            Заполненный экземпляр ScanResult с метриками и найденными портами.
        """
        # Единоразовый DNS-резолвинг цели для стабильности всех сетевых запросов
        try:
            resolved_ip = socket.gethostbyname(self.target)
        except socket.gaierror as exc:
            logger.error("Ошибка DNS-резолвинга для '%s': %s", self.target, exc)
            sys.exit(1)

        total_ports = end_port - start_port + 1
        logger.info(
            "Сканирование %s (%s) | порты %d-%d | всего: %d | "
            "параллелизм: %d | таймаут: %.1fc",
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

        # Собираем результаты без сокрытия системных исключений
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
        """Вывод структурированного итогового отчета в консоль."""
        logger.info("-" * 60)
        logger.info("Сканирование завершено за %.3fc", result.scan_duration_seconds)
        logger.info("Найдено открытых портов : %d", len(result.open_ports))
        if result.open_ports:
            logger.info("Открытые порты          : %s", result.open_ports)
            if result.banners:
                logger.info("Захвачено баннеров      : %d", len(result.banners))
                for port in result.open_ports:
                    banner = result.banners.get(port, "")
                    if banner:
                        logger.info("  %-6d  %s", port, banner)
        else:
            logger.info("Открытых портов в указанном диапазоне не обнаружено.")
        logger.info("-" * 60)


# ==============================================================================
# 4. ЭКСПОРТ В JSON
# ==============================================================================

def export_json(result: ScanResult, output_path: Path) -> None:
    """
    Сохранение результатов сканирования в структурированный JSON-файл.

    Args:
        result: Объект результатов сканирования ScanResult.
        output_path: Путь к целевому файлу.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, indent=2, ensure_ascii=False)
    logger.info("Результаты экспортированы -> %s", output_path.resolve())


# ==============================================================================
# 5. CLI ИНТЕРФЕЙС И ВАЛИДАЦИЯ
# ==============================================================================

def build_parser() -> argparse.ArgumentParser:
    """Создание и конфигурация парсера аргументов командной строки."""
    parser = argparse.ArgumentParser(
        prog="scanner",
        description=(
            "⚡ Async TCP Port Scanner -- высокопроизводительный асинхронный сканер "
            "с контролем параллелизма, захватом баннеров и экспортом в JSON."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python scanner.py 192.168.1.1
  python scanner.py scanme.nmap.org -p 1-1024
  python scanner.py example.com -p 20-9000 -c 300 -t 1.5 -o results.json
  python scanner.py 10.0.0.1 -p 1-65535 -c 1000 --verbose
        """,
    )

    parser.add_argument(
        "target",
        type=str,
        help="Имя хоста или IP-адрес цели сканирования.",
    )
    parser.add_argument(
        "-p", "--ports",
        type=str,
        default="1-1024",
        metavar="START-END",
        help="Диапазон портов в формате НАЧАЛО-КОНЕЦ (по умолчанию: 1-1024).",
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=500,
        metavar="N",
        help="Максимальное число параллельных соединений (по умолчанию: 500).",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        metavar="SECS",
        help="Таймаут на соединение в секундах (по умолчанию: 1.0).",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        metavar="FILE",
        help="Путь для выгрузки отчета в формате JSON (опционально).",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Подробный вывод уровня DEBUG (показывает проверку каждого порта).",
    )

    return parser


def parse_port_range(port_str: str) -> tuple[int, int]:
    """
    Парсинг и валидация строки диапазона портов 'НАЧАЛО-КОНЕЦ'.

    Args:
        port_str: Строка диапазона, например '20-1024'.

    Returns:
        Кортеж целых чисел (начальный_порт, конечный_порт).

    Raises:
        SystemExit: При некорректном формате или выходе за границы 1-65535.
    """
    try:
        parts = port_str.split("-")
        if len(parts) != 2:
            raise ValueError
        start, end = int(parts[0]), int(parts[1])
    except ValueError:
        logger.error(
            "Некорректный диапазон портов '%s'. Ожидается формат: НАЧАЛО-КОНЕЦ (например, 1-1024).",
            port_str,
        )
        sys.exit(1)

    if not (1 <= start <= 65535 and 1 <= end <= 65535):
        logger.error("Номера портов должны быть в диапазоне от 1 до 65535.")
        sys.exit(1)

    if start > end:
        logger.error("Начальный порт (%d) не может быть больше конечного (%d).", start, end)
        sys.exit(1)

    return start, end


# ==============================================================================
# 6. ТОЧКА ВХОДА (MAIN)
# ==============================================================================

async def main() -> None:
    """Главная асинхронная функция: парсинг аргументов, сканирование и экспорт."""
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
        logger.warning("\nСканирование прервано пользователем.")
        sys.exit(130)
