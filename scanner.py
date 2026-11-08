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
import ipaddress
import json
import logging
from pathlib import Path
import re
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
# 3. САНИТИЗАЦИЯ И АСИНХРОННЫЙ ДВИЖОК СКАНИРОВАНИЯ
# ==============================================================================

ANSI_ESCAPE_PATTERN = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def sanitize_banner(raw_banner: str, max_length: int = 120) -> str:
    """
    Санитизация сервисного баннера (защита от ANSI Escape Injection CWE-150 / CWE-117):
    1. Удаляет терминальные ANSI escape-последовательности.
    2. Удаляет управляющие символы ASCII (коды < 32, включая \\r, \\0, \\x01-0x1f).
    3. Ограничивает длину до max_length (по умолчанию 120 символов).
    """
    if not raw_banner:
        return ""
    # Удаляем ANSI escape-последовательности
    cleaned = ANSI_ESCAPE_PATTERN.sub("", raw_banner)
    # Фильтруем управляющие и непечатаемые символы
    cleaned = "".join(
        ch for ch in cleaned
        if (32 <= ord(ch) <= 126 or ch.isalnum() or ch.isspace()) and ord(ch) >= 32
    ).strip()
    # Сжимаем множественные пробелы
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length - 3] + "..."
    return cleaned


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
        self.resolved_ip: Optional[str] = None
        self._semaphore: asyncio.Semaphore = asyncio.Semaphore(concurrency)

    # --------------------------------------------------------------------------
    # Внутренние методы сканирования и анализа
    # --------------------------------------------------------------------------

    @staticmethod
    def _resolve_target(target: str) -> str:
        """
        Универсальный DNS-резолвинг с поддержкой IPv4, IPv6 и доменных имен.
        """
        try:
            ip_obj = ipaddress.ip_address(target)
            return str(ip_obj)
        except ValueError:
            pass

        try:
            addr_info = socket.getaddrinfo(
                target, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
            )
            if not addr_info:
                raise socket.gaierror(f"Не удалось разрешить имя хоста: {target}")
            return str(addr_info[0][4][0])
        except socket.gaierror:
            raise

    async def _grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> str:
        """
        Захват сервисного баннера (Banner Grabbing) из установленного соединения.

        Алгоритм работы:
          1. Ожидание ответа от сервера с динамическим таймаутом (пассивный режим: SSH, FTP, SMTP).
          2. Если сервер молчит — отправка HTTP GET триггера и повторное ожидание (активный режим).
          3. Санитизация баннера и очистка от ANSI escape-последовательностей (CWE-150).

        Args:
            reader: Поток чтения установленного TCP-сокета.
            writer: Поток записи для отправки триггерного запроса при необходимости.

        Returns:
            Санитизированная строка баннера сервиса или пустая строка.
        """
        # Динамический таймаут: не более self.timeout / 2 и не более 1.0 сек
        banner_timeout = max(0.02, min(self.timeout / 2.0, 1.0))

        raw = b""
        try:
            raw = await asyncio.wait_for(reader.read(1024), timeout=banner_timeout)
        except (asyncio.TimeoutError, OSError):
            pass

        if not raw:
            # Сервер не прислал приветствие пассивно — отправляем HTTP GET триггер
            try:
                writer.write(b"GET / HTTP/1.1\r\n\r\n")
                await asyncio.wait_for(writer.drain(), timeout=banner_timeout)
                raw = await asyncio.wait_for(reader.read(1024), timeout=banner_timeout)
            except (asyncio.TimeoutError, OSError):
                pass

        if not raw:
            return ""

        decoded = raw.decode(errors="replace")
        first_line = decoded.split("\n")[0].strip()
        return sanitize_banner(first_line, max_length=120)

    async def _probe_port(self, port: int) -> Optional[tuple[int, str]]:
        """
        Проверка одного TCP-порта на цели с захватом баннера сервиса.

        Использует asyncio.wait_for для обеспечения жесткого таймаута,
        семафор для контроля параллелизма и гарантированное закрытие
        сокетов в блоке finally для предотвращения утечек дескрипторов (CWE-404).

        Args:
            port: Номер целевого TCP-порта.

        Returns:
            Кортеж (порт, баннер), если порт открыт, иначе None.
        """
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrency)

        writer: Optional[asyncio.StreamWriter] = None
        async with self._semaphore:
            try:
                target_host = self.resolved_ip or self.target
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target_host, port),
                    timeout=self.timeout,
                )

                banner = await self._grab_banner(reader, writer)

                if banner:
                    logger.debug("Порт %d  ->  ОТКРЫТ  |  баннер: %s", port, banner)
                else:
                    logger.debug("Порт %d  ->  ОТКРЫТ", port)
                return port, banner

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                logger.debug("Порт %d  ->  закрыт / фильтруется", port)
                return None
            finally:
                if writer is not None:
                    try:
                        writer.close()
                    except Exception:
                        pass
                    try:
                        await asyncio.shield(writer.wait_closed())
                    except Exception:
                        pass

    # --------------------------------------------------------------------------
    # Публичный интерфейс сканирования
    # --------------------------------------------------------------------------

    async def scan(self, start_port: int, end_port: int) -> ScanResult:
        """
        Асинхронное сканирование диапазона TCP-портов [start_port, end_port] включительно
        с использованием пула воркеров (Worker Pool) для постоянной O(1) памяти.

        Args:
            start_port: Начальный порт диапазона.
            end_port: Конечный порт диапазона (включительно).

        Returns:
            Заполненный экземпляр ScanResult с метриками и найденными портами.
        """
        # Единоразовый DNS-резолвинг цели с поддержкой IPv4 и IPv6
        try:
            self.resolved_ip = self._resolve_target(self.target)
        except socket.gaierror as exc:
            logger.error("Ошибка DNS-резолвинга для '%s': %s", self.target, exc)
            sys.exit(1)

        total_ports = end_port - start_port + 1
        logger.info(
            "Сканирование %s (%s) | порты %d-%d | всего: %d | "
            "параллелизм: %d | таймаут: %.1fc",
            self.target,
            self.resolved_ip,
            start_port,
            end_port,
            total_ports,
            self.concurrency,
            self.timeout,
        )

        self._semaphore = asyncio.Semaphore(self.concurrency)
        t0 = time.perf_counter()

        # Высокопроизводительный пул воркеров (Worker Pool):
        # Вместо единовременного создания 65 535 тасок запускаем строго num_workers
        queue: asyncio.Queue[int] = asyncio.Queue()
        for port in range(start_port, end_port + 1):
            queue.put_nowait(port)

        results: list[tuple[int, str]] = []
        lock = asyncio.Lock()

        async def worker() -> None:
            while True:
                try:
                    port = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                try:
                    res = await self._probe_port(port)
                    if res is not None:
                        async with lock:
                            results.append(res)
                finally:
                    queue.task_done()

        num_workers = min(self.concurrency, total_ports)
        workers = [asyncio.create_task(worker()) for _ in range(num_workers)]
        await asyncio.gather(*workers)

        elapsed = time.perf_counter() - t0

        open_entries = sorted(results, key=lambda x: x[0])
        open_ports = [port for port, _ in open_entries]
        banners: dict[int, str] = {
            port: banner for port, banner in open_entries if banner
        }

        result = ScanResult(
            target=self.target,
            resolved_ip=self.resolved_ip,
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
        if len(parts) == 1:
            start = end = int(parts[0])
        elif len(parts) == 2:
            start, end = int(parts[0]), int(parts[1])
        else:
            raise ValueError
    except ValueError:
        logger.error(
            "Некорректный диапазон портов '%s'. Ожидается формат: ПОРТ или НАЧАЛО-КОНЕЦ (например, 80 или 1-1024).",
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
