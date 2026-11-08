#!/usr/bin/env python3
"""
==============================================================================
🔥 Stress Test & Security Audit Suite: Async_TCP_Scanner
==============================================================================
Автор: V1PER (viper86rus-arch)
GitHub: https://github.com/viper86rus-arch/Async_TCP_Scanner
Лицензия: MIT License (2026)
Назначение: Автоматизированное стресс-тестирование, аудит сокетов,
            проверка утечек дескрипторов (FD), DoS-устойчивости,
            безопасности баннеров и грациозного завершения.
==============================================================================
"""

import asyncio
import gc
import os
import socket
import sys
import time
import tracemalloc
import warnings
from pathlib import Path

# Добавление корня проекта
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

import scanner
from scanner import AsyncPortScanner, ScanResult


def get_open_fd_count() -> int:
    """Подсчет активных файловых дескрипторов процесса через /proc/self/fd."""
    try:
        return len(os.listdir("/proc/self/fd"))
    except Exception:
        return -1


# ==============================================================================
# 1. ТЕСТ: УТЕЧКА СОКЕТОВ ПРИ СБРОСЕ СОЕДИНЕНИЯ (RST/ABRUPT RESET В BANNER GRABBING)
# ==============================================================================

async def test_socket_leak_on_connection_reset():
    """
    Проверка утечки сокетов: сервер принимает соединение и немедленно сбрасывает его.
    В scanner.py writer.close() находится вне блока finally.
    Если reader.read() падает с ConnectionResetError или TimeoutError,
    вызывается ли writer.close()?
    """
    print("\n" + "=" * 70)
    print("TEST 1: Socket & FD Leak on Connection Reset during Banner Grabbing")
    print("=" * 70)

    # Запускаем локальный сервер-сбрасыватель
    server_sockets = []

    async def handle_client(reader, writer):
        # Принимаем соединение и принудительно абортируем сокет
        await asyncio.sleep(0.01)
        writer.transport.abort()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    # Включаем перехват предупреждений ResourceWarning
    caught_warnings = []
    with warnings.catch_warnings(record=True) as warn_list:
        warnings.simplefilter("always", ResourceWarning)

        fd_before = get_open_fd_count()

        scan_engine = AsyncPortScanner(target="127.0.0.1", concurrency=50, timeout=0.5)
        scan_engine._semaphore = asyncio.Semaphore(50)

        iterations = 50
        print(f"[*] Отправка {iterations} проб на порт с мгновенным RST...")

        tasks = [scan_engine._probe_port(port) for _ in range(iterations)]
        await asyncio.gather(*tasks)

        # Вызываем сборщик мусора для выявления не закрытых ресурсов
        gc.collect()
        await asyncio.sleep(0.1)

        fd_after = get_open_fd_count()
        resource_warnings = [w for w in warn_list if issubclass(w.category, ResourceWarning)]

    server.close()
    await server.wait_closed()

    print(f"[*] FD до теста: {fd_before} | FD после теста: {fd_after} (дельта: {fd_after - fd_before})")
    print(f"[*] Перехвачено ResourceWarning: {len(resource_warnings)}")
    for w in resource_warnings[:5]:
        print(f"    ⚠️  {w.message}")

    if resource_warnings or (fd_after - fd_before) > 5:
        print("❌ УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: Обнаружена утечка сокетов / unclosed transport!")
        return False
    else:
        print("✅ Сокеты закрыты корректно.")
        return True


# ==============================================================================
# 2. ТЕСТ: ОБРЫВ ПО CANCELLATION (CTRL+C) И TARPIT (ЗАВИСШИЕ СЕРВЕРЫ)
# ==============================================================================

async def test_cancellation_and_tarpit():
    """
    Проверка поведения при отмене тасок (Ctrl+C / CancelledError):
    Сервер-ловушка (Tarpit) принимает TCP SYN-ACK и молчит.
    При отмене таски сканера — закрываются ли сокеты или бросаются в фоне?
    """
    print("\n" + "=" * 70)
    print("TEST 2: Cancellation (Ctrl+C) & Tarpit (Pending Tasks & Socket Cleanup)")
    print("=" * 70)

    # Tarpit сервер: принимает соединение и ничего не делает
    tarpit_clients = []

    async def tarpit_handler(reader, writer):
        tarpit_clients.append(writer)
        try:
            while True:
                await asyncio.sleep(100)
        except asyncio.CancelledError:
            pass

    server = await asyncio.start_server(tarpit_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    with warnings.catch_warnings(record=True) as warn_list:
        warnings.simplefilter("always", ResourceWarning)

        fd_before = get_open_fd_count()

        scan_engine = AsyncPortScanner(target="127.0.0.1", concurrency=10, timeout=2.0)
        scan_engine._semaphore = asyncio.Semaphore(10)

        # Запускаем зондирование в отдельной таске и отменяем её через 0.2 сек (эмуляция Ctrl+C)
        task = asyncio.create_task(scan_engine._probe_port(port))
        await asyncio.sleep(0.2)
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            print("[*] Таска _probe_port успешно получила CancelledError")

        gc.collect()
        await asyncio.sleep(0.1)

        fd_after = get_open_fd_count()
        resource_warnings = [w for w in warn_list if issubclass(w.category, ResourceWarning)]

    # Закрываем сервер
    for c in tarpit_clients:
        c.close()
    server.close()
    await server.wait_closed()

    print(f"[*] FD до: {fd_before} | FD после отмены: {fd_after}")
    print(f"[*] Unclosed ResourceWarnings после отмены: {len(resource_warnings)}")
    for w in resource_warnings[:5]:
        print(f"    ⚠️  {w.message}")

    if resource_warnings:
        print("❌ УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: При отмене таски сокет НЕ закрывается в finally!")
        return False
    else:
        print("✅ Сокет очищен.")
        return True


# ==============================================================================
# 3. ТЕСТ: БЕЗОПАСНОСТЬ БАННЕРОВ (ANSI ESCAPE INJECTION & MEMORY FLOOD)
# ==============================================================================

async def test_malicious_banner_injection():
    """
    Проверка на внедрение ANSI-последовательностей и терминальных эксплойтов:
    Вредоносный сервер возвращает ANSI-эскейп последовательности (очистка экрана,
    подделка вывода, смена заголовка терминала, колор-бомба).
    """
    print("\n" + "=" * 70)
    print("TEST 3: Malicious Banner Grabbing (ANSI Escape & Injection Attack)")
    print("=" * 70)

    # ANSI-инъекция: очистить экран, переместить курсор, вывести поддельное сообщение
    evil_payload = (
        b"\x1b[2J\x1b[H\x1b[31;1m=== PWNED BY MALICIOUS BANNER ===\x1b[0m\r\n"
        b"\x1b]0;MALICIOUS TITLE\x07\x00\x01\x02" + (b"A" * 2000)
    )

    async def evil_server_handler(reader, writer):
        writer.write(evil_payload)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(evil_server_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    scan_engine = AsyncPortScanner(target="127.0.0.1", concurrency=1, timeout=1.0)
    scan_engine._semaphore = asyncio.Semaphore(1)

    result = await scan_engine._probe_port(port)

    server.close()
    await server.wait_closed()

    if result:
        port_num, banner = result
        print(f"[*] Длина захваченного баннера: {len(banner)} символов")
        print(f"[*] Сырое представление баннера: {repr(banner[:80])}...")

        has_ansi = "\x1b" in banner or "\x1b[" in banner
        has_ctrl = any(ord(c) < 32 and c not in "\t " for c in banner)

        if has_ansi or has_ctrl:
            print("❌ УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА (CWE-150): Баннер содержит сырые ANSI escape-коды и управляющие символы!")
            print("   Атакующий может очистить консоль оператора, подделать статус открытых портов или эксплуатировать уязвимости терминала.")
            return False
        else:
            print("✅ Баннер санитизирован.")
            return True
    return True


# ==============================================================================
# 4. ТЕСТ: РАСХОД ПАМЯТИ ПРИ ПОРОЖДЕНИИ 65 535 ТАСОК В ПАМЯТИ
# ==============================================================================

async def test_memory_dos_on_full_port_range():
    """
    Проверка архитектуры Worker Pool:
    При сканировании 1-65535 scanner.py не порождает 65 535 тасок одновременно,
    а использует пул воркеров и очередь, потребляя минимальный объем RAM.
    """
    print("\n" + "=" * 70)
    print("TEST 4: Memory Footprint & Event Loop Congestion (Worker Pool vs 65k Tasks)")
    print("=" * 70)

    scan_engine = AsyncPortScanner(target="127.0.0.1", concurrency=500)

    # Мокаем _probe_port для мгновенного завершения
    async def fast_mock_probe(port):
        return None

    scan_engine._probe_port = fast_mock_probe  # type: ignore

    tracemalloc.start()
    gc.collect()
    snapshot1 = tracemalloc.take_snapshot()
    t0 = time.perf_counter()

    # Запускаем сканирование полного диапазона через Worker Pool
    await scan_engine.scan(1, 65535)
    execution_time = time.perf_counter() - t0

    snapshot2 = tracemalloc.take_snapshot()
    top_stats = snapshot2.compare_to(snapshot1, 'lineno')
    total_memory_allocated = sum(stat.size for stat in top_stats) / (1024 * 1024)

    print(f"[*] Время сканирования 65,535 портов через Worker Pool: {execution_time:.4f} с")
    print(f"[*] Дополнительная память под структуры Worker Pool: {total_memory_allocated:.2f} МБ")
    tracemalloc.stop()

    if total_memory_allocated > 15.0:
        print("⚠️  АРХИТЕКТУРНЫЙ РИСК: Создание тасок потребляет слишком много памяти (> 15 МБ)!")
        return False
    print("✅ Worker Pool обеспечивает константный и минимальный расход памяти (< 15 МБ).")
    return True


# ==============================================================================
# 5. ТЕСТ: DNS-РЕЗОЛВИНГ И ПЕРЕДАЧА ХОСТА В open_connection
# ==============================================================================

def test_dns_and_ipv6_architectural_flaw():
    """
    Проверка DNS-резолвинга и поддержки IPv6:
    1. _probe_port не должен передавать 'self.target' напрямую в open_connection
    2. _resolve_target должен поддерживать IPv6 и доменные имена без падений
    """
    print("\n" + "=" * 70)
    print("TEST 5: DNS Resolution Redundancy & IPv6 Compatibility")
    print("=" * 70)

    import inspect
    probe_src = inspect.getsource(AsyncPortScanner._probe_port)

    uses_target_directly = "asyncio.open_connection(self.target" in probe_src
    print(f"[*] _probe_port использует 'self.target' в open_connection напрямую: {uses_target_directly}")

    if uses_target_directly:
        print("❌ КРИТИЧЕСКИЙ БАГ DNS: _probe_port передает доменное имя self.target напрямую!")
    else:
        print("✅ _probe_port использует кэшированный target_host / resolved_ip.")

    # 2. Проверка IPv6
    ipv6_target = "::1"
    try:
        ip = AsyncPortScanner._resolve_target(ipv6_target)
        print(f"[*] AsyncPortScanner._resolve_target('::1') -> {ip}")
        ipv6_ok = (ip == "::1")
    except Exception as e:
        print(f"❌ НЕСОВМЕСТИМОСТЬ С IPv6: {e}")
        ipv6_ok = False

    return (not uses_target_directly) and ipv6_ok


# ==============================================================================
# 6. ТЕСТ: РАССОГЛАСОВАНИЕ ТАЙМАУТОВ (TIMEOUT DESYNC & HARDCODED 2.0s STALL)
# ==============================================================================

async def test_timeout_desync():
    """
    Проверка игнорирования пользовательского таймаута:
    Пользователь указывает -t 0.1 (быстрое сканирование).
    Но в _grab_banner захардкожены два вызова wait_for(..., timeout=1.0).
    Если порт открыт, но сервер молчит (Silent Open Port / Tarpit),
    проба зависает на 2.0+ секунды вместо 0.1 секунды!
    """
    print("\n" + "=" * 70)
    print("TEST 6: Timeout Desynchronization (CLI -t vs Hardcoded 1.0s in Banner)")
    print("=" * 70)

    # Сервер принимает соединение и молчит
    async def silent_handler(reader, writer):
        await asyncio.sleep(5.0)

    server = await asyncio.start_server(silent_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    # Пользователь запросил таймаут 0.05 сек (50 мс)
    user_timeout = 0.05
    scan_engine = AsyncPortScanner(target="127.0.0.1", concurrency=1, timeout=user_timeout)
    scan_engine._semaphore = asyncio.Semaphore(1)

    t0 = time.perf_counter()
    res = await scan_engine._probe_port(port)
    elapsed = time.perf_counter() - t0

    server.close()
    await server.wait_closed()

    print(f"[*] Запрошенный таймаут : {user_timeout:.3f} с")
    print(f"[*] Фактическое время   : {elapsed:.3f} с")

    if elapsed > (user_timeout * 5):
        print(f"❌ АРХИТЕКТУРНЫЙ ДЕФЕКТ: Проба выполнялась {elapsed:.2f}с вместо {user_timeout}с!")
        print("   В _grab_banner жестко зашиты два wait_for(..., timeout=1.0), полностью")
        print("   игнорирующие параметр self.timeout. Открытые молчащие порты замедляют сканер в 20-40 раз!")
        return False
    return True


# ==============================================================================
# 7. ТЕСТ: ОБЪЕМНЫЙ БАННЕР / БИНАРНАЯ БОМБА
# ==============================================================================

async def test_massive_binary_banner_bomb():
    """
    Проверка поведения при получении невалидного бинарного потока без \\n.
    Хотя reader.read(1024) читает до 1024 байт, raw.decode(errors='replace')
    может породить невалидные символы, а split('\\n')[0] выдаст строку в 1024 байта,
    забивая JSON и консоль мусором.
    """
    print("\n" + "=" * 70)
    print("TEST 7: Banner Flood & Control Character Sanitization")
    print("=" * 70)

    # Генерация 1024 байт мусора БЕЗ переносов строк (бинарные нули, escape-коды)
    bomb_payload = (bytes(range(1, 256)).replace(b"\n", b"X")) * 4
    bomb_payload = bomb_payload[:1024]

    async def bomb_server_handler(reader, writer):
        writer.write(bomb_payload)
        await writer.drain()
        writer.close()
        await server.wait_closed()

    server = await asyncio.start_server(bomb_server_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    scan_engine = AsyncPortScanner(target="127.0.0.1", concurrency=1, timeout=1.0)
    scan_engine._semaphore = asyncio.Semaphore(1)

    res = await scan_engine._probe_port(port)

    server.close()
    await server.wait_closed()

    if res:
        _, banner = res
        print(f"[*] Длина сохраненного баннера: {len(banner)}")
        print(f"[*] Есть непечатаемые/управляющие символы: {any(ord(c) < 32 for c in banner)}")
        if len(banner) > 120 or any(ord(c) < 32 for c in banner):
            print("⚠️  НЕДОЧЕТ: Баннер не усекается по длине (1024 символа) и содержит сырые бинарные байты,")
            print("   засоряя JSON-отчеты и логи оператора.")
            return False
    return True


# ==============================================================================
# ТОЧКА ВХОДА СТРЕСС-ТЕСТА
# ==============================================================================

async def main():
    print("=" * 70)
    print("🔥 ЗАПУСК СТРЕСС-ТЕСТИРОВАНИЯ И АУДИТА БЕЗОПАСНОСТИ ASYNC_TCP_SCANNER")
    print("=" * 70)

    results = {}
    results["Socket Leak on RST"] = await test_socket_leak_on_connection_reset()
    results["Cancellation & Tarpit Cleanup"] = await test_cancellation_and_tarpit()
    results["Malicious Banner Injection"] = await test_malicious_banner_injection()
    results["Memory Footprint (65k tasks)"] = await test_memory_dos_on_full_port_range()
    results["DNS & IPv6 Flaws"] = test_dns_and_ipv6_architectural_flaw()
    results["Timeout Desynchronization"] = await test_timeout_desync()
    results["Banner Flood & Sanitization"] = await test_massive_binary_banner_bomb()

    print("\n" + "=" * 70)
    print("📊 ИТОГОВАЯ СВОДКА СТРЕСС-ТЕСТИРОВАНИЯ:")
    print("=" * 70)
    for test_name, passed in results.items():
        status = "✅ PASS" if passed else "❌ VULNERABLE / FAILED"
        print(f"  {test_name:<35} : {status}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
