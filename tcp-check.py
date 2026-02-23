import asyncio
import urllib.parse
import os

# Настройки для слабого сервера (1GB RAM)
CONCURRENT_CHECKS = 200  # Снизил с 200 до 100 для экономии памяти
TIMEOUT = 3.0            # Тайм-аут на соединение (секунды)

async def check_tcp(link, semaphore):
    """Проверяет доступность TCP порта для одной ссылки."""
    try:
        link = link.strip()
        if not link: return None

        parsed = urllib.parse.urlparse(link)
        netloc = parsed.netloc

        # Обработка разных форматов (с @ и без)
        host_port = netloc.split('@')[-1] if '@' in netloc else netloc

        if ':' in host_port:
            host, port = host_port.split(':')
            port = int(port)
        else:
            host = host_port
            port = 443

        async with semaphore:
            # Пытаемся открыть соединение
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
            return link
    except Exception:
        return None

def get_input_file():
    print("\n=== ВЫБОР ФАЙЛА ДЛЯ TCP-ТЕСТА ===")
    print("1. Проверить work.txt (Общие)")
    print("2. Проверить vk-ya.txt (Локальные/РФ)")
    print("3. Проверить cidr2-work.txt (Дополнительные)")
    print("4. Проверить all-work.txt (ОБЪЕДИНЕННЫЙ СПИСОК)")

    choice = input("Выберите вариант (1, 2, 3 или 4): ").strip()

    if choice == '1':
        return 'work.txt', 'tcp_live_work.txt'
    elif choice == '2':
        return 'vk-ya.txt', 'tcp_live_vk_ya.txt'
    elif choice == '3':
        return 'cidr2-work.txt', 'tcp_live_cidr2.txt'
    elif choice == '4':
        return 'all-work.txt', 'tcp_live_all.txt'
    else:
        print("[-] Неверный выбор.")
        return None, None

async def main():
    input_file, output_file = get_input_file()

    if not input_file or not os.path.exists(input_file):
        print(f"[-] Файл {input_file} не найден. Сначала запустите основной фильтр.")
        return

    # Читаем конфиги (UTF-8) с обработкой ошибок
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            links = [l.strip() for l in f if l.strip()]
    except Exception as e:
        print(f"[-] Ошибка при чтении файла: {e}")
        return

    if not links:
        print(f"[-] Файл {input_file} пуст.")
        return

    print(f"[*] Начинаю TCP тест для {len(links)} конфигов...")
    print(f"[*] Лимит: {CONCURRENT_CHECKS} соединений, Тайм-аут: {TIMEOUT}с")

    semaphore = asyncio.Semaphore(CONCURRENT_CHECKS)
    tasks = [check_tcp(link, semaphore) for link in links]

    live_configs = []
    done_count = 0

    # Асинхронное выполнение с прогресс-баром
    for task in asyncio.as_completed(tasks):
        result = await task
        done_count += 1
        if result:
            live_configs.append(result)

        if done_count % 50 == 0 or done_count == len(links):
            print(f"[*] Прогресс: {done_count}/{len(links)} | Живых: {len(live_configs)}", end='\r')

    # Сохраняем результат
    with open(output_file, 'w', encoding='utf-8') as f:
        for config in live_configs:
            f.write(config + '\n')

    print(f"\n\n[DONE] TCP тест завершен!")
    print(f"[*] Живых прокси: {len(live_configs)}")
    print(f"[*] Результат сохранен в {output_file}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Тест прерван пользователем.")