import ipaddress
import socket
import urllib.parse
import requests
import base64
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor

# --- НАСТРОЙКИ ---
GITHUB_PUSH = True
COMMIT_MESSAGE = "Update proxies: automated check (optimized)"

WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/cidrwhitelist.txt"
LOCAL_CIDR_FILE = 'cidr.txt'
LOCAL_CIDR_FILE2 = 'cidr2.txt'
CONFIGS_FILE = 'configs.txt'
SUBS_FILE = 'subs.txt'

# Лимиты оптимизированы под сервер (0.87GB RAM / 1 CPU)
MAX_RESOLVE_THREADS = 1000  # Снижено с 1000 для стабильности DNS
CONCURRENT_TCP_CHECKS = 1000  # Снижено с 1000, чтобы не вешать проц на TCP
TCP_TIMEOUT = 5.5  # Оптимальное время ожидания


def parse_cidr_lines(lines):
    nets = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#'):
            try:
                nets.append(ipaddress.ip_network(line))
            except:
                continue
    return nets


def load_all_networks():
    sources = {'git': [], 'cidr1': [], 'cidr2': []}
    print("[*] Загрузка источников CIDR...")
    try:
        r = requests.get(WHITELIST_URL, timeout=10)
        if r.status_code == 200:
            sources['git'] = parse_cidr_lines(r.text.splitlines())
    except:
        print("[-] Ошибка загрузки GitHub")

    for filename, key in [(LOCAL_CIDR_FILE, 'cidr1'), (LOCAL_CIDR_FILE2, 'cidr2')]:
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                sources[key] = parse_cidr_lines(f.readlines())
    return sources


def fetch_all_configs():
    raw = []
    # Загрузка локальных конфигов
    if os.path.exists(CONFIGS_FILE):
        with open(CONFIGS_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            raw.extend([l.strip() for l in f if l.strip()])

    # Загрузка подписок
    if os.path.exists(SUBS_FILE):
        print("[*] Сбор ссылок из подписок...")
        with open(SUBS_FILE, 'r') as f:
            subs = [l.strip() for l in f if l.strip().startswith('http')]
        for url in subs:
            try:
                r = requests.get(url, timeout=10)
                try:
                    # Проверка на Base64
                    decoded = base64.b64decode(r.text.strip()).decode('utf-8')
                    lines = decoded.splitlines()
                except:
                    lines = r.text.splitlines()
                raw.extend([l.strip() for l in lines if l.strip()])
            except:
                continue
    return raw


def resolve_full_data(link):
    try:
        parsed = urllib.parse.urlparse(link)
        # Очистка хоста от логинов/паролей
        netloc = parsed.netloc.split('@')[-1]
        host = netloc.split(':')[0] if ':' in netloc else netloc
        port = int(netloc.split(':')[1]) if ':' in netloc else 443
        try:
            ip_obj = ipaddress.ip_address(host)
        except:
            # DNS резолвинг
            ip_obj = ipaddress.ip_address(socket.gethostbyname(host))
        return {'link': link, 'ip': ip_obj, 'host': host, 'port': port, 'key': f"{ip_obj}:{port}"}
    except:
        return None


async def check_tcp(item, semaphore):
    if not item: return None
    async with semaphore:
        try:
            # Асинхронная проверка порта
            conn = asyncio.open_connection(item['host'], item['port'])
            _, writer = await asyncio.wait_for(conn, timeout=TCP_TIMEOUT)
            writer.close()
            await writer.wait_closed()
            return item
        except:
            return None


def push_to_github():
    print("\n[*] Синхронизация с GitHub...")
    # 1. Силой забираем всё из облака, чтобы не было конфликтов
    os.system("git fetch origin main")
    os.system("git reset --mixed origin/main")

    # 2. Добавляем только наши текстовики
    os.system("git add cidr-git.txt cidr-1.txt cidr-2.txt cidr-all.txt")

    status = os.popen("git status --porcelain").read().strip()
    if status:
        os.system(f'git commit -m "{COMMIT_MESSAGE}"')
        # 3. Пушим. Если будет конфликт — пушим силой (--force)
        if os.system("git push origin main") != 0:
            print("[!] Обычный пуш не прошел, используем силу...")
            os.system("git push origin main --force")
        else:
            print("[+] GitHub обновлен!")
    else:
        print("[*] Изменений в прокси нет, пуш не нужен.")

async def main():
    # 1. Загрузка данных
    sources = load_all_networks()
    raw_links_list = fetch_all_configs()
    if not raw_links_list:
        print("[-] Ссылки не найдены.")
        return

    # 2. Первая дедупликация (по тексту ссылок)
    unique_raw_links = list(set(raw_links_list))
    print(f"[*] Собрано: {len(raw_links_list)} ссылок. Уникальных: {len(unique_raw_links)}")

    # 3. DNS Резолвинг
    print(f"[*] Резолвинг доменов (потоков: {MAX_RESOLVE_THREADS})...")
    resolved_raw = []
    with ThreadPoolExecutor(max_workers=MAX_RESOLVE_THREADS) as executor:
        loop = asyncio.get_event_loop()
        futures = [loop.run_in_executor(executor, resolve_full_data, l) for l in unique_raw_links]
        for res in await asyncio.gather(*futures):
            if res: resolved_raw.append(res)

    # 4. Вторая дедупликация (по IP:Port)
    # Если разные ссылки ведут на один сервер, проверяем его только 1 раз
    unique_hosts = {}
    for item in resolved_raw:
        if item['key'] not in unique_hosts:
            unique_hosts[item['key']] = item

    final_to_check = list(unique_hosts.values())
    print(f"[*] Готово к TCP тесту: {len(final_to_check)} уникальных IP:Port")

    # 5. TCP Тест
    semaphore = asyncio.Semaphore(CONCURRENT_TCP_CHECKS)
    tasks = [check_tcp(item, semaphore) for item in final_to_check]
    live_items = []

    print(f"[*] TCP тест (лимит: {CONCURRENT_TCP_CHECKS})...")
    for task in asyncio.as_completed(tasks):
        res = await task
        if res: live_items.append(res)
    print(f"[+] Найдено живых: {len(live_items)}")

    # 6. Фильтрация по сетям и распределение
    results = {'cidr-git.txt': {}, 'cidr-1.txt': {}, 'cidr-2.txt': {}, 'cidr-all.txt': {}}
    for item in live_items:
        ip, key, link = item['ip'], item['key'], item['link']
        in_git = any(ip in net for net in sources['git'])
        in_c1 = any(ip in net for net in sources['cidr1'])
        in_c2 = any(ip in net for net in sources['cidr2'])

        if in_git: results['cidr-git.txt'][key] = link
        if in_c1: results['cidr-1.txt'][key] = link
        if in_c2: results['cidr-2.txt'][key] = link
        if (in_git or in_c1 or in_c2): results['cidr-all.txt'][key] = link

    # 7. Сохранение
    for filename, unique_proxies in results.items():
        links = list(unique_proxies.values())
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(links) + '\n' if links else "")
        print(f"[SAVED] {filename:15} | Прокси: {len(links)}")

    # 8. Пуш
    if GITHUB_PUSH:
        push_to_github()


if __name__ == "__main__":
    asyncio.run(main())