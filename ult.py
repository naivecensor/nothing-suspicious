import ipaddress
import socket
import urllib.parse
import requests
import base64
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor

# --- НАСТРОЙКИ ---
GITHUB_PUSH = True  # На ноуте тоже будет работать, если Git настроен
COMMIT_MESSAGE = "Update proxies: automated check"

WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/cidrwhitelist.txt"
LOCAL_CIDR_FILE = 'cidr.txt'
LOCAL_CIDR_FILE2 = 'cidr2.txt'
CONFIGS_FILE = 'configs.txt'
SUBS_FILE = 'subs.txt'

# Лимиты (на ноуте можно поставить и побольше, но оставим для сервера)
MAX_RESOLVE_THREADS = 1000
CONCURRENT_TCP_CHECKS = 1000
TCP_TIMEOUT = 3.0


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
        if r.status_code == 200: sources['git'] = parse_cidr_lines(r.text.splitlines())
    except:
        print("[-] Ошибка загрузки GitHub")

    for filename, key in [(LOCAL_CIDR_FILE, 'cidr1'), (LOCAL_CIDR_FILE2, 'cidr2')]:
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                sources[key] = parse_cidr_lines(f.readlines())
    return sources


def fetch_all_configs():
    raw = []
    if os.path.exists(CONFIGS_FILE):
        with open(CONFIGS_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            raw.extend([l.strip() for l in f if l.strip()])

    if os.path.exists(SUBS_FILE):
        print("[*] Сбор ссылок из подписок...")
        with open(SUBS_FILE, 'r') as f:
            subs = [l.strip() for l in f if l.strip().startswith('http')]
        for url in subs:
            try:
                r = requests.get(url, timeout=10)
                try:
                    lines = base64.b64decode(r.text.strip()).decode('utf-8').splitlines()
                except:
                    lines = r.text.splitlines()
                raw.extend([l.strip() for l in lines if l.strip()])
            except:
                continue
    return list(set(raw))


def resolve_full_data(link):
    try:
        parsed = urllib.parse.urlparse(link)
        netloc = parsed.netloc.split('@')[-1]
        host = netloc.split(':')[0] if ':' in netloc else netloc
        port = int(netloc.split(':')[1]) if ':' in netloc else 443
        try:
            ip_obj = ipaddress.ip_address(host)
        except:
            ip_obj = ipaddress.ip_address(socket.gethostbyname(host))
        return {'link': link, 'ip': ip_obj, 'host': host, 'port': port, 'key': f"{ip_obj}:{port}"}
    except:
        return None


async def check_tcp(item, semaphore):
    if not item: return None
    async with semaphore:
        try:
            conn = asyncio.open_connection(item['host'], item['port'])
            _, writer = await asyncio.wait_for(conn, timeout=TCP_TIMEOUT)
            writer.close()
            await writer.wait_closed()
            return item
        except:
            return None


def push_to_github():
    print("\n[*] Синхронизация с GitHub...")

    # Добавляем только те 4 файла, которые РЕАЛЬНО должны быть на GitHub
    os.system("git add cidr-git.txt cidr-1.txt cidr-2.txt cidr-all.txt")

    status = os.popen("git status --porcelain").read().strip()
    if status:
        os.system(f'git commit -m "{COMMIT_MESSAGE}"')
        # Просто пушим. Если не идет - пишем ошибку, но ничего не сбрасываем!
        if os.system("git push origin main") != 0:
            print("[!] Ошибка: GitHub отклонил пуш. Попробуй сделать 'git pull' вручную.")
        else:
            print("[+] GitHub обновлен!")
    else:
        print("[*] Новых прокси нет, пуш не нужен.")

async def main():
    sources = load_all_networks()
    raw_links = fetch_all_configs()
    if not raw_links: return

    print(f"[*] Собрано {len(raw_links)} ссылок. Резолвинг...")
    resolved_items = []
    with ThreadPoolExecutor(max_workers=MAX_RESOLVE_THREADS) as executor:
        loop = asyncio.get_event_loop()
        futures = [loop.run_in_executor(executor, resolve_full_data, l) for l in raw_links]
        for res in await asyncio.gather(*futures):
            if res: resolved_items.append(res)

    print(f"[*] TCP тест {len(resolved_items)} хостов...")
    semaphore = asyncio.Semaphore(CONCURRENT_TCP_CHECKS)
    tasks = [check_tcp(item, semaphore) for item in resolved_items]
    live_items = []
    for task in asyncio.as_completed(tasks):
        res = await task
        if res: live_items.append(res)

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

    for filename, unique_proxies in results.items():
        links = list(unique_proxies.values())
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(links) + '\n' if links else "")
        print(f"[SAVED] {filename:15} | Уникальных: {len(links)}")

    if GITHUB_PUSH: push_to_github()


if __name__ == "__main__":
    asyncio.run(main())