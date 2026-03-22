import ipaddress
import socket
import urllib.parse
import requests
import base64
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor

# --- НАСТРОЙКИ ПУТЕЙ ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def get_path(filename):
    return os.path.join(BASE_DIR, filename)


# --- НАСТРОЙКИ ---
GITHUB_PUSH = True
COMMIT_MESSAGE = "Update proxies: automated check (optimized)"

WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/cidrwhitelist.txt"

LOCAL_CIDR_FILE = get_path('cidr.txt')
LOCAL_CIDR_FILE2 = get_path('cidr2.txt')
CHECKED_CIDR_FILE = get_path('checked-cidr.txt')
CONFIGS_FILE = get_path('configs.txt')
SUBS_FILE = get_path('subs.txt')

# Лимиты
MAX_RESOLVE_THREADS = 50
CONCURRENT_TCP_CHECKS = 100
TCP_TIMEOUT = 5.5


def parse_cidr_lines(lines):
    nets = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#'):
            try:
                # Берем только первое слово (адрес), игнорируя комментарии в строке
                clean_line = line.split()[0]
                nets.append(ipaddress.ip_network(clean_line, strict=False))
            except:
                continue
    return nets


def load_all_networks():
    sources = {'git': [], 'cidr1': [], 'cidr2': [], 'checked': []}
    print("[*] Загрузка источников CIDR...")
    try:
        r = requests.get(WHITELIST_URL, timeout=10)
        if r.status_code == 200:
            sources['git'] = parse_cidr_lines(r.text.splitlines())
    except:
        print("[-] Ошибка загрузки GitHub")

    files_map = [
        (LOCAL_CIDR_FILE, 'cidr1'),
        (LOCAL_CIDR_FILE2, 'cidr2'),
        (CHECKED_CIDR_FILE, 'checked')
    ]

    for filename, key in files_map:
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
        print(f"[*] Сбор ссылок из подписок: {SUBS_FILE}")
        with open(SUBS_FILE, 'r') as f:
            subs = [l.strip() for l in f if l.strip().startswith('http')]
        for url in subs:
            try:
                r = requests.get(url, timeout=10)
                content = r.text.strip()
                try:
                    decoded = base64.b64decode(content).decode('utf-8')
                    lines = decoded.splitlines()
                except:
                    lines = content.splitlines()
                raw.extend([l.strip() for l in lines if l.strip()])
            except:
                continue
    return raw


def resolve_full_data(link):
    try:
        # Убираем префиксы типа если они попали в файл
        clean_link = link
        if 'vless://' in link:
            clean_link = 'vless://' + link.split('vless://')[-1]
        elif 'ss://' in link:
            clean_link = 'ss://' + link.split('ss://')[-1]

        parsed = urllib.parse.urlparse(clean_link)
        netloc = parsed.netloc.split('@')[-1]
        host = netloc.split(':')[0] if ':' in netloc else netloc
        # Очищаем порт от возможных параметров
        port_raw = netloc.split(':')[1] if ':' in netloc else "443"
        port = int(port_raw.split('?')[0].split('/')[0])

        try:
            ip_obj = ipaddress.ip_address(host)
        except:
            ip_obj = ipaddress.ip_address(socket.gethostbyname(host))

        return {'link': clean_link, 'ip': ip_obj, 'host': host, 'port': port, 'key': f"{ip_obj}:{port}"}
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
    os.chdir(BASE_DIR)
    
    # 1. Сначала затягиваем изменения из облака с параметром autostash.
    # Это позволит сделать pull, даже если файлы уже изменены.
    os.system("git pull origin main --rebase --autostash")
    
    # 2. Добавляем обновленные файлы в индекс
    os.system("git add cidr-git.txt cidr-1.txt cidr-2.txt cidr-all.txt all-dedup.txt checked-configs.txt")
    
    # 3. Проверяем, есть ли что коммитить
    status = os.popen("git status --porcelain").read().strip()
    if status:
        os.system(f'git commit -m "{COMMIT_MESSAGE}"')
        
        # 4. Пытаемся отправить. Если за это время кто-то еще успел запушить, 
        # цикл повторится при следующем запуске скрипта.
        push_status = os.system("git push origin main")
        if push_status == 0:
            print("[*] Успешно запушено на GitHub.")
        else:
            print("[-] Ошибка при push. Попробуем в следующий раз.")
    else:
        print("[*] Изменений для коммита нет.")
async def main():
    sources = load_all_networks()
    raw_links_list = fetch_all_configs()
    if not raw_links_list:
        print("[-] Ссылки не найдены.")
        return

    unique_raw_links = list(set(raw_links_list))
    print(f"[*] Уникальных ссылок: {len(unique_raw_links)}")

    resolved_raw = []
    with ThreadPoolExecutor(max_workers=MAX_RESOLVE_THREADS) as executor:
        loop = asyncio.get_event_loop()
        futures = [loop.run_in_executor(executor, resolve_full_data, l) for l in unique_raw_links]
        for res in await asyncio.gather(*futures):
            if res: resolved_raw.append(res)

    unique_hosts = {}
    for item in resolved_raw:
        if item['key'] not in unique_hosts:
            unique_hosts[item['key']] = item

    final_to_check = list(unique_hosts.values())
    semaphore = asyncio.Semaphore(CONCURRENT_TCP_CHECKS)
    tasks = [check_tcp(item, semaphore) for item in final_to_check]
    live_items = []

    print(f"[*] TCP тест {len(final_to_check)} хостов...")
    for task in asyncio.as_completed(tasks):
        res = await task
        if res: live_items.append(res)

    # Инициализация словарей для результатов
    results = {
        'cidr-git.txt': {},
        'cidr-1.txt': {},
        'cidr-2.txt': {},
        'cidr-all.txt': {},
        'checked-configs.txt': {}
    }

    for item in live_items:
        ip, key, link = item['ip'], item['key'], item['link']

        in_git = any(ip in net for net in sources['git'])
        in_c1 = any(ip in net for net in sources['cidr1'])
        in_c2 = any(ip in net for net in sources['cidr2'])
        in_checked = any(ip in net for net in sources['checked'])

        if in_git: results['cidr-git.txt'][key] = link
        if in_c1: results['cidr-1.txt'][key] = link
        if in_c2: results['cidr-2.txt'][key] = link
        if in_checked: results['checked-configs.txt'][key] = link
        if (in_git or in_c1 or in_c2): results['cidr-all.txt'][key] = link

    final_merged = {}
    for filename, unique_proxies in results.items():
        links = list(unique_proxies.values())
        if filename != 'checked-configs.txt':
            for k, v in unique_proxies.items():
                final_merged[k] = v

        with open(get_path(filename), 'w', encoding='utf-8') as f:
            f.write('\n'.join(links) + '\n' if links else "")
        print(f"[SAVED] {filename:20} | Прокси: {len(links)}")

    # Итоговый дедуп (без учета checked)
    final_list = list(final_merged.values())
    with open(get_path('all-dedup.txt'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_list) + '\n' if final_list else "")

    if GITHUB_PUSH:
        push_to_github()


if __name__ == "__main__":
    asyncio.run(main())
