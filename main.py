import ipaddress
import socket
import urllib.parse
import requests
import base64
import os
from concurrent.futures import ThreadPoolExecutor

# Настройки
WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/cidrwhitelist.txt"
LOCAL_CIDR_FILE = 'cidr.txt'
LOCAL_CIDR_FILE2 = 'cidr2.txt'
CONFIGS_FILE = 'configs.txt'
SUBS_FILE = 'subs.txt'
THREADS = 50  # Уменьшил для стабильности на 1GB RAM


def parse_cidr_lines(lines):
    """Парсит строки и возвращает список объектов ip_network."""
    nets = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#'):
            try:
                nets.append(ipaddress.ip_network(line))
            except ValueError:
                continue
    return nets


def get_networks():
    print("\n=== ВЫБОР ИСТОЧНИКА CIDR ===")
    print("1. Использовать список с GitHub")
    print("2. Использовать локальный cidr.txt")
    print("3. Использовать локальный cidr2.txt")
    print("4. ОБЪЕДИНИТЬ ВСЕ ИСТОЧНИКИ (GitHub + cidr.txt + cidr2.txt)")

    choice = input("Выберите вариант (1, 2, 3 или 4): ").strip()

    networks = []
    output_name = 'work.txt'

    # Вариант 1 или 4: Загрузка с GitHub
    if choice in ['1', '4']:
        print(f"[*] Загрузка списка из GitHub...")
        try:
            resp = requests.get(WHITELIST_URL, timeout=10)
            if resp.status_code == 200:
                nets = parse_cidr_lines(resp.text.splitlines())
                networks.extend(nets)
                print(f"[+] С GitHub получено: {len(nets)} сетей.")
        except Exception as e:
            print(f"[!] Ошибка GitHub: {e}")

    # Вариант 2 или 4: Локальный cidr.txt
    if choice in ['2', '4']:
        if choice == '2': output_name = 'vk-ya.txt'
        if os.path.exists(LOCAL_CIDR_FILE):
            print(f"[*] Чтение {LOCAL_CIDR_FILE}...")
            with open(LOCAL_CIDR_FILE, 'r', encoding='utf-8') as f:
                nets = parse_cidr_lines(f.readlines())
                networks.extend(nets)
                print(f"[+] Из {LOCAL_CIDR_FILE} получено: {len(nets)} сетей.")

    # Вариант 3 или 4: Локальный cidr2.txt
    if choice in ['3', '4']:
        if choice == '3': output_name = 'cidr2-work.txt'
        if os.path.exists(LOCAL_CIDR_FILE2):
            print(f"[*] Чтение {LOCAL_CIDR_FILE2}...")
            with open(LOCAL_CIDR_FILE2, 'r', encoding='utf-8') as f:
                nets = parse_cidr_lines(f.readlines())
                networks.extend(nets)
                print(f"[+] Из {LOCAL_CIDR_FILE2} получено: {len(nets)} сетей.")

    if choice == '4':
        output_name = 'all-work.txt'
        # Убираем дубликаты сетей, если они пересекаются
        networks = list(set(networks))
        print(f"[!] Итого объединено уникальных CIDR: {len(networks)}")

    if not networks:
        print("[-] Сети не загружены. Проверьте источники.")
        return None, None

    return networks, output_name


def decode_subs(content):
    try:
        return base64.b64decode(content.strip()).decode('utf-8').splitlines()
    except:
        return content.splitlines()


def fetch_subscriptions():
    all_links = []
    if not os.path.exists(SUBS_FILE): return all_links

    print(f"[*] Сбор ссылок из подписок...")
    with open(SUBS_FILE, 'r', encoding='utf-8') as f:
        subs = [l.strip() for l in f if l.strip() and l.startswith('http')]

    for url in subs:
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                links = decode_subs(resp.text)
                all_links.extend([l.strip() for l in links if l.strip()])
        except Exception:
            continue
    return all_links


def resolve_and_check(link, networks):
    try:
        parsed = urllib.parse.urlparse(link)
        netloc = parsed.netloc.split('@')[-1]
        host = netloc.split(':')[0] if ':' in netloc else netloc
        port = netloc.split(':')[1] if ':' in netloc else "443"

        try:
            ip_obj = ipaddress.ip_address(host)
        except ValueError:
            ip_obj = ipaddress.ip_address(socket.gethostbyname(host))

        # Проверка вхождения IP в любую из сетей
        for net in networks:
            if ip_obj in net:
                return link, f"{ip_obj}:{port}"
    except:
        pass
    return None


def main():
    networks, output_file = get_networks()
    if not networks: return

    raw_configs = []
    if os.path.exists(CONFIGS_FILE):
        with open(CONFIGS_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            raw_configs.extend([l.strip() for l in f if l.strip()])

    raw_configs.extend(fetch_subscriptions())

    initial_len = len(raw_configs)
    raw_configs = list(set(raw_configs))
    print(f"[*] Собрано ссылок: {initial_len}. После удаления дублей строк: {len(raw_configs)}")

    final_configs = {}

    print(f"[*] Фильтрация и дедупликация в {THREADS} потоков...")
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        results = executor.map(lambda l: resolve_and_check(l, networks), raw_configs)

        for res in results:
            if res:
                link, server_key = res
                if server_key not in final_configs:
                    final_configs[server_key] = link

    with open(output_file, 'w', encoding='utf-8') as out:
        for link in final_configs.values():
            out.write(link + '\n')

    print(f"\n[DONE] Проверка завершена.")
    print(f"[*] Найдено уникальных серверов: {len(final_configs)}")
    print(f"[*] Результат сохранен в: {output_file}")


if __name__ == "__main__":
    main()