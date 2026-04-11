import json
import urllib.parse
import subprocess
import time
import os
import socket
import requests
import threading
import tempfile
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# ========= НАСТРОЙКИ =========
XRAY_BIN = "/usr/local/bin/xray" 

SOURCES = list(set([
    # основные
    "https://raw.githubusercontent.com/naivecensor/nothing-suspicious/refs/heads/main/all-dedup.txt",
    "https://raw.githubusercontent.com/naivecensor/nothing-suspicious/refs/heads/main/WORKING_PROXIES.txt",
    "https://raw.githubusercontent.com/VPN-cat/VPN/refs/heads/main/configs/VPN-cat-top-100",

    # wl / bypass
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://wlrus.lol/confs/selected.txt",
    "https://bp.wl.free.nf/confs/wl.txt",
    "https://bp.wl.free.nf/confs/selected.txt",

    # ru configs
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",

    # misc
    "https://mygala.ru/vpn/subscription.txt",
    "https://storage.yandexcloud.net/cid-vpn/whitelist.txt",
    "https://raw.githubusercontent.com/prominbro/KfWL/refs/heads/main/KfWL.txt",
    "https://raw.githubusercontent.com/55prosek-lgtm/vpn_config_for_russia/refs/heads/main/whitelist.txt",
    "https://raw.githubusercontent.com/4nba/vpn-free-russia/refs/heads/master/subscription.txt",

    # mirrors
    "https://github.com/restlycames/RestlyConnect_sub/raw/refs/heads/main/whitelists.txt",
    "https://github.com/KiryaScript/white-lists/raw/refs/heads/main/githubmirror/26.txt",
    "https://github.com/KiryaScript/white-lists/raw/refs/heads/main/githubmirror/27.txt",
    "https://github.com/KiryaScript/white-lists/raw/refs/heads/main/githubmirror/28.txt",

    # configs
    "https://raw.githubusercontent.com/twinkalex1470-crypto/CatWhiteVPN/refs/heads/main/CaTWhiteVPN.txt",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
    "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt",
    "https://cdn.jsdelivr.net/gh/EtoNeYaProject/EtoNeYaProject.github.io@refs/heads/main/1",
    "https://etoneya.a9fm.site/whitelist",

    # random repos
    "https://gitverse.ru/api/repos/Vsevj/OBS/raw/branch/master/wwh",
    "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/wl.txt",
]))

OUTPUT_FILE = "WORKING_PROXIES.txt"

TIMEOUT = 12  
THREADS = 150  
RETRIES = 3  
TEST_URL = "http://www.gstatic.com/generate_204"

counter = 0
total_count = 0
counter_lock = threading.Lock()

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")

def parse_vless(url: str):
    try:
        if not url.startswith("vless://"): return None
        parsed = urllib.parse.urlparse(url)
        uuid = parsed.username
        address = parsed.hostname
        port = parsed.port or 443
        if not uuid or not address: return None
        query = urllib.parse.parse_qs(parsed.query)
        q = {k: v[0] for k, v in query.items()}
        stream = {"network": q.get("type", "tcp"), "security": q.get("security", "none")}
        if stream["security"] == "tls":
            stream["tlsSettings"] = {"serverName": q.get("sni", address), "allowInsecure": True, "alpn": ["http/1.1"]}
        elif stream["security"] == "reality":
            stream["realitySettings"] = {
                "serverName": q.get("sni"),
                "fingerprint": q.get("fp", "chrome"),
                "publicKey": q.get("pbk"),
                "shortId": q.get("sid", ""),
                "spiderX": q.get("spx", "/")
            }
        if stream["network"] == "ws":
            stream["wsSettings"] = {"path": q.get("path", "/"), "headers": {"Host": q.get("host", address)}}
        elif stream["network"] == "grpc":
            stream["grpcSettings"] = {"serviceName": q.get("serviceName", "")}
        user = {"id": uuid, "encryption": "none"}
        if q.get("flow"): user["flow"] = q.get("flow")
        return {
            "tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{"address": address, "port": port, "users": [user]}]},
            "streamSettings": stream
        }
    except: return None

def get_free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

def wait_socks(port, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5): return True
        except: time.sleep(0.5)
    return False

def test_proxy(link):
    global counter
    outbound = parse_vless(link)
    if not outbound: return None
    
    address = outbound['settings']['vnext'][0]['address']
    with counter_lock:
        counter += 1
        current = counter
    prefix = f"[{current}/{total_count}]"

    port = get_free_port()
    cfg_path = os.path.join(tempfile.gettempdir(), f"x_cfg_{port}.json")
    
    full_config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
        "routing": {
            "rules": [{
                "type": "field",
                "inboundTag": ["socks-in"],
                "outboundTag": "proxy"
            }]
        }
    }
    
    proc = None
    result_link = None
    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(full_config, f)
            
        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", cfg_path], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        
        if wait_socks(port):
            # Отключаем использование системных прокси при проверке
            session = requests.Session()
            session.trust_env = False
            proxies = {"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}
            
            for attempt in range(1, RETRIES + 1):
                try:
                    r = session.get(TEST_URL, proxies=proxies, timeout=TIMEOUT)
                    if r.ok:
                        log(f"{prefix} [OK] {address} (Попытка {attempt})")
                        result_link = link
                        break
                    else:
                        if attempt == RETRIES: log(f"{prefix} [BAD] {address} (Статус: {r.status_code})")
                except Exception:
                    if attempt == RETRIES: log(f"{prefix} [FAIL] {address}")
                    else: time.sleep(0.5)
        else:
            log(f"{prefix} [LATE] {address}")
    except: pass
    finally:
        if proc:
            proc.terminate()
            try: proc.wait(timeout=1)
            except: proc.kill()
        if os.path.exists(cfg_path):
            try: os.remove(cfg_path)
            except: pass
    return result_link

def main():
    global total_count, counter
    all_raw_links = set() 
    
    # Сбор ссылок изо всех источников
    session = requests.Session()
    session.trust_env = False # Игнорируем прокси при скачивании списков
    
    for url in SOURCES:
        log(f"Fetching source: {url}")
        try:
            response = session.get(url, timeout=20)
            if response.ok:
                links = [l.strip() for l in response.text.splitlines() if l.strip()]
                all_raw_links.update(links)
                log(f"Добавлено {len(links)} конфигов.")
            else:
                log(f"[WARN] Ошибка загрузки {url}: {response.status_code}")
        except Exception as e:
            log(f"[WARN] Ошибка подключения к {url}: {e}")

    if not all_raw_links:
        log("[FATAL] Ссылки не найдены.")
        sys.exit(1)

    # Дедупликация по IP:Port
    unique_proxies = {}
    for link in all_raw_links:
        parsed = parse_vless(link)
        if parsed:
            addr = parsed['settings']['vnext'][0]
            unique_proxies[f"{addr['address']}:{addr['port']}"] = link

    links = list(unique_proxies.values())
    total_count = len(links)
    counter = 0
    log(f"Unique: {total_count}. Testing in {THREADS} threads (по {RETRIES} попытки)...")

    working = []
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(test_proxy, link) for link in links]
        for future in as_completed(futures):
            res = future.result()
            if res: working.append(res)

    if working:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(working) + "\n")
        log(f"[✓] SUCCESS: {len(working)} working proxies saved.")
        sys.exit(0)
    else:
        log("[!] No working proxies found.")
        sys.exit(1)

if __name__ == "__main__":
    main()
