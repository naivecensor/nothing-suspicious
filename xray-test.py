import json
import urllib.parse
import subprocess
import time
import os
import socket
import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# ========= НАСТРОЙКИ =========
XRAY_BIN = "xray.exe"
PROXY_URL = "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt"
OUTPUT_FILE = "WORKING_PROXIES.txt"

TIMEOUT = 12  # Чуть увеличил для стабильности
THREADS = 50  # Рекомендую 50 для Windows, 200 может вызывать ошибки портов
RETRIES = 1

TEST_URL = "https://httpbin.org/ip"

# Глобальные счетчики
counter = 0
total_count = 0
counter_lock = threading.Lock()


# ========= ЛОГ =========
def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")


# ========= VLESS PARSER =========
def parse_vless(url: str):
    try:
        if not url.startswith("vless://"):
            return None
        parsed = urllib.parse.urlparse(url)
        uuid = parsed.username
        address = parsed.hostname
        port = parsed.port or 443
        if not uuid or not address:
            return None

        query = urllib.parse.parse_qs(parsed.query)
        q = {k: v[0] for k, v in query.items()}

        stream = {"network": q.get("type", "tcp"), "security": q.get("security", "none")}

        if stream["security"] == "tls":
            stream["tlsSettings"] = {"serverName": q.get("sni", address), "allowInsecure": True}
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
    except:
        return None


# ========= UTILS =========
def get_free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_socks(port, timeout=8):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except:
            time.sleep(0.5)
    return False


# ========= TEST =========
def test_proxy(link):
    global counter
    outbound = parse_vless(link)
    address = outbound['settings']['vnext'][0]['address'] if outbound else "unknown"

    with counter_lock:
        counter += 1
        current = counter

    prefix = f"[{current}/{total_count}]"

    if not outbound:
        return None

    port = get_free_port()
    cfg = f"cfg_{port}.json"

    full_config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
        "routing": {"rules": [{"type": "field", "outboundTag": "proxy", "port": "0-65535"}]}
    }

    proc = None
    result_link = None

    try:
        with open(cfg, "w", encoding="utf-8") as f:
            json.dump(full_config, f)

        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", cfg],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        if wait_socks(port):
            proxies = {"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}
            r = requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT)
            if r.ok:
                log(f"{prefix} [OK] {address}")
                result_link = link
            else:
                log(f"{prefix} [BAD] {address} (Status: {r.status_code})")
        else:
            log(f"{prefix} [TIMEOUT] {address} | SOCKS failed")

    except Exception as e:
        log(f"{prefix} [ERR] {address} | {str(e)[:50]}")

    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except:
                proc.kill()

        # Удаление файла с защитой от занятости процессом
        for _ in range(5):
            try:
                if os.path.exists(cfg):
                    os.remove(cfg)
                break
            except PermissionError:
                time.sleep(0.5)

    return result_link


# ========= MAIN =========
def main():
    global total_count
    log("Downloading and deduplicating proxies...")

    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(PROXY_URL, headers=headers, timeout=20, verify=False)
        raw_links = [l.strip() for l in response.text.splitlines() if l.strip()]
    except Exception as e:
        log(f"[FATAL] Download error: {e}")
        return

    # Дедупликация по IP:Port
    unique_proxies = {}
    for link in raw_links:
        parsed = parse_vless(link)
        if parsed:
            addr_data = parsed['settings']['vnext'][0]
            key = f"{addr_data['address']}:{addr_data['port']}"
            if key not in unique_proxies:
                unique_proxies[key] = link

    links = list(unique_proxies.values())
    total_count = len(links)

    log(f"Unique proxies found: {total_count} (Dropped {len(raw_links) - total_count} duplicates)")
    log(f"Starting test with {THREADS} threads...\n")

    working = []
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(test_proxy, link) for link in links]
        for future in as_completed(futures):
            res = future.result()
            if res:
                working.append(res)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(working) + "\n")

    log(f"\n[✓] DONE: {len(working)} working proxies saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()