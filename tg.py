#!/usr/bin/python3
import os
import json
import asyncio
import requests
import hashlib
from typing import Set

# ========= ФАЙЛЫ И ССЫЛКИ =========
TOKEN_FILE = "bot_token.txt"
SUBSCRIBERS_FILE = "subscribers.json"
# Ссылка на сырой файл с прокси
PROXIES_URL = "https://raw.githubusercontent.com/naivecensor/nothing-suspicious/refs/heads/main/final.txt"
EXCLAVE_APK_URL = "https://github.com/dyhkwong/Exclave/releases/download/0.17.30/Exclave-0.17.30-arm64-v8a.apk"

def load_token() -> str:
    if not os.path.exists(TOKEN_FILE): raise RuntimeError("bot_token.txt not found")
    with open(TOKEN_FILE, "r", encoding="utf-8") as f: return f.read().strip()

BOT_TOKEN = load_token()
API_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"

# ========= ПОДПИСЧИКИ =========
def load_subscribers() -> Set[int]:
    if not os.path.exists(SUBSCRIBERS_FILE): return set()
    with open(SUBSCRIBERS_FILE, "r", encoding="utf-8") as f: return set(json.load(f))

def save_subscribers(subs: Set[int]):
    with open(SUBSCRIBERS_FILE, "w", encoding="utf-8") as f: json.dump(sorted(subs), f)

subscribers = load_subscribers()

# ========= ФУНКЦИИ ОТПРАВКИ =========
async def send_message(chat_id: int, text: str):
    requests.post(f"{API_URL}/sendMessage", data={"chat_id": chat_id, "text": text}, timeout=15)

async def send_proxies_batched(chat_id: int, n: int):
    """Качает прокси и отправляет порциями по 10 штук"""
    try:
        r = requests.get(PROXIES_URL, timeout=10)
        all_lines = r.text.splitlines()
        target_lines = all_lines[:n]
        
        if not target_lines:
            await send_message(chat_id, "чето пусто")
            return

        # Режем на куски по 10 строк
        for i in range(0, len(target_lines), 10):
            chunk = "\n".join(target_lines[i:i+10])
            await send_message(chat_id, chunk)
            await asyncio.sleep(0.2) # Маленькая пауза, чтобы не словить спам-фильтр
            
    except Exception as e:
        await send_message(chat_id, f"ошибка: {e}")

# ========= ОСНОВНОЙ ЦИКЛ БОТА =========
async def bot_task():
    print("[*] Бот запущен. Жду сообщений...")
    offset = None
    while True:
        try:
            params = {"timeout": 30}
            if offset: params["offset"] = offset
            r = requests.get(f"{API_URL}/getUpdates", params=params, timeout=35)
            data = r.json()

            for upd in data.get("result", []):
                offset = upd["update_id"] + 1
                msg = upd.get("message")
                if not msg: continue

                chat_id = msg["chat"]["id"]
                text = msg.get("text", "").strip().lower()

                # 1. Регистрация / Start
                if text == "/start":
                    subscribers.add(chat_id)
                    save_subscribers(subscribers)
                    await send_message(chat_id, "число. \nили 'дай' / 'неко'.")

                # 2. Обработка ЧИСЛА
                elif text.isdigit():
                    count = int(text)
                    await send_message(chat_id, f"ща скину {count} проксей")
                    await send_proxies_batched(chat_id, count)

                # 3. Команда "дай" (теперь тянет файл WORKING_PROXIES)
                elif text == "дай":
                    await send_message(chat_id, "ща скину")
                    try:
                        r = requests.get(PROXIES_URL)
                        with open("working_proxies.txt", "wb") as f:
                            f.write(r.content)
                        with open("working_proxies.txt", "rb") as f:
                            requests.post(f"{API_URL}/sendDocument", data={"chat_id": chat_id}, files={"document": f})
                    except Exception as e:
                        await send_message(chat_id, f"ошибка чето {e}")

                # 4. Команда "неко" (Exclave)
                elif text == "неко":
                    await send_message(chat_id, "ща скину")
                    apk_name = "exclave.apk"
                    try:
                        r = requests.get(EXCLAVE_APK_URL, stream=True)
                        with open(apk_name, 'wb') as f:
                            for chunk in r.iter_content(chunk_size=1024*1024):
                                if chunk: f.write(chunk)
                        with open(apk_name, 'rb') as f:
                            requests.post(f"{API_URL}/sendDocument", 
                                         data={"chat_id": chat_id, "caption": "Exclave 0.17.30"},
                                         files={"document": f}, timeout=60)
                        os.remove(apk_name)
                    except Exception as e:
                        await send_message(chat_id, f"ошибка apkшки: {e}")

        except Exception as e:
            print("[!] Ошибка бота:", e)
            await asyncio.sleep(5)

# (Остальные части кода: file_checker_task и main — остаются без изменений)
async def file_checker_task():
    # Твоя логика проверки all-dedup.txt остается здесь
    while True:
        await asyncio.sleep(300)

async def main():
    await asyncio.gather(bot_task(), file_checker_task())

if __name__ == "__main__":
    asyncio.run(main())
