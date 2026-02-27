import os
import json
import asyncio
import requests
import hashlib
from typing import Set

# ========= ФАЙЛЫ =========
TOKEN_FILE = "bot_token.txt"
SUBSCRIBERS_FILE = "subscribers.json"
FILE_TO_SEND = "all-dedup.txt"
HASH_FILE = "file.hash"


# ========= ЧТЕНИЕ ТОКЕНА =========
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


# ========= TELEGRAM АСИНХРОННО =========
async def send_message(chat_id: int, text: str):
    requests.post(f"{API_URL}/sendMessage", data={"chat_id": chat_id, "text": text}, timeout=10)


async def send_file(chat_id: int, path: str):
    if not os.path.exists(path):
        await send_message(chat_id, "файла нет")
        return
    with open(path, "rb") as f:
        requests.post(f"{API_URL}/sendDocument", data={"chat_id": chat_id}, files={"document": f}, timeout=30)


# ========= ЛОГИКА ФАЙЛА =========
def get_file_hash(path):
    if not os.path.exists(path): return None
    hasher = hashlib.md5()
    with open(path, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()


# ========= ЗАДАЧА: ПРОВЕРКА ФАЙЛА (раз в 5 минут) =========
async def file_checker_task():
    print("[*] Задача проверки файла запущена.")
    while True:
        if os.path.exists(FILE_TO_SEND):
            current_hash = get_file_hash(FILE_TO_SEND)

            old_hash = None
            if os.path.exists(HASH_FILE):
                with open(HASH_FILE, "r") as f:
                    old_hash = f.read().strip()

            if current_hash != old_hash:
                print("[+] Файл изменился! Делаю рассылку...")
                with open(HASH_FILE, "w") as f:
                    f.write(current_hash)

                caption = "обнова"
                for chat_id in list(subscribers):
                    try:
                        await send_message(chat_id, caption)
                        await send_file(chat_id, FILE_TO_SEND)
                        await asyncio.sleep(0.3)
                    except Exception as e:
                        print(f"[!] Failed for {chat_id}: {e}")

        await asyncio.sleep(300)  # Ждем 5 минут (300 секунд)


# ========= ЗАДАЧА: БОТ (long-polling) =========
async def bot_task():
    print("[*] Задача бота запущена.")
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

                if text == "/start":
                    if chat_id not in subscribers:
                        subscribers.add(chat_id)
                        save_subscribers(subscribers)
                        await send_message(chat_id, "жди обнов либо пиши 'дай'")
                    else:
                        await send_message(chat_id, "пр")

                elif text == "дай":
                    if chat_id not in subscribers:
                        subscribers.add(chat_id)
                        save_subscribers(subscribers)
                    await send_message(chat_id, "отправляю")
                    await send_file(chat_id, FILE_TO_SEND)

        except Exception as e:
            print("[!] Bot error:", e)
            await asyncio.sleep(5)


# ========= ЗАПУСК =========
async def main():
    # Запускаем две задачи параллельно
    await asyncio.gather(
        bot_task(),
        file_checker_task()
    )


if __name__ == "__main__":
    asyncio.run(main())