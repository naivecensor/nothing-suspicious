import requests
import urllib.parse
import os

# --- НАСТРОЙКИ ---
GITHUB_USER = "naivecensor"
REPO_NAME = "nothing-suspicious"
BRANCH = "main"
# Список файлов, которые нужно стянуть
FILES_TO_FETCH = ['cidr-1.txt', 'cidr-2.txt', 'cidr-git.txt', 'cidr-all.txt']
OUTPUT_FILE = 'final_cleaned_proxies.txt'


def extract_ip_port(link):
    """Извлекает уникальный ключ ip:port из ссылки"""
    try:
        link = link.strip()
        if not link: return None
        parsed = urllib.parse.urlparse(link)
        netloc = parsed.netloc.split('@')[-1]
        host_port = netloc.split('?')[0].split('#')[0]
        return host_port
    except:
        return None


def main():
    unique_proxies = {}
    total_downloaded = 0

    print(f"[*] Подключение к репозиторию {GITHUB_USER}/{REPO_NAME}...")

    for filename in FILES_TO_FETCH:
        # Формируем прямую ссылку на файл
        url = f"https://raw.githubusercontent.com/{GITHUB_USER}/{REPO_NAME}/{BRANCH}/{filename}"

        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                lines = response.text.splitlines()
                added_from_file = 0

                for line in lines:
                    line = line.strip()
                    if not line: continue

                    total_downloaded += 1
                    key = extract_ip_port(line)

                    if key and key not in unique_proxies:
                        unique_proxies[key] = line
                        added_from_file += 1

                print(f"[+] {filename:15} | Скачано строк: {len(lines):<5} | Новых уникальных: {added_from_file}")
            else:
                print(f"[!] Файл {filename} не найден (HTTP {response.status_code})")
        except Exception as e:
            print(f"[!] Ошибка при загрузке {filename}: {e}")

    # Сохранение результата
    if unique_proxies:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(unique_proxies.values()) + '\n')

        print("\n" + "=" * 40)
        print(f"ИТОГО:")
        print(f"Всего обработано из GitHub: {total_downloaded}")
        print(f"Уникальных прокси по IP:Port: {len(unique_proxies)}")
        print(f"Результат в файле: {os.path.abspath(OUTPUT_FILE)}")
        print("=" * 40)
    else:
        print("[!] Не найдено данных для сохранения.")


if __name__ == "__main__":
    main()