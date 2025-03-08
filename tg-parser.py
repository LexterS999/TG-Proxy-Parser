import requests
import threading
import json
import os
import time
import random
import re
import base64
from bs4 import BeautifulSoup
from datetime import datetime
import logging
import binascii
import urllib.parse as urllib_parse
from typing import List

# --- Настройка логирования ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Конец настройки логирования ---
requests.post = lambda url, **kwargs: requests.request(
method="POST", url=url, verify=False, **kwargs
)
requests.get = lambda url, **kwargs: requests.request(
method="GET", url=url, verify=False, **kwargs
)

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# --- Глобальные константы ---
MAX_THREADS_PARSING = 50  # Оптимизировано: уменьшено количество потоков для стабильности
REQUEST_TIMEOUT = 10      # Оптимизировано: увеличено время ожидания ответа
MIN_PROFILES_TO_DOWNLOAD = 20 # Оптимизировано: увеличено минимальное количество профилей для сохранения
MAX_PROFILES_TO_DOWNLOAD = 100000 # Оптимизировано: увеличено максимальное количество профилей для сохранения
ALLOWED_PROTOCOLS = {"vless", "hy2", "tuic", "trojan"}
PROFILE_SCORE_WEIGHTS = { # Веса параметров для расчета скора профиля
"security": 2,
"sni": 2,
"alpn": 2,
"flow": 2,
"headerType": 1,
"path": 1,
"obfs": 1, # Для trojan и hy2, если применимо
"mport": 1, # Для tuic, если применимо
}

# --- НОВЫЕ КОНСТАНТЫ ДЛЯ ПЕРИОДА СКАЧИВАНИЯ ---
START_DAY_PROFILE_DOWNLOAD = 1  # День начала периода скачивания профилей (включительно)
END_DAY_PROFILE_DOWNLOAD = 14   # День окончания периода скачивания профилей (включительно)
# --- КОНЕЦ НОВЫХ КОНСТАНТ ---

# --- Новые поисковые запросы ---
SEARCH_QUERIES = ["vless config", "trojan profile", "hy2 channel", "tuic proxy", "vpn server", "proxy config"] #  Расширенный список запросов
# --- Конец новых поисковых запросов ---

# --- Конец глобальных констант ---
if not os.path.exists('config-tg.txt'):
    with open('config-tg.txt', 'w'): pass

def json_load(path):
    """Загружает JSON файл."""
    try:
        with open(path, 'r', encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        logging.error(f"Файл не найден: {path}")
        return []
    except json.JSONDecodeError:
        logging.error(f"Ошибка декодирования JSON в файле: {path}. Возвращен пустой список.")
        return []

def substring_del(string_list):
    """Удаляет подстроки из списка строк."""
    list1 = list(string_list)
    list2 = list(string_list)
    list1.sort(key=lambda s: len(s), reverse=False)
    list2.sort(key=lambda s: len(s), reverse=True)
    out = list()
    for s1 in list1:
        for s2 in list2:
            if s1 in s2 and len(s1) < len(s2):
                out.append(s1)
                break
        if len(s1) >= len(s2):
            break
    out = list(set(string_list)-set(out))
    return out

def find_telegram_channels(search_queries: List[str]) -> List[str]:
    """
    Автоматически ищет Telegram-каналы по заданным поисковым запросам в Telegram Web.

    Args:
        search_queries: Список поисковых запросов для Telegram Web.

    Returns:
        Список уникальных имен найденных Telegram-каналов (без 't.me/').
        Возвращает пустой список в случае ошибок или если каналы не найдены.
    """
    found_channels = set()
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' # Важно для имитации браузера
    }
    for query in search_queries:
        try:
            search_url = f"https://t.me/search?q={urllib_parse.quote_plus(query)}" # URL-кодирование запроса
            logging.info(f"Выполняется поиск каналов по запросу: '{query}'")
            response = requests.get(search_url, headers=headers, timeout=REQUEST_TIMEOUT) # Добавляем headers
            response.raise_for_status() # Проверка на HTTP ошибки

            soup = BeautifulSoup(response.text, 'html.parser')
            channel_links = soup.find_all('a', class_='tgme_channel_item_username') #  Ищем ссылки с классом tgme_channel_item_username

            for link_tag in channel_links:
                channel_name = link_tag.get_text(strip=True)[1:] # Извлекаем текст ссылки, убираем первый символ '@'
                if channel_name: # Проверка на пустое имя канала
                    found_channels.add(channel_name)

            time.sleep(random.randint(3, 7)) # Задержка между запросами, чтобы не перегружать сервер

        except requests.Timeout:
            logging.warning(f"Таймаут при поиске каналов по запросу '{query}'.")
        except requests.RequestException as e:
            logging.error(f"Ошибка при поиске каналов по запросу '{query}': {e}")
        except Exception as e:
            logging.error(f"Непредвиденная ошибка при обработке поиска по запросу '{query}': {e}")

    return list(found_channels)


tg_name_json = json_load('telegram_channels.json') # Загружаем список каналов из telegram_channels.json

discovered_channels = find_telegram_channels(SEARCH_QUERIES)
logging.info(f"Найдено новых каналов через поиск: {len(discovered_channels)}")
tg_name_json.extend(discovered_channels) # Добавляем найденные каналы к существующему списку
tg_name_json = list(set(tg_name_json)) # Удаляем дубликаты, включая новые и старые

initial_channels_count = len(tg_name_json) # Запоминаем начальное количество каналов

logging.info(f'Всего имен каналов в telegram_channels.json после поиска: {initial_channels_count}') # Логируем обновленное количество каналов


# --- ПРОВЕРКА ТЕКУЩЕГО ДНЯ МЕСЯЦА ---
current_day = datetime.now().day
if not (START_DAY_PROFILE_DOWNLOAD <= current_day <= END_DAY_PROFILE_DOWNLOAD):
    logging.info(f"Текущий день месяца ({current_day}) не попадает в заданный период скачивания ({START_DAY_PROFILE_DOWNLOAD}-{END_DAY_PROFILE_DOWNLOAD}). Парсинг профилей отменен.")
    logging.info(f'Завершено!') # Завершаем работу скрипта информационным сообщением
    exit() # Завершаем скрипт, если текущая дата вне периода
# --- КОНЕЦ ПРОВЕРКИ ДНЯ МЕСЯЦА ---

logging.info(f'Начинаем парсинг...') # Обновленное сообщение лога

start_time = datetime.now()

sem_pars = threading.Semaphore(MAX_THREADS_PARSING)

new_tg_name_json = list() # Инициализация здесь, так как используется ниже в process_channel и сохранении

htmltag_pattern = re.compile(r'<.*?>')
parsed_profiles = []

def calculate_profile_score(profile):
    """Вычисляет скор профиля на основе количества и важности параметров."""
    protocol = profile.split("://")[0]
    if protocol not in ALLOWED_PROTOCOLS:
        return 0

    score = 0
    params_str = profile.split("://")[1]
    if "@" in params_str:
        params_str = params_str.split("@")[1]
    if "#" in params_str:
        params_str = params_str.split("#")[0]

    params = urllib_parse.parse_qs(params_str)

    if protocol == "vless":
        if "security" in params:
            if params["security"][0] == "tls":
                score += PROFILE_SCORE_WEIGHTS.get("security", 0)
                if "sni" in params:
                    score += PROFILE_SCORE_WEIGHTS.get("sni", 0)
                if "alpn" in params:
                    score += PROFILE_SCORE_WEIGHTS.get("alpn", 0)
                if "flow" in params:
                    score += PROFILE_SCORE_WEIGHTS.get("flow", 0)
        if "headerType" in params:
            score += PROFILE_SCORE_WEIGHTS.get("headerType", 0)
        if "path" in params:
            score += PROFILE_SCORE_WEIGHTS.get("path", 0)

    elif protocol == "hy2":
        if "security" in params:
            if params["security"][0] == "tls":
                score += PROFILE_SCORE_WEIGHTS.get("security", 0)
                if "sni" in params:
                    score += PROFILE_SCORE_WEIGHTS.get("sni", 0)
                if "alpn" in params:
                    score += PROFILE_SCORE_WEIGHTS.get("alpn", 0)
        if "obfs" in params: # Добавлена поддержка obfs для hy2
            score += PROFILE_SCORE_WEIGHTS.get("obfs", 0)

    elif protocol == "tuic":
        if "alpn" in params:
            score += PROFILE_SCORE_WEIGHTS.get("alpn", 0)
        if "mport" in params: # Добавлена поддержка mport для tuic
            score += PROFILE_SCORE_WEIGHTS.get("mport", 0)

    elif protocol == "trojan":
        if "security" in params:
            if params["security"][0] == "tls":
                score += PROFILE_SCORE_WEIGHTS.get("security", 0)
                if "sni" in params:
                    score += PROFILE_SCORE_WEIGHTS.get("sni", 0)
                if "alpn" in params:
                    score += PROFILE_SCORE_WEIGHTS.get("alpn", 0)
        if "obfs" in params: # Добавлена поддержка obfs для trojan (может быть не стандартным, но для полноты)
            score += PROFILE_SCORE_WEIGHTS.get("obfs", 0)

    base_params_count = len(profile.split("://")[1].split("@")[0].split(":")) # host, port, userinfo
    score += base_params_count

    return score

def process_channel(i_url):
    """Обрабатывает один телеграм канал для извлечения профилей."""
    sem_pars.acquire()
    html_pages = list()
    cur_url = i_url
    god_tg_name = False
    channel_profiles = []
    pattern_datbef = re.compile(r'(?:data-before=")(\d*)') # pattern_datbef moved inside function to avoid potential scope issues if it's modified later

    for itter in range(1, 2+1): # pars_dp = 2, hardcoded for now for clarity
        while True:
            try:
                response = requests.get(f'https://t.me/s/{cur_url}', timeout=REQUEST_TIMEOUT)
            except requests.Timeout:
                logging.error(f"Таймаут при запросе к {cur_url}, попытка {itter}/2") # pars_dp = 2, hardcoded for now for clarity
                time.sleep(random.randint(5,15))
                continue
            except requests.RequestException as e:
                logging.error(f"Ошибка при запросе к {cur_url}: {e}, попытка {itter}/2") # pars_dp = 2, hardcoded for now for clarity
                time.sleep(random.randint(5, 15))
                continue
            else:
                if response.status_code == 200:
                    if itter == 2: # pars_dp = 2, hardcoded for now for clarity
                        logging.info(f'{tg_name_json.index(i_url)+1} из {walen} - {i_url}')
                    html_pages.append(response.text)
                    last_datbef = re.findall(pattern_datbef, response.text)
                    break
                else:
                    logging.error(f"Ошибка HTTP {response.status_code} при запросе к {cur_url}, код статуса: {response.status_code}, попытка {itter}/2") # pars_dp = 2, hardcoded for now for clarity
                    time.sleep(random.randint(5, 15))
                    continue

        if not last_datbef: # Проверка last_datbef после цикла while
            break # <--- Теперь этот break корректно расположен внутри цикла 'for itter in range(1, 2+1):'

        cur_url = f'{i_url}?before={last_datbef[0]}'

    for page in html_pages:
        soup = BeautifulSoup(page, 'html.parser')
        code_tags = soup.find_all(class_='tgme_widget_message_text')
        for code_tag in code_tags:
            code_content2 = str(code_tag).split('<br/>')
            for code_content in code_content2:
                cleaned_content = re.sub(htmltag_pattern, '', code_content).strip()
                for protocol in ALLOWED_PROTOCOLS:
                    if f"{protocol}://" in cleaned_content:
                        profile_link = cleaned_content
                        score = calculate_profile_score(profile_link)
                        channel_profiles.append({'profile': profile_link, 'score': score})
                        new_tg_name_json.append(i_url) #  оставляем для статистики, но запись в файл убираем
                        god_tg_name = True
                        break

    if not god_tg_name:
        pass
    parsed_profiles.extend(channel_profiles)
    sem_pars.release()

tg_name_json[:] = [x for x in tg_name_json if len(x) >= 5] # Убедимся, что имена каналов валидны после загрузки
tg_name_json = list(set(tg_name_json)) # Удаляем дубликаты
tg_name_json = sorted(tg_name_json) # Сортируем каналы

walen = len(tg_name_json)
logging.info(f'Начинаем парсинг {walen} телеграм каналов...') # Обновлено сообщение лога
threads = []
for url in tg_name_json:
    thread = threading.Thread(target=process_channel, args=(url,))
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()

logging.info(f'Парсинг завершен - {str(datetime.now() - start_time).split(".")[0]}')
logging.info(f'Начинаем проверку и удаление дубликатов из спарсенных конфигов...')

processed_profiles = []
for item in parsed_profiles:
    part = item['profile']
    part = re.sub('%0A', '', part)
    part = re.sub('%250A', '', part)
    part = re.sub('%0D', '', part)
    part = requests.utils.unquote(requests.utils.unquote(part)).strip()
    part = re.sub(' ', '', part)
    part = re.sub(r'\x00', '', part)
    part = re.sub(r'\x01', '', part)
    part = re.sub('amp;', '', part)
    part = re.sub('�', '', part)
    part = re.sub('fp=firefox', 'fp=chrome', part)
    part = re.sub('fp=safari', 'fp=chrome', part)
    part = re.sub('fp=edge', 'fp=chrome', part)
    part = re.sub('fp=360', 'fp=chrome', part)
    part = re.sub('fp=qq', 'fp=chrome', part)
    part = re.sub('fp=ios', 'fp=chrome', part)
    part = re.sub('fp=android', 'fp=chrome', part)
    part = re.sub('fp=randomized', 'fp=chrome', part)
    part = re.sub('fp=random', 'fp=chrome', part)

    protocol = ""
    if "vless://" in part:
        protocol = "vless"
        part = f'vless://{part.split("vless://")[1]}'
        if "flow=xtls-rprx-direct" in part:
            continue
        if "@" in part and ":" in part[8:]:
             processed_profiles.append({'profile': part.strip(), 'score': item['score']})
        continue
    elif "hy2://" in part:
        protocol = "hy2"
        part = f'hy2://{part.split("hy2://")[1]}'
        if "@" in part and ":" in part[6:]:
            processed_profiles.append({'profile': part.strip(), 'score': item['score']})
        continue
    elif "tuic://" in part:
        protocol = "tuic"
        part = f'tuic://{part.split("tuic://")[1]}'
        if ":" in part[7:] and "@" in part:
            processed_profiles.append({'profile': part.strip(), 'score': item['score']})
        continue
    elif "trojan://" in part:
        protocol = "trojan"
        part = f'trojan://{part.split("trojan://")[1]}'
        if "@" in part and ":" in part[9:]:
            processed_profiles.append({'profile': part.strip(), 'score': item['score']})
        continue

logging.info(f'Пытаемся удалить поврежденные конфигурации...')

unique_profiles_scored = []
seen_profiles = set()
for profile_data in processed_profiles:
    profile = profile_data['profile']
    if profile not in seen_profiles and (len(profile)>13) and (("…" in profile and "#" in profile) or ("…" not in profile)):
        unique_profiles_scored.append(profile_data)
        seen_profiles.add(profile)

new_processed_profiles_scored = []
for profile_data in unique_profiles_scored:
    x = profile_data['profile']
    if x[-2:] == '…»':
        x=x[:-2]
    if x[-1:] == '…':
        x=x[:-1]
    if x[-1:] == '»':
        x=x[:-1]
    if x[-2:-1] == '%':
        x=x[:-2]
    if x[-1:] == '%':
        x=x[:-1]
    if x[-1:] == '`':
        x=x[:-1]
    new_processed_profiles_scored.append({'profile': x.strip(), 'score': profile_data['score']})

processed_profiles_scored = new_processed_profiles_scored

processed_profiles_strings = [item['profile'] for item in processed_profiles_scored]
processed_profiles_strings = substring_del(processed_profiles_strings)

final_profiles_scored = []
profile_strings_set = set(processed_profiles_strings)
for profile_data in processed_profiles_scored:
    if profile_data['profile'] in profile_strings_set:
        final_profiles_scored.append(profile_data)
        profile_strings_set.remove(profile_data['profile'])

final_profiles_scored.sort(key=lambda item: item['score'], reverse=True)


num_profiles_to_save = min(max(len(final_profiles_scored), MIN_PROFILES_TO_DOWNLOAD), MAX_PROFILES_TO_DOWNLOAD)

profiles_to_save = final_profiles_scored[:num_profiles_to_save]

with open("config-tg.txt", "w", encoding="utf-8") as file:
    for profile_data in profiles_to_save:
        file.write(profile_data['profile'].encode("utf-8").decode("utf-8") + "\n")

end_time = datetime.now()
total_time = end_time - start_time

logging.info(f'{"-"*40}')
logging.info(f'{"--- Итоговая статистика ---":^40}')
logging.info(f'{"-"*40}')
logging.info(f'Общее время выполнения: {str(total_time).split(".")[0]}')
logging.info(f'Начальное количество каналов в telegram_channels.json: {initial_channels_count}') # Используем сохраненное значение
logging.info(f'Всего каналов после обработки: {len(tg_name_json)}') #  Оставил для информации, даже если не меняется. Можно удалить если не нужно.
logging.info(f'Каналов обработано: {walen}')
logging.info(f'Профилей найдено во время парсинга (до обработки): {len(parsed_profiles)}')
logging.info(f'Уникальных профилей после обработки и фильтрации: {len(final_profiles_scored)}')
logging.info(f'Профилей сохранено в config-tg.txt: {len(profiles_to_save)}')
logging.info(f'{"-"*40}')
logging.info('Завершено!')

if __name__ == "__main__":
    # Этот блок будет выполнен только при прямом запуске скрипта
    pass # Основная логика уже снаружи, нет необходимости дублировать ее здесь, можно добавить специфическую логику запуска при необходимости
