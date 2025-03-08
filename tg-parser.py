import requests
import threading
import json
import os
import time
import random
import re
import urllib.parse as urllib_parse
from bs4 import BeautifulSoup
from datetime import datetime
import logging

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
MAX_THREADS_PARSING = 50
REQUEST_TIMEOUT = 10
MIN_PROFILES_TO_DOWNLOAD = 20
MAX_PROFILES_TO_DOWNLOAD = 4000
ALLOWED_PROTOCOLS = {"vless", "hy2", "tuic", "trojan"}
PROFILE_SCORE_WEIGHTS = {
    "security": 2,
    "sni": 2,
    "alpn": 2,
    "flow": 2,
    "headerType": 1,
    "path": 1,
    "obfs": 1,
    "mport": 1,
}

START_DAY_PROFILE_DOWNLOAD = 1
END_DAY_PROFILE_DOWNLOAD = 14
# --- Конец глобальных констант ---

if not os.path.exists('config-tg.txt'):
    with open('config-tg.txt', 'w'): pass

def json_load(path):
    """
    Загружает JSON файл и обрабатывает ошибки.

    Возвращает:
        dict или list или None: Содержимое JSON файла, если загрузка успешна.
                                None, если файл не найден или произошла ошибка декодирования.
                                Логгирует ошибки.
    """
    if not os.path.exists(path):
        logging.error(f"Файл не найден: {path}")
        return None

    try:
        with open(path, 'r', encoding="utf-8") as file:
            data = json.load(file)
            if not isinstance(data, (dict, list)):
                logging.error(f"Файл {path} не содержит JSON объект или массив. Возвращаем None.")
                return None
            return data
    except json.JSONDecodeError:
        logging.error(f"Ошибка декодирования JSON в файле: {path}. Возвращаем None.")
        return None

def substring_del(string_list):
    """
    Удаляет подстроки из списка строк.

    Для каждой строки в списке, проверяет, является ли она подстрокой какой-либо другой,
    более длинной строки в том же списке. Если да, то более короткая строка считается
    подстрокой и удаляется из результирующего списка.

    Пример:
    ['abc', 'abcd', 'def', 'ghi'] -> ['abcd', 'def', 'ghi']  ('abc' является подстрокой 'abcd')

    Возвращает:
        list: Список строк, из которого удалены подстроки.
    """
    string_list.sort(key=len)

    strings_to_remove = set()

    for i in range(len(string_list)):
        for j in range(i + 1, len(string_list)):
            if string_list[i] in string_list[j]:
                strings_to_remove.add(string_list[i])
                break

    return [s for s in string_list if s not in strings_to_remove]

def calculate_profile_score(profile):
    """
    Вычисляет скор профиля на основе параметров конфигурации.

    Скор рассчитывается на основе наличия и важности определенных параметров
    в строке профиля, используя веса из PROFILE_SCORE_WEIGHTS.
    Протоколы, не входящие в ALLOWED_PROTOCOLS, получают скор 0.

    Возвращает:
        int: Скорость профиля.
    """
    protocol = profile.split("://")[0]
    if protocol not in ALLOWED_PROTOCOLS:
        return 0

    score = 0
    try:
        params_str = profile.split("://")[1]
        if "@" in params_str:
            params_str = params_str.split("@")[1]
        if "#" in params_str:
            params_str = params_str.split("#")[0]

        params = urllib_parse.parse_qs(params_str)

        def add_tls_score():
            nonlocal score
            if params.get("security", [""])[0] == "tls":
                score += PROFILE_SCORE_WEIGHTS.get("security", 0)
                score += PROFILE_SCORE_WEIGHTS.get("sni", 0) if "sni" in params else 0
                score += PROFILE_SCORE_WEIGHTS.get("alpn", 0) if "alpn" in params else 0

        if protocol == "vless":
            add_tls_score()
            score += PROFILE_SCORE_WEIGHTS.get("flow", 0) if "flow" in params else 0
            score += PROFILE_SCORE_WEIGHTS.get("headerType", 0) if "headerType" in params else 0
            score += PROFILE_SCORE_WEIGHTS.get("path", 0) if "path" in params else 0

        elif protocol == "hy2":
            add_tls_score()
            score += PROFILE_SCORE_WEIGHTS.get("obfs", 0) if "obfs" in params else 0

        elif protocol == "tuic":
            score += PROFILE_SCORE_WEIGHTS.get("alpn", 0) if "alpn" in params else 0
            score += PROFILE_SCORE_WEIGHTS.get("mport", 0) if "mport" in params else 0

        elif protocol == "trojan":
            add_tls_score()
            score += PROFILE_SCORE_WEIGHTS.get("obfs", 0) if "obfs" in params else 0

        base_params_count = len(profile.split("://")[1].split("@")[0].split(":"))
        score += base_params_count

    except Exception as e:
        logging.error(f"Ошибка при расчете скора профиля '{profile}': {e}")
        return 0

    return score

def process_channel(channel_url, parsed_profiles, thread_semaphore, telegram_channel_names, channels_parsed_count, channels_with_profiles):
    """
    Обрабатывает один телеграм канал для извлечения профилей.

    Скачивает несколько страниц сообщений канала, ищет блоки кода с профилями,
    рассчитывает скор для каждого профиля и добавляет в общий список.

    Аргументы:
        channel_url (str): URL канала Telegram (без 'https://t.me/s/').
        parsed_profiles (list): Общий список для хранения найденных профилей.
        thread_semaphore (threading.Semaphore): Семафор для контроля количества потоков.
        telegram_channel_names (list): Список имен телеграм каналов.
        channels_parsed_count (int): Общее количество каналов для парсинга (используется для логирования).
        channels_with_profiles (set): Множество для отслеживания каналов, в которых найдены профили.
    """
    thread_semaphore.acquire()
    try:
        html_pages = []
        current_url = channel_url
        channel_profiles = []
        god_tg_name = False
        htmltag_pattern = re.compile(r'<.*?>')
        pattern_datbef = re.compile(r'(?:data-before=")(\d*)')

        for attempt in range(2):
            while True:
                try:
                    response = requests.get(f'https://t.me/s/{current_url}', timeout=REQUEST_TIMEOUT)
                    response.raise_for_status()
                    html_pages.append(response.text)
                    last_datbef = re.findall(pattern_datbef, response.text)
                    if not last_datbef:
                        logging.info(f"Больше страниц не найдено для {channel_url}")
                        break
                    current_url = f'{channel_url}?before={last_datbef[0]}'
                    break
                except requests.Timeout:
                    log_message = f"Таймаут при запросе к {channel_url}, попытка {attempt + 1}/2"
                    if attempt < 1:
                        log_message += ". Повторная попытка через 5-15 секунд."
                        time.sleep(random.randint(5, 15))
                    logging.warning(log_message)
                    if attempt >= 1:
                        logging.error(f"Превышено количество попыток (2) для {channel_url} из-за таймаутов.")
                        break
                except requests.RequestException as e:
                    log_message = f"Ошибка при запросе к {channel_url}: {e}, попытка {attempt + 1}/2"
                    if attempt < 1:
                        log_message += ". Повторная попытка через 5-15 секунд."
                        time.sleep(random.randint(5, 15))
                    logging.warning(log_message)
                    if attempt >= 1:
                        logging.error(f"Превышено количество попыток (2) для {channel_url} из-за ошибок запроса.")
                        break

        if not html_pages:
            logging.warning(f"Не удалось загрузить страницы для канала {channel_url} после нескольких попыток. Пропускаем канал.")
            return

        channel_index = telegram_channel_names.index(channel_url) + 1
        logging.info(f'{channel_index} из {channels_parsed_count} - {channel_url}')

        for page in html_pages:
            soup = BeautifulSoup(page, 'html.parser')
            code_tags = soup.find_all(class_='tgme_widget_message_text')
            for code_tag in code_tags:
                code_content_lines = str(code_tag).split('<br/>')
                for line in code_content_lines:
                    cleaned_content = re.sub(htmltag_pattern, '', line).strip()
                    for protocol in ALLOWED_PROTOCOLS:
                        if f"{protocol}://" in cleaned_content:
                            profile_link = cleaned_content
                            score = calculate_profile_score(profile_link)
                            channel_profiles.append({'profile': profile_link, 'score': score})
                            god_tg_name = True
                            break

        if god_tg_name:
            channels_with_profiles.add(channel_url)

        if not channel_profiles:
            logging.info(f"Профили не найдены в канале {channel_url}.")

        parsed_profiles.extend(channel_profiles)

    except Exception as channel_exception:
        logging.error(f"Критическая ошибка при обработке канала {channel_url}: {channel_exception}")
    finally:
        thread_semaphore.release()

def clean_profile(profile_string):
    """Очищает строку профиля от лишних символов и артефактов."""
    part = profile_string
    part = re.sub('%0A', '', part)
    part = re.sub('%250A', '', part)
    part = re.sub('%0D', '', part)
    part = requests.utils.unquote(requests.utils.unquote(part)).strip()
    part = re.sub(' ', '', part)
    part = re.sub(r'\x00', '', part)
    part = re.sub(r'\x01', '', part)
    part = re.sub('amp;', '', part)
    part = re.sub('�', '', part)
    part = re.sub('fp=(firefox|safari|edge|360|qq|ios|android|randomized|random)', 'fp=chrome', part, flags=re.IGNORECASE)
    return part

def process_parsed_profiles(parsed_profiles_list):
    """
    Обрабатывает список спарсенных профилей: очистка, фильтрация по протоколам,
    удаление дубликатов и подстрок, итоговая сортировка.

    Аргументы:
        parsed_profiles_list (list): Список словарей с профилями и их скорами.

    Возвращает:
        list: Список обработанных и отсортированных профилей (словари).
    """
    processed_profiles = []
    for item in parsed_profiles_list:
        cleaned_profile_string = clean_profile(item['profile'])
        protocol = ""
        profile_to_add = None

        if "vless://" in cleaned_profile_string:
            protocol = "vless"
            part = f'vless://{cleaned_profile_string.split("vless://")[1]}'
            if "flow=xtls-rprx-direct" not in part and "@" in part and ":" in part[8:]:
                profile_to_add = {'profile': part.strip(), 'score': item['score']}

        elif "hy2://" in cleaned_profile_string:
            protocol = "hy2"
            part = f'hy2://{cleaned_profile_string.split("hy2://")[1]}'
            if "@" in part and ":" in part[6:]:
                profile_to_add = {'profile': part.strip(), 'score': item['score']}

        elif "tuic://" in cleaned_profile_string:
            protocol = "tuic"
            part = f'tuic://{cleaned_profile_string.split("tuic://")[1]}'
            if ":" in part[7:] and "@" in part:
                profile_to_add = {'profile': part.strip(), 'score': item['score']}

        elif "trojan://" in cleaned_profile_string:
            protocol = "trojan"
            part = f'trojan://{cleaned_profile_string.split("trojan://")[1]}'
            if "@" in part and ":" in part[9:]:
                profile_to_add = {'profile': part.strip(), 'score': item['score']}

        if profile_to_add:
            processed_profiles.append(profile_to_add)

    logging.info(f'Пытаемся удалить поврежденные конфигурации и дубликаты...')

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
        x = re.sub(r'…»$|…$|»$|%$|`$', '', x).strip() # Refactored and more efficient regex for removing trailing chars
        if x[-2:-1] == '%': # Handling double percentage encoding case, after regex cleanup
            x=x[:-2]
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
    return final_profiles_scored

if __name__ == "__main__":
    telegram_channel_names = json_load('telegram_channels.json')
    if telegram_channel_names is None:
        logging.critical("Не удалось загрузить список каналов из telegram_channels.json. Завершение работы.")
        exit(1)

    initial_channels_count = len(telegram_channel_names)
    logging.info(f'Всего имен каналов в telegram_channels.json: {initial_channels_count}')

    current_day = datetime.now().day
    if not (START_DAY_PROFILE_DOWNLOAD <= current_day <= END_DAY_PROFILE_DOWNLOAD):
        logging.info(f"Текущий день месяца ({current_day}) не попадает в заданный период скачивания ({START_DAY_PROFILE_DOWNLOAD}-{END_DAY_PROFILE_DOWNLOAD}). Парсинг профилей отменен.")
        logging.info(f'Завершено!')
        exit()

    logging.info(f'Начинаем парсинг...')
    start_time = datetime.now()

    thread_semaphore = threading.Semaphore(MAX_THREADS_PARSING)
    parsed_profiles = []
    channels_with_profiles = set()
    channels_parsed_count = len(telegram_channel_names)

    logging.info(f'Начинаем парсинг {channels_parsed_count} телеграм каналов из telegram_channels.json...')

    threads = []
    for channel_name in telegram_channel_names:
        thread = threading.Thread(target=process_channel, args=(channel_name, parsed_profiles, thread_semaphore, telegram_channel_names, channels_parsed_count, channels_with_profiles))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    logging.info(f'Парсинг завершен - {str(datetime.now() - start_time).split(".")[0]}')
    logging.info(f'Начинаем обработку и фильтрацию спарсенных конфигов...')

    final_profiles_scored = process_parsed_profiles(parsed_profiles)

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
    logging.info(f'Начальное количество каналов в telegram_channels.json: {initial_channels_count}')
    logging.info(f'Каналов обработано: {channels_parsed_count}')
    logging.info(f'Каналов, в которых найдены профили: {len(channels_with_profiles)}')
    logging.info(f'Профилей найдено во время парсинга (до обработки): {len(parsed_profiles)}')
    logging.info(f'Уникальных профилей после обработки и фильтрации: {len(final_profiles_scored)}')
    logging.info(f'Профилей сохранено в config-tg.txt: {len(profiles_to_save)}')
    logging.info(f'{"-"*40}')
    logging.info('Завершено!')
