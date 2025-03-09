import requests
import threading
import json
import os
import time
import random
import re
import urllib.parse as urllib_parse
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone
import logging
import asyncio
import ip2location
import asyncio.exceptions
import zipfile
from typing import Dict

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
MAX_FAILED_CHECKS = 4 # Максимальное количество неудачных проверок перед удалением канала
FAILURE_HISTORY_FILE = 'channel_failure_history.json' # Файл для хранения истории неудач
NO_MORE_PAGES_HISTORY_FILE = 'no_more_pages_history.json' # Файл для хранения истории "Больше страниц не найдено"
MAX_NO_MORE_PAGES_COUNT = 4 # Максимальное количество "Больше страниц не найдено" подряд перед удалением канала
PROFILE_FRESHNESS_DAYS = 7 # Период свежести профилей в днях (от момента запуска скрипта)

IP2LOCATION_DB_URL = "https://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.BIN.ZIP" # URL для скачивания IP2Location LITE DB1
IP2LOCATION_DB_PATH = "IP2LOCATION-LITE-DB1.BIN" # Путь к файлу базы данных IP2Location
COUNTRY_CODE_TO_FLAG_EMOJI: Dict[str, str] = { # Словарь соответствия кодов стран и эмодзи флагов (ISO 3166-1 alpha-2)
    "US": "🇺🇸", "DE": "🇩🇪", "GB": "🇬🇧", "FR": "🇫🇷", "JP": "🇯🇵",
    "CN": "🇨🇳", "RU": "🇷🇺", "KR": "🇰🇷", "SG": "🇸🇬", "CA": "🇨🇦",
    "AU": "🇦🇺", "IN": "🇮🇳", "BR": "🇧🇷", "CH": "🇨🇭", "SE": "🇸🇪",
    "NL": "🇳🇱", "ES": "🇪🇸", "IT": "🇮🇹", "BE": "🇧🇪", "HK": "🇭🇰",
    "TR": "🇹🇷", "UA": "🇺🇦", "VN": "🇻🇳", "PL": "🇵🇱", "AR": "🇦🇷",
    "MX": "🇲🇽", "ID": "🇮🇩", "MY": "🇲🇾", "PH": "🇵🇭", "TH": "🇹🇭",
    "ZA": "🇿🇦", "AE": "🇦🇪", "PT": "🇵🇹", "IE": "🇮🇪", "CL": "🇨🇱",
    "CO": "🇨🇴", "SA": "🇸🇦", "NZ": "🇳🇿", "CZ": "🇨🇿", "GR": "🇬🇷",
    "RO": "🇷🇴", "IL": "🇮🇱", "EG": "🇪🇬", "NG": "🇳🇬", "KE": "🇰🇪",
    "PK": "🇵🇰", "BD": "🇧🇩", "LK": "🇱🇰", "IR": "🇮🇷", "IQ": "🇮🇶",
    "SY": "🇸🇾", "JO": "🇯🇴", "KW": "🇰🇼", "QA": "🇶🇦", "BH": "🇧🇭",
    "OM": "🇴🇲", "LB": "🇱🇧", "CY": "🇨🇾", "GLOBAL": "🌐", "UNKNOWN": "🤔" # Default flags
}
DEFAULT_FLAG_EMOJI = COUNTRY_CODE_TO_FLAG_EMOJI["GLOBAL"] # Emoji for unknown country
UNKNOWN_FLAG_EMOJI = COUNTRY_CODE_TO_FLAG_EMOJI["UNKNOWN"] # Emoji for when country can't be determined

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

def json_save(data, path):
    """Сохраняет данные в JSON файл."""
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        return True
    except Exception as e:
        logging.error(f"Ошибка при сохранении JSON в файл {path}: {e}")
        return False

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

async def get_country_flag_emoji(ip_address: str, db_path: str) -> str:
    """
    Асинхронно определяет страну по IP-адресу и возвращает эмодзи флага.

    Аргументы:
        ip_address: IP-адрес сервера.
        db_path: Путь к базе данных IP2Location.

    Возвращает:
        str: Эмодзи флага страны или DEFAULT_FLAG_EMOJI, если страна не определена или произошла ошибка.
    """
    try:
        IP2LocObj = ip2location.IP2Location(db_path) # type: ignore

        def blocking_lookup(): # Функция для блокирующего вызова в отдельном потоке
            try:
                rec = IP2LocObj.get_country_short(ip_address)
                if rec and rec != '??': # rec может быть None или '??' в случае ошибки
                    return rec
            except ip2location.IP2LocationError as e: # type: ignore
                logging.warning(f"Ошибка IP2Location для IP '{ip_address}': {e}")
            return None # Возвращаем None в случае ошибки или '??'

        country_code = await asyncio.to_thread(blocking_lookup) # Запускаем блокирующий вызов в пуле потоков

        if country_code and country_code in COUNTRY_CODE_TO_FLAG_EMOJI:
            return COUNTRY_CODE_TO_FLAG_EMOJI[country_code]
        else:
            return DEFAULT_FLAG_EMOJI # Используем default flag если код страны не найден в словаре или lookup вернул None

    except Exception as e: # Ловим любые ошибки, включая отсутствие файла базы данных, ошибки открытия и т.д.
        logging.error(f"Критическая ошибка при определении страны для IP '{ip_address}': {e}")
        return UNKNOWN_FLAG_EMOJI # Используем unknown flag emoji в случае крит. ошибки

async def process_channel(channel_url, parsed_profiles, thread_semaphore, telegram_channel_names, channels_parsed_count, channels_with_profiles, channel_failure_counts, channels_to_remove, no_more_pages_counts, ip2location_db_path):
    """
    Обрабатывает один телеграм канал для извлечения профилей.

    Скачивает несколько страниц сообщений канала, ищет блоки кода с профилями,
    рассчитывает скор для каждого профиля и добавляет в общий список.
    Если после проверки не найдено профилей, увеличивает счетчик неудачных проверок
    и, при достижении лимита, добавляет канал в список на удаление.
    Также отслеживает случаи "Больше страниц не найдено" для удаления неактивных каналов.

    Аргументы:
        channel_url (str): URL канала Telegram (без 'https://t.me/s/').
        parsed_profiles (list): Общий список для хранения найденных профилей.
        thread_semaphore (threading.Semaphore): Семафор для контроля количества потоков.
        telegram_channel_names (list): Список имен телеграм каналов.
        channels_parsed_count (int): Общее количество каналов для парсинга (используется для логирования).
        channels_with_profiles (set): Множество для отслеживания каналов, в которых найдены профили.
        channel_failure_counts (dict): Словарь для хранения счетчиков неудачных проверок каналов.
        channels_to_remove (list): Список каналов для удаления.
        no_more_pages_counts (dict): Словарь для хранения счетчиков "Больше страниц не найдено" для каналов.
        ip2location_db_path (str): Путь к базе данных IP2Location.
    """
    thread_semaphore.acquire()
    channel_removed_in_run = False # Флаг, чтобы избежать двойного добавления в channels_to_remove за один проход
    try:
        html_pages = []
        current_url = channel_url
        channel_profiles = []
        god_tg_name = False
        htmltag_pattern = re.compile(r'<.*?>')
        pattern_datbef = re.compile(r'(?:data-before=")(\d*)')
        no_more_pages_in_run = False # Флаг, чтобы отслеживать "Больше страниц не найдено" в текущем проходе
        country_flag_emoji_tasks = [] # Список для хранения асинхронных задач определения страны

        for attempt in range(2):
            while True:
                try:
                    response = requests.get(f'https://t.me/s/{current_url}', timeout=REQUEST_TIMEOUT)
                    response.raise_for_status()
                    html_pages.append(response.text)
                    last_datbef = re.findall(pattern_datbef, response.text)
                    if not last_datbef:
                        logging.info(f"Больше страниц не найдено для {channel_url}")
                        no_more_pages_in_run = True # Устанавливаем флаг, если страниц больше нет
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
            failed_check = True # Считаем как неудачная проверка из-за проблем с загрузкой
        else:
            failed_check = False # Считаем как успешная загрузка страниц (даже если профилей не нашлось)


        channel_index = telegram_channel_names.index(channel_url) + 1
        logging.info(f'{channel_index} из {channels_parsed_count} - {channel_url}')

        if not failed_check: # Продолжаем парсинг, только если загрузка страниц прошла успешно
            for page in html_pages:
                soup = BeautifulSoup(page, 'html.parser')
                message_blocks = soup.find_all('div', class_='tgme_widget_message') # Находим блоки сообщений
                for message_block in message_blocks: # Итерируемся по блокам сообщений
                    code_tags = message_block.find_all(class_='tgme_widget_message_text') # Ищем code_tags внутри блока сообщения
                    time_tag = message_block.find('time', class_='datetime') # Ищем time_tag внутри блока сообщения
                    message_datetime = None
                    if time_tag and 'datetime' in time_tag.attrs:
                        try:
                            message_datetime = datetime.fromisoformat(time_tag['datetime']).replace(tzinfo=timezone.utc) # Добавляем timezone awareness
                        except ValueError:
                            logging.warning(f"Не удалось распарсить дату из time tag: {time_tag['datetime']}")

                    for code_tag in code_tags:
                        code_content_lines = str(code_tag).split('<br/>')
                        for line in code_content_lines:
                            cleaned_content = re.sub(htmltag_pattern, '', line).strip()
                            for protocol in ALLOWED_PROTOCOLS:
                                if f"{protocol}://" in cleaned_content:
                                    profile_link = cleaned_content
                                    score = calculate_profile_score(profile_link)
                                    host_match = re.search(r"@([\w\.\-]+):", profile_link) # Extract host before port
                                    ip_address = host_match.group(1) if host_match else None # Get IP address
                                    country_flag_emoji_task = asyncio.create_task(get_country_flag_emoji(ip_address, ip2location_db_path)) if ip_address else asyncio.Future() # Start async task, or create a dummy future if no IP
                                    if not ip_address:
                                        country_flag_emoji_task.set_result(DEFAULT_FLAG_EMOJI) # If no IP, set default emoji immediately
                                    country_flag_emoji_tasks.append(country_flag_emoji_task) # Add task to list
                                    channel_profiles.append({'profile': profile_link, 'score': score, 'date': message_datetime, 'country_flag_emoji_task': country_flag_emoji_task}) # Сохраняем задачу

                                    god_tg_name = True
                                    break

        if god_tg_name:
            channels_with_profiles.add(channel_url)
            channel_failure_counts[channel_url] = 0 # Сброс счетчика неудач, если профили найдены
            no_more_pages_counts[channel_url] = 0 # Сброс счетчика "Больше страниц не найдено", если профили найдены
        else:
            if channel_url in channel_failure_counts:
                channel_failure_counts[channel_url] += 1
            else:
                channel_failure_counts[channel_url] = 1

            if channel_failure_counts[channel_url] >= MAX_FAILED_CHECKS and channel_url not in channels_to_remove:
                channels_to_remove.append(channel_url)
                channel_removed_in_run = True # Помечаем, что канал был добавлен на удаление в этом проходе
                logging.info(f"Канал '{channel_url}' будет удален из списка за {MAX_FAILED_CHECKS} последовательных неудачных проверок.")
            elif not god_tg_name and not channel_removed_in_run: # Чтобы не было лишнего лога, если канал уже удален в этом проходе
                logging.info(f"Профили не найдены в канале {channel_url}. Неудачных проверок подряд: {channel_failure_counts[channel_url]}/{MAX_FAILED_CHECKS}.")
            elif channel_removed_in_run: # Лог для случая, когда канал удален
                pass # Уже залогировано выше

        if no_more_pages_in_run: # Проверяем флаг "Больше страниц не найдено"
            if channel_url in no_more_pages_counts:
                no_more_pages_counts[channel_url] += 1
            else:
                no_more_pages_counts[channel_url] = 1

            if no_more_pages_counts[channel_url] >= MAX_NO_MORE_PAGES_COUNT and channel_url not in channels_to_remove:
                channels_to_remove.append(channel_url)
                channel_removed_in_run = True # Помечаем, что канал был добавлен на удаление в этом проходе
                logging.info(f"Канал '{channel_url}' будет удален из списка за {MAX_NO_MORE_PAGES_COUNT} последовательных сообщений 'Больше страниц не найдено'. Канал вероятно неактивен.")
            elif no_more_pages_in_run and not channel_removed_in_run:
                 logging.info(f"Для канала '{channel_url}' зафиксировано сообщение 'Больше страниц не найдено'. Сообщений подряд: {no_more_pages_counts[channel_url]}/{MAX_NO_MORE_PAGES_COUNT}.")
            elif channel_removed_in_run:
                pass # Уже залогировано выше

        parsed_profiles.extend(channel_profiles)

    except Exception as channel_exception:
        logging.error(f"Критическая ошибка при обработке канала {channel_url}: {channel_exception}")
    finally:
        thread_semaphore.release()

def clean_profile(profile_string):
    """Очищает строку профиля от лишних символов и артефактов."""
    part = profile_string
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

async def process_parsed_profiles(parsed_profiles_list):
    """
    Обрабатывает список спарсенных профилей: очистка, фильтрация по протоколам,
    удаление дубликатов и подстрок, фильтрация по свежести, итоговая сортировка.

    Аргументы:
        parsed_profiles_list (list): Список словарей с профилями и их скорами и датами.

    Возвращает:
        list: Список обработанных и отсортированных профилей (словари).
    """
    processed_profiles = []
    country_flag_emojis = await asyncio.gather(*(item['country_flag_emoji_task'] for item in parsed_profiles_list if 'country_flag_emoji_task' in item), return_exceptions=True) # Получаем результаты асинхронных задач

    for index, item in enumerate(parsed_profiles_list):
        cleaned_profile_string = clean_profile(item['profile'])
        protocol = ""
        profile_to_add = None

        country_flag_emoji = None # Default value if no task or error
        if 'country_flag_emoji_task' in item:
            emoji_result = country_flag_emojis[index] # Get corresponding emoji result
            if isinstance(emoji_result, Exception): # Handle exceptions from tasks
                logging.warning(f"Ошибка при получении флага страны для профиля '{item['profile'][:50]}...': {emoji_result}")
                country_flag_emoji = UNKNOWN_FLAG_EMOJI # Use unknown flag emoji on error
            else:
                country_flag_emoji = emoji_result
        else:
            country_flag_emoji = DEFAULT_FLAG_EMOJI # Default if no country task

        port_match = re.search(r":(\d+)", cleaned_profile_string) # Find port number
        port = port_match.group(1) if port_match else "unknown_port" # Extract port or use "unknown_port"

        if "vless://" in cleaned_profile_string:
            protocol = "vless"
            part = f'vless://{cleaned_profile_string.split("vless://")[1]}'
            if "flow=xtls-rprx-direct" not in part and "@" in part and ":" in part[8:]:
                profile_to_add = {'profile': part.strip(), 'score': item['score'], 'date': item['date'], 'country_flag_emoji': country_flag_emoji, 'profile_name': f"{protocol}-{port}-{country_flag_emoji}"} # Add flag emoji and profile name

        elif "hy2://" in cleaned_profile_string:
            protocol = "hy2"
            part = f'hy2://{cleaned_profile_string.split("hy2://")[1]}'
            if "@" in part and ":" in part[6:]:
                profile_to_add = {'profile': part.strip(), 'score': item['score'], 'date': item['date'], 'country_flag_emoji': country_flag_emoji, 'profile_name': f"{protocol}-{port}-{country_flag_emoji}"} # Add flag emoji and profile name

        elif "tuic://" in cleaned_profile_string:
            protocol = "tuic"
            part = f'tuic://{cleaned_profile_string.split("tuic://")[1]}'
            if ":" in part[7:] and "@" in part:
                profile_to_add = {'profile': part.strip(), 'score': item['score'], 'date': item['date'], 'country_flag_emoji': country_flag_emoji, 'profile_name': f"{protocol}-{port}-{country_flag_emoji}"} # Add flag emoji and profile name

        elif "trojan://" in cleaned_profile_string:
            protocol = "trojan"
            part = f'trojan://{cleaned_profile_string.split("trojan://")[1]}'
            if "@" in part and ":" in part[9:]:
                profile_to_add = {'profile': part.strip(), 'score': item['score'], 'date': item['date'], 'country_flag_emoji': country_flag_emoji, 'profile_name': f"{protocol}-{port}-{country_flag_emoji}"} # Add flag emoji and profile name

        if profile_to_add:
            processed_profiles.append(profile_to_add)

    logging.info(f'Пытаемся удалить поврежденные конфигурации, дубликаты и фильтровать по свежести...')

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
        x = re.sub(r'…»$|…$|»$|%$|`$', '', x).strip()
        if x[-2:-1] == '%':
            x=x[:-2]
        new_processed_profiles_scored.append({'profile': x.strip(), 'score': profile_data['score'], 'date': profile_data['date'], 'country_flag_emoji': profile_data['country_flag_emoji'], 'profile_name': profile_data['profile_name']}) # Keep profile name and flag emoji

    processed_profiles_scored = new_processed_profiles_scored

    processed_profiles_strings = [item['profile'] for item in processed_profiles_scored]
    processed_profiles_strings = substring_del(processed_profiles_strings)

    final_profiles_scored = []
    profile_strings_set = set(processed_profiles_strings)
    for profile_data in processed_profiles_scored:
        if profile_data['profile'] in profile_strings_set:
            final_profiles_scored.append(profile_data)
            profile_strings_set.remove(profile_data['profile'])

    # --- Фильтрация по свежести ---
    fresh_profiles_scored = []
    now = datetime.now(tz=timezone.utc) # Timezone aware current datetime
    for profile_data in final_profiles_scored:
        if 'date' in profile_data and isinstance(profile_data['date'], datetime):
            time_difference = now - profile_data['date']
            if time_difference <= timedelta(days=PROFILE_FRESHNESS_DAYS):
                fresh_profiles_scored.append(profile_data)
            else:
                logging.info(f"Удален устаревший профиль (старше {PROFILE_FRESHNESS_DAYS} дней): дата {profile_data['date'].strftime('%Y-%m-%d %H:%M:%S UTC')}, профиль: {profile_data['profile'][:100]}...") # Лог об удалении
        else:
            fresh_profiles_scored.append(profile_data) # Оставляем профили без даты (если не удалось извлечь) и логируем это, чтобы не потерять их полностью, но можно пересмотреть это решение

    final_profiles_scored = fresh_profiles_scored
    logging.info(f"После фильтрации по свежести осталось {len(final_profiles_scored)} профилей.") # Лог о количестве профилей после фильтрации

    final_profiles_scored.sort(key=lambda item: item['score'], reverse=True)
    return final_profiles_scored

def load_failure_history():
    """Загружает историю неудачных проверок каналов из файла."""
    history = json_load(FAILURE_HISTORY_FILE)
    return history if history else {}

def save_failure_history(history):
    """Сохраняет историю неудачных проверок каналов в файл."""
    return json_save(history, FAILURE_HISTORY_FILE)

def load_no_more_pages_history():
    """Загружает историю 'Больше страниц не найдено' для каналов из файла."""
    history = json_load(NO_MORE_PAGES_HISTORY_FILE)
    return history if history else {}

def save_no_more_pages_history(history):
    """Сохраняет историю 'Больше страниц не найдено' для каналов в файл."""
    return json_save(history, NO_MORE_PAGES_HISTORY_FILE)

def download_ip2location_db(db_url, db_path):
    """
    Загружает базу данных IP2Location LITE DB1.

    Аргументы:
        db_url: URL для скачивания ZIP-архива базы данных.
        db_path: Путь для сохранения извлеченного файла базы данных (BIN).
    """
    logging.info(f"Загрузка базы данных IP2Location...")
    try:
        response = requests.get(db_url, stream=True, timeout=30) # Увеличиваем таймаут для скачивания
        response.raise_for_status() # Проверка на ошибки HTTP

        zip_path = "ip2location_temp.zip" # Временный файл для ZIP архива
        with open(zip_path, "wb") as zip_file:
            for chunk in response.iter_content(chunk_size=8192): # Скачиваем по частям
                zip_file.write(chunk)

        with zipfile.ZipFile(zip_path, 'r') as zip_ref: # Открываем ZIP архив
            for filename in zip_ref.namelist(): # Ищем BIN файл в архиве (может быть в подпапке)
                if filename.upper().endswith(".BIN"):
                    zip_ref.extract(filename, ".") # Извлекаем в текущую директорию
                    extracted_path = filename # Путь к извлеченному файлу
                    os.rename(extracted_path, db_path) # Переименовываем в db_path
                    break # Нашли и извлекли, выходим из цикла
            else: # for...else, выполнится если BIN файл не найден в архиве
                raise FileNotFoundError("BIN файл не найден в ZIP архиве.")

        os.remove(zip_path) # Удаляем временный ZIP файл
        logging.info(f"База данных IP2Location успешно загружена и сохранена в '{db_path}'.")

    except requests.exceptions.RequestException as e:
        logging.error(f"Ошибка при скачивании базы данных IP2Location: {e}")
    except zipfile.BadZipFile:
        logging.error(f"Ошибка: Поврежденный ZIP архив базы данных IP2Location.")
        if os.path.exists(zip_path): # Пытаемся удалить поврежденный zip, если он есть
            os.remove(zip_path)
    except FileNotFoundError as e:
        logging.error(f"Ошибка: {e}")
    except Exception as e: # Ловим все остальные исключения
        logging.error(f"Непредвиденная ошибка при загрузке и обработке базы данных IP2Location: {e}")


if __name__ == "__main__":
    if not os.path.exists(IP2LOCATION_DB_PATH): # Проверяем наличие базы данных IP2Location
        download_ip2location_db(IP2LOCATION_DB_URL, IP2LOCATION_DB_PATH) # Скачиваем, если нет

    telegram_channel_names_original = json_load('telegram_channels.json') # Загружаем оригинальный список, чтобы не менять его во время итерации
    if telegram_channel_names_original is None:
        logging.critical("Не удалось загрузить список каналов из telegram_channels.json. Завершение работы.")
        exit(1)

    # Фильтрация и удаление каналов с некорректными именами до начала обработки
    telegram_channel_names_original[:] = [x for x in telegram_channel_names_original if len(x) >= 5] # Убедимся, что имена каналов валидны после загрузки
    telegram_channel_names_original = list(set(telegram_channel_names_original)) # Удаляем дубликаты
    telegram_channel_names_original.sort() # Сортируем каналы

    initial_channels_count = len(telegram_channel_names_original)
    logging.info(f'Начальное количество каналов в telegram_channels.json: {initial_channels_count}')

    channel_failure_counts = load_failure_history() # Загрузка истории неудач
    no_more_pages_counts = load_no_more_pages_history() # Загрузка истории "Больше страниц не найдено"
    channels_to_remove = [] # Список каналов на удаление в этом прогоне

    # Создаем копию списка каналов для итерации, чтобы можно было удалять из оригинала
    telegram_channel_names_to_parse = list(telegram_channel_names_original) # Работаем с копией списка каналов
    channels_parsed_count = len(telegram_channel_names_to_parse)

    logging.info(f'Начинаем парсинг...')
    start_time = datetime.now()

    thread_semaphore = threading.Semaphore(MAX_THREADS_PARSING)
    parsed_profiles = []
    channels_with_profiles = set()

    logging.info(f'Начинаем парсинг {channels_parsed_count} телеграм каналов из telegram_channels.json...')

    async def main(): # Определяем асинхронную функцию main
        threads = []
        for channel_name in telegram_channel_names_to_parse: # Итерируемся по копии списка
            thread = threading.Thread(target=lambda ch_name=channel_name: asyncio.run(process_channel(ch_name, parsed_profiles, thread_semaphore, telegram_channel_names_original, channels_parsed_count, channels_with_profiles, channel_failure_counts, channels_to_remove, no_more_pages_counts, IP2LOCATION_DB_PATH))) # Запускаем асинхронную функцию process_channel в отдельном потоке
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        logging.info(f'Парсинг завершен - {str(datetime.now() - start_time).split(".")[0]}')
        logging.info(f'Начинаем обработку и фильтрацию спарсенных конфигов...')

        final_profiles_scored = await process_parsed_profiles(parsed_profiles) # process_parsed_profiles теперь фильтрует по свежести и асинхронная

        num_profiles_to_save = min(max(len(final_profiles_scored), MIN_PROFILES_TO_DOWNLOAD), MAX_PROFILES_TO_DOWNLOAD)
        profiles_to_save = final_profiles_scored[:num_profiles_to_save]

        with open("config-tg.txt", "w", encoding="utf-8") as file:
            for profile_data in profiles_to_save:
                file.write(f"{profile_data['profile_name']} - {profile_data['profile'].encode('utf-8').decode('utf-8')}\n") # Save profile name and profile

        # Удаление каналов из telegram_channel_names_original и сохранение в файл
        if channels_to_remove:
            logging.info(f"Удаляем каналы: {channels_to_remove}")
            telegram_channel_names_updated = [chan for chan in telegram_channel_names_original if chan not in channels_to_remove]
            if telegram_channel_names_updated != telegram_channel_names_original: # Проверка на изменения перед сохранением
                json_save(telegram_channel_names_updated, 'telegram_channels.json')
                logging.info(f"Обновленный список каналов сохранен в telegram_channels.json. Удалено каналов: {len(channels_to_remove)}.")
            else:
                logging.info("Список каналов в telegram_channels.json не изменился (удаление не потребовалось).")
        else:
            logging.info("Нет каналов для удаления.")

        save_failure_history(channel_failure_counts) # Сохранение истории неудач
        save_no_more_pages_history(no_more_pages_counts) # Сохранение истории "Больше страниц не найдено"

    asyncio.run(main()) # Запускаем асинхронную функцию main

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
    logging.info(f'Уникальных профилей после обработки и фильтрации: {len(final_profiles_scored)}') # Количество уникальных профилей уже после фильтрации по свежести
    logging.info(f'Профилей сохранено в config-tg.txt: {len(profiles_to_save)}')
    if channels_to_remove:
        logging.info(f'Каналов удалено из списка: {len(channels_to_remove)}')
    else:
        logging.info(f'Каналов удалено из списка: 0')
    logging.info(f'{"-"*40}')
    logging.info('Завершено!')
