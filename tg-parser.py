import aiohttp
import asyncio
import json
import os
import time
import random
import re
import urllib.parse as urllib_parse
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone
import logging
import tempfile
import shutil
from typing import Dict, List, Set, Optional

# --- Настройка логирования ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
# --- Конец настройки логирования ---

# Отключаем warnings для InsecureRequestWarning (так как verify=False)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Глобальные константы ---
MAX_THREADS_PARSING = 100
REQUEST_TIMEOUT_AIOHTTP = 30
MIN_PROFILES_TO_DOWNLOAD = 1
MAX_PROFILES_TO_DOWNLOAD = 9000
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
MAX_FAILED_CHECKS = 4  # Максимальное количество неудачных проверок перед удалением канала
FAILURE_HISTORY_FILE = 'channel_failure_history.json'  # Файл для хранения истории неудач
NO_MORE_PAGES_HISTORY_FILE = 'no_more_pages_history.json'  # Файл для хранения истории "Больше страниц не найдено"
MAX_NO_MORE_PAGES_COUNT = 4  # Максимальное количество "Больше страниц не найдено" подряд перед удалением канала
PROFILE_FRESHNESS_DAYS = 3  # Период свежести профилей в днях (от момента запуска скрипта)

CONFIG_FILE = 'config.json' # Файл конфигурации
PROFILE_CLEANING_RULES_DEFAULT = [ # Правила очистки профилей по умолчанию
    '%0A', '%250A', '%0D', 'amp;', '�', 'fp=(firefox|safari|edge|360|qq|ios|android|randomized|random)'
]
PROFILE_CLEANING_RULES = PROFILE_CLEANING_RULES_DEFAULT

# --- Эмодзи для протоколов ---
VLESS_EMOJI = "🌠"
HY2_EMOJI = "⚡"
TUIC_EMOJI = "🚀"
TROJAN_EMOJI = "🛡️"
# --- Конец глобальных констант ---

if not os.path.exists('config-tg.txt'):
    with open('config-tg.txt', 'w'): pass

def json_load(path: str) -> Optional[dict]:
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
    except json.JSONDecodeError as e:
        logging.error(f"Ошибка декодирования JSON в файле: {path} - {e}. Возвращаем None.")
        return None

def json_save(data: dict, path: str, indent: int = 4, backup: bool = True) -> bool:
    """Сохраняет данные в JSON файл с атомарным сохранением и опциональным резервным копированием."""
    try:
        if backup and os.path.exists(path):
            backup_path = path + '.bak'
            shutil.copy2(path, backup_path) # copy2 сохраняет метаданные

        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False) as tmp_file:
            json.dump(data, tmp_file, ensure_ascii=False, indent=indent)
        temp_filepath = tmp_file.name
        os.replace(temp_filepath, path) # Атомарное перемещение из временного в целевой файл
        return True
    except Exception as e:
        logging.error(f"Ошибка при сохранении JSON в файл {path}: {e}")
        return False

def filter_out_substrings(string_list: List[str]) -> List[str]:
    """
    Удаляет подстроки из списка строк.
    Переименовано из substring_del для большей понятности.
    """
    string_list.sort(key=len)
    strings_to_remove = set()
    for i in range(len(string_list)):
        for j in range(i + 1, len(string_list)):
            if string_list[i] in string_list[j]:
                strings_to_remove.add(string_list[i])
                break
    return [s for s in string_list if s not in strings_to_remove]

def calculate_profile_score(profile: str) -> int:
    """
    Вычисляет скор профиля на основе параметров конфигурации.
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

async def fetch_channel_page_async(session: aiohttp.ClientSession, channel_url: str, attempt: int) -> Optional[str]:
    """Асинхронно загружает страницу канала с обработкой ошибок и повторными попытками."""
    for attempt_num in range(attempt, 3): # Увеличим количество попыток до 3 для примера
        try:
            async with session.get(f'https://t.me/s/{channel_url}', timeout=REQUEST_TIMEOUT_AIOHTTP, ssl=False) as response: # ssl=False для обхода InsecureRequestWarning
                response.raise_for_status()
                return await response.text()
        except aiohttp.ClientError as e: # Ловим более общие ошибки aiohttp
            log_message = f"Ошибка aiohttp при запросе к {channel_url}: {e}, попытка {attempt_num + 1}/3"
            if attempt_num < 2:
                delay = (2**attempt_num) + random.random() # Экспоненциальная задержка + джиттер
                log_message += f". Повторная попытка через {delay:.2f} секунд."
                await asyncio.sleep(delay)
            logging.warning(log_message)
            if attempt_num >= 2:
                logging.error(f"Превышено количество попыток (3) для {channel_url} из-за ошибок запроса aiohttp.")
                return None # Возвращаем None, если не удалось загрузить страницу
        except asyncio.TimeoutError:
            log_message = f"Таймаут aiohttp при запросе к {channel_url}, попытка {attempt_num + 1}/3"
            if attempt_num < 2:
                delay = (2**attempt_num) + random.random() # Экспоненциальная задержка + джиттер
                log_message += f". Повторная попытка через {delay:.2f} секунд."
                await asyncio.sleep(delay)
            logging.warning(log_message)
            if attempt_num >= 2:
                logging.error(f"Превышено количество попыток (3) для {channel_url} из-за таймаутов aiohttp.")
                return None # Возвращаем None, если не удалось загрузить страницу
    return None # Если все попытки неудачны

async def parse_profiles_from_page_async(html_page: str, channel_url: str, allowed_protocols: Set[str], profile_score_func) -> List[Dict]:
    """Асинхронно парсит профили из HTML страницы."""
    channel_profiles = []
    soup = BeautifulSoup(html_page, 'html.parser')
    message_blocks = soup.find_all('div', class_='tgme_widget_message')
    htmltag_pattern = re.compile(r'<.*?>')

    for message_block in message_blocks:
        code_tags = message_block.find_all(class_='tgme_widget_message_text')
        time_tag = message_block.find('time', class_='datetime')
        message_datetime = None
        if time_tag and 'datetime' in time_tag.attrs:
            try:
                message_datetime = datetime.fromisoformat(time_tag['datetime']).replace(tzinfo=timezone.utc)
            except ValueError:
                logging.warning(f"Не удалось распарсить дату из time tag для канала {channel_url}: {time_tag['datetime']}")

        for code_tag in code_tags:
            code_content_lines = str(code_tag).split('<br/>')
            for line in code_content_lines:
                cleaned_content = re.sub(htmltag_pattern, '', line).strip()
                for protocol in allowed_protocols:
                    if f"{protocol}://" in cleaned_content:
                        profile_link = cleaned_content
                        score = profile_score_func(profile_link) # Используем переданную функцию для скоринга
                        channel_profiles.append({'profile': profile_link, 'score': score, 'date': message_datetime})
    return channel_profiles

async def process_channel_async(channel_url: str, parsed_profiles: List[Dict], thread_semaphore: asyncio.Semaphore, telegram_channel_names: List[str], channels_parsed_count: int, channels_with_profiles: Set[str], channel_failure_counts: Dict[str, int], channels_to_remove: List[str], no_more_pages_counts: Dict[str, int], allowed_protocols: Set[str], profile_score_func) -> None:
    """Асинхронно обрабатывает один телеграм канал для извлечения профилей."""
    failed_check = False # Инициализация переменной failed_check
    channel_removed_in_run = False # Флаг, чтобы избежать двойного добавления в channels_to_remove за один проход
    async with thread_semaphore: # Используем асинхронный семафор
        try:
            html_pages = []
            current_url = channel_url
            channel_profiles = []
            god_tg_name = False
            pattern_datbef = re.compile(r'(?:data-before=")(\d*)')
            no_more_pages_in_run = False


            async with aiohttp.ClientSession() as session: # Создаем асинхронную сессию aiohttp
                for attempt in range(2): # Оставляем 2 попытки на загрузку страниц
                    while True:
                        html_page = await fetch_channel_page_async(session, current_url, attempt + 1) # Асинхронная загрузка страницы
                        if html_page:
                            html_pages.append(html_page)
                            last_datbef = re.findall(pattern_datbef, html_page)
                            if not last_datbef:
                                logging.info(f"Больше страниц не найдено для {channel_url}")
                                no_more_pages_in_run = True
                                break
                            current_url = f'{channel_url}?before={last_datbef[0]}'
                            break
                        else:
                            failed_check = True # Если fetch_channel_page_async вернул None, считаем неудачной проверкой
                            break # Выходим из внутреннего цикла while True, так как не удалось загрузить страницу

                    if failed_check: # Если не удалось загрузить страницы, выходим из внешнего цикла for attempt
                        break

                if not html_pages:
                    logging.warning(f"Не удалось загрузить страницы для канала {channel_url} после нескольких попыток. Пропускаем канал.")
                    failed_check = True
                else:
                    failed_check = False

                channel_index = telegram_channel_names.index(channel_url) + 1
                logging.info(f'{channel_index} из {channels_parsed_count} - {channel_url}')

                if not failed_check:
                    for page in html_pages:
                        profiles_on_page = await parse_profiles_from_page_async(page, channel_url, allowed_protocols, profile_score_func) # Асинхронный парсинг профилей
                        channel_profiles.extend(profiles_on_page)

            if channel_profiles:
                channels_with_profiles.add(channel_url)
                channel_failure_counts[channel_url] = 0  # Сброс счетчика неудач, если профили найдены
                no_more_pages_counts[channel_url] = 0  # Сброс счетчика "Больше страниц не найдено", если профили найдены
                god_tg_name = True # Профили найдены
            else:
                god_tg_name = False # Профили не найдены

            if god_tg_name:
                pass # Уже обработано выше
            else:
                if channel_url in channel_failure_counts:
                    channel_failure_counts[channel_url] += 1
                else:
                    channel_failure_counts[channel_url] = 1

                if channel_failure_counts[channel_url] >= MAX_FAILED_CHECKS and channel_url not in channels_to_remove:
                    channels_to_remove.append(channel_url)
                    channel_removed_in_run = True
                    logging.info(f"Канал '{channel_url}' будет удален из списка за {MAX_FAILED_CHECKS} последовательных неудачных проверок.")
                elif not god_tg_name and not channel_removed_in_run:
                    logging.info(f"Профили не найдены в канале {channel_url}. Неудачных проверок подряд: {channel_failure_counts[channel_url]}/{MAX_FAILED_CHECKS}.")
                elif channel_removed_in_run:
                    pass

            if no_more_pages_in_run:
                if channel_url in no_more_pages_counts:
                    no_more_pages_counts[channel_url] += 1
                else:
                    no_more_pages_counts[channel_url] = 1

                if no_more_pages_counts[channel_url] >= MAX_NO_MORE_PAGES_COUNT and channel_url not in channels_to_remove:
                    channels_to_remove.append(channel_url)
                    channel_removed_in_run = True
                    logging.info(f"Канал '{channel_url}' будет удален из списка за {MAX_NO_MORE_PAGES_COUNT} последовательных сообщений 'Больше страниц не найдено'. Канал вероятно неактивен.")
                elif no_more_pages_in_run and not channel_removed_in_run:
                    logging.info(f"Для канала '{channel_url}' зафиксировано сообщение 'Больше страниц не найдено'. Сообщений подряд: {no_more_pages_counts[channel_url]}/{MAX_NO_MORE_PAGES_COUNT}.")
                elif channel_removed_in_run:
                    pass

            parsed_profiles.extend(channel_profiles)

        except Exception as channel_exception:
            logging.error(f"Критическая ошибка при обработке канала {channel_url}: {channel_exception}")

def clean_profile(profile_string: str) -> str:
    """Очищает строку профиля от лишних символов и артефактов, используя правила из конфигурации."""
    part = profile_string
    for rule in PROFILE_CLEANING_RULES:
        part = re.sub(rule, '', part, flags=re.IGNORECASE) # Применяем каждое правило из списка
    part = urllib_parse.unquote(urllib_parse.unquote(part)).strip()
    part = re.sub(' ', '', part)
    part = re.sub(r'\x00', '', part)
    part = re.sub(r'\x01', '', part)
    return part

async def process_parsed_profiles_async(parsed_profiles_list: List[Dict]) -> List[Dict]:
    """
    Обрабатывает список спарсенных профилей: очистка, фильтрация по протоколам,
    удаление дубликатов и подстрок, фильтрация по свежести, итоговая сортировка.
    """
    processed_profiles = []

    for item in parsed_profiles_list:
        cleaned_profile_string = clean_profile(item['profile'])
        protocol = ""
        profile_to_add = None

        params_str = cleaned_profile_string.split("://")[1]
        if "@" in params_str:
            params_str = params_str.split("@")[1]
        if "#" in params_str:
            params_str = params_str.split("#")[0]
        params = urllib_parse.parse_qs(params_str)

        security_info = "NoTLS"  # Значение по умолчанию
        if params.get("security", [""])[0] == "tls":
            security_info = "TLS"

        if "vless://" in cleaned_profile_string:
            protocol = "vless"
            part = f'vless://{cleaned_profile_string.split("vless://")[1]}'
            if "flow=xtls-rprx-direct" not in part and "@" in part and ":" in part[8:]:
                profile_to_add = {
                    'profile': part.strip(),
                    'score': item['score'],
                    'date': item['date'],
                    'profile_name': f"{VLESS_EMOJI}{protocol.upper()} ({security_info})"
                }
        elif "hy2://" in cleaned_profile_string:
            protocol = "hy2"
            part = f'hy2://{cleaned_profile_string.split("hy2://")[1]}'
            if "@" in part and ":" in part[6:]:
                profile_to_add = {
                    'profile': part.strip(),
                    'score': item['score'],
                    'date': item['date'],
                    'profile_name': f"{HY2_EMOJI}{protocol.upper()} ({security_info})"
                }
        elif "tuic://" in cleaned_profile_string:
            protocol = "tuic"
            part = f'tuic://{cleaned_profile_string.split("tuic://")[1]}'
            profile_to_add = {
                'profile': part.strip(),
                'score': item['score'],
                'date': item['date'],
                'profile_name': f"{TUIC_EMOJI}{protocol.upper()} (QUIC)"
            }
        elif "trojan://" in cleaned_profile_string:
            protocol = "trojan"
            part = f'trojan://{cleaned_profile_string.split("trojan://")[1]}'
            if "@" in part and ":" in part[9:]:
                profile_to_add = {
                    'profile': part.strip(),
                    'score': item['score'],
                    'date': item['date'],
                    'profile_name': f"{TROJAN_EMOJI}{protocol.upper()} ({security_info})"
                }
        if profile_to_add:
            processed_profiles.append(profile_to_add)

    logging.info(f'Пытаемся удалить поврежденные конфигурации, дубликаты и фильтровать по свежести...')

    unique_profiles_scored = []
    seen_profiles = set()
    for profile_data in processed_profiles:
        profile = profile_data['profile']
        if profile not in seen_profiles and (len(profile) > 13) and (("…" in profile and "#" in profile) or ("…" not in profile)):
            unique_profiles_scored.append(profile_data)
            seen_profiles.add(profile)

    new_processed_profiles_scored = []
    for profile_data in unique_profiles_scored:
        x = profile_data['profile']
        x = re.sub(r'…»$|…$|»$|%$|`$', '', x).strip()
        if x[-2:-1] == '%':
            x = x[:-2]
        new_processed_profiles_scored.append({
            'profile': x.strip(),
            'score': profile_data['score'],
            'date': profile_data['date'],
            'profile_name': profile_data['profile_name']
        })

    processed_profiles_scored = new_processed_profiles_scored
    processed_profiles_strings = [item['profile'] for item in processed_profiles_scored]
    processed_profiles_strings = filter_out_substrings(processed_profiles_strings) # Используем переименованную функцию

    final_profiles_scored = []
    profile_strings_set = set(processed_profiles_strings)
    for profile_data in processed_profiles_scored:
        if profile_data['profile'] in profile_strings_set:
            final_profiles_scored.append(profile_data)
            profile_strings_set.remove(profile_data['profile'])

    # --- Фильтрация по свежести ---
    fresh_profiles_scored = []
    now = datetime.now(tz=timezone.utc)
    for profile_data in final_profiles_scored:
        if 'date' in profile_data and isinstance(profile_data['date'], datetime):
            time_difference = now - profile_data['date']
            if time_difference <= timedelta(days=PROFILE_FRESHNESS_DAYS):
                fresh_profiles_scored.append(profile_data)
            else:
                logging.info(f"Удален устаревший профиль (старше {PROFILE_FRESHNESS_DAYS} дней): дата {profile_data['date'].strftime('%Y-%m-%d %H:%M:%S UTC')}, профиль: {profile_data['profile'][:100]}...")
        else:
            fresh_profiles_scored.append(profile_data)

    final_profiles_scored = fresh_profiles_scored
    logging.info(f"После фильтрации по свежести осталось {len(final_profiles_scored)} профилей.")

    # Исправленная сортировка: если score равен None, используется 0
    final_profiles_scored.sort(key=lambda item: item.get('score') or 0, reverse=True)
    return final_profiles_scored

class ChannelHistoryManager:
    """Менеджер для загрузки и сохранения истории каналов (неудач и 'Больше страниц не найдено')."""
    def __init__(self, failure_file: str = FAILURE_HISTORY_FILE, no_more_pages_file: str = NO_MORE_PAGES_HISTORY_FILE):
        self.failure_file = failure_file
        self.no_more_pages_file = no_more_pages_file

    def _load_json_history(self, filepath: str) -> Dict:
        if not os.path.exists(filepath):
            logging.warning(f"Файл истории '{filepath}' не найден при первом запуске. Создаем пустой файл.")
            if not json_save({}, filepath): # Обработка ошибки создания файла
                logging.error(f"Не удалось создать файл истории: {filepath}")
                return {} # Возвращаем пустой словарь в случае ошибки создания
            return {}
        history = json_load(filepath)
        return history if history else {}

    def _save_json_history(self, history: Dict, filepath: str) -> bool:
        return json_save(history, filepath)

    def load_failure_history(self) -> Dict:
        return self._load_json_history(self.failure_file)

    def save_failure_history(self, history: Dict) -> bool:
        return self._save_json_history(history, self.failure_file)

    def load_no_more_pages_history(self) -> Dict:
        return self._load_json_history(self.no_more_pages_file)

    def save_no_more_pages_history(self, history: Dict) -> bool:
        return self._save_json_history(history, self.no_more_pages_file)

async def load_channels_async(channels_file: str = 'telegram_channels.json') -> List[str]:
    """Загружает список каналов из JSON файла."""
    telegram_channel_names_original = json_load(channels_file)
    if telegram_channel_names_original is None:
        logging.critical(f"Не удалось загрузить список каналов из {channels_file}. Завершение работы.")
        exit(1)
    telegram_channel_names_original[:] = [x for x in telegram_channel_names_original if len(x) >= 5]
    return list(set(telegram_channel_names_original))

async def run_parsing_async(telegram_channel_names_to_parse: List[str], channel_history_manager: ChannelHistoryManager) -> tuple[List[Dict], Set[str], List[str], Dict, Dict]:
    """Запускает асинхронный парсинг каналов."""
    channels_parsed_count = len(telegram_channel_names_to_parse)
    logging.info(f'Начинаем парсинг {channels_parsed_count} телеграм каналов...')

    channel_failure_counts = channel_history_manager.load_failure_history()
    no_more_pages_counts = channel_history_manager.load_no_more_pages_history()
    channels_to_remove = []
    thread_semaphore = asyncio.Semaphore(MAX_THREADS_PARSING)
    parsed_profiles = []
    channels_with_profiles = set()

    tasks = [] # Список асинхронных задач
    for channel_name in telegram_channel_names_to_parse:
        task = asyncio.create_task(
            process_channel_async(channel_name, parsed_profiles, thread_semaphore, telegram_channel_names_to_parse,
                                channels_parsed_count, channels_with_profiles, channel_failure_counts,
                                channels_to_remove, no_more_pages_counts, ALLOWED_PROTOCOLS, calculate_profile_score)
        )
        tasks.append(task)

    await asyncio.gather(*tasks) # Запускаем все задачи параллельно и ждем их завершения

    return parsed_profiles, channels_with_profiles, channels_to_remove, channel_failure_counts, no_more_pages_counts

def save_results(final_profiles_scored: List[Dict], profiles_to_save: List[Dict], channels_to_remove: List[str], telegram_channel_names_original: List[str], channel_history_manager: ChannelHistoryManager, channel_failure_counts: Dict, no_more_pages_counts: Dict) -> None:
    """Сохраняет результаты парсинга: профили, обновленный список каналов, историю."""
    num_profiles_to_save = min(max(len(final_profiles_scored), MIN_PROFILES_TO_DOWNLOAD), MAX_PROFILES_TO_DOWNLOAD)
    profiles_to_save = final_profiles_scored[:num_profiles_to_save]

    with open("config-tg.txt", "w", encoding="utf-8") as file:
        for profile_data in profiles_to_save:
            file.write(f"{profile_data['profile'].encode('utf-8').decode('utf-8')} {profile_data['profile_name']}\n")

    if channels_to_remove:
        logging.info(f"Удаляем каналы: {channels_to_remove}")
        telegram_channel_names_updated = [chan for chan in telegram_channel_names_original if chan not in channels_to_remove]
        if telegram_channel_names_updated != telegram_channel_names_original:
            json_save(telegram_channel_names_updated, 'telegram_channels.json')
            logging.info(f"Обновленный список каналов сохранен в telegram_channels.json. Удалено каналов: {len(channels_to_remove)}.")
        else:
            logging.info("Список каналов в telegram_channels.json не изменился (удаление не потребовалось).")
    else:
        logging.info("Нет каналов для удаления.")

    channel_history_manager.save_failure_history(channel_failure_counts)
    channel_history_manager.save_no_more_pages_history(no_more_pages_counts)

def log_statistics(start_time: datetime, initial_channels_count: int, channels_parsed_count: int, parsed_profiles: List[Dict], final_profiles_scored: List[Dict], profiles_to_save: List[Dict], channels_with_profiles: Set[str], channels_to_remove: List[str]) -> None:
    """Логирует итоговую статистику парсинга."""
    end_time = datetime.now()
    total_time = end_time - start_time

    logging.info(f'{"-"*40}')
    logging.info(f'{"--- Итоговая статистика ---":^40}')
    logging.info(f'{"-"*40}')
    logging.info(f'Общее время выполнения: {str(total_time).split(".")[0]}')
    logging.info(f'Начальное количество каналов в telegram_channels.json: {initial_channels_count}')
    logging.info(f'Каналов обработано: {channels_parsed_count}')
    logging.info(f'Каналов, в которых найдены профили: {len(channels_with_profiles)}')
    logging.info(f'Профелей найдено во время парсинга (до обработки): {len(parsed_profiles)}')
    logging.info(f'Уникальных профилей после обработки и фильтрации: {len(final_profiles_scored)}')
    logging.info(f'Профелей сохранено в config-tg.txt: {len(profiles_to_save)}')
    if channels_to_remove:
        logging.info(f'Каналов удалено из списка: {len(channels_to_remove)}')
    else:
        logging.info(f'Каналов удалено из списка: 0')
    logging.info(f'{"-"*40}')
    logging.info('Завершено!')

async def main_async():
    """Главная асинхронная функция для запуска парсинга и обработки профилей."""
    logging.info(f'Загрузка конфигурации из {CONFIG_FILE}...')
    config_data = json_load(CONFIG_FILE)
    if config_data:
        global PROFILE_SCORE_WEIGHTS, PROFILE_CLEANING_RULES, PROFILE_FRESHNESS_DAYS, MAX_FAILED_CHECKS, MAX_NO_MORE_PAGES_COUNT, MAX_THREADS_PARSING, REQUEST_TIMEOUT_AIOHTTP, MIN_PROFILES_TO_DOWNLOAD, MAX_PROFILES_TO_DOWNLOAD
        PROFILE_SCORE_WEIGHTS = config_data.get('profile_score_weights', PROFILE_SCORE_WEIGHTS)
        PROFILE_CLEANING_RULES = config_data.get('profile_cleaning_rules', PROFILE_CLEANING_RULES_DEFAULT)
        PROFILE_FRESHNESS_DAYS = config_data.get('profile_freshness_days', PROFILE_FRESHNESS_DAYS)
        MAX_FAILED_CHECKS = config_data.get('max_failed_checks', MAX_FAILED_CHECKS)
        MAX_NO_MORE_PAGES_COUNT = config_data.get('max_no_more_pages_count', MAX_NO_MORE_PAGES_COUNT)
        MAX_THREADS_PARSING = config_data.get('max_threads_parsing', MAX_THREADS_PARSING)
        REQUEST_TIMEOUT_AIOHTTP = config_data.get('request_timeout_aiohttp', REQUEST_TIMEOUT_AIOHTTP)
        MIN_PROFILES_TO_DOWNLOAD = config_data.get('min_profiles_to_download', MIN_PROFILES_TO_DOWNLOAD)
        MAX_PROFILES_TO_DOWNLOAD = config_data.get('max_profiles_to_download', MAX_PROFILES_TO_DOWNLOAD)
        logging.info(f'Конфигурация загружена.')
    else:
        logging.warning(f'Не удалось загрузить конфигурацию из {CONFIG_FILE}. Используются значения по умолчанию.')

    start_time = datetime.now()
    telegram_channel_names_original = await load_channels_async()
    telegram_channel_names_to_parse = list(telegram_channel_names_original) # Копируем список для итераций
    initial_channels_count = len(telegram_channel_names_original)
    logging.info(f'Начальное количество каналов в telegram_channels.json: {initial_channels_count}')

    channel_history_manager = ChannelHistoryManager()
    logging.info(f'Начинаем парсинг...')
    parsed_profiles, channels_with_profiles, channels_to_remove, channel_failure_counts, no_more_pages_counts = await run_parsing_async(telegram_channel_names_to_parse, channel_history_manager)
    logging.info(f'Парсинг завершен. Начинаем обработку и фильтрацию спарсенных конфигов...')

    final_profiles_scored = await process_parsed_profiles_async(parsed_profiles)
    profiles_to_save = final_profiles_scored[:min(max(len(final_profiles_scored), MIN_PROFILES_TO_DOWNLOAD), MAX_PROFILES_TO_DOWNLOAD)]
    save_results(final_profiles_scored, profiles_to_save, channels_to_remove, telegram_channel_names_original, channel_history_manager, channel_failure_counts, no_more_pages_counts)
    log_statistics(start_time, initial_channels_count, len(telegram_channel_names_to_parse), parsed_profiles, final_profiles_scored, profiles_to_save, channels_with_profiles, channels_to_remove)

if __name__ == "__main__":
    asyncio.run(main_async())
