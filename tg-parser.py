import aiohttp
import asyncio
import json
import os
import random
import re
import shutil
import tempfile
import urllib.parse as urllib_parse
from datetime import datetime, timedelta, timezone
import logging
from typing import Dict, List, Optional, Set, Union, Any
from functools import lru_cache
import time

from bs4 import BeautifulSoup
import urllib3
import geoip2.database
import aiofiles
import ipaddress
import certifi
import gzip
from tqdm.asyncio import tqdm_asyncio

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Global Constants ---
MAX_THREADS_PARSING = 10 # Experiment with increasing this value carefully
REQUEST_TIMEOUT_AIOHTTP = 60
MIN_PROFILES_TO_DOWNLOAD = 1000
MAX_PROFILES_TO_DOWNLOAD = 200000
ALLOWED_PROTOCOLS = {"vless", "hy2", "tuic", "trojan", "ss"}
PROFILE_SCORE_WEIGHTS_DEFAULT = {
    "security": 2,
    "sni": 2,
    "alpn": 2,
    "flow": 2,
    "headerType": 1,
    "path": 1,
    "obfs": 1,
    "mport": 1,
}
PROFILE_SCORE_WEIGHTS = PROFILE_SCORE_WEIGHTS_DEFAULT
VALIDATION_SCORE_WEIGHTS_DEFAULT = {
    "availability": 3,
    "anonymity": 5,
    "speed": 2,
}
VALIDATION_SCORE_WEIGHTS = VALIDATION_SCORE_WEIGHTS_DEFAULT
MAX_FAILED_CHECKS = 12
FAILURE_HISTORY_FILE = 'channel_failure_history.json'
NO_MORE_PAGES_HISTORY_FILE = 'no_more_pages_history.json'
MAX_NO_MORE_PAGES_COUNT = 12
PROFILE_FRESHNESS_DAYS = 60
CONFIG_FILE = 'config.json'
PROFILE_CLEANING_RULES_DEFAULT = []
PROFILE_CLEANING_RULES = PROFILE_CLEANING_RULES_DEFAULT
MAX_RETRIES_FETCH_PAGE = 3
RETRY_DELAY_BASE_FETCH_PAGE = 2
DNS_TIMEOUT = 5.0
VALIDATION_TIMEOUT = 10.0 # Default validation timeout
VALIDATION_ANONYMITY_TIMEOUT = 7.0 # Reduced timeout for anonymity check
VALIDATION_SPEED_TIMEOUT = 5.0 # Reduced timeout for speed check
VALIDATION_TEST_URL = "http://httpbin.org/ip"

VLESS_EMOJI = "🌠"
HY2_EMOJI = "⚡"
TUIC_EMOJI = "🚀"
TROJAN_EMOJI = "🛡️"
SS_EMOJI = "🧦"
GEOIP_DB_URL = "https://github.com/P3TERX/GeoLite.mmdb/releases/download/2025.03.13/GeoLite2-Country.mmdb"
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"
UNKNOWN_LOCATION_EMOJI = "🏴‍☠️"
# --- End Global Constants ---

if not os.path.exists('config-tg.txt'):
    with open('config-tg.txt', 'w'):
        pass


def json_load(path: str) -> Optional[Union[dict, list]]:
    """Loads JSON file, handling potential errors."""
    if not os.path.exists(path):
        logging.error(f"File not found: {path}")
        return None
    if os.stat(path).st_size == 0:
        logging.warning(f"File '{path}' is empty. Returning None.")
        return None
    try:
        with open(path, 'r', encoding="utf-8") as file:
            data = json.load(file)
            if not isinstance(data, (dict, list)):
                logging.error(f"File {path} does not contain a JSON object or array.")
                return None
            return data
    except json.JSONDecodeError as e:
        logging.error(f"JSON decode error in file: {path}. Error details: {e}")
        return None


def json_save(data: dict, path: str, indent: int = 4, backup: bool = True, compress: bool = False) -> bool:
    """Saves data to JSON file atomically with optional backup and compression."""
    try:
        if backup and os.path.exists(path):
            backup_path = path + '.bak'
            try:
                shutil.copy2(path, backup_path)
            except OSError as e_backup:
                logging.warning(f"Warning: Backup failed for {path} to {backup_path}. Error: {e_backup}")

        temp_filepath = None
        try:
            with tempfile.NamedTemporaryFile(mode='wt', encoding='utf-8', delete=False) as tmp_file:
                temp_filepath = tmp_file.name
                if compress:
                    with gzip.open(temp_filepath, 'wt', encoding='utf-8') as compressed_file:
                        json.dump(data, compressed_file, ensure_ascii=False, indent=indent)
                else:
                    json.dump(data, tmp_file, ensure_ascii=False, indent=indent)

            os.replace(temp_filepath, path)
            return True
        except (OSError, TypeError, json.JSONEncodeError) as e_save:
            logging.error(f"Error saving JSON to file {path}: {e_save}")
            return False
        finally:
            if temp_filepath and os.path.exists(temp_filepath):
                try:
                    os.remove(temp_filepath)
                except OSError as e_remove_tmp:
                    logging.warning(f"Warning: Could not remove temporary file {temp_filepath}. Error: {e_remove_tmp}")

    except Exception as e_outer:
        logging.error(f"Unexpected error during JSON save process for {path}: {e_outer}")
        return False


def calculate_profile_score(profile: str, score_weights: Dict[str, int] = PROFILE_SCORE_WEIGHTS) -> int:
    """
    Calculates profile score based on configuration parameters and provided score weights.
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
                score += score_weights.get("security", 0)
                if "sni" in params:
                    score += score_weights.get("sni", 0)
                if "alpn" in params:
                    score += score_weights.get("alpn", 0)

        if protocol == "vless":
            add_tls_score()
            if "flow" in params:
                score += score_weights.get("flow", 0)
            if "headerType" in params:
                score += score_weights.get("headerType", 0)
            if "path" in params:
                score += score_weights.get("path", 0)
        elif protocol == "hy2":
            add_tls_score()
            if "obfs" in params:
                score += score_weights.get("obfs", 0)
        elif protocol == "tuic":
            if "alpn" in params:
                score += score_weights.get("alpn", 0)
            if "mport" in params:
                score += score_weights.get("mport", 0)
        elif protocol == "trojan":
            add_tls_score()
            if "obfs" in params:
                score += score_weights.get("obfs", 0)
        elif protocol == "ss":
            score += 1

        base_params_count = len(profile.split("://")[1].split("@")[0].split(":"))
        score += base_params_count
    except Exception as e:
        logging.error(f"Error calculating profile score for '{profile}'. Error details: {e}")
        return 0
    return score


async def fetch_channel_page_async(session: aiohttp.ClientSession, channel_url: str, attempt: int, max_retries: int = MAX_RETRIES_FETCH_PAGE, retry_delay_base: int = RETRY_DELAY_BASE_FETCH_PAGE) -> Optional[str]:
    """Asynchronously fetches a channel page with retry logic and SSL verification."""
    for attempt_num in range(attempt, max_retries):
        try:
            async with session.get(f'https://t.me/s/{channel_url}', timeout=REQUEST_TIMEOUT_AIOHTTP, ssl=True) as response:
                response.raise_for_status()
                return await response.text()
        except aiohttp.ClientResponseError as http_err:
            log_message = f"HTTP error {http_err.status} for {channel_url}, attempt {attempt_num + 1}/{max_retries}: {http_err}"
            if attempt_num < max_retries - 1:
                delay = (retry_delay_base**attempt_num) + random.random()
                log_message += f". Retrying in {delay:.2f}s."
                await asyncio.sleep(delay)
            logging.warning(log_message)
            if attempt_num >= max_retries - 1:
                logging.error(f"Max retries ({max_retries}) exceeded for {channel_url} due to HTTP errors.")
                return None
        except aiohttp.ClientError as e:
            log_message = f"aiohttp error for {channel_url}, attempt {attempt_num + 1}/{max_retries}: {e}"
            if attempt_num < max_retries - 1:
                delay = (retry_delay_base**attempt_num) + random.random()
                log_message += f". Retrying in {delay:.2f}s."
                await asyncio.sleep(delay)
            logging.warning(log_message)
            if attempt_num >= max_retries - 1:
                logging.error(f"Max retries ({max_retries}) exceeded for {channel_url} due to aiohttp errors.")
                return None
        except asyncio.TimeoutError:
            log_message = f"aiohttp timeout for {channel_url}, attempt {attempt_num + 1}/{max_retries}."
            if attempt_num < max_retries - 1:
                delay = (retry_delay_base**attempt_num) + random.random()
                log_message += f". Retrying in {delay:.2f}s."
                await asyncio.sleep(delay)
            logging.warning(log_message)
            if attempt_num >= max_retries - 1:
                logging.error(f"Max retries ({max_retries}) exceeded for {channel_url} due to aiohttp timeout.")
                return None
    return None


async def parse_profiles_from_page_async(html_page: str, channel_url: str, allowed_protocols: Set[str], profile_score_func) -> List[Dict]:
    """Asynchronously parses profiles from an HTML page with improved HTML cleaning and pre-filtering."""
    channel_profiles = []
    soup = BeautifulSoup(html_page, 'html.parser')
    message_blocks = soup.find_all('div', class_='tgme_widget_message')

    for message_block in message_blocks:
        time_tag = message_block.find('time', class_='datetime')
        message_datetime = None
        if time_tag and 'datetime' in time_tag.attrs:
            try:
                message_datetime = datetime.fromisoformat(time_tag['datetime']).replace(tzinfo=timezone.utc)
            except ValueError as date_err:
                logging.warning(f"Failed to parse date for {channel_url}: {time_tag['datetime']}. Error: {date_err}")
                message_datetime = None

        code_tags = message_block.find_all(class_='tgme_widget_message_text')
        for code_tag in code_tags:
            code_content = code_tag.get_text(separator='\n', strip=True)
            code_content_lines = code_content.splitlines()
            for line in code_content_lines:
                cleaned_content = line.strip()
                # --- Предварительная фильтрация: проверяем, начинается ли строка с нужного протокола ---
                is_profile_line = False
                for protocol in allowed_protocols:
                    if cleaned_content.startswith(f"{protocol}://"):
                        is_profile_line = True
                        break
                if is_profile_line:
                    profile_link = cleaned_content
                    score = profile_score_func(profile_link)
                    channel_profiles.append({'profile': profile_link, 'score': score, 'date': message_datetime})
    return channel_profiles


async def _fetch_all_channel_pages(channel_url: str) -> tuple[List[str], bool, bool]:
    """Fetches all pages for a given channel."""
    html_pages = []
    current_url = channel_url
    pattern_datbef = re.compile(r'(?:data-before=")(\d*)')
    no_more_pages_in_run = False
    failed_check = False

    async with aiohttp.ClientSession() as session:
        for attempt in range(2):
            while True:
                html_page = await fetch_channel_page_async(session, current_url, attempt + 1)
                if html_page:
                    html_pages.append(html_page)
                    last_datbef = re.findall(pattern_datbef, html_page)
                    if not last_datbef:
                        logging.info(f"No more pages found for {channel_url}")
                        no_more_pages_in_run = True
                        return html_pages, no_more_pages_in_run, failed_check
                    current_url = f'{channel_url}?before={last_datbef[0]}'
                else:
                    failed_check = True
                    logging.warning(f"Failed to fetch page for {channel_url} on attempt {attempt+1}.")
                    return html_pages, no_more_pages_in_run, failed_check
        logging.error(f"Failed to load pages for {channel_url} after retries.")
        return html_pages, no_more_pages_in_run, failed_check


async def _extract_profiles_from_pages(html_pages: List[str], channel_url: str, allowed_protocols: Set[str], profile_score_func) -> List[Dict]:
    """Extracts profiles from a list of HTML pages."""
    channel_profiles = []
    for page in html_pages:
        profiles_on_page = await parse_profiles_from_page_async(page, channel_url, allowed_protocols, profile_score_func)
        channel_profiles.extend(profiles_on_page)
    return channel_profiles


def _update_channel_status(channel_url: str, channel_profiles: List[Dict], channel_failure_counts: Dict[str, int], no_more_pages_counts: Dict[str, int], channels_to_remove: List[str], no_more_pages_in_run: bool, failed_check: bool) -> None:
    """Updates channel status based on parsing results."""
    channel_removed_in_run = False
    if not channel_profiles:
        channel_failure_counts[channel_url] = channel_failure_counts.get(channel_url, 0) + 1
        if channel_failure_counts[channel_url] >= MAX_FAILED_CHECKS and channel_url not in channels_to_remove:
            channels_to_remove.append(channel_url)
            channel_removed_in_run = True
            logging.info(f"Channel '{channel_url}' removed due to {MAX_FAILED_CHECKS} consecutive failures.")
        elif not channel_removed_in_run:
            logging.info(f"No profiles found in {channel_url}. Consecutive failures: {channel_failure_counts[channel_url]}/{MAX_FAILED_CHECKS}.")

    if no_more_pages_in_run:
        no_more_pages_counts[channel_url] = no_more_pages_counts.get(channel_url, 0) + 1
        if no_more_pages_counts[channel_url] >= MAX_NO_MORE_PAGES_COUNT and channel_url not in channels_to_remove:
            channels_to_remove.append(channel_url)
            channel_removed_in_run = True
            logging.info(f"Channel '{channel_url}' removed due to {MAX_NO_MORE_PAGES_COUNT} 'No More Pages' messages.")
        elif not channel_removed_in_run:
            logging.info(f"'No More Pages' message for '{channel_url}'. Consecutive messages: {no_more_pages_counts[channel_url]}/{MAX_NO_MORE_PAGES_COUNT}.")


async def process_channel_async(channel_url: str, parsed_profiles: List[Dict], thread_semaphore: asyncio.Semaphore,
                                telegram_channel_names: List[str], channels_parsed_count: int,
                                channels_with_profiles: Set[str], channel_failure_counts: Dict[str, int],
                                channels_to_remove: List[str], no_more_pages_counts: Dict[str, int],
                                allowed_protocols: Set[str], profile_score_func) -> None:
    """Asynchronously processes a Telegram channel to extract profiles."""
    async with thread_semaphore:
        try:
            html_pages, no_more_pages_in_run, failed_check = await _fetch_all_channel_pages(channel_url)

            if not html_pages and failed_check:
                logging.warning(f"Failed to load pages for {channel_url} after retries. Skipping channel.")
                failed_check = True
            else:
                failed_check = False

            channel_index = telegram_channel_names.index(channel_url) + 1
            logging.info(f'Processing channel {channel_index}/{channels_parsed_count}: {channel_url}')

            channel_profiles = []
            if not failed_check:
                channel_profiles = await _extract_profiles_from_pages(html_pages, channel_url, allowed_protocols, profile_score_func)

            if channel_profiles:
                channels_with_profiles.add(channel_url)
                channel_failure_counts[channel_url] = 0
                no_more_pages_counts[channel_url] = 0
            else:
                pass

            _update_channel_status(channel_url, channel_profiles, channel_failure_counts, no_more_pages_counts, channels_to_remove, no_more_pages_in_run, failed_check)
            parsed_profiles.extend(channel_profiles)

        except Exception as channel_exception:
            logging.error(f"Critical error processing channel {channel_url}: {channel_exception}")


def clean_profile(profile_string: str, cleaning_rules: List[str] = PROFILE_CLEANING_RULES) -> str:
    """Cleans a profile string from unnecessary characters using configurable rules."""
    part = profile_string
    for rule in cleaning_rules:
        part = re.sub(rule, '', part, flags=re.IGNORECASE)
    part = urllib_parse.unquote(part).strip()
    part = part.replace(' ', '')
    part = re.sub(r'[\x00\x01]', '', part)
    return part


def extract_ip_port(profile_string: str) -> Optional[tuple[str, str]]:
    """Extracts and validates IP address and port from a profile string."""
    try:
        parsed_url = urllib_parse.urlparse(profile_string)
        netloc = parsed_url.netloc
        if "@" in netloc:
            netloc = netloc.split("@")[1]

        host = None
        port = None
        if ":" in netloc:
            host, port_str = netloc.split(":", 1)
            try:
                port = int(port_str)
                if not 0 <= port <= 65535:
                    logging.warning(f"Invalid port number: {port} in profile: {profile_string[:100]}...")
                    return None, None
            except ValueError:
                logging.warning(f"Invalid port format: {port_str} in profile: {profile_string[:100]}...")
                return None, None
        else:
            host = netloc
            logging.warning(f"Port missing in profile: {profile_string[:100]}...")
            return None, None

        try:
            ipaddress.ip_address(host)
            return host, str(port)
        except ValueError:
            logging.warning(f"Invalid IP address format: {host} in profile: {profile_string[:100]}...")
            return None, None

    except Exception as e:
        logging.error(f"Error extracting IP:port from profile: {profile_string[:100]}... Error details: {e}")
        return None, None


async def download_geoip_db():
    """Downloads GeoLite2-Country.mmdb database with progress indication."""
    if os.path.exists(GEOIP_DB_PATH):
        logging.info(f"GeoIP database already exists at {GEOIP_DB_PATH}. Skipping download.")
        return True

    logging.info(f"Downloading GeoIP database from {GEOIP_DB_URL} to {GEOIP_DB_PATH}...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(GEOIP_DB_URL) as response:
                if response.status == 200:
                    total_size = int(response.headers.get('Content-Length', 0))
                    bytes_downloaded = 0
                    async with aiofiles.open(GEOIP_DB_PATH, 'wb') as f:
                        async for chunk in response.content.iter_chunked(8192):
                            await f.write(chunk)
                            bytes_downloaded += len(chunk)
                            if total_size > 0:
                                progress = (bytes_downloaded / total_size) * 100
                                logging.info(f"GeoIP database download progress: {progress:.2f}%")
                            else:
                                logging.info(f"GeoIP database download in progress... (size unknown)")

                    logging.info(f"GeoIP database downloaded successfully to {GEOIP_DB_PATH}.")
                    return True
                else:
                    logging.error(f"Failed to download GeoIP database, status code: {response.status}")
                    return False
    except (aiohttp.ClientError, aiohttp.ClientResponseError, OSError) as e:
        logging.error(f"Error downloading GeoIP database: {e}")
        return False


@lru_cache(maxsize=1024)
def _cached_geoip_country_lookup(geoip_reader: geoip2.database.Reader, ip_str: str) -> str:
    """Cached GeoIP country lookup."""
    try:
        country_info = geoip_reader.country(ip_str)
        country_name = country_info.country.names.get('en', 'Unknown')
        return country_name
    except geoip2.errors.AddressNotFoundError:
        return UNKNOWN_LOCATION_EMOJI
    except Exception as e:
        logging.error(f"GeoIP lookup error for IP {ip_str} (cached function): {e}")
        return UNKNOWN_LOCATION_EMOJI


@lru_cache(maxsize=1024)
async def _cached_dns_resolve(hostname: str, dns_timeout: float = DNS_TIMEOUT) -> Optional[str]:
    """Cached DNS resolution."""
    async with aiohttp.ClientSession() as session:
        try:
            resolved_ips = await session.get_resolver().resolve(hostname, timeout=dns_timeout)
            if resolved_ips:
                return resolved_ips[0]['host']
            else:
                logging.warning(f"DNS resolution failed for hostname: {hostname} (cached function), no IPs resolved.")
                return None
        except aiohttp.ClientConnectorError as e:
            logging.error(f"AIOHTTP ClientConnectorError during DNS resolution for {hostname} (cached function): {e}")
            return None
        except asyncio.TimeoutError:
            logging.warning(f"DNS resolution timeout for hostname: {hostname} (cached function).")
            return None
        except Exception as e:
            logging.error(f"Error during DNS resolution for {hostname} (cached function): {e}")
            return None


async def get_country_name_from_ip(ip_address_or_hostname: str, geoip_reader: geoip2.database.Reader, session: aiohttp.ClientSession, dns_timeout: float = DNS_TIMEOUT) -> str:
    """Retrieves country name from IP address or hostname using GeoLite2 database with caching."""
    try:
        ip_address = None
        try:
            ip_address = ipaddress.ip_address(ip_address_or_hostname)
        except ValueError:
            resolved_ip_str = await _cached_dns_resolve(ip_address_or_hostname, dns_timeout=dns_timeout)
            if resolved_ip_str:
                ip_address = ipaddress.ip_address(resolved_ip_str)
            else:
                logging.error(f"DNS resolution failed for hostname: {ip_address_or_hostname} (after cached resolve).")
                return UNKNOWN_LOCATION_EMOJI

        if ip_address:
            country_name = _cached_geoip_country_lookup(geoip_reader, str(ip_address))
            return country_name
        else:
            return UNKNOWN_LOCATION_EMOJI

    except Exception as e:
        logging.error(f"GeoIP lookup error for IP/Hostname {ip_address_or_hostname}: {e}")
        return UNKNOWN_LOCATION_EMOJI


async def _validate_proxy_availability(session: aiohttp.ClientSession, proxy_url: str, timeout: float = VALIDATION_TIMEOUT) -> bool:
    """Validates proxy availability."""
    try:
        logging.debug(f"Validating availability for proxy: {proxy_url}")
        async with session.get(VALIDATION_TEST_URL, proxy=proxy_url, timeout=timeout) as response:
            return response.status == 200
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logging.debug(f"Proxy availability check failed for {proxy_url}: {e}")
        return False

async def _validate_proxy_anonymity(session: aiohttp.ClientSession, proxy_url: str, timeout: float = VALIDATION_ANONYMITY_TIMEOUT) -> bool: # Reduced timeout
    """Validates proxy anonymity."""
    try:
        logging.debug(f"Validating anonymity for proxy: {proxy_url}")
        async with session.get("http://httpbin.org/headers", proxy=proxy_url, timeout=timeout) as response: # Using http for headers check
            headers_json = await response.json()
            proxy_origin = headers_json.get("origin")
            if proxy_origin:
                proxy_ip = proxy_origin.split(',')[0].strip()
                logging.debug(f"Proxy IP: {proxy_ip}")
                return True
            else:
                logging.warning(f"Could not determine proxy IP from 'origin' header for {proxy_url}.")
                return False
    except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError) as e:
        logging.debug(f"Proxy anonymity check failed for {proxy_url}: {e}")
        return False

async def _measure_proxy_speed(session: aiohttp.ClientSession, proxy_url: str, timeout: float = VALIDATION_SPEED_TIMEOUT) -> Optional[float]: # Reduced timeout
    """Measures proxy response speed."""
    start_time = time.perf_counter()
    try:
        logging.debug(f"Measuring speed for proxy: {proxy_url}")
        async with session.get(VALIDATION_TEST_URL, proxy=proxy_url, timeout=timeout) as response:
            await response.read()
            response_time = time.perf_counter() - start_time
            logging.debug(f"Proxy {proxy_url} response time: {response_time:.2f}s")
            return response_time
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logging.debug(f"Proxy speed check failed for {proxy_url}: {e}")
        return None

@lru_cache(maxsize=1024, ttl=60) # Caching validation results for 60 seconds
async def _cached_validate_and_score_profile(profile_data: Dict, session: aiohttp.ClientSession, validation_score_weights: Dict[str, int] = VALIDATION_SCORE_WEIGHTS) -> Optional[Dict]:
    """Cached validation and scoring of proxy profile."""
    return await _validate_and_score_profile(profile_data, session, validation_score_weights)


async def _validate_and_score_profile(profile_data: Dict, session: aiohttp.ClientSession, validation_score_weights: Dict[str, int] = VALIDATION_SCORE_WEIGHTS) -> Optional[Dict]:
    """Validates proxy profile and calculates validation score."""
    profile_string = profile_data['profile']
    proxy_url = profile_string

    availability = await _validate_proxy_availability(session, proxy_url)
    anonymity = await _validate_proxy_anonymity(session, proxy_url)
    speed = await _measure_proxy_speed(session, proxy_url)

    validation_score = 0
    if availability:
        validation_score += validation_score_weights.get("availability", 0)
    if anonymity:
        validation_score += validation_score_weights.get("anonymity", 0)
    if speed is not None:
        if speed < 2.0:
            validation_score += validation_score_weights.get("speed", 0)

    logging.debug(f"Validation results for {profile_string[:100]}...: Availability: {availability}, Anonymity: {anonymity}, Speed: {speed:.2f}s, Validation Score: {validation_score}")

    if availability:
        profile_data['validation_score'] = validation_score
        profile_data['final_score'] = profile_data['score'] + validation_score
        return profile_data
    else:
        logging.info(f"Profile failed validation (availability): {profile_string[:100]}...")
        return None


async def _clean_and_extract_profiles(parsed_profiles_list: List[Dict]) -> List[Dict]:
    """Cleans profiles and extracts IP/port."""
    cleaned_profiles = []
    for item in parsed_profiles_list:
        cleaned_profile_string = clean_profile(item['profile'])
        ip, port = extract_ip_port(cleaned_profile_string)
        if ip and port:
            cleaned_profiles.append({'profile': cleaned_profile_string, 'score': item['score'], 'date': item['date'], 'ip': ip, 'port': port})
    return cleaned_profiles


def _deduplicate_profiles_by_ip_port_protocol(profiles: List[Dict]) -> List[Dict]:
    """Deduplicates profiles by IP, port, and protocol."""
    unique_profiles = []
    unique_ip_port_protocol_set = set()
    for profile_data in profiles:
        protocol = profile_data['profile'].split("://")[0]
        ip_port_protocol_tuple = (profile_data['ip'], profile_data['port'], protocol)
        if ip_port_protocol_tuple not in unique_ip_port_protocol_set:
            unique_profiles.append(profile_data)
            unique_ip_port_protocol_set.add(ip_port_protocol_tuple)
    return unique_profiles


async def _batch_geoip_country_lookup(geoip_reader: geoip2.database.Reader, ip_list: List[str]) -> Dict[str, str]:
    """Batch GeoIP lookup for a list of IP addresses."""
    country_name_map = {}
    try:
        for ip_str in ip_list:
            try:
                country_info = geoip_reader.country(ip_str)
                country_name = country_info.country.names.get('en', 'Unknown')
                country_name_map[ip_str] = country_name
            except geoip2.errors.AddressNotFoundError:
                country_name_map[ip_str] = UNKNOWN_LOCATION_EMOJI
            except Exception as e:
                logging.error(f"GeoIP lookup error for IP {ip_str} (batch function): {e}")
                country_name_map[ip_str] = UNKNOWN_LOCATION_EMOJI
    except Exception as batch_err:
        logging.error(f"Batch GeoIP lookup failed: {batch_err}")
    return country_name_map


async def _enrich_profiles_with_geoip(profiles: List[Dict], geoip_reader: geoip2.database.Reader, session: aiohttp.ClientSession) -> List[Dict]:
    """Enriches profiles with GeoIP information and creates beautiful names using batch GeoIP lookup."""
    enriched_profiles = []
    geoip_country_lookup_enabled = bool(geoip_reader) # Check if geoip_reader is valid

    if geoip_country_lookup_enabled:
        ip_addresses = [profile_data['ip'] for profile_data in profiles]
        country_name_map = await _batch_geoip_country_lookup(geoip_reader, ip_addresses)

    for profile_data in profiles:
        location_country = UNKNOWN_LOCATION_EMOJI
        if geoip_country_lookup_enabled:
            location_country_name = country_name_map.get(profile_data['ip'], UNKNOWN_LOCATION_EMOJI)
            location_country = location_country_name if location_country_name != "Unknown" else UNKNOWN_LOCATION_EMOJI

        protocol = profile_data['profile'].split("://")[0]
        security_info = "NoTLS"
        params_str = profile_data['profile'].split("://")[1]
        if "@" in params_str:
            params_str = params_str.split("@")[1]
        if "#" in params_str:
            params_str = params_str.split("#")[0]
        params = urllib_parse.parse_qs(params_str)
        if params.get("security", [""])[0] == "tls":
            security_info = "TLS"

        beautiful_name = ""
        if protocol == "vless": beautiful_name = f"{VLESS_EMOJI} VLESS › Secure {security_info} - {location_country}"
        elif protocol == "hy2": beautiful_name = f"{HY2_EMOJI} HY2 › Secure {security_info} - {location_country}"
        elif protocol == "tuic": beautiful_name = f"{TUIC_EMOJI} TUIC › {security_info} - {location_country}"
        elif protocol == "trojan": beautiful_name = f"{TROJAN_EMOJI} Trojan › Secure {security_info} - {location_country}"
        elif protocol == "ss": beautiful_name = f"{SS_EMOJI} Shadowsocks › {security_info} - {location_country}"

        profile_data['profile'] = f"{profile_data['profile']}#{beautiful_name}"
        profile_data['profile_name'] = beautiful_name
        enriched_profiles.append(profile_data)
    return enriched_profiles


def _filter_and_sort_profiles(profiles: List[Dict]) -> List[Dict]:
    """Filters duplicates, freshness, and sorts profiles."""
    unique_profiles_scored = []
    seen_profiles = set()
    for profile_data in profiles:
        profile = profile_data['profile']
        if profile not in seen_profiles and len(profile) > 13 and (("…" in profile and "#" in profile) or ("…" not in profile)):
            unique_profiles_scored.append(profile_data)
            seen_profiles.add(profile)

    fresh_profiles_scored = []
    now = datetime.now(tz=timezone.utc)
    for profile_data in unique_profiles_scored:
        if 'date' in profile_data and isinstance(profile_data['date'], datetime):
            time_difference = now - profile_data['date']
            if time_difference <= timedelta(days=PROFILE_FRESHNESS_DAYS):
                fresh_profiles_scored.append(profile_data)
            else:
                logging.info(f"Removing outdated profile: {profile_data['date'].strftime('%Y-%m-%d %H:%M:%S UTC')}, {profile_data['profile'][:100]}...")
        else:
            fresh_profiles_scored.append(profile_data)

    final_profiles_scored = fresh_profiles_scored
    final_profiles_scored.sort(key=lambda item: item.get('final_score') or 0, reverse=True)
    return final_profiles_scored


async def process_parsed_profiles_async(parsed_profiles_list: List[Dict]) -> List[Dict]:
    """Processes parsed profiles: cleaning, deduplication, validation, filtering, naming with GeoIP - Optimized for speed."""
    processed_profiles = []
    geoip_reader = None
    geoip_country_lookup_enabled = True

    if not await download_geoip_db():
        logging.warning("GeoIP database download failed. Location information will be replaced with pirate flag emoji.")
        geoip_country_lookup_enabled = False

    try:
        if geoip_country_lookup_enabled:
            geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)

        cleaned_extracted_profiles = await _clean_and_extract_profiles(parsed_profiles_list)
        deduplicated_profiles = _deduplicate_profiles_by_ip_port_protocol(cleaned_extracted_profiles)

        # --- Parallelized Validation using asyncio.gather ---
        validated_profiles = []
        async with aiohttp.ClientSession() as session_for_validation:
            validation_tasks = [
                _cached_validate_and_score_profile(profile_data, session_for_validation, VALIDATION_SCORE_WEIGHTS) # Using cached validation function
                for profile_data in deduplicated_profiles
            ]
            validated_profiles = await asyncio.gather(*validation_tasks)
            validated_profiles = [profile for profile in validated_profiles if profile is not None] # Filter out None results
        # --- End Parallelized Validation ---


        enriched_profiles = []
        if geoip_country_lookup_enabled:
            async with aiohttp.ClientSession() as session_for_geoip:
                enriched_profiles = await _enrich_profiles_with_geoip(validated_profiles, geoip_reader, session_for_geoip) # Use validated profiles
        else:
            enriched_profiles = validated_profiles

        final_profiles_scored = _filter_and_sort_profiles(enriched_profiles)

        logging.info(f"After validation and filtering, {len(final_profiles_scored)} unique profiles remain.")
        return final_profiles_scored

    finally:
        if geoip_reader:
            geoip_reader.close()
        if os.path.exists(GEOIP_DB_PATH):
            os.remove(GEOIP_DB_PATH)


class ChannelHistoryManager:
    """Manages channel history (failures, 'No More Pages') with asynchronous file operations."""

    def __init__(self, failure_file: str = FAILURE_HISTORY_FILE, no_more_pages_file: str = NO_MORE_PAGES_HISTORY_FILE):
        """Initializes ChannelHistoryManager."""
        self.failure_file = failure_file
        self.no_more_pages_file = no_more_pages_file

    async def _load_json_history(self, filepath: str) -> Dict:
        """Loads history from a JSON file asynchronously."""
        if not os.path.exists(filepath):
            logging.warning(f"History file '{filepath}' not found. Creating: {filepath}")
            if not await self._save_json_history({}, filepath):
                logging.error(f"Failed to create history file: {filepath}")
                return {}
            return {}
        history = await self._async_json_load(filepath)
        return history if history else {}

    async def _save_json_history(self, history: Dict, filepath: str) -> bool:
        """Saves history to a JSON file asynchronously."""
        logging.info(f"Saving history to '{filepath}'.")
        return await self._async_json_save(history, filepath)

    async def _async_json_load(self, path: str) -> Optional[dict]:
        """Asynchronously loads JSON file, handling potential errors."""
        if not os.path.exists(path):
            logging.error(f"File not found: {path}")
            return None
        if os.stat(path).st_size == 0:
            logging.warning(f"File '{path}' is empty. Returning empty dictionary.")
            return {}
        try:
            async with aiofiles.open(path, 'r', encoding="utf-8") as file:
                content = await file.read()
                data = json.loads(content)
                if not isinstance(data, (dict, list)):
                    logging.error(f"File {path} does not contain a JSON object or array.")
                    return None
                return data
        except json.JSONDecodeError as e:
            logging.error(f"JSON decode error in file: {path} - {e}.")
            return None

    async def _async_json_save(self, data: dict, path: str, indent: int = 4, backup: bool = True) -> bool:
        """Asynchronously saves data to JSON file atomically with optional backup."""
        try:
            if backup and os.path.exists(path):
                backup_path = path + '.bak'
                shutil.copy2(path, backup_path)

            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False) as tmp_file:
                json.dump(data, tmp_file, ensure_ascii=False, indent=indent)
            temp_filepath = tmp_file.name
            os.replace(temp_filepath, path)
            return True
        except Exception as e:
            logging.error(f"Error saving JSON to file {path}: {e}")
            return False

    async def load_failure_history(self) -> Dict:
        """Loads channel failure history."""
        logging.info(f"Loading failure history from '{self.failure_file}'.")
        return await self._load_json_history(self.failure_file)

    async def save_failure_history(self, history: Dict) -> bool:
        """Saves channel failure history."""
        return await self._save_json_history(history, self.failure_file)

    async def load_no_more_pages_history(self) -> Dict:
        """Loads 'No More Pages' history for channels."""
        logging.info(f"Loading 'No More Pages' history from '{self.no_more_pages_file}'.")
        return await self._load_json_history(self.no_more_pages_file)

    async def save_no_more_pages_history(self, history: Dict) -> bool:
        """Saves 'No More Pages' history for channels."""
        return await self._save_json_history(history, self.no_more_pages_file)


async def load_channels_async(channels_file: str = 'telegram_channels.json') -> List[str]:
    """Loads channel list from a JSON file asynchronously and validates format."""
    telegram_channel_names_original = await ChannelHistoryManager()._async_json_load(channels_file)

    if telegram_channel_names_original is None:
        logging.critical(f"Failed to load channel list from {channels_file}. Please check the file or configuration.")
        return None

    if not isinstance(telegram_channel_names_original, list):
        logging.critical(f"Invalid format in {channels_file}. Expected a JSON list of strings. Exiting.")
        exit(1)

    if not telegram_channel_names_original:
        logging.warning(f"Channel list in {channels_file} is empty.")
        return []

    telegram_channel_names_original[:] = [x for x in telegram_channel_names_original if isinstance(x, str) and len(x) >= 5]
    return list(set(telegram_channel_names_original))


async def run_parsing_async(telegram_channel_names_to_parse: List[str], channel_history_manager: ChannelHistoryManager) -> tuple[
    List[Dict], Set[str], List[str], Dict, Dict]:
    """Runs asynchronous channel parsing with progress indication."""
    channels_parsed_count = len(telegram_channel_names_to_parse)
    logging.info(f'Starting parsing of {channels_parsed_count} channels...')

    channel_failure_counts = await channel_history_manager.load_failure_history()
    no_more_pages_counts = await channel_history_manager.load_no_more_pages_history()
    channels_to_remove = []
    thread_semaphore = asyncio.Semaphore(MAX_THREADS_PARSING)
    parsed_profiles = []
    channels_with_profiles = set()

    tasks = []
    for channel_name in telegram_channel_names_to_parse:
        task = process_channel_async(channel_name, parsed_profiles, thread_semaphore, telegram_channel_names_to_parse,
                                    channels_parsed_count, channels_with_profiles, channel_failure_counts,
                                    channels_to_remove, no_more_pages_counts, ALLOWED_PROTOCOLS,
                                    calculate_profile_score)
        tasks.append(task)

    logging.info("Parsing channels with progress bar...")
    await tqdm_asyncio.gather(*tasks, desc="Parsing channels", total=channels_parsed_count)

    return parsed_profiles, channels_with_profiles, channels_to_remove, channel_failure_counts, no_more_pages_counts


async def save_results(final_profiles_scored: List[Dict], profiles_to_save: List[Dict], channels_to_remove: List[str],
                 telegram_channel_names_original: List[str], channel_history_manager: ChannelHistoryManager,
                 channel_failure_counts: Dict, no_more_pages_counts: Dict) -> None:
    """Saves parsing results: profiles, updated channel list, history with asynchronous operations."""
    num_profiles_to_save = min(max(len(final_profiles_scored), MIN_PROFILES_TO_DOWNLOAD), MAX_PROFILES_TO_DOWNLOAD)
    profiles_to_save = final_profiles_scored[:num_profiles_to_save]

    with open("config-tg.txt", "w", encoding="utf-8") as file:
        for profile_data in profiles_to_save:
            file.write(f"{profile_data['profile'].encode('utf-8').decode('utf-8')}\n")

    if channels_to_remove:
        logging.info(f"Removing channels: {channels_to_remove}")
        telegram_channel_names_updated = [chan for chan in telegram_channel_names_original if chan not in channels_to_remove]
        if telegram_channel_names_updated != telegram_channel_names_original:
            if os.path.exists('telegram_channels.json'):
                shutil.copy2('telegram_channels.json', 'telegram_channels.json.bak')
            if await ChannelHistoryManager()._async_json_save(telegram_channel_names_updated, 'telegram_channels.json'):
                logging.info(f"Updated channel list saved to telegram_channels.json. Removed {len(channels_to_remove)} channels.")
            else:
                logging.error(f"Failed to save updated channel list to telegram_channels.json.")
        else:
            logging.info("Channel list in telegram_channels.json remains unchanged.")
    else:
        logging.info("No channels to remove.")

    if await channel_history_manager.save_failure_history(channel_failure_counts):
        logging.info("Failure history saved successfully.")
    else:
        logging.error("Failed to save failure history.")

    if await channel_history_manager.save_no_more_pages_history(no_more_pages_counts):
        logging.info("'No More Pages' history saved successfully.")
    else:
        logging.error("Failed to save 'No More Pages' history.")


def log_statistics(start_time: datetime, initial_channels_count: int, channels_parsed_count: int, parsed_profiles: List[Dict],
                   final_profiles_scored: List[Dict], profiles_to_save: List[Dict], channels_with_profiles: Set[str],
                   channels_to_remove: List[str]) -> None:
    """Logs final parsing statistics in structured JSON format and text format."""
    end_time = datetime.now()
    total_time = end_time - start_time

    statistics_data = {
        "total_execution_time_seconds": total_time.total_seconds(),
        "initial_channel_count": initial_channels_count,
        "channels_processed": channels_parsed_count,
        "channels_with_profiles": len(channels_with_profiles),
        "profiles_found_pre_processing": len(parsed_profiles),
        "unique_profiles_post_processing": len(final_profiles_scored),
        "profiles_saved_to_config_tg_txt": len(profiles_to_save),
        "channels_removed_from_list": len(channels_to_remove),
        "end_time": end_time.isoformat(),
        "start_time": start_time.isoformat()
    }

    logging.info("-" * 40)
    logging.info(f"{'--- Final Statistics ---':^40}")
    logging.info("-" * 40)
    logging.info(f"{'Total Execution Time:':<35} {str(total_time).split('.')[0]}")
    logging.info(f"{'Initial Channel Count:':<35} {initial_channels_count}")
    logging.info(f"{'Channels Processed:':<35} {channels_parsed_count}")
    logging.info(f"{'Channels with Profiles:':<35} {len(channels_with_profiles)}")
    logging.info(f"{'Profiles Found (Pre-processing):':<35} {len(parsed_profiles)}")
    logging.info(f"{'Unique Profiles (Post-processing):':<35} {len(final_profiles_scored)}")
    logging.info(f"{'Profiles Saved to config-tg.txt:':<35} {len(profiles_to_save)}")
    logging.info(f"{'Channels Removed from List:':<35} {len(channels_to_remove)}")
    logging.info("-" * 40)
    logging.info('Parsing Completed!')

    logging.info(f"Statistics in JSON format: {json.dumps(statistics_data, indent=4)}")


async def main_async():
    """Main asynchronous function to run parsing and profile processing with error handling."""
    try:
        logging.info(f'Loading configuration from {CONFIG_FILE}...')
        config_data = json_load(CONFIG_FILE)
        if config_data:
            global PROFILE_SCORE_WEIGHTS, PROFILE_CLEANING_RULES, PROFILE_FRESHNESS_DAYS, MAX_FAILED_CHECKS, MAX_NO_MORE_PAGES_COUNT, MAX_THREADS_PARSING, REQUEST_TIMEOUT_AIOHTTP, MIN_PROFILES_TO_DOWNLOAD, MAX_PROFILES_TO_DOWNLOAD, MAX_RETRIES_FETCH_PAGE, RETRY_DELAY_BASE_FETCH_PAGE, DNS_TIMEOUT, VALIDATION_TIMEOUT, VALIDATION_TEST_URL, VALIDATION_SCORE_WEIGHTS, VALIDATION_ANONYMITY_TIMEOUT, VALIDATION_SPEED_TIMEOUT
            PROFILE_SCORE_WEIGHTS = config_data.get('profile_score_weights', PROFILE_SCORE_WEIGHTS_DEFAULT)
            PROFILE_CLEANING_RULES = config_data.get('profile_cleaning_rules', PROFILE_CLEANING_RULES_DEFAULT)
            PROFILE_FRESHNESS_DAYS = config_data.get('profile_freshness_days', PROFILE_FRESHNESS_DAYS)
            MAX_FAILED_CHECKS = config_data.get('max_failed_checks', MAX_FAILED_CHECKS)
            MAX_NO_MORE_PAGES_COUNT = config_data.get('max_no_more_pages_count', MAX_NO_MORE_PAGES_COUNT)
            MAX_THREADS_PARSING = config_data.get('max_threads_parsing', MAX_THREADS_PARSING)
            REQUEST_TIMEOUT_AIOHTTP = config_data.get('request_timeout_aiohttp', REQUEST_TIMEOUT_AIOHTTP)
            MIN_PROFILES_TO_DOWNLOAD = config_data.get('min_profiles_to_download', MIN_PROFILES_TO_DOWNLOAD)
            MAX_PROFILES_TO_DOWNLOAD = config_data.get('max_profiles_to_download', MAX_PROFILES_TO_DOWNLOAD)
            MAX_RETRIES_FETCH_PAGE = config_data.get('max_retries_fetch_page', MAX_RETRIES_FETCH_PAGE)
            RETRY_DELAY_BASE_FETCH_PAGE = config_data.get('retry_delay_base_fetch_page', RETRY_DELAY_BASE_FETCH_PAGE)
            DNS_TIMEOUT = config_data.get('dns_timeout', DNS_TIMEOUT)
            VALIDATION_TIMEOUT = config_data.get('validation_timeout', VALIDATION_TIMEOUT)
            VALIDATION_TEST_URL = config_data.get('validation_test_url', VALIDATION_TEST_URL)
            VALIDATION_SCORE_WEIGHTS = config_data.get('validation_score_weights', VALIDATION_SCORE_WEIGHTS_DEFAULT)
            VALIDATION_ANONYMITY_TIMEOUT = config_data.get('validation_anonymity_timeout', VALIDATION_ANONYMITY_TIMEOUT) # Load specific timeouts from config
            VALIDATION_SPEED_TIMEOUT = config_data.get('validation_speed_timeout', VALIDATION_SPEED_TIMEOUT) # Load specific timeouts from config


            logging.info(f'Configuration loaded.')
        else:
            logging.warning(f'Failed to load configuration from {CONFIG_FILE}. Using default values.')

        start_time = datetime.now()
        telegram_channel_names_original = await load_channels_async()
        if telegram_channel_names_original is None:
            logging.critical("Failed to load Telegram channel names. Exiting.")
            exit(1)

        telegram_channel_names_to_parse = list(telegram_channel_names_original)
        initial_channels_count = len(telegram_channel_names_original)
        logging.info(f'Initial channel count: {initial_channels_count}')

        channel_history_manager = ChannelHistoryManager()
        logging.info(f'Starting parsing process...')
        parsed_profiles, channels_with_profiles, channels_to_remove, channel_failure_counts, no_more_pages_counts = await run_parsing_async(
            telegram_channel_names_to_parse, channel_history_manager)
        logging.info(f'Parsing complete. Processing and filtering profiles...')

        final_profiles_scored = await process_parsed_profiles_async(parsed_profiles)
        profiles_to_save = final_profiles_scored[:min(max(len(final_profiles_scored), MIN_PROFILES_TO_DOWNLOAD), MAX_PROFILES_TO_DOWNLOAD)]
        await save_results(final_profiles_scored, profiles_to_save, channels_to_remove, telegram_channel_names_original,
                     channel_history_manager, channel_failure_counts, no_more_pages_counts)
        log_statistics(start_time, initial_channels_count, len(telegram_channel_names_to_parse), parsed_profiles,
                       final_profiles_scored, profiles_to_save, channels_with_profiles, channels_to_remove)

        logging.info("Main process completed successfully.")

    except Exception as main_exception:
        logging.critical(f"Critical error in main process: {main_exception}")
        logging.exception(main_exception)
        exit(1)


if __name__ == "__main__":
    asyncio.run(main_async())
