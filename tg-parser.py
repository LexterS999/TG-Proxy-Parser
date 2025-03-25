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
from typing import Dict, List, Optional, Set

from bs4 import BeautifulSoup
import urllib3
import geoip2.database
import aiofiles
import ipaddress  # Import ipaddress module

# --- Configuration Class ---
class Config:
    """Configuration parameters for the profile parser."""
    MAX_THREADS_PARSING = 30
    REQUEST_TIMEOUT_AIOHTTP = 30
    REQUEST_DELAY = 1.0  # Delay between requests in seconds
    MIN_PROFILES_TO_DOWNLOAD = 1000
    MAX_PROFILES_TO_DOWNLOAD = 200000
    ALLOWED_PROTOCOLS = {"vless", "hy2", "tuic", "trojan", "ss"}
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
    MAX_FAILED_CHECKS = 9
    FAILURE_HISTORY_FILE = 'channel_failure_history.json'
    NO_MORE_PAGES_HISTORY_FILE = 'no_more_pages_history.json'
    CIRCUIT_BREAKER_HISTORY_FILE = 'circuit_breaker_history.json'
    MAX_NO_MORE_PAGES_COUNT = 9
    PROFILE_FRESHNESS_DAYS = 7
    CONFIG_FILE = 'config.json'
    PROFILE_CLEANING_RULES_DEFAULT = []
    PROFILE_CLEANING_RULES = PROFILE_CLEANING_RULES_DEFAULT
    TELEGRAM_CHANNELS_FILE = 'telegram_channels.json'
    OUTPUT_CONFIG_FILE = 'config-tg.txt'
    GEOIP_DB_URL = "https://github.com/P3TERX/GeoLite.mmdb/releases/download/2025.03.13/GeoLite2-Country.mmdb"
    GEOIP_DB_PATH = "GeoLite2-Country.mmdb"
    GEOIP_ENABLED_DEFAULT = True
    GEOIP_ENABLED = GEOIP_ENABLED_DEFAULT
    CHANNEL_RETRY_ATTEMPTS = 3  # Number of retries for channel processing
    CHANNEL_RETRY_DELAY = 5  # Delay between channel retries in seconds
    CIRCUIT_BREAKER_THRESHOLD = 3  # Consecutive failures to activate circuit breaker
    CIRCUIT_BREAKER_COOLDOWN = 3600  # Circuit breaker cooldown period in seconds (1 hour)
    USER_AGENTS = [  # List of User-Agent strings for rotation
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
    ]


VLESS_EMOJI = "🌠"
HY2_EMOJI = "⚡"
TUIC_EMOJI = "🚀"
TROJAN_EMOJI = "🛡️"
SS_EMOJI = "🧦"
UNKNOWN_LOCATION_EMOJI = "🏴‍☠️"
# --- End Configuration ---

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Consider removing this and handling SSL properly

# Create config instance
config = Config()

if not os.path.exists(config.OUTPUT_CONFIG_FILE):
    with open(config.OUTPUT_CONFIG_FILE, 'w'):
        pass

class ChannelHistoryManager:
    """Manages channel history (failures, 'No More Pages', circuit breaker)."""

    def __init__(self, failure_file: str = config.FAILURE_HISTORY_FILE,
                 no_more_pages_file: str = config.NO_MORE_PAGES_HISTORY_FILE,
                 circuit_breaker_file: str = config.CIRCUIT_BREAKER_HISTORY_FILE): # Add circuit breaker file
        """Initializes ChannelHistoryManager."""
        self.failure_file = failure_file
        self.no_more_pages_file = no_more_pages_file
        self.circuit_breaker_file = circuit_breaker_file

    def _load_json_history(self, filepath: str) -> Dict:
        """Loads history from a JSON file, returns empty dict if file not found or load fails."""
        history = json_load(filepath)
        return history if history else {}

    def _save_json_history(self, history: Dict, filepath: str) -> bool:
        """Saves history to a JSON file."""
        logging.debug(f"Saving history to '{filepath}'.") # Changed log level to debug
        return json_save(history, filepath)

    def load_failure_history(self) -> Dict:
        """Loads channel failure history."""
        logging.debug(f"Loading failure history from '{self.failure_file}'.") # Changed log level to debug
        return self._load_json_history(self.failure_file)

    def save_failure_history(self, history: Dict) -> bool:
        """Saves channel failure history."""
        return self._save_json_history(history, self.failure_file)

    def load_no_more_pages_history(self) -> Dict:
        """Loads 'No More Pages' history for channels."""
        logging.debug(f"Loading 'No More Pages' history from '{self.no_more_pages_file}'.") # Changed log level to debug
        return self._load_json_history(self.no_more_pages_file)

    def save_no_more_pages_history(self, history: Dict) -> bool:
        """Saves 'No More Pages' history for channels."""
        return self._save_json_history(history, self.no_more_pages_file)

    def load_circuit_breaker_history(self) -> Dict:
        """Loads circuit breaker history from JSON file."""
        logging.debug(f"Loading circuit breaker history from '{self.circuit_breaker_file}'.") # Changed log level to debug
        return self._load_json_history(self.circuit_breaker_file)

    def save_circuit_breaker_history(self, history: Dict) -> bool:
        """Saves circuit breaker history to JSON file."""
        return self._save_json_history(history, self.circuit_breaker_file)

    def activate_circuit_breaker(self, channel_url: str) -> None:
        """Activates circuit breaker for a channel, records activation time."""
        history = self.load_circuit_breaker_history()
        history[channel_url] = datetime.now(timezone.utc).isoformat() # Store activation timestamp
        self.save_circuit_breaker_history(history)
        logging.info(f"Circuit breaker activated for channel '{channel_url}'.")

    def deactivate_circuit_breaker(self, channel_url: str) -> None:
        """Deactivates circuit breaker for a channel."""
        history = self.load_circuit_breaker_history()
        if channel_url in history:
            del history[channel_url]
            self.save_circuit_breaker_history(history)
            logging.info(f"Circuit breaker deactivated for channel '{channel_url}'.")

    def is_circuit_breaker_active(self, channel_url: str) -> bool:
        """Checks if circuit breaker is active for a channel and if cooldown period has expired."""
        history = self.load_circuit_breaker_history()
        if channel_url in history:
            activation_time_str = history[channel_url]
            try:
                activation_time = datetime.fromisoformat(activation_time_str).replace(tzinfo=timezone.utc)
                cooldown_expiration_time = activation_time + timedelta(seconds=config.CIRCUIT_BREAKER_COOLDOWN)
                if datetime.now(timezone.utc) < cooldown_expiration_time:
                    logging.debug(f"Circuit breaker is active for '{channel_url}', cooldown expires at {cooldown_expiration_time.strftime('%Y-%m-%d %H:%M:%S UTC')}.") # Debug log
                    return True
                else:
                    logging.info(f"Circuit breaker cooldown expired for '{channel_url}'. Deactivating.")
                    self.deactivate_circuit_breaker(channel_url) # Deactivate if cooldown expired
                    return False
            except ValueError as e:
                logging.error(f"Error parsing circuit breaker activation time for '{channel_url}': {e}. Deactivating circuit breaker.")
                self.deactivate_circuit_breaker(channel_url) # Deactivate if parsing error
                return False
        return False # Circuit breaker not active


def json_load(path: str) -> Optional[dict]:
    """Loads JSON file, handling file not found, empty file and JSON decode errors."""
    if not os.path.exists(path):
        logging.error(f"File not found: {path}")
        return None
    if os.stat(path).st_size == 0:
        logging.warning(f"File '{path}' is empty. Returning empty dictionary.")
        return {}
    try:
        with open(path, 'r', encoding="utf-8") as file:
            data = json.load(file)
            if not isinstance(data, (dict, list)):
                logging.error(f"File {path} does not contain a JSON object or array.")
                return None
            return data
    except json.JSONDecodeError as e:
        with open(path, 'r', encoding="utf-8") as f:
            content = f.read()
            if not content.strip():
                logging.warning(f"File '{path}' is empty, despite decode attempt. Returning empty dictionary.") # Single warning for empty file
                return {}
        logging.error(f"JSON decode error in file: {path} - {e}.")
        return None


def json_save(data: dict, path: str, indent: int = 4, backup: bool = True) -> bool:
    """Saves data to JSON file atomically with optional backup."""
    try:
        if backup and os.path.exists(path):
            backup_path = path + '.bak'
            shutil.copy2(path, backup_path)
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False) as tmp_file:
            json.dump(data, tmp_file, ensure_ascii=False, indent=indent)
        temp_filepath = tmp_file.name
        os.replace(temp_filepath, path)
        return True
    except (IOError, OSError, TypeError) as e: # More specific exception handling
        logging.error(f"Error saving JSON to file {path}: {e}")
        return False


def calculate_profile_score(profile: str, score_weights: Dict) -> int:
    """Calculates profile score based on configuration parameters."""
    protocol = profile.split("://")[0]
    if protocol not in config.ALLOWED_PROTOCOLS:
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
                score += score_weights.get("sni", 0) if "sni" in params else 0
                score += score_weights.get("alpn", 0) if "alpn" in params else 0

        if protocol == "vless":
            add_tls_score()
            score += score_weights.get("flow", 0) if "flow" in params else 0
            score += score_weights.get("headerType", 0) if "headerType" in params else 0
            score += score_weights.get("path", 0) if "path" in params else 0
        elif protocol == "hy2":
            add_tls_score()
            score += score_weights.get("obfs", 0) if "obfs" in params else 0
        elif protocol == "tuic":
            score += score_weights.get("alpn", 0) if "alpn" in params else 0
            score += score_weights.get("mport", 0) if "mport" in params else 0
        elif protocol == "trojan":
            add_tls_score()
            score += score_weights.get("obfs", 0) if "obfs" in params else 0
        elif protocol == "ss":
            score += 1

        base_params_count = len(profile.split("://")[1].split("@")[0].split(":"))
        score += base_params_count
    except (IndexError, KeyError, TypeError) as e: # More specific exception handling
        logging.error(f"Error calculating profile score for '{profile}': {e}")
        return 0
    return score


async def fetch_channel_page_async(session: aiohttp.ClientSession, channel_url: str, attempt: int) -> Optional[str]:
    """Asynchronously fetches a channel page with retry logic, handling specific aiohttp errors."""
    random_user_agent = random.choice(config.USER_AGENTS)
    headers = {'User-Agent': random_user_agent}

    for attempt_num in range(attempt, 3):
        try:
            async with session.get(f'https://t.me/s/{channel_url}', timeout=config.REQUEST_TIMEOUT_AIOHTTP, ssl=False, headers=headers) as response:
                response.raise_for_status()
                await asyncio.sleep(config.REQUEST_DELAY)  # Rate limiting delay
                return await response.text()
        except (aiohttp.ClientConnectionError, aiohttp.ClientResponseError) as e: # Specific ClientErrors
            log_message = f"aiohttp connection error for {channel_url}, attempt {attempt_num + 1}/3: {e}"
            if attempt_num < 2:
                delay = (2**attempt_num) + random.random()
                log_message += f". Retrying in {delay:.2f}s."
                await asyncio.sleep(delay)
            logging.warning(log_message)
            if attempt_num >= 2:
                logging.error(f"Max retries (3) exceeded for {channel_url} due to persistent connection errors.")
                return None
        except asyncio.TimeoutError:
            log_message = f"aiohttp timeout for {channel_url}, attempt {attempt_num + 1}/3."
            if attempt_num < 2:
                delay = (2**attempt_num) + random.random()
                log_message += f". Retrying in {delay:.2f}s."
                await asyncio.sleep(delay)
            logging.warning(log_message)
            if attempt_num >= 2:
                logging.error(f"Max retries (3) exceeded for {channel_url} due to persistent timeouts.")
                return None
    return None


async def parse_profiles_from_page_async(html_page: str, channel_url: str, allowed_protocols: Set[str], profile_score_func) -> List[Dict]:
    """Asynchronously parses profiles from an HTML page."""
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
                logging.warning(f"Failed to parse date for {channel_url}: {time_tag['datetime']}")

        for code_tag in code_tags:
            code_content_lines = str(code_tag).split('<br/>')
            for line in code_content_lines:
                cleaned_content = re.sub(htmltag_pattern, '', line).strip()
                for protocol in allowed_protocols:
                    if f"{protocol}://" in cleaned_content:
                        profile_link = cleaned_content
                        score = profile_score_func(profile_link, config.PROFILE_SCORE_WEIGHTS) # Pass score weights
                        channel_profiles.append({'profile': profile_link, 'score': score, 'date': message_datetime})
    return channel_profiles


async def process_channel_async(channel_url: str, parsed_profiles: List[Dict], thread_semaphore: asyncio.Semaphore,
                                telegram_channel_names: List[str], channels_parsed_count: int,
                                channels_with_profiles: Set[str], channel_failure_counts: Dict[str, int],
                                channels_to_remove: List[str], no_more_pages_counts: Dict[str, int],
                                allowed_protocols: Set[str], profile_score_func, channel_history_manager: ChannelHistoryManager) -> None: # Pass history manager
    """Asynchronously processes a Telegram channel to extract profiles with retry and circuit breaker."""
    if channel_history_manager.is_circuit_breaker_active(channel_url):
        logging.warning(f"Circuit breaker active for {channel_url}. Skipping channel.")
        return

    for retry_attempt in range(config.CHANNEL_RETRY_ATTEMPTS): # Channel-level retry loop
        failed_check = False
        channel_removed_in_run = False
        channel_session = None  # Define session outside try block for wider scope
        try:
            async with thread_semaphore:
                html_pages = []
                current_url = channel_url
                channel_profiles = []
                god_tg_name = False
                pattern_datbef = re.compile(r'(?:data-before=")(\d*)')
                no_more_pages_in_run = False

                channel_session = aiohttp.ClientSession() # Create session within retry loop
                for page_attempt in range(2): # Page fetch retry attempts
                    while True:
                        html_page = await fetch_channel_page_async(channel_session, current_url, page_attempt + 1)
                        if html_page:
                            html_pages.append(html_page)
                            last_datbef = re.findall(pattern_datbef, html_page)
                            if not last_datbef:
                                logging.info(f"No more pages found for {channel_url}")
                                no_more_pages_in_run = True
                                break
                            current_url = f'{channel_url}?before={last_datbef[0]}'
                            break
                        else:
                            failed_check = True
                            break # Break inner while loop to retry page fetch or move to next attempt
                    if failed_check:
                        break # Break page fetch retry loop if failed after attempts

                if not html_pages:
                    logging.warning(f"Failed to load pages for {channel_url} after retries. Skipping channel in this run.")
                    failed_check = True
                else:
                    failed_check = False

                channel_index = telegram_channel_names.index(channel_url) + 1
                logging.info(f'Processing channel {channel_index}/{channels_parsed_count}: {channel_url}')

                if not failed_check:
                    for page in html_pages:
                        profiles_on_page = await parse_profiles_from_page_async(page, channel_url, allowed_protocols, profile_score_func)
                        channel_profiles.extend(profiles_on_page)

                if channel_profiles:
                    channels_with_profiles.add(channel_url)
                    channel_failure_counts[channel_url] = 0 # Reset failure count on success
                    no_more_pages_counts[channel_url] = 0
                    god_tg_name = True
                else:
                    god_tg_name = False

                if not god_tg_name:
                    channel_failure_counts[channel_url] = channel_failure_counts.get(channel_url, 0) + 1
                    if channel_failure_counts[channel_url] >= config.MAX_FAILED_CHECKS and channel_url not in channels_to_remove:
                        channels_to_remove.append(channel_url)
                        channel_removed_in_run = True
                        logging.info(f"Channel '{channel_url}' removed due to {config.MAX_FAILED_CHECKS} consecutive failures.")
                    elif not channel_removed_in_run:
                        logging.info(f"No profiles found in {channel_url}. Consecutive failures: {channel_failure_counts[channel_url]}/{config.MAX_FAILED_CHECKS}.")

                if no_more_pages_in_run:
                    no_more_pages_counts[channel_url] = no_more_pages_counts.get(channel_url, 0) + 1
                    if no_more_pages_counts[channel_url] >= config.MAX_NO_MORE_PAGES_COUNT and channel_url not in channels_to_remove:
                        channels_to_remove.append(channel_url)
                        channel_removed_in_run = True
                        logging.info(f"Channel '{channel_url}' removed due to {config.MAX_NO_MORE_PAGES_COUNT} 'No More Pages' messages.")
                    elif not channel_removed_in_run:
                        logging.info(f"'No More Pages' message for '{channel_url}'. Consecutive messages: {no_more_pages_counts[channel_url]}/{config.MAX_NO_MORE_PAGES_COUNT}.")

                parsed_profiles.extend(channel_profiles)
                channel_history_manager.deactivate_circuit_breaker(channel_url) # Deactivate circuit breaker on successful processing
                break # Break retry loop on successful channel processing

        except Exception as channel_exception: # Catch-all for channel processing errors for retry logic
            logging.error(f"Error processing channel {channel_url} (attempt {retry_attempt + 1}/{config.CHANNEL_RETRY_ATTEMPTS}): {channel_exception}")
            if retry_attempt < config.CHANNEL_RETRY_ATTEMPTS - 1:
                retry_delay = config.CHANNEL_RETRY_DELAY * (retry_attempt + 1) # Exponential backoff or similar could be implemented
                logging.info(f"Retrying channel {channel_url} in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
            else:
                channel_failure_counts[channel_url] = channel_failure_counts.get(channel_url, 0) + 1 # Increment failure count even after retries fail
                if channel_failure_counts[channel_url] >= config.CIRCUIT_BREAKER_THRESHOLD:
                    channel_history_manager.activate_circuit_breaker(channel_url) # Activate circuit breaker after max retries fail
                    logging.warning(f"Circuit breaker activated for {channel_url} after {config.CIRCUIT_BREAKER_THRESHOLD} failures.")
                logging.error(f"Max retries for channel {channel_url} exceeded. Circuit breaker might be activated.")

        finally:
            if channel_session:
                await channel_session.close()
            if not failed_check and not channel_removed_in_run:
                break # Exit retry loop if channel was processed successfully

    else: # else block of for loop, executed if no 'break' was called in the loop (all retries failed)
        logging.error(f"Channel {channel_url} processing failed after {config.CHANNEL_RETRY_ATTEMPTS} retries.")


def clean_profile(profile_string: str, cleaning_rules: List[str]) -> str:
    """Cleans a profile string from unnecessary characters using provided rules."""
    part = profile_string
    for rule in cleaning_rules:
        part = re.sub(rule, '', part, flags=re.IGNORECASE)
    part = urllib_parse.unquote(urllib_parse.unquote(part)).strip()
    part = part.replace(' ', '') # Efficient space removal
    part = re.sub(r'[\x00\x01]', '', part) # Remove null and SOH characters in one go
    return part


def extract_ip_port(profile_string: str) -> Optional[tuple[str, str]]:
    """Extracts IP address and port from a profile string, returns None if extraction fails."""
    try:
        parsed_url = urllib_parse.urlparse(profile_string)
        netloc = parsed_url.netloc
        if "@" in netloc:
            netloc = netloc.split("@")[1]
        host_port = netloc.split(":")
        ip_address = host_port[0]
        port = host_port[1] if len(host_port) > 1 else None
        return ip_address, port
    except Exception: # Specific exceptions are harder to predict here, keep it broad, but consider logging exception type if needed
        return None, None


async def download_geoip_db(geoip_db_url: str, geoip_db_path: str) -> bool:
    """Downloads GeoLite2-Country.mmdb database if it doesn't exist or is outdated."""
    if os.path.exists(geoip_db_path):
        logging.info(f"GeoIP database already exists at {geoip_db_path}. Skipping download.") # Consider adding logic to update if outdated
        return True

    logging.info(f"Downloading GeoIP database from {geoip_db_url} to {geoip_db_path}...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(geoip_db_url) as response:
                if response.status == 200:
                    async with aiofiles.open(geoip_db_path, 'wb') as f:
                        await f.write(await response.read())
                    logging.info(f"GeoIP database downloaded successfully to {geoip_db_path}.")
                    return True
                else:
                    logging.error(f"Failed to download GeoIP database, status code: {response.status}")
                    return False
    except (aiohttp.ClientError, OSError) as e: # Specific exception handling
        logging.error(f"Error downloading GeoIP database: {e}")
        return False


async def get_country_name_from_ip(ip_address_or_hostname: str, geoip_reader: geoip2.database.Reader, session: aiohttp.ClientSession) -> str:
    """Retrieves country name from IP address or hostname using GeoLite2 database."""
    try:
        ip_address = None
        try:
            ip_address = ipaddress.ip_address(ip_address_or_hostname)
        except ValueError:
            # If not a valid IP, assume it's a hostname and resolve it
            try:
                resolved_ips = await session.get_resolver().resolve(ip_address_or_hostname)
                if resolved_ips:
                    ip_address = resolved_ips[0]['host'] # Take the first resolved IP
                else:
                    logging.warning(f"DNS resolution failed for hostname: {ip_address_or_hostname}") # Log as warning, not error
                    return UNKNOWN_LOCATION_EMOJI
            except aiohttp.ClientConnectorError as e:
                logging.warning(f"AIOHTTP ClientConnectorError during DNS resolution for {ip_address_or_hostname}: {e}") # Log as warning
                return UNKNOWN_LOCATION_EMOJI
            except Exception as e: # Broad exception for DNS resolution issues
                logging.error(f"Unexpected error during DNS resolution for {ip_address_or_hostname}: {e}")
                return UNKNOWN_LOCATION_EMOJI

        if ip_address:
            country_info = geoip_reader.country(str(ip_address)) # Pass string representation of IP
            country_name = country_info.country.names.get('en', 'Unknown')
            return country_name
        else:
            return UNKNOWN_LOCATION_EMOJI

    except geoip2.errors.AddressNotFoundError:
        return UNKNOWN_LOCATION_EMOJI
    except Exception as e: # Broad exception for GeoIP lookup errors
        logging.error(f"GeoIP lookup error for IP/Hostname {ip_address_or_hostname}: {e}")
        return UNKNOWN_LOCATION_EMOJI


async def _create_profile_dict(cleaned_profile_string: str, protocol: str, security_info: str, location_country: str, item_score: int, item_date: datetime) -> Optional[Dict]:
    """Helper function to create profile dictionary with beautiful name."""
    protocol_emojis = {
        "vless": VLESS_EMOJI,
        "hy2": HY2_EMOJI,
        "tuic": TUIC_EMOJI,
        "trojan": TROJAN_EMOJI,
        "ss": SS_EMOJI,
    }
    emoji = protocol_emojis.get(protocol)
    if not emoji:
        return None  # Unknown protocol

    part_no_fragment, _ = cleaned_profile_string.split('#', 1) if '#' in cleaned_profile_string else (cleaned_profile_string, "")
    beautiful_name = f"{emoji} {protocol.upper()} › Secure {security_info} - {location_country}" if security_info in ("TLS", "QUIC", "Shadowsocks") else f"{emoji} {protocol.upper()} › {security_info} - {location_country}"
    return {
        'profile': f"{part_no_fragment}#{beautiful_name}",
        'score': item_score,
        'date': item_date,
        'profile_name': beautiful_name
    }


async def process_parsed_profiles_async(parsed_profiles_list: List[Dict]) -> List[Dict]:
    """Processes parsed profiles: cleaning, deduplication, filtering, naming with GeoIP."""
    processed_profiles = []
    unique_ip_port_protocol_set = set()
    geoip_reader = None
    session_for_geoip = aiohttp.ClientSession() # Session for GeoIP lookups

    if config.GEOIP_ENABLED and not await download_geoip_db(config.GEOIP_DB_URL, config.GEOIP_DB_PATH): # Download only if enabled in config
        logging.warning("GeoIP database download failed. Location information will be replaced with pirate flag emoji.")
        geoip_country_lookup_enabled = False
    else:
        geoip_country_lookup_enabled = config.GEOIP_ENABLED # Respect config setting

    try:
        if geoip_country_lookup_enabled:
            try:
                geoip_reader = geoip2.database.Reader(config.GEOIP_DB_PATH)
            except Exception as e: # Handle potential GeoIP DB loading errors
                logging.error(f"Error initializing GeoIP database reader: {e}. Disabling GeoIP lookup.")
                geoip_country_lookup_enabled = False
                geoip_reader = None # Ensure geoip_reader is None in case of failure

        for item in parsed_profiles_list:
            cleaned_profile_string = clean_profile(item['profile'], config.PROFILE_CLEANING_RULES) # Pass cleaning rules
            protocol = ""
            profile_to_add = None

            ip, port = extract_ip_port(cleaned_profile_string)
            if not ip or not port:
                logging.warning(f"Failed to extract IP:port from profile: {cleaned_profile_string[:100]}...")
                continue

            if "vless://" in cleaned_profile_string:
                protocol = "vless"
            elif "hy2://" in cleaned_profile_string:
                protocol = "hy2"
            elif "tuic://" in cleaned_profile_string:
                protocol = "tuic"
            elif "trojan://" in cleaned_profile_string:
                protocol = "trojan"
            elif "ss://" in cleaned_profile_string:
                protocol = "ss"

            ip_port_protocol_tuple = (ip, port, protocol)
            if ip_port_protocol_tuple in unique_ip_port_protocol_set:
                logging.debug(f"Duplicate IP:port:protocol, profile skipped: {cleaned_profile_string[:100]}...")
                continue
            unique_ip_port_protocol_set.add(ip_port_protocol_tuple)

            params_str = cleaned_profile_string.split("://")[1]
            if "@" in params_str:
                params_str = params_str.split("@")[1]
            if "#" in params_str:
                params_str = params_str.split("#")[0]
            params = urllib_parse.parse_qs(params_str)

            security_info = "NoTLS"
            if params.get("security", [""])[0] == "tls":
                security_info = "TLS"
            elif protocol == "tuic":
                security_info = "QUIC" # Explicitly set security_info for TUIC
            elif protocol == "ss":
                security_info = "Shadowsocks" # Explicitly set security_info for SS


            location_country = UNKNOWN_LOCATION_EMOJI # Default emoji
            if geoip_country_lookup_enabled and geoip_reader:
                location_country_name = await get_country_name_from_ip(ip, geoip_reader, session_for_geoip)
                location_country = UNKNOWN_LOCATION_EMOJI if location_country_name == "Unknown" else location_country_name # Ensure emoji if "Unknown" from GeoIP

            profile_to_add = await _create_profile_dict(cleaned_profile_string, protocol, security_info, location_country, item['score'], item['date'])

            if profile_to_add:
                processed_profiles.append(profile_to_add)
                security_log_info = f"({security_info})" if security_info != UNKNOWN_LOCATION_EMOJI else "" # Correctly compare with emoji
                logging.debug(f"Added profile {protocol} {security_log_info} IP:Port {ip}:{port} Location: {location_country}")

        logging.info(f'Final profile processing: deduplication, freshness filtering...')

        unique_profiles_scored = []
        seen_profiles = set()
        for profile_data in processed_profiles:
            profile = profile_data['profile']
            # Improved filtering logic with comments
            is_unique = profile not in seen_profiles
            is_long_enough = len(profile) > 13 # Basic length check
            has_valid_fragment = (("…" in profile and "#" in profile) or ("…" not in profile)) # Check for "..." and "#" consistency, adjust as needed
            if is_unique and is_long_enough and has_valid_fragment:
                unique_profiles_scored.append(profile_data)
                seen_profiles.add(profile)

        processed_profiles_scored = unique_profiles_scored
        processed_profiles_strings = [item['profile'] for item in processed_profiles_scored]

        final_profiles_scored = []
        profile_strings_set = set(processed_profiles_strings)
        for profile_data in processed_profiles_scored:
            if profile_data['profile'] in profile_strings_set:
                final_profiles_scored.append(profile_data)
                profile_strings_set.remove(profile_data['profile'])

        fresh_profiles_scored = []
        now = datetime.now(timezone.utc)
        for profile_data in final_profiles_scored:
            if 'date' in profile_data and isinstance(profile_data['date'], datetime):
                time_difference = now - profile_data['date']
                if time_difference <= timedelta(days=config.PROFILE_FRESHNESS_DAYS):
                    fresh_profiles_scored.append(profile_data)
                    logging.debug(f"Keeping fresh profile (<{config.PROFILE_FRESHNESS_DAYS} days): {profile_data['date'].strftime('%Y-%m-%d %H:%M:%S UTC')}, {profile_data['profile'][:100]}...")
                else:
                    logging.info(f"Removing outdated profile (>={config.PROFILE_FRESHNESS_DAYS} days): {profile_data['date'].strftime('%Y-%m-%d %H:%M:%S UTC')}, {profile_data['profile'][:100]}...")
            else:
                fresh_profiles_scored.append(profile_data)

        final_profiles_scored = fresh_profiles_scored
        logging.info(f"After filtering, {len(final_profiles_scored)} unique profiles remain.")
        final_profiles_scored.sort(key=lambda item: item.get('score') or 0, reverse=True)
        return final_profiles_scored

    finally:
        if geoip_reader: # Safe close - check if geoip_reader is initialized
            geoip_reader.close()
        if config.GEOIP_ENABLED and os.path.exists(config.GEOIP_DB_PATH): # Remove only if GeoIP was enabled and DB exists
            os.remove(config.GEOIP_DB_PATH)
        await session_for_geoip.close() # Close GeoIP session


async def load_channels_async(channels_file: str = config.TELEGRAM_CHANNELS_FILE) -> List[str]: # Use config for default channel file
    """Loads channel list from a JSON file."""
    telegram_channel_names_original = json_load(channels_file)
    if telegram_channel_names_original is None:
        logging.critical(f"Failed to load channel list from {channels_file}. Exiting.")
        exit(1)
    telegram_channel_names_original[:] = [x for x in telegram_channel_names_original if len(x) >= 5]
    return list(set(telegram_channel_names_original))


async def run_parsing_async(telegram_channel_names_to_parse: List[str], channel_history_manager: ChannelHistoryManager, config: Config) -> tuple[ # Pass config object
    List[Dict], Set[str], List[str], Dict, Dict]:
    """Runs asynchronous channel parsing."""
    channels_parsed_count = len(telegram_channel_names_to_parse)
    logging.info(f'Starting parsing of {channels_parsed_count} channels...')

    channel_failure_counts = channel_history_manager.load_failure_history()
    no_more_pages_counts = channel_history_manager.load_no_more_pages_history()
    channels_to_remove = []
    thread_semaphore = asyncio.Semaphore(config.MAX_THREADS_PARSING)
    parsed_profiles = []
    channels_with_profiles = set()

    tasks = []
    for channel_name in telegram_channel_names_to_parse:
        task = asyncio.create_task(
            process_channel_async(channel_name, parsed_profiles, thread_semaphore, telegram_channel_names_to_parse,
                                    channels_parsed_count, channels_with_profiles, channel_failure_counts,
                                    channels_to_remove, no_more_pages_counts, config.ALLOWED_PROTOCOLS,
                                    calculate_profile_score, channel_history_manager) # Pass history manager and score function
        )
        tasks.append(task)

    await asyncio.gather(*tasks)
    return parsed_profiles, channels_with_profiles, channels_to_remove, channel_failure_counts, no_more_pages_counts


def save_results(final_profiles_scored: List[Dict], profiles_to_save: List[Dict], channels_to_remove: List[str],
                 telegram_channel_names_original: List[str], channel_history_manager: ChannelHistoryManager,
                 channel_failure_counts: Dict, no_more_pages_counts: Dict, config: Config) -> None: # Pass config object
    """Saves parsing results: profiles, updated channel list, history."""
    num_profiles_to_save = min(max(len(final_profiles_scored), config.MIN_PROFILES_TO_DOWNLOAD), config.MAX_PROFILES_TO_DOWNLOAD) # Use config values
    profiles_to_save = final_profiles_scored[:num_profiles_to_save]

    with open(config.OUTPUT_CONFIG_FILE, "w", encoding="utf-8") as file: # Use config for output file path
        for profile_data in profiles_to_save:
            file.write(f"{profile_data['profile'].encode('utf-8').decode('utf-8')}\n")

    if channels_to_remove:
        logging.info(f"Removing channels: {channels_to_remove}")
        telegram_channel_names_updated = [chan for chan in telegram_channel_names_original if chan not in channels_to_remove]
        if telegram_channel_names_updated != telegram_channel_names_original:
            json_save(telegram_channel_names_updated, config.TELEGRAM_CHANNELS_FILE) # Use config for channel list file
            logging.info(f"Updated channel list saved to {config.TELEGRAM_CHANNELS_FILE}. Removed {len(channels_to_remove)} channels.")
        else:
            logging.info("Channel list in {config.TELEGRAM_CHANNELS_FILE} remains unchanged.")
    else:
        logging.info("No channels to remove.")

    channel_history_manager.save_failure_history(channel_failure_counts)
    channel_history_manager.save_no_more_pages_history(no_more_pages_counts)
    channel_history_manager.save_circuit_breaker_history(channel_history_manager.load_circuit_breaker_history()) # Ensure circuit breaker history is also saved


def log_statistics(start_time: datetime, initial_channels_count: int, channels_parsed_count: int, parsed_profiles: List[Dict],
                   final_profiles_scored: List[Dict], profiles_to_save: List[Dict], channels_with_profiles: Set[str],
                   channels_to_remove: List[str], config: Config) -> None: # Pass config object
    """Logs final parsing statistics."""
    end_time = datetime.now()
    total_time = end_time - start_time

    logging.info("-" * 40)
    logging.info(f"{'--- Final Statistics ---':^40}")
    logging.info("-" * 40)
    logging.info(f"{'Total Execution Time:':<35} {str(total_time).split('.')[0]}")
    logging.info(f"{'Initial Channel Count:':<35} {initial_channels_count}")
    logging.info(f"{'Channels Processed:':<35} {channels_parsed_count}")
    logging.info(f"{'Channels with Profiles:':<35} {len(channels_with_profiles)}")
    logging.info(f"{'Profiles Found (Pre-processing):':<35} {len(parsed_profiles)}")
    logging.info(f"{'Unique Profiles (Post-processing):':<35} {len(final_profiles_scored)}")
    logging.info(f"{'Profiles Saved to config-tg.txt:':<35} {len(profiles_to_save)}") # Corrected log message
    logging.info(f"{'Channels Removed from List:':<35} {len(channels_to_remove)}")
    logging.info("-" * 40)
    logging.info('Parsing Completed!')


async def load_config_from_json(config: Config, config_file_path: str):
    """Loads configuration from JSON file into Config object."""
    logging.info(f'Loading configuration from {config_file_path}...')
    config_data = json_load(config_file_path)
    if config_data:
        config.PROFILE_SCORE_WEIGHTS = config_data.get('profile_score_weights', config.PROFILE_SCORE_WEIGHTS)
        config.PROFILE_CLEANING_RULES = config_data.get('profile_cleaning_rules', config.PROFILE_CLEANING_RULES_DEFAULT)
        config.PROFILE_FRESHNESS_DAYS = config_data.get('profile_freshness_days', config.PROFILE_FRESHNESS_DAYS)
        config.MAX_FAILED_CHECKS = config_data.get('max_failed_checks', config.MAX_FAILED_CHECKS)
        config.MAX_NO_MORE_PAGES_COUNT = config_data.get('max_no_more_pages_count', config.MAX_NO_MORE_PAGES_COUNT)
        config.MAX_THREADS_PARSING = config_data.get('max_threads_parsing', config.MAX_THREADS_PARSING)
        config.REQUEST_TIMEOUT_AIOHTTP = config_data.get('request_timeout_aiohttp', config.REQUEST_TIMEOUT_AIOHTTP)
        config.MIN_PROFILES_TO_DOWNLOAD = config_data.get('min_profiles_to_download', config.MIN_PROFILES_TO_DOWNLOAD)
        config.MAX_PROFILES_TO_DOWNLOAD = config_data.get('max_profiles_to_download', config.MAX_PROFILES_TO_DOWNLOAD)
        config.GEOIP_ENABLED = config_data.get('geoip_enabled', config.GEOIP_ENABLED_DEFAULT) # Load GeoIP enabled setting
        config.CHANNEL_RETRY_ATTEMPTS = config_data.get('channel_retry_attempts', config.CHANNEL_RETRY_ATTEMPTS)
        config.CHANNEL_RETRY_DELAY = config_data.get('channel_retry_delay', config.CHANNEL_RETRY_DELAY)
        config.CIRCUIT_BREAKER_THRESHOLD = config_data.get('circuit_breaker_threshold', config.CIRCUIT_BREAKER_THRESHOLD)
        config.CIRCUIT_BREAKER_COOLDOWN = config_data.get('circuit_breaker_cooldown', config.CIRCUIT_BREAKER_COOLDOWN)
        config.REQUEST_DELAY = config_data.get('request_delay', config.REQUEST_DELAY)
        user_agents_config = config_data.get('user_agents')
        if isinstance(user_agents_config, list) and user_agents_config: # Validate user_agents from config
            config.USER_AGENTS = user_agents_config
        logging.info(f'Configuration loaded from {config_file_path}.')
    else:
        logging.warning(f'Failed to load configuration from {config_file_path}. Using default values.')


async def main_async():
    """Main asynchronous function to run parsing and profile processing."""
    await load_config_from_json(config, config.CONFIG_FILE) # Load config at start

    start_time = datetime.now()
    telegram_channel_names_original = await load_channels_async()
    telegram_channel_names_to_parse = list(telegram_channel_names_original)
    initial_channels_count = len(telegram_channel_names_original)
    logging.info(f'Initial channel count: {initial_channels_count}')

    channel_history_manager = ChannelHistoryManager()
    logging.info(f'Starting parsing process...')
    parsed_profiles, channels_with_profiles, channels_to_remove, channel_failure_counts, no_more_pages_counts = await run_parsing_async(
        telegram_channel_names_to_parse, channel_history_manager, config) # Pass config object
    logging.info(f'Parsing complete. Processing and filtering profiles...')

    final_profiles_scored = await process_parsed_profiles_async(parsed_profiles)
    profiles_to_save = final_profiles_scored[:min(max(len(final_profiles_scored), config.MIN_PROFILES_TO_DOWNLOAD), config.MAX_PROFILES_TO_DOWNLOAD)] # Use config values here as well
    save_results(final_profiles_scored, profiles_to_save, channels_to_remove, telegram_channel_names_original,
                 channel_history_manager, channel_failure_counts, no_more_pages_counts, config) # Pass config object to save_results
    log_statistics(start_time, initial_channels_count, len(telegram_channel_names_to_parse), parsed_profiles,
                   final_profiles_scored, profiles_to_save, channels_with_profiles, channels_to_remove, config) # Pass config object to log_statistics


if __name__ == "__main__":
    asyncio.run(main_async())
