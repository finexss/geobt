import requests
import re
from urllib.parse import urlparse
import datetime
import ipaddress
import tldextract # 用于验证域名有效性
import logging
import sys
import os
import time
import json # 用于生成 JSON 文件

# --- Constants ---
SITE_JSON_FILE = "bt-site.json"
IP_JSON_FILE = "bt-ip.json"
SITE_TXT_FILE = "bt-site.txt"
IP_TXT_FILE = "bt-ip.txt"
LOG_ALL_FILE = "logall.txt" # Detailed log for the current run
LOG_SUMMARY_FILE = "log.txt" # Append-only summary log

# --- Configuration ---
# URLs list using multiline string for easier editing
TRACKER_URLS_TEXT = """
    https://api.yaozuopan.top:88/composite?key=bt&auth=3cae9a3a53f1daef137126648a535ab7
    https://www.gbsat.org/bt/tracker.txt
    https://github.com/XIU2/TrackersListCollection/raw/master/all.txt
    https://raw.githubusercontent.com/Tunglies/TrackersList/refs/heads/main/all.txt
    https://github.com/XIU2/TrackersListCollection/raw/master/all_aria2.txt
    https://github.com/XIU2/TrackersListCollection/raw/master/best.txt
    https://github.com/XIU2/TrackersListCollection/raw/master/best_aria2.txt
    https://github.com/XIU2/TrackersListCollection/raw/master/blacklist.txt
    https://github.com/XIU2/TrackersListCollection/raw/master/http.txt
    https://github.com/XIU2/TrackersListCollection/raw/master/http_aria2.txt
    https://github.com/XIU2/TrackersListCollection/raw/master/nohttp.txt
    https://github.com/XIU2/TrackersListCollection/raw/master/nohttp_aria2.txt
    https://github.com/XIU2/TrackersListCollection/raw/master/other.txt
    https://cf.trackerslist.com/all.txt
    https://cf.trackerslist.com/best.txt
    https://cf.trackerslist.com/http.txt
    https://cf.trackerslist.com/nohttp.txt
    https://github.com/ngosang/trackerslist/raw/master/blacklist.txt
    https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best.txt
    https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt
    https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_udp.txt
    https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_http.txt
    https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_https.txt
    https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_ws.txt
    https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best_ip.txt
    https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_ip.txt
    https://newtrackon.com/api/all
    # https://github.com/anthrax10/trakx/blob/master/public/trackers.txt # HTML format needs specific parser
    https://raw.githubusercontent.com/Anshuman8/open-trackers-list/master/trackers.txt
    https://raw.githubusercontent.com/adysec/tracker/refs/heads/main/trackers_all.txt
    https://raw.githubusercontent.com/adysec/tracker/refs/heads/main/trackers_best.txt
    https://raw.githubusercontent.com/hezhijie0327/Trackerslist/refs/heads/main/trackerslist_exclude.txt
    https://raw.githubusercontent.com/hezhijie0327/Trackerslist/refs/heads/main/trackerslist_combine.txt
    https://raw.githubusercontent.com/hezhijie0327/Trackerslist/refs/heads/main/trackerslist_tracker.txt
"""

# --- Setup Detailed Logging (logall.txt) ---
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('detailed_logger') # Use a specific name
logger.setLevel(logging.INFO) # Set to INFO for general logs, DEBUG for extraction details
logger.handlers.clear() # Ensure no duplicate handlers

# Handler for detailed log (overwrite)
log_all_handler = logging.FileHandler(LOG_ALL_FILE, mode='w', encoding='utf-8')
log_all_handler.setFormatter(log_formatter)
logger.addHandler(log_all_handler)

# Handler for console output (INFO level)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(log_formatter)
stream_handler.setLevel(logging.INFO) # Console shows INFO and above
logger.addHandler(stream_handler)
# --- Detailed Logging Ends ---

def parse_urls_from_text(text):
    """Parses URLs from the multiline text, handling potential errors."""
    urls = []
    for line in text.strip().splitlines():
        line = line.strip()
        if line and not line.startswith(('#', '//')): # Also ignore lines starting with //
            # Simple check if it looks like a URL before adding
            if re.match(r'^(https?|udp|wss?)://', line) or '.' in line:
              urls.append(line)
            else:
              logger.warning(f"Skipping line in URL list as it doesn't look like a URL: {line}")
    return urls

def download_and_split_trackers(url):
    """Downloads and splits tracker list from a URL."""
    tracker_entries = []
    try:
        logger.info(f"开始下载: {url}")
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, timeout=20, headers=headers)
        response.raise_for_status()
        content = response.text
        logger.info(f"下载成功: {url} (状态码: {response.status_code})")

        # Split by common delimiters, filter empty and comments robustly
        potential_entries = re.split(r'[,\n\s]+', content)
        for entry in potential_entries:
            entry = entry.strip()
            if entry and not entry.startswith('#'):
                # Check if entry looks like a valid part of a URL/address before adding
                if re.search(r'[:./\[\]]', entry) or '.' in entry: # More robust check
                    tracker_entries.append(entry)
                else:
                    logger.warning(f"忽略无效条目: '{entry}' (来自: {url})")

    except requests.exceptions.Timeout:
        logger.error(f"下载超时: {url}")
    except requests.exceptions.RequestException as e:
        logger.error(f"下载失败: {url} - {e}")
    except Exception as e:
        logger.error(f"处理下载内容时出错 ({url}): {e}")

    logger.info(f"从 {url} 提取了 {len(tracker_entries)} 个有效条目")
    return tracker_entries

def extract_domain_or_ip(tracker_entry):
    """Extracts domain (no port) or IP address from a tracker entry."""
    domain = None
    ip = None
    original_entry = tracker_entry
    logger.debug(f"开始处理条目: {original_entry}") # Use debug for this level

    try:
        # 1. Remove protocol if present
        entry_no_proto = re.sub(r"^\w+://", "", tracker_entry)

        # 2. Get the part before the first slash (potential netloc)
        netloc_part = entry_no_proto.split("/", 1)[0]

        # 3. Use regex to correctly separate host from optional port, handling IPv6 brackets
        # Regex: Group 1 captures bracketed IPv6 OR non-colon chars (host). Group 3 captures optional port digits.
        match = re.match(r'(\[([0-9a-fA-F:]+)\]|([^:]+))(?::(\d+))?', netloc_part)

        if not match:
            logger.warning(f"无法从 netloc '{netloc_part}' 分离 host/port (来自: {original_entry})")
            return None, None

        # The actual host is either group 2 (IPv6 inside brackets) or group 3 (non-IPv6 host)
        host_candidate = match.group(2) if match.group(2) else match.group(3)

        if not host_candidate: # Should not happen if regex matched, but as a safeguard
             logger.warning(f"无法从 netloc '{netloc_part}' 提取 host (来自: {original_entry})")
             return None, None

        logger.debug(f"分离得到 Host Candidate: {host_candidate} (来自 netloc: {netloc_part})")

        # 4.优先尝试解析为 IP 地址 (using the correctly extracted host)
        try:
            ip_addr = ipaddress.ip_address(host_candidate)
            ip = str(ip_addr)
            logger.debug(f"识别为 IP: {ip} (来自: {original_entry})")
            domain = None # It's an IP
        except ValueError:
            # 5. 如果不是 IP 地址, 认为是域名
            domain_candidate = host_candidate # The extracted host IS the candidate
            # Basic validation for domain structure - Check TLD presence and basic chars
            if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", domain_candidate):
                domain = domain_candidate
                logger.debug(f"识别为域名: {domain} (来自: {original_entry})")
                # Optional: Further validation with tldextract if needed
                # try:
                #     ext = tldextract.extract(domain)
                #     if not ext.suffix:
                #         logger.warning(f"域名 '{domain}' 缺少有效后缀 (来自: {original_entry})")
                #         domain = None # Discard if no valid suffix found by tldextract
                # except Exception as tld_e:
                #      logger.error(f"tldextract validation error for '{domain}': {tld_e}")
                #      # Decide whether to keep the domain or discard it on error
            else:
                logger.warning(f"提取的主机名 '{domain_candidate}' 不符合基本域名格式 (来自: {original_entry})")
                domain = None

    except Exception as e:
        logger.error(f"解析条目时发生未知错误 '{original_entry}': {e}")

    return domain, ip

def read_existing_items(filepath):
    """Reads existing items (one per line) from a txt file."""
    items = set()
    if not os.path.exists(filepath):
        logger.info(f"文件不存在，将创建新文件: {filepath}")
        return items
    try:
        with open(filepath, "r", encoding='utf-8') as f:
            for line in f:
                item = line.strip()
                if item:
                    items.add(item)
        logger.info(f"从 {filepath} 读取了 {len(items)} 个现有条目")
    except Exception as e:
        logger.error(f"读取文件 {filepath} 失败: {e}")
    return items

def append_items_to_txt(filepath, items_to_add):
    """Appends new items (one per line) to a txt file."""
    if not items_to_add:
        logger.info(f"没有新条目需要追加到 {filepath}")
        return
    try:
        # Ensure directory exists before writing
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        with open(filepath, "a", encoding='utf-8') as f:
            f.write("\n") # Add a newline before appending new items if file is not empty
            for item in sorted(list(items_to_add)):
                f.write(f"{item}\n")
        logger.info(f"向 {filepath} 增量添加了 {len(items_to_add)} 个条目")
    except IOError as e:
        logger.error(f"追加写入文件 {filepath} 失败: {e}")

def write_json_like_file(filepath, all_items):
    """Writes items to a file mimicking the specified JSON-like format."""
    lines = []
    for item in sorted(list(all_items)):
        lines.append(f'\t\t    "{item}",')
    content = "\n".join(lines)
    try:
        # Ensure directory exists before writing
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        with open(filepath, "w", encoding='utf-8') as f:
            f.write(content)
        logger.info(f"成功覆盖写入 {filepath} (包含 {len(all_items)} 条目)")
    except IOError as e:
        logger.error(f"覆盖写入文件 {filepath} 失败: {e}")

def write_summary_log(data):
    """Appends a summary to the summary log file."""
    # Format duration nicely
    duration_td = datetime.timedelta(seconds=data['duration_seconds'])
    # Remove microseconds for cleaner output
    duration_str = str(duration_td).split('.')[0]

    summary = f"""
--- 运行总结 ({data['timestamp']}) ---
总耗时: {duration_str}
处理的 URL 数量: {data['url_count']}
收集的原始条目数: {data['raw_entries']}
提取的唯一域名数 (本次): {data['new_domains_count']} (总计: {data['total_domains']})
提取的唯一 IP 地址数 (本次): {data['new_ips_count']} (总计: {data['total_ips']})
-------------------------------------
"""
    try:
        # Ensure directory exists before writing
        os.makedirs(os.path.dirname(LOG_SUMMARY_FILE) or '.', exist_ok=True)
        with open(LOG_SUMMARY_FILE, "a", encoding='utf-8') as f:
            f.write(summary)
        logger.info("写入运行总结到 " + LOG_SUMMARY_FILE)
        # Also log summary to the detailed log
        for line in summary.strip().splitlines():
            logger.info(line)
    except IOError as e:
        logger.error(f"写入总结日志 {LOG_SUMMARY_FILE} 失败: {e}")

# --- Main Execution ---
def main():
    logger.info("脚本开始运行")
    start_time = time.time()

    # 1. Parse URLs from multiline text
    tracker_list_urls = parse_urls_from_text(TRACKER_URLS_TEXT)
    logger.info(f"解析得到 {len(tracker_list_urls)} 个 tracker URLs")

    # 2. Read existing data from .txt files for incremental update
    existing_domains = read_existing_items(SITE_TXT_FILE)
    existing_ips = read_existing_items(IP_TXT_FILE)

    # 3. Download and process all URLs
    all_tracker_entries = []
    for url in tracker_list_urls:
        entries = download_and_split_trackers(url)
        if entries:
            all_tracker_entries.extend(entries)

    logger.info(f"总共收集到 {len(all_tracker_entries)} 个潜在 Tracker 条目")

    # 4. Extract domains and IPs from collected entries
    current_domains = set()
    current_ips = set()
    processed_count = 0
    for entry in all_tracker_entries:
        processed_count += 1
        domain, ip = extract_domain_or_ip(entry)
        if ip:
            current_ips.add(ip)
        elif domain:
            # Domain validation happened inside extract_domain_or_ip
            current_domains.add(domain)

    logger.info(f"处理完成 {processed_count} 个条目")
    logger.info(f"本次运行提取到 {len(current_domains)} 个唯一域名和 {len(current_ips)} 个唯一 IP 地址")

    # 5. Calculate newly added items for incremental update
    added_domains = current_domains - existing_domains
    added_ips = current_ips - existing_ips
    logger.info(f"发现 {len(added_domains)} 个新域名")
    logger.info(f"发现 {len(added_ips)} 个新 IP 地址")

    # 6. Incrementally update .txt files
    append_items_to_txt(SITE_TXT_FILE, added_domains)
    append_items_to_txt(IP_TXT_FILE, added_ips)

    # 7. Overwrite .json files with the full current set (old + new)
    all_final_domains = existing_domains.union(added_domains)
    all_final_ips = existing_ips.union(added_ips)
    write_json_like_file(SITE_JSON_FILE, all_final_domains)
    write_json_like_file(IP_JSON_FILE, all_final_ips)

    # 8. Write summary log
    end_time = time.time()
    duration_seconds = end_time - start_time
    summary_data = {
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'duration_seconds': duration_seconds,
        'url_count': len(tracker_list_urls),
        'raw_entries': len(all_tracker_entries),
        'new_domains_count': len(added_domains),
        'total_domains': len(all_final_domains),
        'new_ips_count': len(added_ips),
        'total_ips': len(all_final_ips),
    }
    write_summary_log(summary_data)
    logger.info("脚本运行成功结束")

if __name__ == "__main__":
    main()
