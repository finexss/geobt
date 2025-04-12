import requests
import re
from urllib.parse import urlparse, unquote # Added unquote
import datetime
import ipaddress
import tldextract
import logging
import sys
import os
import time
import json

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
    # https://github.com/anthrax10/trakx/blob/master/public/trackers.txt # HTML
    https://raw.githubusercontent.com/Anshuman8/open-trackers-list/master/trackers.txt
    https://raw.githubusercontent.com/adysec/tracker/refs/heads/main/trackers_all.txt
    https://raw.githubusercontent.com/adysec/tracker/refs/heads/main/trackers_best.txt
    https://raw.githubusercontent.com/hezhijie0327/Trackerslist/refs/heads/main/trackerslist_exclude.txt
    https://raw.githubusercontent.com/hezhijie0327/Trackerslist/refs/heads/main/trackerslist_combine.txt
    https://raw.githubusercontent.com/hezhijie0327/Trackerslist/refs/heads/main/trackerslist_tracker.txt
"""

# --- Setup Detailed Logging (logall.txt) ---
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('detailed_logger')
logger.setLevel(logging.INFO) # Keep INFO default, set DEBUG for dev
logger.handlers.clear()

log_all_handler = logging.FileHandler(LOG_ALL_FILE, mode='w', encoding='utf-8')
log_all_handler.setFormatter(log_formatter)
logger.addHandler(log_all_handler)

stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(log_formatter)
stream_handler.setLevel(logging.INFO)
logger.addHandler(stream_handler)
# --- Detailed Logging Ends ---

def parse_urls_from_text(text):
    """Parses URLs from the multiline text."""
    urls = []
    for line in text.strip().splitlines():
        line = line.strip()
        # Allow http/https/udp/wss protocols or lines containing a dot
        if line and not line.startswith(('#', '//')) and \
           (re.match(r'^(https?|udp|wss?)://', line) or '.' in line):
            urls.append(line)
        elif line and not line.startswith(('#', '//')):
             logger.warning(f"Skipping line in URL list (doesn't look like URL/domain): {line}")
    return urls

def download_and_split_trackers(url):
    """Downloads tracker list and splits into individual tracker entries."""
    tracker_entries = set() # Use a set to avoid duplicates from the same source
    try:
        logger.info(f"开始下载: {url}")
        headers = {'User-Agent': 'Mozilla/5.0'} # Simpler UA
        response = requests.get(url, timeout=20, headers=headers, stream=True) # stream=True for potentially large files
        response.raise_for_status()
        content_type = response.headers.get('content-type', '').lower()
        logger.info(f"下载成功: {url} (状态码: {response.status_code}, 类型: {content_type})")

        # --- Robust Splitting Logic ---
        full_content = ""
        for chunk in response.iter_content(chunk_size=8192, decode_unicode=True):
             if chunk: # filter out keep-alive new chunks
                 full_content += chunk
        
        # Split content primarily by newline, secondary by comma within lines
        lines = full_content.splitlines()
        processed_line_count = 0
        for line in lines:
            processed_line_count += 1
            line = line.strip()
            # Remove comments first
            line_no_comment = line.split('#', 1)[0].strip()
            
            if not line_no_comment:
                continue

            # Now split the cleaned line by comma or whitespace
            # Prioritize comma, then space
            potential_entries = []
            if ',' in line_no_comment:
                potential_entries = [p.strip() for p in line_no_comment.split(',') if p.strip()]
            else:
                potential_entries = [p.strip() for p in re.split(r'\s+', line_no_comment) if p.strip()]

            # Add valid-looking entries to the set
            for entry in potential_entries:
                 # Basic filter: ignore single words, numbers, likely garbage
                 if len(entry) > 3 and ('.' in entry or ':' in entry or '[' in entry):
                    # Decode URL encoding which might be present
                    try:
                        decoded_entry = unquote(entry)
                        tracker_entries.add(decoded_entry)
                        logger.debug(f"Added potential entry: '{decoded_entry}' (from {url})")
                    except Exception as decode_err:
                         logger.error(f"URL 解码失败 for '{entry}': {decode_err}")
                 else:
                     logger.warning(f"忽略分割后看起来无效的条目: '{entry}' (来自行: '{line}' in {url})")

    except requests.exceptions.Timeout:
        logger.error(f"下载超时: {url}")
    except requests.exceptions.RequestException as e:
        logger.error(f"下载失败: {url} - {e}")
    except Exception as e:
        logger.error(f"处理下载内容时出错 ({url}): {e}")

    logger.info(f"从 {url} 提取了 {len(tracker_entries)} 个唯一有效条目")
    return list(tracker_entries) # Return as list

def extract_domain_or_ip(tracker_entry):
    """Extracts domain (no port) or IP address from a tracker entry."""
    domain = None
    ip = None
    original_entry = tracker_entry
    logger.debug(f"开始处理条目: {original_entry}")

    try:
        # 1. Remove known protocol prefixes robustly
        entry_no_proto = re.sub(r"^(?:https?|udp|wss?)://", "", tracker_entry, count=1)

        # 2. Get the part before the first slash
        netloc_part = entry_no_proto.split("/", 1)[0]

        if not netloc_part:
            logger.warning(f"处理后 netloc 为空 (来自: {original_entry})")
            return None, None

        # 3. Separate host and optional port (Handles IPv6 brackets and missing colons correctly)
        host_candidate = ""
        port = None

        # Regex explanation:
        # ^                     - Start of string
        # (?:                   - Start of non-capturing group for host part
        #   \[(.*?)\]         - Group 1: Literal [, capture anything inside lazily, literal ] (IPv6)
        #   |                 - OR
        #   ([^:/\[]+)        - Group 2: Capture chars NOT colon, slash, or bracket (IPv4/Domain)
        # )                     - End of non-capturing group for host part
        # (?:[:](\d+))?        - Optional non-capturing group for port: literal :, capture digits (Group 3)
        # $                     - End of string
        match = re.match(r'^(?:\[(.*?)\]|([^:/\[]+))(?:[:](\d+))?$', netloc_part)

        if match:
            host_candidate = match.group(1) if match.group(1) else match.group(2)
            port = match.group(3) # Port number as string, or None
            logger.debug(f"Regex分离: Host='{host_candidate}', Port='{port}' (来自 netloc: {netloc_part})")
        else:
            # If regex fails, maybe it's just a bare domain/IP without protocol/path?
            # Check if the original cleaned netloc_part itself is an IP or basic domain
             if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", netloc_part) or \
                (netloc_part and not any(c in netloc_part for c in ['/','?', '#'])): # Avoid path chars
                 try:
                     ipaddress.ip_address(netloc_part) # Check if bare string is IP
                     host_candidate = netloc_part
                 except ValueError:
                     if '.' in netloc_part: # Assume domain-like if it has a dot
                         host_candidate = netloc_part
                     else:
                          logger.warning(f"复杂 Netloc 无法解析: '{netloc_part}' (来自: {original_entry})")
                          return None, None
             else:
                logger.warning(f"复杂 Netloc 无法解析: '{netloc_part}' (来自: {original_entry})")
                return None, None

        if not host_candidate:
             logger.warning(f"最终无法提取 Host Candidate (来自: {original_entry})")
             return None, None

        # 4. Prioritize IP address identification
        try:
            ip_addr = ipaddress.ip_address(host_candidate)
            ip = str(ip_addr)
            logger.debug(f"识别为 IP: {ip} (来自: {original_entry})")
            domain = None
        except ValueError:
            # 5. If not IP, treat as domain candidate
            domain_candidate = host_candidate
            # Validate basic domain structure AND that it has a valid TLD using tldextract
            if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", domain_candidate):
                try:
                    ext = tldextract.extract(domain_candidate)
                    # Check BOTH domain part AND suffix are present
                    if ext.domain and ext.suffix:
                        domain = domain_candidate # Use the full hostname
                        logger.debug(f"识别为有效域名: {domain} (来自: {original_entry})")
                    else:
                        logger.warning(f"tldextract 验证失败 (缺少 domain/suffix): '{domain_candidate}' (来自: {original_entry})")
                        domain = None
                except Exception as tld_e:
                    logger.error(f"tldextract 在验证 '{domain_candidate}' 时出错: {tld_e}, 保留")
                    domain = domain_candidate # Keep if tldextract caused error
            else:
                # This catches things like 'tracker.renfei.net80' because 'net80' isn't a valid TLD structure
                logger.warning(f"提取的主机名 '{domain_candidate}' 不符合基本域名格式或无效 TLD (来自: {original_entry})")
                domain = None

    except Exception as e:
        logger.error(f"解析条目时发生严重错误 '{original_entry}': {e}", exc_info=True) # Log traceback

    return domain, ip

# --- Utility Functions (No changesNeeded) ---
def read_existing_items(filepath):
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
    if not items_to_add:
        logger.info(f"没有新条目需要追加到 {filepath}")
        return
    try:
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        is_new_file = not os.path.exists(filepath) or os.path.getsize(filepath) == 0
        with open(filepath, "a", encoding='utf-8') as f:
            if not is_new_file: # Add newline only if file existed and wasn't empty
                f.write("\n")
            f.write("\n".join(sorted(list(items_to_add))))
        logger.info(f"向 {filepath} 增量添加了 {len(items_to_add)} 个条目")
    except IOError as e:
        logger.error(f"追加写入文件 {filepath} 失败: {e}")

def write_json_like_file(filepath, all_items):
    lines = []
    for item in sorted(list(all_items)):
        lines.append(f'\t\t    "{item}",')
    content = "\n".join(lines)
    try:
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        with open(filepath, "w", encoding='utf-8') as f:
            f.write(content)
        logger.info(f"成功覆盖写入 {filepath} (包含 {len(all_items)} 条目)")
    except IOError as e:
        logger.error(f"覆盖写入文件 {filepath} 失败: {e}")

def write_summary_log(data):
    duration_td = datetime.timedelta(seconds=data['duration_seconds'])
    duration_str = str(duration_td).split('.')[0] # HH:MM:SS format
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
        os.makedirs(os.path.dirname(LOG_SUMMARY_FILE) or '.', exist_ok=True)
        with open(LOG_SUMMARY_FILE, "a", encoding='utf-8') as f:
            f.write(summary)
        logger.info("写入运行总结到 " + LOG_SUMMARY_FILE)
        for line in summary.strip().splitlines():
            logger.info(line)
    except IOError as e:
        logger.error(f"写入总结日志 {LOG_SUMMARY_FILE} 失败: {e}")

# --- Main Execution ---
def main():
    logger.info("脚本开始运行")
    start_time = time.time()

    tracker_list_urls = parse_urls_from_text(TRACKER_URLS_TEXT)
    logger.info(f"解析得到 {len(tracker_list_urls)} 个 tracker URLs")

    existing_domains = read_existing_items(SITE_TXT_FILE)
    existing_ips = read_existing_items(IP_TXT_FILE)

    all_tracker_entries = []
    for url in tracker_list_urls:
        entries = download_and_split_trackers(url)
        if entries:
            all_tracker_entries.extend(entries)

    logger.info(f"总共收集到 {len(all_tracker_entries)} 个潜在 Tracker 条目")

    current_domains = set()
    current_ips = set()
    processed_count = 0
    for entry in all_tracker_entries:
        processed_count += 1
        domain, ip = extract_domain_or_ip(entry)
        if ip:
            current_ips.add(ip)
        elif domain:
            current_domains.add(domain)

    logger.info(f"处理完成 {processed_count} 个条目")
    logger.info(f"本次运行提取到 {len(current_domains)} 个唯一域名和 {len(current_ips)} 个唯一 IP 地址")

    added_domains = current_domains - existing_domains
    added_ips = current_ips - existing_ips
    logger.info(f"发现 {len(added_domains)} 个新域名")
    logger.info(f"发现 {len(added_ips)} 个新 IP 地址")

    append_items_to_txt(SITE_TXT_FILE, added_domains)
    append_items_to_txt(IP_TXT_FILE, added_ips)

    all_final_domains = existing_domains.union(added_domains)
    all_final_ips = existing_ips.union(added_ips)
    write_json_like_file(SITE_JSON_FILE, all_final_domains)
    write_json_like_file(IP_JSON_FILE, all_final_ips)

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
