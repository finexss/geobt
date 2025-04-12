import requests
import re
from urllib.parse import urlparse, unquote
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
    https://raw.githubusercontent.com/Anshuman8/open-trackers-list/master/trackers.txt
    https://raw.githubusercontent.com/adysec/tracker/refs/heads/main/trackers_all.txt
    https://raw.githubusercontent.com/adysec/tracker/refs/heads/main/trackers_best.txt
    https://raw.githubusercontent.com/hezhijie0327/Trackerslist/refs/heads/main/trackerslist_exclude.txt
    https://raw.githubusercontent.com/hezhijie0327/Trackerslist/refs/heads/main/trackerslist_combine.txt
    https://raw.githubusercontent.com/hezhijie0327/Trackerslist/refs/heads/main/trackerslist_tracker.txt
"""

# --- Setup Detailed Logging ---
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('detailed_logger')
logger.setLevel(logging.INFO) # Keep INFO default
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
        if line and not line.startswith(('#', '//')):
            # Basic check if it looks like a URL or domain structure
            if re.match(r'^(https?|udp|wss?)://', line) or '.' in line:
                urls.append(line)
            else:
                logger.warning(f"Skipping line in URL list (doesn't look like URL/domain): {line}")
    return urls

def clean_html_and_extract_urls(text):
    """Removes basic HTML tags and extracts potential URLs."""
    # Basic removal of HTML tags
    text_no_html = re.sub(r'<[^>]+>', '', text)
    # Find potential URLs using a more specific regex after cleaning
    potential_urls = re.findall(r'(?:udp|https?|wss)://(?:\[[a-fA-F0-9:]+\]|[^:/\s\'"<>]+)(?::\d+)?(?:/[^\s\'"<>]*)?', text_no_html)
    return [url.strip() for url in potential_urls if url]

def download_and_split_trackers(url):
    """Downloads tracker list and splits into individual tracker entries."""
    tracker_entries = set()
    try:
        logger.info(f"开始下载: {url}")
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, timeout=20, headers=headers, stream=True)
        response.raise_for_status()
        content_type = response.headers.get('content-type', '').lower()
        logger.info(f"下载成功: {url} (状态码: {response.status_code}, 类型: {content_type})")

        # --- V5: Refined Splitting Logic ---
        is_json_attempted = False
        if 'json' in content_type or url.endswith('/api/all'):
            is_json_attempted = True
            try:
                 # Read the full content for JSON parsing
                 full_content = response.content.decode('utf-8', errors='ignore')
                 data = json.loads(full_content)
                 if isinstance(data, list):
                     count = 0
                     for item in data:
                         if isinstance(item, str):
                             entry = item.strip()
                             if entry:
                                 # Further clean potential HTML remnants even from JSON
                                 cleaned_entries = clean_html_and_extract_urls(unquote(entry))
                                 if cleaned_entries:
                                     tracker_entries.update(cleaned_entries)
                                     logger.debug(f"Added from JSON list: {cleaned_entries}")
                                     count += len(cleaned_entries)
                                 elif '.' in entry or ':' in entry: # Keep simple domain/ip if clean fails
                                      tracker_entries.add(unquote(entry))
                                      logger.debug(f"Added simple entry from JSON list: {unquote(entry)}")
                                      count += 1

                     logger.info(f"从 JSON {url} 解析了 {count} 个条目")
                 else:
                     logger.warning(f"URL 返回了非列表的 JSON ({type(data)})，未处理: {url}")
                 return list(tracker_entries) # Return early if JSON was successfully processed
            except json.JSONDecodeError:
                 logger.warning(f"URL {url} 检测到 JSON 类型但解析失败，将尝试文本分割。")
            except Exception as e:
                 logger.error(f"处理 JSON 内容时出错 ({url}): {e}")
                 # Fall through to text processing if JSON handling fails

        # --- Text Processing (if not JSON or JSON failed) ---
        processed_lines = 0
        for line in response.iter_lines(decode_unicode=True, errors='ignore'):
            processed_lines +=1
            if not line: continue
            line = line.strip()
            line_no_comment = line.split('#', 1)[0].strip()
            if not line_no_comment: continue

            # V5 Fix: Use regex to find potential tracker URLs within the line
            # This handles comments better and extracts URLs even if mixed with other text
            # It also helps clean the HTML remnants seen in logs '/>udp://...'
            found_urls = re.findall(r'(?:udp|https?|wss)://(?:\[[a-fA-F0-9:]+\]|[^:/\s\'"<>]+)(?::\d+)?(?:/[^\s\'"<>]*)?', line_no_comment)

            if found_urls:
                for found_url in found_urls:
                    try:
                        decoded_entry = unquote(found_url.strip())
                        if decoded_entry:
                             tracker_entries.add(decoded_entry)
                             logger.debug(f"从文本行通过 Regex 添加: '{decoded_entry}' (来自 {url})")
                    except Exception as decode_err:
                         logger.error(f"URL 解码失败 for '{found_url}': {decode_err}")
            elif '.' in line_no_comment or ':' in line_no_comment:
                 # If no full URL found, but line has potential hosts, treat the whole line as one entry
                 # (This covers cases where a source just lists domains/IPs)
                 try:
                     decoded_entry = unquote(line_no_comment)
                     if decoded_entry:
                         tracker_entries.add(decoded_entry)
                         logger.debug(f"将整行非注释部分作为条目添加: '{decoded_entry}' (来自 {url})")
                 except Exception as decode_err:
                     logger.error(f"URL 解码失败 for line '{line_no_comment}': {decode_err}")

    except requests.exceptions.Timeout:
        logger.error(f"下载超时: {url}")
    except requests.exceptions.RequestException as e:
        logger.error(f"下载失败: {url} - {e}")
    except Exception as e:
        logger.error(f"处理下载内容时出错 ({url}): {e}", exc_info=True)

    logger.info(f"从 {url} 提取了 {len(tracker_entries)} 个唯一有效条目 (JSON尝试: {is_json_attempted})")
    return list(tracker_entries)

def extract_domain_or_ip(tracker_entry):
    """Extracts domain (no port) or IP address from a tracker entry. V5"""
    domain = None
    ip = None
    original_entry = tracker_entry
    logger.debug(f"开始处理条目: {original_entry}")

    try:
        # 1. Add default scheme if missing, needed for urlparse
        if not re.match(r"^\w+://", tracker_entry):
             temp_netloc_guess = tracker_entry.split('/', 1)[0]
             if '.' in temp_netloc_guess or ':' in temp_netloc_guess or (temp_netloc_guess.startswith('[') and temp_netloc_guess.endswith(']')):
                 parsed = urlparse(f"udp://{tracker_entry}") # Assume UDP
                 logger.debug(f"为 '{tracker_entry}' 添加默认 scheme 'udp://'")
             else:
                  logger.warning(f"条目缺少协议且不像 netloc: '{tracker_entry}'")
                  return None, None
        else:
             # Check for malformed nested protocols like "udp://http://..."
             if re.match(r"^(?:udp|wss)://(?:https?)://", tracker_entry):
                  logger.warning(f"检测到嵌套协议，尝试提取内部 URL: '{tracker_entry}'")
                  inner_url_match = re.search(r"(?:https?)://.*", tracker_entry)
                  if inner_url_match:
                       tracker_entry = inner_url_match.group(0) # Reparse the inner part
                       logger.debug(f"将重新解析内部部分: '{tracker_entry}'")
                  else:
                       logger.error(f"无法提取嵌套协议中的内部 URL: '{tracker_entry}'")
                       return None, None # Discard malformed entry
             parsed = urlparse(tracker_entry)

        if not parsed.netloc:
            logger.warning(f"urlparse 未能提取 netloc (来自: {original_entry})")
            return None, None

        hostname_from_parse = parsed.hostname # Handles IPv6 brackets
        if not hostname_from_parse:
            # Check if netloc itself is maybe an IP? (urlparse sometimes makes hostname None for IPs)
            try:
                 ip_addr_netloc = ipaddress.ip_address(parsed.netloc.split(':')[0]) # Check netloc directly
                 hostname_from_parse = str(ip_addr_netloc)
                 logger.debug(f"从 netloc '{parsed.netloc}' 中直接提取 IP 作为 hostname: {hostname_from_parse}")
            except ValueError:
                logger.warning(f"urlparse 未能提取 hostname 且 netloc 不是 IP (来自: {original_entry})")
                return None, None

        logger.debug(f"urlparse 提取 Hostname: '{hostname_from_parse}'")

        # 2. --- V5: Clean implicit ports BEFORE IP/Domain check ---
        cleaned_hostname = hostname_from_parse
        # Regex finds TLD-like ending (\.[a-zA-Z]{2,}) followed by digits (\d{2,5})
        implicit_port_match = re.match(r'^(.*\.[a-zA-Z]{2,})(\d{2,5})$', hostname_from_parse)
        if implicit_port_match:
            potential_domain = implicit_port_match.group(1)
            potential_port = implicit_port_match.group(2)
            # Check if the part before the numbers IS a valid domain structure
            if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", potential_domain):
                 logger.info(f"检测到并移除隐式端口 '{potential_port}' from hostname '{hostname_from_parse}'. 使用: '{potential_domain}' (来自: {original_entry})")
                 cleaned_hostname = potential_domain
            else:
                 logger.warning(f"找到类似隐式端口的数字 '{potential_port}' 但前面的 '{potential_domain}' 不是有效域名结构。保留原样: '{hostname_from_parse}'")
                 # Keep original hostname if the base isn't valid

        # 3. Prioritize IP identification using the potentially cleaned hostname
        try:
            ip_addr = ipaddress.ip_address(cleaned_hostname)
            ip = str(ip_addr)
            logger.debug(f"识别为 IP: {ip} (来自: {original_entry})")
            domain = None
        except ValueError:
            # 4. If not IP, treat cleaned hostname as domain candidate
            domain_candidate = cleaned_hostname
            # Validate structure AND TLD using tldextract
            if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", domain_candidate):
                try:
                    ext = tldextract.extract(domain_candidate)
                    if ext.suffix and ext.domain: # Must have domain and suffix
                        domain = domain_candidate
                        logger.debug(f"识别为有效域名: {domain} (来自: {original_entry})")
                    else:
                         logger.warning(f"tldextract 无法验证域名/后缀: '{domain_candidate}' (来自: {original_entry}), 已丢弃")
                         domain = None
                except Exception as tld_e:
                     logger.error(f"tldextract 在验证 '{domain_candidate}' 时出错: {tld_e}. 已丢弃.")
                     domain = None # Discard if tldextract errors
            else:
                logger.warning(f"清理后的主机名 '{domain_candidate}' 不符合基本域名结构 (来自: {original_entry})")
                domain = None

    except Exception as e:
        logger.error(f"解析条目时发生严重错误 '{original_entry}': {e}", exc_info=True)

    return domain, ip

# --- Utility Functions (Remain the same)---
def read_existing_items(filepath):
    # ... (same as V4) ...
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
    # ... (same as V4) ...
    if not items_to_add:
        logger.info(f"没有新条目需要追加到 {filepath}")
        return
    try:
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        file_exists_and_not_empty = os.path.exists(filepath) and os.path.getsize(filepath) > 0
        with open(filepath, "a", encoding='utf-8') as f:
            if file_exists_and_not_empty:
                f.write("\n")
            f.write("\n".join(sorted(list(items_to_add))))
        logger.info(f"向 {filepath} 增量添加了 {len(items_to_add)} 个条目")
    except IOError as e:
        logger.error(f"追加写入文件 {filepath} 失败: {e}")

def write_json_like_file(filepath, all_items):
    # ... (same as V4) ...
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
    # ... (same as V4) ...
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
    # ...(Main logic remains the same as V4)...
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
            current_domains.add(domain) # Domain validation is now inside extract

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
