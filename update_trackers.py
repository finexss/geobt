import requests
import re
from urllib.parse import urlparse
import datetime
import ipaddress
import tldextract # 仍然导入，可用作验证
import logging
import sys

# --- 配置日志 ---
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# 输出到文件
file_handler = logging.FileHandler("log.txt", mode='w', encoding='utf-8')
file_handler.setFormatter(log_formatter)
logger.addHandler(file_handler)

# 输出到控制台
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(log_formatter)
logger.addHandler(stream_handler)
# --- 日志配置结束 ---

def download_and_split_trackers(url):
    """下载 Tracker 列表，并分割成条目列表."""
    tracker_entries = []
    try:
        logger.info(f"开始下载: {url}")
        response = requests.get(url, timeout=15) # 增加超时
        response.raise_for_status()  # 检查是否有 HTTP 错误
        content = response.text
        logger.info(f"下载成功: {url} (状态码: {response.status_code})")

        # 同时按换行符和逗号分割，然后清理
        potential_entries = re.split(r'[,\n\s]+', content) # 使用正则分割多种分隔符包括空格

        for entry in potential_entries:
            entry = entry.strip()
            if entry and not entry.startswith('#'): # 忽略空行和注释
                 # 检查是否是有效的URL格式（简单检查）
                if '://' in entry or re.match(r'^[\w\[\]\.\-:]+(:\d+)?(/.*)?$', entry): # 调整正则匹配IPv6括号
                    tracker_entries.append(entry)
                else:
                    logger.warning(f"忽略无效条目: {entry} (来自: {url})")

    except requests.exceptions.Timeout:
        logger.error(f"下载超时: {url}")
    except requests.exceptions.RequestException as e:
        logger.error(f"下载失败: {url} - {e}")
    except Exception as e:
        logger.error(f"处理下载内容时出错 ({url}): {e}")

    logger.info(f"从 {url} 提取了 {len(tracker_entries)} 个有效条目")
    return tracker_entries

def extract_domain_or_ip(tracker_entry):
    """从单个 Tracker 条目中提取域名(不含端口) 或 IP 地址。"""
    domain = None
    ip = None
    original_entry = tracker_entry # 保留原始条目用于日志

    try:
        # 1. 移除协议头 (http, https, udp, wss) - 可选，因为后面会处理 netloc
        if "://" in tracker_entry:
            tracker_entry_no_proto = tracker_entry.split("://", 1)[1]
        else:
            tracker_entry_no_proto = tracker_entry # 如果没有协议头，直接使用

        # 2. 分离 netloc (host:port 或 host) 和 path
        netloc_part = tracker_entry_no_proto.split("/", 1)[0]

        # 3. 分离 host 和 port，并处理 IPv6
        host_for_check = "" # 用于 ipaddress 检查的部分
        hostname_candidate = "" # 存储提取出的完整主机名(无端口)

        if netloc_part.startswith("[") and "]" in netloc_part:
            # 处理 IPv6 地址 [address]:port or [address]
            ipv6_match = re.match(r'\[([0-9a-fA-F:]+)\](?::(\d+))?', netloc_part)
            if ipv6_match:
                host_for_check = ipv6_match.group(1)
                hostname_candidate = host_for_check # IPv6 地址本身也可以是候选主机名
            else:
                 logger.warning(f"无法解析括号内的 IPv6 地址: {netloc_part}")
                 return None, None # 格式错误，直接跳过
        else:
             # 处理 IPv4 或 域名 host:port or host
             host_parts = netloc_part.split(':', 1)
             host_for_check = host_parts[0]
             hostname_candidate = host_parts[0]

        # 4. 优先尝试解析为 IP 地址
        try:
            ip_addr = ipaddress.ip_address(host_for_check)
            ip = str(ip_addr)
            logger.info(f"提取到 IP: {ip} (来自: {original_entry})")
            domain = None # 确定是 IP，则域名置空
        except ValueError:
            # 5. 如果不是 IP，则认为是域名
            if hostname_candidate:
                # 使用基本的正则表达式验证一下域名结构是否合理
                # 这个正则比较宽松，主要排除明显不是域名的字符串
                if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", hostname_candidate):
                    domain = hostname_candidate # 使用提取出的完整主机名
                    logger.info(f"提取到域名: {domain} (来自: {original_entry})")
                else:
                    logger.warning(f"提取的主机名 '{hostname_candidate}' 不符合基本域名格式 (来自: {original_entry})")
                    domain = None
            else:
                logger.warning(f"无法从 '{netloc_part}' 提取主机名 (来自: {original_entry})")
                domain = None

    except Exception as e:
        logger.error(f"解析条目时发生未知错误 '{original_entry}': {e}")

    return domain, ip

def main():
    """主函数，用于下载、解析、去重、并生成 txt 文件和日志。"""
    logger.info("脚本开始运行")
    start_time = datetime.datetime.now()

    tracker_list_urls = [
        "https://api.yaozuopan.top:88/composite?key=bt&auth=3cae9a3a53f1daef137126648a535ab7",
        "https://www.gbsat.org/bt/tracker.txt",
        "https://github.com/XIU2/TrackersListCollection/raw/master/all.txt",
        "https://raw.githubusercontent.com/Tunglies/TrackersList/refs/heads/main/all.txt",
        "https://github.com/XIU2/TrackersListCollection/raw/master/all_aria2.txt",
        "https://github.com/XIU2/TrackersListCollection/raw/master/best.txt",
        "https://github.com/XIU2/TrackersListCollection/raw/master/best_aria2.txt",
        "https://github.com/XIU2/TrackersListCollection/raw/master/blacklist.txt",
        "https://github.com/XIU2/TrackersListCollection/raw/master/http.txt",
        "https://github.com/XIU2/TrackersListCollection/raw/master/http_aria2.txt",
        "https://github.com/XIU2/TrackersListCollection/raw/master/nohttp.txt",
        "https://github.com/XIU2/TrackersListCollection/raw/master/nohttp_aria2.txt",
        "https://github.com/XIU2/TrackersListCollection/raw/master/other.txt",
        "https://cf.trackerslist.com/all.txt",
        "https://cf.trackerslist.com/best.txt",
        "https://cf.trackerslist.com/http.txt",
        "https://cf.trackerslist.com/nohttp.txt",
        "https://github.com/ngosang/trackerslist/raw/master/blacklist.txt",
        "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best.txt",
        "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt",
        "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_udp.txt",
        "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_http.txt",
        "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_https.txt",
        "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_ws.txt",
        "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best_ip.txt",
        "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_ip.txt",
        "https://newtrackon.com/api/all", # 注意：这个可能是JSON或单行逗号分隔
        # "https://github.com/anthrax10/trakx/blob/master/public/trackers.txt", # 这个是HTML页面，需要特殊处理，暂时注释
        "https://raw.githubusercontent.com/Anshuman8/open-trackers-list/master/trackers.txt",
    ]

    all_tracker_entries = []
    for url in tracker_list_urls:
        entries = download_and_split_trackers(url)
        if entries:
             all_tracker_entries.extend(entries)

    logger.info(f"总共收集到 {len(all_tracker_entries)} 个潜在 Tracker 条目")

    # 使用集合进行去重
    unique_domains = set()
    unique_ips = set()
    processed_count = 0

    for entry in all_tracker_entries:
        processed_count += 1
        domain, ip = extract_domain_or_ip(entry)
        if ip:
            unique_ips.add(ip)
        elif domain:
            # 这里不再需要额外的正则检查，因为 extract_domain_or_ip 内部已经做了基础验证
            unique_domains.add(domain)

    logger.info(f"处理完成 {processed_count} 个条目")
    logger.info(f"提取并去重后得到 {len(unique_domains)} 个域名和 {len(unique_ips)} 个 IP 地址")

    # --- 生成文件内容 ---
    site_lines = []
    for domain in sorted(list(unique_domains)):
        site_lines.append(f'\t\t    "{domain}",') # 注意移除了行尾的\n，最后统一加

    ip_lines = []
    for ip in sorted(list(unique_ips)):
        ip_lines.append(f'\t\t    "{ip}",') # 注意移除了行尾的\n，最后统一加

    # --- 保存文件 ---
    try:
        with open("bt-site.txt", "w", encoding='utf-8') as f:
            f.write("\n".join(site_lines)) # 最后用换行连接所有行
        logger.info("成功生成 bt-site.txt")
    except IOError as e:
        logger.error(f"保存 bt-site.txt 文件失败: {e}")

    try:
        with open("bt-ip.txt", "w", encoding='utf-8') as f:
             f.write("\n".join(ip_lines)) # 最后用换行连接所有行
        logger.info("成功生成 bt-ip.txt")
    except IOError as e:
        logger.error(f"保存 bt-ip.txt 文件失败: {e}")

    # --- 运行结束与总结 ---
    end_time = datetime.datetime.now()
    duration = end_time - start_time
    logger.info(f"脚本运行结束，总耗时: {duration}")
    logger.info("--- 运行总结 ---")
    logger.info(f"处理的 URL 数量: {len(tracker_list_urls)}")
    logger.info(f"收集的原始条目数: {len(all_tracker_entries)}")
    logger.info(f"最终生成的唯一域名数: {len(unique_domains)}")
    logger.info(f"最终生成的唯一 IP 地址数: {len(unique_ips)}")
    logger.info("---------------")

if __name__ == "__main__":
    main()
