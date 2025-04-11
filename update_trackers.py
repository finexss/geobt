import requests
import re
from urllib.parse import urlparse
import datetime
import ipaddress
import tldextract  # 导入 tldextract 模块
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
                if '://' in entry or re.match(r'^[\w.-]+(\:\d+)?(/.*)?$', entry):
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
    """从单个 Tracker 条目中提取域名或 IP 地址。"""
    domain = None
    ip = None
    original_entry = tracker_entry # 保留原始条目用于日志

    try:
        # 移除协议头 (http, https, udp, wss)
        if "://" in tracker_entry:
            tracker_entry = tracker_entry.split("://", 1)[1]

        # 分离 netloc (host:port 或 host) 和 path
        netloc_part = tracker_entry.split("/", 1)[0]

        # --- 核心解析逻辑 ---
        host = netloc_part
        is_ipv6 = False

        # 处理 IPv6 地址的方括号
        if host.startswith("[") and "]" in host:
            ipv6_match = re.match(r'\[([0-9a-fA-F:]+)\](?::(\d+))?', host)
            if ipv6_match:
                host = ipv6_match.group(1)
                is_ipv6 = True
            else:
                 logger.warning(f"无法解析括号内的 IPv6 地址: {netloc_part}")
                 return None, None # 格式错误，直接跳过
        else:
             # 对于非括号IPv6或域名/IPv4，分离端口
             host_parts = host.split(':', 1)
             host = host_parts[0]

        # 尝试解析为 IP 地址
        try:
            ip_addr = ipaddress.ip_address(host)
            ip = str(ip_addr)
            logger.info(f"提取到 IP: {ip} (来自: {original_entry})")
        except ValueError:
            # 如果不是 IP 地址，尝试提取域名
            try:
                # 使用 tldextract 获取注册域名 (去除子域名和端口)
                ext = tldextract.extract(host)
                if ext.domain and ext.suffix: # 确保提取到了有效的域名和后缀
                    domain = f"{ext.domain}.{ext.suffix}"
                    logger.info(f"提取到域名: {domain} (来自: {original_entry})")
                else:
                    # 如果 tldextract 失败，但 host 看起来像域名，也保留（作为后备）
                    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", host):
                         domain = host
                         logger.warning(f"tldextract 未能完全解析，但保留疑似域名: {domain} (来自: {original_entry})")
                    else:
                        logger.warning(f"无法识别为有效域名: {host} (来自: {original_entry})")
            except Exception as e:
                logger.error(f"域名提取 (tldextract) 出错 for '{host}': {e}")

    except Exception as e:
        logger.error(f"解析条目时发生未知错误 '{original_entry}': {e}")

    return domain, ip

def main():
    """主函数，用于下载、解析、去重、并生成 txt 文件和日志。"""
    logger.info("脚本开始运行")
    start_time = datetime.datetime.now()

    tracker_list_urls = [
        "https://github.com/XIU2/TrackersListCollection/raw/master/all.txt",
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
             # 基本的域名有效性检查
            if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
                unique_domains.add(domain)
            else:
                 logger.warning(f"忽略提取后无效的域名格式: {domain} (来自: {entry})")

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
            # 可以选择在最后一行不加逗号
            # if site_lines:
            #     f.write("\n".join(site_lines[:-1]) + "\n" + site_lines[-1].rstrip(','))
        logger.info("成功生成 bt-site.txt")
    except IOError as e:
        logger.error(f"保存 bt-site.txt 文件失败: {e}")

    try:
        with open("bt-ip.txt", "w", encoding='utf-8') as f:
             f.write("\n".join(ip_lines)) # 最后用换行连接所有行
             # 可以选择在最后一行不加逗号
             # if ip_lines:
             #    f.write("\n".join(ip_lines[:-1]) + "\n" + ip_lines[-1].rstrip(','))

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
