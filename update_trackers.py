import requests
import re
from urllib.parse import urlparse
import datetime
import ipaddress  # 导入 ipaddress 模块

def download_trackers(url):
    """下载 Tracker 列表并返回内容."""
    try:
        response = requests.get(url)
        response.raise_for_status()  # 检查是否有 HTTP 错误
        print(f"下载 {url} 成功，状态码: {response.status_code}")
        content = response.text
        # 使用逗号分割内容
        trackers = content.split(',')
        return [tracker.strip() for tracker in trackers]
    except requests.exceptions.RequestException as e:
        print(f"下载 {url} 失败: {e}")
        return []

def extract_domain_and_ip(tracker_url):
    """从 Tracker URL 中提取域名和 IP 地址."""
    try:
        print(f"原始 Tracker URL: {tracker_url}")

        # 处理 UDP 协议
        if tracker_url.startswith("udp://"):
            # 移除 "udp://" 前缀
            tracker_url = tracker_url[6:]
            # 分割域名/IP 和路径
            parts = tracker_url.split("/", 1)
            if len(parts) > 0:
                netloc = parts[0]
            else:
                print(f"无法解析 UDP URL: {tracker_url}")
                return None, None
        elif tracker_url.startswith("wss://"):
            # 移除 "wss://" 前缀
            tracker_url = tracker_url[6:]
            # 分割域名/IP 和路径
            parts = tracker_url.split("/", 1)
            if len(parts) > 0:
                netloc = parts[0]
            else:
                print(f"无法解析 WSS URL: {tracker_url}")
                return None, None
        else:
            parsed_url = urlparse(tracker_url)
            netloc = parsed_url.netloc

        print(f"Netloc: {netloc}")

        # 尝试解析为 IP 地址
        try:
            ip_addr = ipaddress.ip_address(netloc.split(':')[0])  # 同时处理 IPv4 和 IPv6
            print(f"IP 地址: {ip_addr}")
            return None, str(ip_addr)
        except ValueError:
            # 提取域名 (不包括端口号)
            domain = netloc.split(':')[0]
            print(f"域名: {domain}")
            return domain, None

    except Exception as e:
        print(f"解析 URL {tracker_url} 失败: {e}")
        return None, None

def main():
    """主函数，用于下载、解析、去重、并生成 geosite 和 geoip 文件."""
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
    ]

    all_trackers = []
    for url in tracker_list_urls:
        all_trackers.extend(download_trackers(url))
    print(f"下载了 {len(all_trackers)} 个 Tracker URL")

    domains = set()
    ips = set()
    for tracker in all_trackers:
        tracker = tracker.lower().strip()  # 转换为小写并去除空格
        domain, ip = extract_domain_and_ip(tracker)
        if domain:
            domains.add(domain)
        if ip:
            ips.add(ip)
    print(f"去重前，有 {len(domains)} 个域名和 {len(ips)} 个 IP 地址")

    # 清洗域名，移除无效或非域名的条目 (可选，可以根据需要添加更多规则)
    valid_domains = {
        domain for domain in domains if re.match(r"^[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})?$", domain)
    }
    print(f"去重后，有 {len(valid_domains)} 个域名")

    # 生成文件内容
    geosite_txt_content = ""
    for domain in sorted(valid_domains):
        geosite_txt_content += f'\t\t    "{domain}",\n'

    geoip_txt_content = ""
    for ip in sorted(ips):
        geoip_txt_content += f'\t\t    "{ip}",\n'

    # 保存文件
    try:
        with open("bt-site.txt", "w") as f:
            f.write(geosite_txt_content)
        print("成功生成 bt-site.txt")
        with open("bt-ip.txt", "w") as f:
            f.write(geoip_txt_content)
        print("成功生成 bt-ip.txt")
    except IOError as e:
        print(f"保存文件失败: {e}")

if __name__ == "__main__":
    main()
