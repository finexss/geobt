import requests
import re
from urllib.parse import urlparse
import datetime

def download_trackers(url):
    """下载 Tracker 列表并返回内容."""
    try:
        response = requests.get(url)
        response.raise_for_status()  # 检查是否有 HTTP 错误
        return response.text.splitlines()
    except requests.exceptions.RequestException as e:
        print(f"下载 {url} 失败: {e}")
        return []

def extract_domain_and_ip(tracker_url):
    """从 Tracker URL 中提取域名和 IP 地址."""
    try:
        parsed_url = urlparse(tracker_url)
        netloc = parsed_url.netloc
        # 尝试解析为 IP 地址
        try:
            import ipaddress
            ipaddress.ip_address(netloc.split(':')[0]) # 仅判断是否为有效IP，不捕获带端口的
            return None, netloc.split(':')[0]
        except ValueError:
            return netloc, None
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

    domains = set()
    ips = set()
    for tracker in all_trackers:
        domain, ip = extract_domain_and_ip(tracker)
        if domain:
            domains.add(domain)
        if ip:
            ips.add(ip)

    # 清洗域名，移除无效或非域名的条目 (可选，可以根据需要添加更多规则)
    valid_domains = {
        domain for domain in domains if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain)
    }

    # 生成 geosite 文件内容
    geosite_content = f"""# geosite-bittorrent.dat
# Last updated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
    for domain in sorted(valid_domains):
        geosite_content += domain + "\n"

    # 生成 geoip 文件内容
    geoip_content = f"""# geoip-bittorrent.dat
# Last updated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
    for ip in sorted(ips):
        geoip_content += f"{ip},CN\n"  # 假设所有 IP 地址都位于中国，你需要根据实际情况修改

    # 保存文件
    output_geosite_file = "data/geosite-bittorrent"  # 替换为你希望保存的文件路径
    output_geoip_file = "data/geoip-bittorrent"
    try:
        with open(output_geosite_file, "w") as f:
            f.write(geosite_content)
        print(f"成功生成 {output_geosite_file}")
        with open(output_geoip_file, "w") as f:
            f.write(geoip_content)
        print(f"成功生成 {output_geoip_file}")
    except IOError as e:
        print(f"保存文件失败: {e}")

if __name__ == "__main__":
    main()
