从全网收集公开的BT trackers服务器地址和IP，txt格式内容为每行一条域名/IP，

定时收集时间：    - cron: '0 0 * * 5'


# 简介

# 1.生成文件btip.dat,仅有一个IP标签：bttracker

仓库：https://github.com/finexss/geoip 

定时生成时间：    - cron: "10 0 * * 5"

# 2.生成geosite.dat文件，增加标签：bttracker

仓库：https://github.com/finexss/meta-rules-dat 

定时生成时间：    - cron: "15 0 * * 5"

Xray：

geoip文件：

https://raw.githubusercontent.com/finexss/geoip/refs/heads/release/btip.dat

geosite文件：

https://raw.githubusercontent.com/finexss/meta-rules-dat/refs/heads/release/geosite.dat


<hr>


```
        "rules": [
            {
                "type": "field",
                "outboundTag": "block",
                "ip": [
                   "ext:btip.dat:bttracker"
                ]
          },
            {
                "type": "field",
		"outboundTag": "block",
                "domain": [
		    "geosite:bttracker"
                ]
          },
```
<hr>

Singbox：
<hr>


```
      {
        "rule_set": [
          "btip-bttracker",
          "btsite-bttracker"
        ],
        "outbound": "block"
      },

TAG：

      {
        "tag": "btip-bttracker",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/finexss/geoip/refs/heads/release/srs/bttracker.srs",
       "download_detour": "IPv4_out"
      },
      {
        "tag": "btsite-bttracker",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/finexss/meta-rules-dat/refs/heads/sing/geo/geosite/bttracker.srs",
       "download_detour": "IPv4_out"
      },

```
<hr>
