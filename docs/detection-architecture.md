# 网络指纹检测架构

## 网络层级与检测点

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              应用层 (Application Layer)                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  HTTP Headers                                                        │    │
│  │  ├── User-Agent: "Mozilla/5.0 (Windows NT 10.0...) Chrome/131"      │    │
│  │  ├── Accept-Language, Accept-Encoding                               │    │
│  │  └── sec-ch-ua-platform: "Windows"                                  │    │
│  │                                                                      │    │
│  │  检测点: UA 声称的 OS/Browser 与其他层级是否一致                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              HTTP/2 层 (HTTP/2 Layer)                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Akamai Fingerprint: SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo_order   │    │
│  │                                                                      │    │
│  │  Chrome:  1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p         │    │
│  │  Safari:  2:0;3:100;4:2097152;9:1|10420225|0|m,s,a                  │    │
│  │  Firefox: 1:65536;4:131072;5:16384|12517377|...|m,p,a,s             │    │
│  │  curl-impersonate: Chrome SETTINGS + |m,a,s| (缺少 :path)           │    │
│  │                                                                      │    │
│  │  检测点: SETTINGS + WINDOW_UPDATE + pseudo_header_order 组合        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              TLS 层 (TLS/SSL Layer)                          │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  JA3 Fingerprint: TLSVersion,Ciphers,Extensions,EllipticCurves,...  │    │
│  │  JA4 Fingerprint: t13d1516h2_8daaf6152771_e5627efa2ab1              │    │
│  │                                                                      │    │
│  │  Browser 特征:                                                       │    │
│  │  ├── 15-50 个 Cipher Suites                                         │    │
│  │  ├── 12-20 个 Extensions                                            │    │
│  │  ├── GREASE 扩展 (Chrome/Edge)                                      │    │
│  │  ├── ECH, compress_certificate 等浏览器专属扩展                      │    │
│  │  └── SNI (Server Name Indication)                                   │    │
│  │                                                                      │    │
│  │  Library 特征:                                                       │    │
│  │  ├── 5-15 个 Cipher Suites                                          │    │
│  │  ├── 5-10 个 Extensions                                             │    │
│  │  ├── 无 GREASE                                                      │    │
│  │  └── 经常缺少 SNI                                                   │    │
│  │                                                                      │    │
│  │  检测点: Cipher/Extension 数量、GREASE、SNI、特征模式               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              TCP/IP 层 (Transport/Network Layer)             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  TCP/IP Fingerprint: TTL:WindowSize:Options                         │    │
│  │                                                                      │    │
│  │  ┌─────────────┬─────────┬─────────────┬───────────────────────┐    │    │
│  │  │ OS          │ TTL     │ Window Size │ TCP Options           │    │    │
│  │  ├─────────────┼─────────┼─────────────┼───────────────────────┤    │    │
│  │  │ Windows     │ 128     │ 65535       │ 通常无 Timestamp      │    │    │
│  │  │ Linux       │ 64      │ ~29200      │ 有 Timestamp          │    │    │
│  │  │ macOS/iOS   │ 64      │ 65535       │ 有 Timestamp          │    │    │
│  │  │ Android     │ 64      │ <20000      │ 有 Timestamp          │    │    │
│  │  └─────────────┴─────────┴─────────────┴───────────────────────┘    │    │
│  │                                                                      │    │
│  │  检测点: TTL + WindowSize + TCP Options 推断真实 OS                 │    │
│  │  ** 这是最底层的真实信号，无法被应用层伪造 **                        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 跨层一致性检测

```
                    ┌──────────────────────────────────────┐
                    │         Cross-Layer Validation        │
                    └──────────────────────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        │                             │                             │
        ▼                             ▼                             ▼
┌───────────────┐           ┌───────────────┐           ┌───────────────┐
│  Layer 1      │           │  Layer 2      │           │  Layer 3      │
│  UA vs TLS    │           │  TLS vs HTTP/2│           │  UA vs TCP    │
└───────────────┘           └───────────────┘           └───────────────┘
        │                             │                             │
        ▼                             ▼                             ▼
┌───────────────┐           ┌───────────────┐           ┌───────────────┐
│ UA 说 Chrome  │           │ TLS 说 Chrome │           │ UA 说 Windows │
│ TLS 是 Library│           │ HTTP/2 不匹配 │           │ TCP 是 Linux  │
│               │           │               │           │               │
│  => 异常!     │           │  => 异常!     │           │  => 异常!     │
└───────────────┘           └───────────────┘           └───────────────┘
```

## 检测场景示例

### 场景 1: 原生 Python requests 伪装 Chrome

```
请求来源: Linux 服务器上的 Python requests 库

┌─────────────┬────────────────────────────────────┬─────────────┐
│    层级     │              实际值                 │   检测结果   │
├─────────────┼────────────────────────────────────┼─────────────┤
│ User-Agent  │ Chrome/131.0.0.0 (Windows NT 10.0) │ 声称 Chrome │
│ HTTP/2      │ 不支持 (只有 HTTP/1.1)             │ ❌ 异常     │
│ TLS (JA3)   │ 5 ciphers, 6 extensions, 无 GREASE │ ❌ Library  │
│ TCP         │ TTL=64, WindowSize=29200           │ ❌ Linux    │
└─────────────┴────────────────────────────────────┴─────────────┘

检测结论: is_bot=true, is_spoofed=true
异常列表:
  - UA claims to be Chrome browser but TLS fingerprint indicates HTTP library
  - UA claims Windows but TCP fingerprint suggests Linux (TTL=64)
```

### 场景 2: curl_cffi 模拟 Chrome (在 Linux 容器中)

```
请求来源: Linux 容器中的 curl_cffi (impersonate="chrome131")

┌─────────────┬────────────────────────────────────┬─────────────┐
│    层级     │              实际值                 │   检测结果   │
├─────────────┼────────────────────────────────────┼─────────────┤
│ User-Agent  │ Chrome/131.0.0.0 (Windows NT 10.0) │ 声称 Chrome │
│ HTTP/2      │ Chrome SETTINGS, pseudo=m,a,s      │ ❌ 缺少 :path│
│ TLS (JA3)   │ 完美模拟 Chrome                    │ ✓ Chrome    │
│ TCP         │ TTL=64, WindowSize=29200           │ ❌ Linux    │
└─────────────┴────────────────────────────────────┴─────────────┘

检测结论: is_bot=true, is_spoofed=true, type=impersonator
异常列表:
  - Chrome SETTINGS+WU but pseudo_header_order='m,a,s' (expected 'm,a,s,p')
  - UA claims Windows but TCP fingerprint suggests Linux (TTL=64)
```

### 场景 3: 真实 Chrome 浏览器

```
请求来源: macOS 上的真实 Chrome 浏览器

┌─────────────┬────────────────────────────────────┬─────────────┐
│    层级     │              实际值                 │   检测结果   │
├─────────────┼────────────────────────────────────┼─────────────┤
│ User-Agent  │ Chrome/131.0.0.0 (Macintosh)       │ 声称 macOS  │
│ HTTP/2      │ Chrome SETTINGS, pseudo=m,a,s,p    │ ✓ Chrome    │
│ TLS (JA3)   │ 20+ ciphers, GREASE, ECH           │ ✓ Chrome    │
│ TCP         │ TTL=64, WindowSize=65535           │ ✓ macOS     │
└─────────────┴────────────────────────────────────┴─────────────┘

检测结论: is_bot=false, is_spoofed=false, type=browser
异常列表: (空)
```

## 检测优先级

```
                        检测可靠性金字塔

                              /\
                             /  \
                            /    \
                           / TCP  \      ← 最可靠 (OS内核层，无法伪造)
                          /________\
                         /          \
                        /   HTTP/2   \   ← 可靠 (帧级别实现细节)
                       /______________\
                      /                \
                     /       TLS        \  ← 中等 (可被 curl-impersonate 模拟)
                    /____________________\
                   /                      \
                  /      User-Agent        \ ← 最不可靠 (任意字符串)
                 /__________________________\
```

## 检测逻辑流程图

```
                              开始分析
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │   解析 User-Agent      │
                    │   提取: Browser, OS    │
                    └────────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │   分析 TLS 指纹        │
                    │   JA3/JA4, 特征模式    │
                    └────────────────────────┘
                                 │
                    ┌────────────┴────────────┐
                    ▼                          ▼
           ┌──────────────┐           ┌──────────────┐
           │ Cipher < 15  │           │ Cipher >= 15 │
           │ 无 GREASE    │           │ 有 GREASE    │
           │ 无 SNI       │           │ 有 SNI       │
           └──────────────┘           └──────────────┘
                    │                          │
                    ▼                          ▼
              type=Library              type=Browser
                    │                          │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │   分析 HTTP/2 指纹     │
                    │   SETTINGS + WU + pseudo│
                    └────────────────────────┘
                                 │
                    ┌────────────┴────────────┐
                    ▼                          ▼
           ┌──────────────────┐      ┌──────────────────┐
           │ Chrome SETTINGS  │      │ 其他/无 HTTP/2   │
           │ pseudo != m,a,s,p│      │                  │
           └──────────────────┘      └──────────────────┘
                    │                          │
                    ▼                          │
           type=impersonator                   │
                    │                          │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │   分析 TCP/IP 指纹     │
                    │   TTL + WindowSize     │
                    └────────────────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
       ┌───────────┐      ┌───────────┐      ┌───────────┐
       │ TTL=128   │      │ TTL=64    │      │ TTL=64    │
       │           │      │ WS=65535  │      │ WS<65535  │
       └───────────┘      └───────────┘      └───────────┘
              │                  │                  │
              ▼                  ▼                  ▼
          Windows           macOS/iOS            Linux
              │                  │                  │
              └──────────────────┼──────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │   跨层一致性校验       │
                    │   UA OS == TCP OS ?    │
                    │   UA Browser == TLS ?  │
                    │   TLS == HTTP/2 ?      │
                    └────────────────────────┘
                                 │
                    ┌────────────┴────────────┐
                    ▼                          ▼
           ┌──────────────┐           ┌──────────────┐
           │   全部一致    │           │   存在矛盾   │
           │              │           │              │
           │ is_spoofed   │           │ is_spoofed   │
           │   = false    │           │   = true     │
           └──────────────┘           └──────────────┘
                                              │
                                              ▼
                                    生成 anomalies 列表
```

## API 返回示例

```json
{
  "risk_score": 35,
  "risk_level": "high",
  "is_bot": true,
  "is_spoofed": true,
  "client": {
    "type": "impersonator",
    "claimed": "Chrome 131.0.0.0 on Windows 10",
    "detected": "curl-impersonate/curl_cffi on Linux",
    "match": false
  },
  "fingerprints": {
    "ja3": "a5aaabff415e527dad6ee831bd172e1f",
    "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
    "http2": "13b183c767c7c6dcd27a1930a9fde684",
    "tcp": "64:29200:M1460,S,T,N,W7",
    "tcp_os": "Linux"
  },
  "anomalies": [
    "Chrome SETTINGS+WU but pseudo_header_order='m,a,s' (expected 'm,a,s,p') - likely curl-impersonate",
    "UA claims Windows but TCP fingerprint suggests Linux (TTL=64, WindowSize=29200)"
  ]
}
```

## 参考资料

- [HTTP/2 Fingerprinting - lwthiker](https://lwthiker.com/networks/2022/06/17/http2-fingerprinting.html)
- [Akamai Passive Fingerprinting of HTTP/2 Clients - Black Hat EU 2017](https://blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf)
- [curl-cffi Documentation](https://curl-cffi.readthedocs.io/en/latest/impersonate/fingerprint.html)
- [Understanding HTTP/2 fingerprinting - Trickster Dev](https://www.trickster.dev/post/understanding-http2-fingerprinting/)
