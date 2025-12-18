# Browser Fingerprint Collector

多层网络指纹采集与分析工具，支持 TLS/HTTP2/TCP/浏览器指纹采集，提供跨层一致性检测和安全分析。

## 功能特性

- **TLS 指纹**: JA3, JA4, Cipher Suites, Extensions
- **HTTP/2 指纹**: Akamai 格式 (SETTINGS, WINDOW_UPDATE, Pseudo-header order)
- **TCP/IP 指纹**: TTL, Window Size, TCP Options, 操作系统推断
- **浏览器指纹**: Canvas, WebGL, Audio, Navigator, Screen, Fonts, WebRTC
- **安全分析**: Bot 检测, 指纹伪造检测, 跨层一致性校验
- **设备 ID**: 基于硬件信号的稳定浏览器标识

## 快速开始 (本地开发)

```bash
# 克隆项目
git clone https://github.com/zhizhuodemao/fingerprint-collector.git
cd fingerprint-collector

# 安装 Python 依赖
pip install -r requirements.txt

# 生成 TLS 证书
cd tls-server
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
  -sha256 -days 365 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
cd ..

# 启动服务 (包含 TCP 指纹采集，需要 sudo)
sudo -v && ENABLE_TCP=1 python app.py

# 或不启用 TCP 指纹采集
python app.py
```

访问: **http://localhost:5000**

## Linux 服务器部署

### 1. 环境准备

```bash
# Ubuntu/Debian
apt update
apt install -y python3 python3-pip libpcap-dev golang-go

# CentOS/RHEL
yum install -y python3 python3-pip libpcap-devel golang
```

### 2. 部署项目

```bash
# 克隆项目
git clone https://github.com/zhizhuodemao/fingerprint-collector.git
cd fingerprint-collector

# 安装 Python 依赖
pip3 install -r requirements.txt

# 编译 TLS Server (Linux 需要本地编译以支持 TCP 指纹)
cd tls-server
go mod tidy
go build -o tls-server-linux-amd64 .
cd ..
```

### 3. 生成 TLS 证书

```bash
cd tls-server

# 本地测试证书
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
  -sha256 -days 365 -nodes -subj "/CN=your-domain.com" \
  -addext "subjectAltName=DNS:your-domain.com,IP:YOUR_SERVER_IP"

cd ..
```

### 4. 配置环境变量

```bash
# 设置公网访问地址 (用于前端显示 TLS Server URL)
export SERVER_HOST=your-domain.com
# 或使用 IP
export SERVER_HOST=YOUR_SERVER_IP
```

### 5. 启动服务

```bash
# 完整功能 (包含 TCP 指纹，需要 root)
sudo ENABLE_TCP=1 SERVER_HOST=your-domain.com python3 app.py

# 或使用 systemd (推荐生产环境)
```

### 6. Systemd 服务配置 (可选)

创建 `/etc/systemd/system/fingerprint.service`:

```ini
[Unit]
Description=Fingerprint Collector
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/fingerprint-collector
Environment=ENABLE_TCP=1
Environment=SERVER_HOST=your-domain.com
ExecStart=/usr/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable fingerprint
systemctl start fingerprint
```

### 7. 防火墙配置

```bash
# 开放端口
ufw allow 5000/tcp   # Flask Web
ufw allow 8443/tcp   # TLS Server
```

## API 接口

### Flask Server (端口 5000)

| 接口 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 主页面 - 指纹采集 |
| `/history` | GET | 历史记录页面 |
| `/api-docs` | GET | API 文档页面 |
| `/api/collect` | POST | 提交浏览器指纹 |
| `/api/fingerprints` | GET | 获取所有指纹记录 |
| `/api/fingerprint/:id` | GET | 获取指定 ID 的指纹 |
| `/api/server-info` | GET | 获取服务端信息 |

### TLS Server (端口 8443)

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/fingerprint` | GET | 获取原始指纹数据 (TLS/HTTP2/TCP) |
| `/api/analysis` | GET | 获取完整安全分析报告 |

#### /api/analysis 响应示例

```json
{
  "success": true,
  "client_ip": "x.x.x.x",
  "analysis": {
    "summary": {
      "risk_level": "low",
      "is_bot": false,
      "is_spoofed": false,
      "detected_client": "Browser",
      "detected_os": "macOS"
    },
    "tls_analysis": {
      "protocol": "TLS 1.3",
      "client_type": "Browser",
      "cipher_strength": "Strong"
    },
    "http2_analysis": {
      "detected": true,
      "observations": ["Window size matches Chrome default"]
    },
    "tcp_analysis": {
      "inferred_os": "macOS/iOS",
      "ttl_analysis": "Observed TTL: 64, Initial TTL estimate: 64"
    },
    "consistency_check": {
      "passed": true,
      "score": 100
    },
    "security_advice": {
      "for_defenders": [...],
      "for_pentesters": [...]
    }
  }
}
```

## 项目结构

```
fingerprint-collector/
├── app.py                  # Flask 主服务 (自动启动 TLS Server)
├── requirements.txt        # Python 依赖
├── templates/              # HTML 模板
├── static/                 # 静态资源 (CSS, JS)
└── tls-server/
    ├── main.go             # TLS/HTTP2 指纹服务
    ├── tcp.go              # TCP/IP 指纹采集
    ├── analysis.go         # 指纹分析逻辑
    ├── server.crt          # TLS 证书 (需生成)
    └── server.key          # TLS 私钥 (需生成)
```

## 注意事项

- **TLS 证书**: 自签名证书需要在浏览器中手动接受
- **TCP 指纹**: 需要 root/sudo 权限和 libpcap
- **跨平台编译**: TCP 指纹功能需要本地编译 (CGO + libpcap)
- **NAT/VPN**: TTL 可能改变，但仍可推断初始值

## 文档

| 文档 | 说明 |
|------|------|
| [网络指纹综述](docs/fingerprint-overview.md) | TLS/HTTP2/TCP 指纹技术深度研究 |
| [浏览器指纹综述](docs/browser-fingerprint-overview.md) | Canvas/WebGL/Audio 指纹与爬虫对抗 |
| [部署指南](DEPLOY.md) | 详细的 Linux 服务器部署步骤 |

## 参考资料

- [JA3 Fingerprinting](https://github.com/salesforce/ja3)
- [JA4+ Fingerprinting](https://github.com/FoxIO-LLC/ja4)
- [Akamai HTTP/2 Fingerprinting](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf)

## License

仅供教育和研究用途。
