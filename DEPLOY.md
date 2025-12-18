# Fingerprint Collector 部署指南

## 项目结构

```
fingerprint-collector/
├── app.py                      # Flask 主应用 (自动启动 TLS Server)
├── requirements.txt            # Python 依赖
├── fingerprints.db             # SQLite 数据库 (运行时生成)
├── static/                     # 静态文件 (CSS, JS)
├── templates/                  # HTML 模板
└── tls-server/                 # TLS/HTTP2/TCP 指纹服务
    ├── main.go                 # 主程序
    ├── http2.go                # HTTP/2 指纹解析
    ├── tcp.go                  # TCP/IP 指纹采集
    ├── analysis.go             # 指纹分析逻辑
    ├── server.crt              # TLS 证书 (需生成)
    ├── server.key              # TLS 私钥 (需生成)
    └── tls-server-linux-amd64  # Linux 二进制 (需编译)
```

## 服务端口

| 服务 | 端口 | 说明 |
|------|------|------|
| Flask Web | 5000 | 主 Web 界面和 API |
| TLS Server | 8443 | TLS/HTTP2/TCP 指纹采集 |

---

## 部署步骤

### 1. 环境准备

```bash
# Ubuntu/Debian
apt update
apt install -y python3 python3-pip libpcap-dev golang-go

# CentOS/RHEL
yum install -y python3 python3-pip libpcap-devel golang
```

### 2. 上传项目

```bash
# 本地打包
cd /path/to/code
tar -czvf fingerprint-collector.tar.gz fingerprint-collector/

# 上传到服务器
scp fingerprint-collector.tar.gz user@YOUR_SERVER:/opt/

# 服务器上解压
ssh user@YOUR_SERVER "cd /opt && tar -xzvf fingerprint-collector.tar.gz"
```

### 3. 安装依赖

```bash
cd /opt/fingerprint-collector

# Python 依赖
pip3 install -r requirements.txt
```

### 4. 编译 TLS Server

> **重要**: Linux 服务器必须本地编译以支持 TCP 指纹采集

```bash
cd /opt/fingerprint-collector/tls-server

# 安装 Go 依赖
go mod tidy

# 编译 (需要 libpcap-dev)
go build -o tls-server-linux-amd64 .

# 设置执行权限
chmod +x tls-server-linux-amd64
```

### 5. 生成 TLS 证书

```bash
cd /opt/fingerprint-collector/tls-server

# 替换 YOUR_DOMAIN 和 YOUR_IP
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
  -sha256 -days 365 -nodes \
  -subj "/CN=YOUR_DOMAIN" \
  -addext "subjectAltName=DNS:YOUR_DOMAIN,IP:YOUR_IP"
```

### 6. 配置 Systemd 服务

创建 `/etc/systemd/system/fingerprint.service`:

```ini
[Unit]
Description=Fingerprint Collector
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/fingerprint-collector
Environment=ENABLE_TCP=1
Environment=SERVER_HOST=YOUR_DOMAIN_OR_IP
ExecStart=/usr/bin/python3 app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
systemctl daemon-reload
systemctl enable fingerprint
systemctl start fingerprint
systemctl status fingerprint
```

### 7. 防火墙配置

```bash
# UFW (Ubuntu)
ufw allow 5000/tcp
ufw allow 8443/tcp

# Firewalld (CentOS)
firewall-cmd --permanent --add-port=5000/tcp
firewall-cmd --permanent --add-port=8443/tcp
firewall-cmd --reload
```

---

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SERVER_HOST` | 127.0.0.1 | 公网 IP 或域名 (前端显示用) |
| `ENABLE_TCP` | 0 | 设为 1 启用 TCP 指纹采集 (需要 root) |
| `TLS_PORT` | 8443 | TLS 服务端口 |

---

## API 接口

### Flask Server (端口 5000)

| 接口 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 主页面 |
| `/history` | GET | 历史记录 |
| `/api-docs` | GET | API 文档 |
| `/api/collect` | POST | 提交指纹 |
| `/api/fingerprints` | GET | 获取所有指纹 |
| `/api/fingerprint/:id` | GET | 获取指定指纹 |
| `/api/config` | GET | 获取配置 |

### TLS Server (端口 8443)

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/fingerprint` | GET | 原始指纹数据 (TLS/HTTP2/TCP) |
| `/api/analysis` | GET | 安全分析报告 |

---

## 日志查看

```bash
# Systemd 日志
journalctl -u fingerprint -f

# 查看最近 100 行
journalctl -u fingerprint -n 100
```

---

## 故障排查

### 检查服务状态

```bash
systemctl status fingerprint
ps aux | grep -E 'python|tls-server'
```

### 检查端口

```bash
netstat -tlnp | grep -E '5000|8443'
# 或
ss -tlnp | grep -E '5000|8443'
```

### TLS Server 无法启动

```bash
# 手动测试
cd /opt/fingerprint-collector/tls-server
sudo ./tls-server-linux-amd64

# 检查证书
openssl x509 -in server.crt -text -noout
```

### TCP 指纹不工作

```bash
# 确认 libpcap 已安装
ldconfig -p | grep pcap

# 确认以 root 运行
# ENABLE_TCP=1 需要 root 权限
```

### 重新生成证书

```bash
cd /opt/fingerprint-collector/tls-server
rm -f server.crt server.key

openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
  -sha256 -days 365 -nodes \
  -subj "/CN=YOUR_DOMAIN" \
  -addext "subjectAltName=DNS:YOUR_DOMAIN,IP:YOUR_IP"

systemctl restart fingerprint
```

---

## 更新部署

```bash
# 停止服务
systemctl stop fingerprint

# 备份数据库
cp /opt/fingerprint-collector/fingerprints.db /opt/fingerprints.db.bak

# 上传新代码
scp -r fingerprint-collector/* user@SERVER:/opt/fingerprint-collector/

# 重新编译 TLS Server
cd /opt/fingerprint-collector/tls-server
go build -o tls-server-linux-amd64 .

# 启动服务
systemctl start fingerprint
```
