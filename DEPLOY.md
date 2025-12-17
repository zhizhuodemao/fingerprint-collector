# Fingerprint Collector 部署指南

## 项目结构

```
fingerprint-collector/
├── app.py                 # Flask 主应用（自动启动 TLS 服务）
├── requirements.txt       # Python 依赖
├── static/               # 静态文件
├── templates/            # HTML 模板
└── tls-server/           # TLS 指纹服务
    ├── main.go
    ├── server.crt        # TLS 证书
    ├── server.key        # TLS 私钥
    ├── tls-server-linux-amd64
    └── tls-fingerprint.service
```

## 服务器信息

- IP: 222.73.60.30
- Flask 端口: 5000
- TLS 端口: 8443

## 快速部署

### 1. 上传文件

```bash
# 打包上传整个项目
cd /Users/wenbo.chen/Documents/code
tar -czvf fingerprint-collector.tar.gz fingerprint-collector/
scp fingerprint-collector.tar.gz root@222.73.60.30:/opt/

# 在服务器上解压
ssh root@222.73.60.30 "cd /opt && tar -xzvf fingerprint-collector.tar.gz"
```

### 2. 安装依赖

```bash
ssh root@222.73.60.30 << 'EOF'
cd /opt/fingerprint-collector

# 安装 Python 依赖
pip install -r requirements.txt

# 设置 TLS 服务器执行权限
chmod +x tls-server/tls-server-linux-amd64
EOF
```

### 3. 配置环境变量

```bash
# 设置服务器公网地址（用于前端显示）
export SERVER_HOST=222.73.60.30
export TLS_PORT=8443
```

### 4. 启动服务

**方式一：直接运行**
```bash
cd /opt/fingerprint-collector
SERVER_HOST=222.73.60.30 python app.py
```

**方式二：使用 systemd**

创建 `/etc/systemd/system/fingerprint-collector.service`:

```ini
[Unit]
Description=Fingerprint Collector Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/fingerprint-collector
Environment="SERVER_HOST=222.73.60.30"
Environment="TLS_PORT=8443"
ExecStart=/usr/bin/python3 app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

启动服务：
```bash
systemctl daemon-reload
systemctl enable --now fingerprint-collector
systemctl status fingerprint-collector
```

### 5. 防火墙配置

```bash
# 开放端口
firewall-cmd --permanent --add-port=5000/tcp
firewall-cmd --permanent --add-port=8443/tcp
firewall-cmd --reload
```

## 访问地址

部署完成后：

| 服务 | 地址 |
|------|------|
| 主页 | http://222.73.60.30:5000 |
| TLS 指纹服务 | https://222.73.60.30:8443 |
| API - 收集指纹 | POST http://222.73.60.30:5000/api/collect |
| API - 获取配置 | GET http://222.73.60.30:5000/api/config |
| API - TLS 状态 | GET http://222.73.60.30:5000/api/tls-check |

## 使用流程

1. 访问 http://222.73.60.30:5000
2. 点击 "Start Collection" 收集浏览器指纹
3. 对于 TLS 指纹：
   - 先访问 https://222.73.60.30:8443 并接受证书
   - 回到主页点击 "Fetch from Local Server"

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SERVER_HOST` | 127.0.0.1 | 公网 IP 或域名，用于前端显示 |
| `TLS_PORT` | 8443 | TLS 服务端口 |
| `TLS_HOST` | 0.0.0.0 | TLS 服务监听地址 |

## 日志查看

```bash
# systemd 日志
journalctl -u fingerprint-collector -f

# 直接运行时查看控制台输出
```

## 故障排查

### TLS 服务未启动
```bash
# 检查进程
ps aux | grep tls-server

# 手动启动测试
cd /opt/fingerprint-collector/tls-server
./tls-server-linux-amd64 -port 8443
```

### 证书问题
```bash
# 重新生成证书
cd /opt/fingerprint-collector/tls-server
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes \
  -subj "/CN=222.73.60.30" \
  -addext "subjectAltName=IP:222.73.60.30"
```

### 端口占用
```bash
# 检查端口
netstat -tlnp | grep -E '5000|8443'
lsof -i :5000
lsof -i :8443
```
