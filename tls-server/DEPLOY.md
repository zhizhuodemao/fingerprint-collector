# TLS Fingerprint Server 部署指南

## 服务器信息
- IP: 222.73.60.30
- 端口: 8443 (默认)

## 部署步骤

### 1. 上传文件到服务器

将以下文件上传到服务器：

```bash
# 在本地执行
scp tls-server-linux-amd64 server.crt server.key tls-fingerprint.service root@222.73.60.30:/tmp/
```

### 2. 在服务器上安装

```bash
# SSH 登录服务器
ssh root@222.73.60.30

# 创建安装目录
mkdir -p /opt/tls-fingerprint

# 移动文件
mv /tmp/tls-server-linux-amd64 /opt/tls-fingerprint/tls-server
mv /tmp/server.crt /opt/tls-fingerprint/
mv /tmp/server.key /opt/tls-fingerprint/

# 设置权限
chmod +x /opt/tls-fingerprint/tls-server
chmod 600 /opt/tls-fingerprint/server.key
chmod 644 /opt/tls-fingerprint/server.crt

# 安装 systemd 服务
mv /tmp/tls-fingerprint.service /etc/systemd/system/
systemctl daemon-reload
```

### 3. 启动服务

```bash
# 启动服务
systemctl start tls-fingerprint

# 设置开机自启
systemctl enable tls-fingerprint

# 查看状态
systemctl status tls-fingerprint

# 查看日志
journalctl -u tls-fingerprint -f
```

### 4. 防火墙配置

```bash
# 如果使用 firewalld
firewall-cmd --permanent --add-port=8443/tcp
firewall-cmd --reload

# 如果使用 iptables
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
```

### 5. 验证部署

访问以下地址测试：
- https://222.73.60.30:8443/ - 首页
- https://222.73.60.30:8443/api/fingerprint - 获取 TLS 指纹

## 命令行参数

```
./tls-server -h

  -cert string
        TLS 证书文件路径 (default "server.crt")
  -host string
        监听地址 (default "0.0.0.0")
  -key string
        TLS 私钥文件路径 (default "server.key")
  -port int
        服务监听端口 (default 8443)
```

### 示例

```bash
# 使用 443 端口 (需要 root 权限)
./tls-server -port 443

# 指定证书路径
./tls-server -cert /etc/ssl/server.crt -key /etc/ssl/server.key

# 只监听本地
./tls-server -host 127.0.0.1
```

## 使用 443 端口

如果需要使用标准 HTTPS 端口 443：

### 方法 1: 以 root 运行
修改 `/etc/systemd/system/tls-fingerprint.service`，将端口改为 443：
```
ExecStart=/opt/tls-fingerprint/tls-server -port 443 ...
```

### 方法 2: 使用 setcap (推荐)
```bash
# 允许非 root 用户绑定低端口
setcap 'cap_net_bind_service=+ep' /opt/tls-fingerprint/tls-server

# 修改服务文件使用非 root 用户
# User=nobody
```

### 方法 3: 使用 nginx 反向代理
```nginx
server {
    listen 443 ssl;
    server_name 222.73.60.30;

    ssl_certificate /opt/tls-fingerprint/server.crt;
    ssl_certificate_key /opt/tls-fingerprint/server.key;

    location / {
        proxy_pass https://127.0.0.1:8443;
        proxy_ssl_verify off;
    }
}
```
**注意**: 使用 nginx 反向代理会导致无法捕获真实的客户端 TLS 指纹，因为 nginx 会重新建立 TLS 连接。

## 常见问题

### 证书警告
由于使用自签名证书，浏览器会显示安全警告。在测试环境中可以忽略，生产环境建议使用 Let's Encrypt 等 CA 签发的证书。

### 查看日志
```bash
journalctl -u tls-fingerprint -f
```

### 重启服务
```bash
systemctl restart tls-fingerprint
```

### 停止服务
```bash
systemctl stop tls-fingerprint
```
