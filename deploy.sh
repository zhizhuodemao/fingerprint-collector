#!/bin/bash
# Fingerprint Collector 一键部署脚本
# 适用于 Ubuntu/Debian 和 CentOS/RHEL

set -e

# ============ 默认配置 ============
APP_DIR="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_HOST="222.73.60.30"
TLS_PORT="${TLS_PORT:-8443}"
FLASK_PORT="${FLASK_PORT:-5000}"
ENABLE_TCP="${ENABLE_TCP:-1}"

# ============ 颜色输出 ============
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# ============ 交互式配置 SERVER_HOST ============
configure_host() {
    # 如果已通过环境变量设置，则跳过交互
    if [ -n "$SERVER_HOST" ]; then
        log_info "使用环境变量 SERVER_HOST: $SERVER_HOST"
        return
    fi

    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}        服务器地址配置${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo "请输入服务器的公网 IP 或域名"
    echo "(用于 TLS 证书生成和前端访问)"
    echo ""
    read -p "SERVER_HOST [$DEFAULT_HOST]: " input_host
    SERVER_HOST="${input_host:-$DEFAULT_HOST}"
    echo ""
    log_info "使用地址: $SERVER_HOST"
}

# ============ 检查 Root ============
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_warn "建议使用 root 运行以启用 TCP 指纹采集"
        log_warn "当前用户: $(whoami)"
    fi
}

# ============ 检测系统 ============
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        OS="centos"
    else
        OS="unknown"
    fi
    log_info "检测到系统: $OS"
}

# ============ 安装系统依赖 ============
install_dependencies() {
    log_step "安装系统依赖..."

    case $OS in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq python3 python3-pip python3-venv libpcap-dev golang-go curl
            ;;
        centos|rhel|fedora)
            yum install -y python3 python3-pip libpcap-devel golang curl
            ;;
        *)
            log_warn "未知系统，请手动安装: python3, pip, libpcap-dev, golang"
            ;;
    esac

    log_info "系统依赖安装完成"
}

# ============ 检查依赖 ============
check_dependencies() {
    log_step "检查依赖..."

    local missing=()

    command -v python3 >/dev/null 2>&1 || missing+=("python3")
    command -v pip3 >/dev/null 2>&1 || missing+=("pip3")
    command -v go >/dev/null 2>&1 || missing+=("golang")

    # 检查 libpcap
    if [ "$ENABLE_TCP" = "1" ]; then
        if ! ldconfig -p 2>/dev/null | grep -q libpcap; then
            if [ ! -f /usr/include/pcap.h ] && [ ! -f /usr/include/pcap/pcap.h ]; then
                missing+=("libpcap-dev")
            fi
        fi
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        log_warn "缺少依赖: ${missing[*]}"
        read -p "是否自动安装? [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            install_dependencies
        else
            log_error "请手动安装依赖后重试"
            exit 1
        fi
    else
        log_info "所有依赖已满足"
    fi
}

# ============ 安装 Python 依赖 ============
install_python_deps() {
    log_step "安装 Python 依赖..."

    cd "$APP_DIR"

    # 创建虚拟环境
    if [ ! -d ".venv" ]; then
        python3 -m venv .venv
        log_info "虚拟环境已创建"
    fi

    # 激活并安装
    source .venv/bin/activate
    pip install --upgrade pip -q
    pip install -r requirements.txt -q

    log_info "Python 依赖安装完成"
}

# ============ 编译 TLS Server ============
compile_tls_server() {
    log_step "编译 TLS Server..."

    cd "$APP_DIR/tls-server"

    # 检查是否需要重新编译
    if [ -f "tls-server-linux-amd64" ]; then
        local bin_time=$(stat -c %Y tls-server-linux-amd64 2>/dev/null || stat -f %m tls-server-linux-amd64)
        local src_time=$(stat -c %Y main.go 2>/dev/null || stat -f %m main.go)
        if [ "$bin_time" -gt "$src_time" ]; then
            log_info "二进制文件已是最新，跳过编译"
            return
        fi
    fi

    # 编译
    log_info "正在编译 (需要几分钟)..."
    go mod tidy
    go build -o tls-server-linux-amd64 .
    chmod +x tls-server-linux-amd64

    log_info "TLS Server 编译完成"
}

# ============ 生成 TLS 证书 ============
generate_certificate() {
    log_step "检查 TLS 证书..."

    cd "$APP_DIR/tls-server"

    if [ -f "server.crt" ] && [ -f "server.key" ]; then
        # 检查证书是否过期
        if openssl x509 -checkend 86400 -noout -in server.crt 2>/dev/null; then
            log_info "证书有效，跳过生成"
            return
        else
            log_warn "证书即将过期或已过期，重新生成"
        fi
    fi

    log_info "生成自签名证书 (域名/IP: $SERVER_HOST)..."

    openssl req -x509 -newkey rsa:4096 \
        -keyout server.key -out server.crt \
        -sha256 -days 365 -nodes \
        -subj "/CN=$SERVER_HOST" \
        -addext "subjectAltName=DNS:$SERVER_HOST,DNS:localhost,IP:$SERVER_HOST,IP:127.0.0.1" \
        2>/dev/null

    log_info "证书生成完成"
}

# ============ 创建 Systemd 服务 ============
create_systemd_service() {
    log_step "创建 Systemd 服务..."

    local service_file="/etc/systemd/system/fingerprint.service"

    cat > "$service_file" << EOF
[Unit]
Description=Fingerprint Collector
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
Environment=ENABLE_TCP=$ENABLE_TCP
Environment=SERVER_HOST=$SERVER_HOST
Environment=TLS_PORT=$TLS_PORT
ExecStart=$APP_DIR/.venv/bin/python app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_info "Systemd 服务已创建: fingerprint.service"
}

# ============ 创建启动脚本 ============
create_start_script() {
    log_step "创建启动脚本..."

    cat > "$APP_DIR/start.sh" << EOF
#!/bin/bash
cd "$APP_DIR"
source .venv/bin/activate
export SERVER_HOST="${SERVER_HOST}"
export TLS_PORT="${TLS_PORT}"
export ENABLE_TCP="${ENABLE_TCP}"

echo "启动 Fingerprint Collector..."
echo "  Flask:  http://\$SERVER_HOST:5000"
echo "  TLS:    https://\$SERVER_HOST:\$TLS_PORT"
echo ""

if [ "\$ENABLE_TCP" = "1" ] && [ "\$EUID" -ne 0 ]; then
    echo "[WARN] TCP 指纹需要 root 权限，请使用 sudo ./start.sh"
fi

python app.py
EOF

    chmod +x "$APP_DIR/start.sh"
    log_info "启动脚本已创建: start.sh"
}

# ============ 配置防火墙 ============
configure_firewall() {
    log_step "配置防火墙..."

    # UFW (Ubuntu)
    if command -v ufw >/dev/null 2>&1; then
        ufw allow $FLASK_PORT/tcp >/dev/null 2>&1 || true
        ufw allow $TLS_PORT/tcp >/dev/null 2>&1 || true
        log_info "UFW 规则已添加"
    fi

    # Firewalld (CentOS)
    if command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=$FLASK_PORT/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=$TLS_PORT/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        log_info "Firewalld 规则已添加"
    fi
}

# ============ 显示结果 ============
show_result() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}        部署完成!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "配置信息:"
    echo "  SERVER_HOST: $SERVER_HOST"
    echo "  TLS_PORT:    $TLS_PORT"
    echo "  ENABLE_TCP:  $ENABLE_TCP"
    echo ""
    echo "访问地址:"
    echo "  主页:     http://$SERVER_HOST:$FLASK_PORT"
    echo "  TLS:      https://$SERVER_HOST:$TLS_PORT"
    echo "  分析API:  https://$SERVER_HOST:$TLS_PORT/api/analysis"
    echo ""
    echo "启动方式:"
    echo ""
    echo "  1. Systemd (推荐):"
    echo "     systemctl start fingerprint"
    echo "     systemctl enable fingerprint  # 开机自启"
    echo ""
    echo "  2. 直接运行:"
    echo "     cd $APP_DIR && sudo ./start.sh"
    echo ""
    echo "  3. 后台运行:"
    echo "     cd $APP_DIR && sudo nohup ./start.sh > app.log 2>&1 &"
    echo ""
    echo "日志查看:"
    echo "     journalctl -u fingerprint -f"
    echo ""
}

# ============ 启动服务 ============
start_service() {
    read -p "是否立即启动服务? [Y/n] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        log_info "启动服务..."
        systemctl start fingerprint
        systemctl status fingerprint --no-pager
    fi
}

# ============ 主流程 ============
main() {
    echo ""
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}  Fingerprint Collector 部署脚本${NC}"
    echo -e "${BLUE}======================================${NC}"
    echo ""

    # 检查目录
    if [ ! -f "$APP_DIR/app.py" ]; then
        log_error "请在 fingerprint-collector 目录下运行此脚本"
        exit 1
    fi

    log_info "部署目录: $APP_DIR"

    check_root
    configure_host
    detect_os
    check_dependencies
    install_python_deps
    compile_tls_server
    generate_certificate
    create_start_script

    # 只有 root 才能创建 systemd 服务
    if [ "$EUID" -eq 0 ]; then
        create_systemd_service
        configure_firewall
    else
        log_warn "非 root 用户，跳过 systemd 和防火墙配置"
    fi

    show_result

    if [ "$EUID" -eq 0 ]; then
        start_service
    fi
}

# 运行
main "$@"
