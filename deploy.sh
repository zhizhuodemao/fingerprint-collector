#!/bin/bash
# Fingerprint Collector 一键部署脚本
# 适用于 Ubuntu/Debian 和 CentOS/RHEL
# 使用 uv 管理 Python 环境

set -e

# ============ 默认配置 ============
APP_DIR="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_HOST="222.73.60.30"
TLS_PORT="${TLS_PORT:-8443}"
FLASK_PORT="${FLASK_PORT:-5000}"
ENABLE_TCP="${ENABLE_TCP:-1}"
PYTHON_VERSION="${PYTHON_VERSION:-3.11}"

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

# ============ 查找 uv 命令 ============
find_uv() {
    # 直接可用
    if command -v uv >/dev/null 2>&1; then
        UV_CMD="uv"
        return 0
    fi

    # 常见安装路径
    local uv_paths=(
        "$HOME/.cargo/bin/uv"
        "$HOME/.local/bin/uv"
        "/root/.cargo/bin/uv"
        "/root/.local/bin/uv"
        "/usr/local/bin/uv"
    )

    for path in "${uv_paths[@]}"; do
        if [ -x "$path" ]; then
            UV_CMD="$path"
            return 0
        fi
    done

    # 如果是 sudo 运行，尝试获取原用户的 uv
    if [ -n "$SUDO_USER" ]; then
        local user_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        if [ -x "$user_home/.cargo/bin/uv" ]; then
            UV_CMD="$user_home/.cargo/bin/uv"
            return 0
        fi
        if [ -x "$user_home/.local/bin/uv" ]; then
            UV_CMD="$user_home/.local/bin/uv"
            return 0
        fi
    fi

    return 1
}

# ============ 安装 uv ============
install_uv() {
    log_step "安装 uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh

    # 重新查找
    export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
    if find_uv; then
        log_info "uv 安装成功: $UV_CMD"
    else
        log_error "uv 安装失败"
        exit 1
    fi
}

# ============ 交互式配置 SERVER_HOST ============
configure_host() {
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
            apt-get install -y -qq libpcap-dev golang-go curl
            ;;
        centos|rhel|fedora)
            yum install -y libpcap-devel golang curl
            ;;
        *)
            log_warn "未知系统，请手动安装: libpcap-dev, golang, curl"
            ;;
    esac

    log_info "系统依赖安装完成"
}

# ============ 检查依赖 ============
check_dependencies() {
    log_step "检查依赖..."

    local missing=()

    # 检查 uv
    if ! find_uv; then
        log_warn "未找到 uv"
        read -p "是否自动安装 uv? [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            install_uv
        else
            log_error "需要 uv 来管理 Python 环境"
            exit 1
        fi
    else
        log_info "uv 路径: $UV_CMD"
        log_info "uv 版本: $($UV_CMD --version)"
    fi

    # 检查 Go
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

# ============ 安装 Python 依赖 (使用 uv) ============
install_python_deps() {
    log_step "安装 Python 依赖 (使用 uv)..."

    cd "$APP_DIR"

    # 创建虚拟环境
    if [ ! -d ".venv" ]; then
        log_info "创建 Python $PYTHON_VERSION 虚拟环境..."
        $UV_CMD venv --python $PYTHON_VERSION .venv
        log_info "虚拟环境已创建"
    fi

    # 安装依赖
    log_info "安装依赖包..."
    $UV_CMD pip install -r requirements.txt --quiet

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

    # 设置 Go 代理 (中国境内加速)
    export GOPROXY="https://goproxy.cn,https://goproxy.io,direct"
    export GOSUMDB="sum.golang.google.cn"
    log_info "使用 Go 代理: $GOPROXY"

    # 编译
    log_info "正在编译 (需要几分钟)..."
    go mod tidy
    CGO_ENABLED=1 go build -o tls-server-linux-amd64 .
    chmod +x tls-server-linux-amd64

    log_info "TLS Server 编译完成"
}

# ============ 生成 TLS 证书 ============
generate_certificate() {
    log_step "检查 TLS 证书..."

    cd "$APP_DIR/tls-server"

    if [ -f "server.crt" ] && [ -f "server.key" ]; then
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
    echo -e "${BLUE}  (使用 uv 管理 Python 环境)${NC}"
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
