#!/bin/bash
# Fingerprint Collector 自动部署脚本
# 使用 uv 创建虚拟环境并启动服务

set -e

# 配置
APP_DIR="/opt/fingerprint-collector"
PYTHON_VERSION="3.11"
SERVER_HOST="${SERVER_HOST:-222.73.60.30}"
TLS_PORT="${TLS_PORT:-8443}"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 检查是否在正确目录
if [ ! -f "app.py" ]; then
    log_error "请在 fingerprint-collector 目录下运行此脚本"
    exit 1
fi

APP_DIR=$(pwd)
log_info "部署目录: $APP_DIR"

log_info "uv 版本: $(uv --version)"

# 创建虚拟环境（如果不存在）
if [ -d ".venv" ]; then
    log_info "虚拟环境已存在，跳过创建"
else
    log_info "创建 Python $PYTHON_VERSION 虚拟环境..."
    uv venv --python $PYTHON_VERSION .venv
fi

# 激活虚拟环境
source .venv/bin/activate
log_info "Python 路径: $(which python)"
log_info "Python 版本: $(python --version)"

# 安装依赖
log_info "安装依赖..."
uv pip install -r requirements.txt

# 设置 TLS 服务器权限
log_info "设置 TLS 服务器权限..."
chmod +x tls-server/tls-server-linux-amd64 2>/dev/null || true

# 创建启动脚本
log_info "创建启动脚本..."
cat > start.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source .venv/bin/activate
export SERVER_HOST="${SERVER_HOST:-222.73.60.30}"
export TLS_PORT="${TLS_PORT:-8443}"
python app.py
EOF
chmod +x start.sh

# 创建 systemd 服务文件
log_info "创建 systemd 服务文件..."
cat > fingerprint-collector.service << EOF
[Unit]
Description=Fingerprint Collector Service
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
Environment="SERVER_HOST=$SERVER_HOST"
Environment="TLS_PORT=$TLS_PORT"
ExecStart=$APP_DIR/.venv/bin/python app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo ""
log_info "=========================================="
log_info "部署完成!"
log_info "=========================================="
echo ""
echo "启动方式："
echo ""
echo "  方式一：直接运行"
echo "    cd $APP_DIR && ./start.sh"
echo ""
echo "  方式二：使用 systemd（推荐）"
echo "    cp fingerprint-collector.service /etc/systemd/system/"
echo "    systemctl daemon-reload"
echo "    systemctl enable --now fingerprint-collector"
echo ""
echo "  方式三：后台运行"
echo "    nohup ./start.sh > app.log 2>&1 &"
echo ""
echo "访问地址："
echo "  主页: http://$SERVER_HOST:5000"
echo "  TLS:  https://$SERVER_HOST:$TLS_PORT"
echo ""

# 询问是否立即启动
read -p "是否立即启动服务? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log_info "启动服务..."
    ./start.sh
fi
