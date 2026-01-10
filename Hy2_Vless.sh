#!/bin/bash

# --- 路径与常量配置 ---
SINGBOX_BIN="/usr/local/bin/sing-box"
CONF_DIR="/etc/sing-box"
CONF_FILE="${CONF_DIR}/config.json"
CERT_DIR="${CONF_DIR}/certs"
DB_FILE="${CONF_DIR}/.script_data.db"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 核心辅助函数 ---
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# --- 启用 BBR 加速 ---
enable_bbr() {
    info "正在检测并启用 BBR 加速..."
    
    # 检查内核版本是否 >= 4.9
    kernel_version=$(uname -r | awk -F. '{print ($1 * 1000) + $2}')
    if [[ $kernel_version -lt 4009 ]]; then
        warn "内核版本过低（需 >= 4.9），跳过 BBR 启用"
        return
    fi

    # 检查是否已启用 BBR
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q 'bbr'; then
        success "BBR 已启用"
        return
    fi

    # 启用 BBR
    echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
    echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1

    # 验证
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q 'bbr'; then
        success "BBR 已成功启用"
    else
        warn "BBR 启用失败（可能系统不支持）"
    fi
}

# --- 1. 环境准备与依赖安装 ---
install_deps() {
    info "检查并安装必要依赖 (curl, jq, openssl, qrencode)..."
    local deps=("curl" "wget" "jq" "openssl" "tar" "qrencode" "nano")
    if command -v apt &>/dev/null; then
        apt update && apt install -y "${deps[@]}"
    elif command -v dnf &>/dev/null; then
        dnf install -y "${deps[@]}"
    elif command -v yum &>/dev/null; then
        yum install -y epel-release && yum install -y "${deps[@]}"
    fi
}

# --- 2. 自动放行防火墙 ---
open_ports() {
    local ports=("$@")
    info "配置系统防火墙策略..."
    for port in "${ports[@]}"; do
        if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
            ufw allow "$port"/tcp >/dev/null && ufw allow "$port"/udp >/dev/null
            echo -e "  - UFW 已放行端口: $port"
        elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
            firewall-cmd --permanent --add-port="$port"/tcp >/dev/null
            firewall-cmd --permanent --add-port="$port"/udp >/dev/null
            firewall-cmd --reload >/dev/null
            echo -e "  - Firewalld 已放行端口: $port"
        fi
    done
}

# --- 3. 下载官方 Beta 核心 ---
install_core() {
    info "从 GitHub 获取最新官方 Beta 核心..."
    local api_url="https://api.github.com/repos/SagerNet/sing-box/releases"
    response=$(curl -s "$api_url")
    if [[ $? -ne 0 ]] || [[ -z "$response" ]]; then
        error "无法连接 GitHub API"
    fi
    TAG=$(echo "$response" | jq -r 'map(select(.prerelease == true)) | first | .tag_name // empty')
    [[ -z "$TAG" ]] && error "获取版本失败（可能无 prerelease 或 API 限流）"

    VERSION=${TAG#v}
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)   SARCH="linux-amd64" ;;
        aarch64)  SARCH="linux-arm64" ;;
        armv7l)   SARCH="linux-arm-v7" ;;
        *)        error "不支持的 CPU 架构: $ARCH" ;;
    esac
    
    URL="https://github.com/SagerNet/sing-box/releases/download/${TAG}/sing-box-${VERSION}-${SARCH}.tar.gz"
    tmp_dir="/tmp/singbox-install-$$"
    mkdir -p "$tmp_dir"
    if ! wget -qO- "$URL" | tar -xz -C "$tmp_dir"; then
        rm -rf "$tmp_dir"
        error "下载或解压失败"
    fi
    mv "$tmp_dir"/sing-box-*/sing-box "$SINGBOX_BIN"
    chmod +x "$SINGBOX_BIN"
    rm -rf "$tmp_dir"
    mkdir -p "$CONF_DIR" "$CERT_DIR"
    success "Sing-box $TAG 安装成功"
}

# --- 4. 配置生成（支持统一 SNI）---
generate_config() {
    local mode=$1

    read -p "请输入统一的伪装域名 (SNI, 例如: cdn.example.com): " sni_domain
    if [[ -z "$sni_domain" ]]; then
        sni_domain="www.cloudflare.com"
        warn "未指定域名，使用默认伪装域名: $sni_domain"
    fi

    read -p "Hysteria2 端口 (默认8443): " hy2_port
    hy2_port=${hy2_port:-8443}
    read -p "Reality 端口 (默认443): " rel_port
    rel_port=${rel_port:-443}
    
    [[ "$mode" == "all" ]] && open_ports "$hy2_port" "$rel_port"
    [[ "$mode" == "hy2" ]] && open_ports "$hy2_port"
    [[ "$mode" == "reality" ]] && open_ports "$rel_port"

    [[ ! -x "$SINGBOX_BIN" ]] && error "Sing-box 未安装或不可执行"
    
    local uuid=$($SINGBOX_BIN generate uuid)
    local keypair=$($SINGBOX_BIN generate reality-keypair)
    local pk=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
    local pub=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
    local sid=$(openssl rand -hex 4)
    local pass=$(openssl rand -hex 16)
    local ip=$(curl -s https://api.ipify.org)

    local hy2_in="null"
    local rel_in="null"
    
    if [[ "$mode" == "all" || "$mode" == "hy2" ]]; then
        openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/private.key"
        openssl req -new -x509 -days 3650 -nodes -key "$CERT_DIR/private.key" \
            -out "$CERT_DIR/cert.pem" -subj "/CN=$sni_domain"
        
        hy2_in=$(jq -n \
            --arg port "$hy2_port" \
            --arg pass "$pass" \
            --arg cert "$CERT_DIR/cert.pem" \
            --arg key "$CERT_DIR/private.key" \
            '{"type":"hysteria2","tag":"hy2-in","listen":"::","listen_port":($port|tonumber),"users":[{"password":$pass}],"tls":{"enabled":true,"certificate_path":$cert,"key_path":$key}}')
    fi

    if [[ "$mode" == "all" || "$mode" == "reality" ]]; then
        rel_in=$(jq -n \
            --arg port "$rel_port" \
            --arg uuid "$uuid" \
            --arg pk "$pk" \
            --arg sid "$sid" \
            --arg sni "$sni_domain" \
            '{"type":"vless","tag":"vless-in","listen":"::","listen_port":($port|tonumber),"users":[{"uuid":$uuid,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":$sni,"reality":{"enabled":true,"handshake":{"server":$sni,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}')
    fi

    jq -n \
        --argjson hy2 "$hy2_in" \
        --argjson rel "$rel_in" \
        '{"log":{"level":"info","timestamp":true},"inbounds":([$hy2, $rel]|map(select(.!=null))),"outbounds":[{"type":"direct","tag":"direct"}]}' > "$CONF_FILE"

    echo -e "MODE=\"$mode\"\nIP=\"$ip\"\nHY2_P=\"$hy2_port\"\nHY2_K=\"$pass\"\nREL_P=\"$rel_port\"\nREL_U=\"$uuid\"\nREL_B=\"$pub\"\nREL_S=\"$sid\"\nSNI=\"$sni_domain\"" > "$DB_FILE"
}

# --- 5. 服务部署 ---
setup_service() {
    cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-Box Service
After=network.target

[Service]
ExecStart=$SINGBOX_BIN run -c $CONF_FILE
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now sing-box
    success "服务已启动"
}

# --- 查看配置信息 ---
show_info() {
    [[ ! -f "$DB_FILE" ]] && { warn "未找到记录"; return; }
    MODE=$(grep '^MODE=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    IP=$(grep '^IP=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    HY2_P=$(grep '^HY2_P=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    HY2_K=$(grep '^HY2_K=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    REL_P=$(grep '^REL_P=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    REL_U=$(grep '^REL_U=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    REL_B=$(grep '^REL_B=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    REL_S=$(grep '^REL_S=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    SNI=$(grep '^SNI=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')  # ← 关键：读取 SNI

  echo -e "\n${GREEN}======= 配置详情 =======${NC}"
if [[ "$MODE" == "all" || "$MODE" == "hy2" ]]; then
    # 添加 alpn=h3 提高兼容性
    local link="hy2://$HY2_K@$IP:$HY2_P?insecure=1&sni=$SNI&alpn=h3#Hy2-VPS"
    echo -e "Hysteria2: $link"
    qrencode -t ANSIUTF8 "$link"
fi
if [[ "$MODE" == "all" || "$MODE" == "reality" ]]; then
    local link="vless://$REL_U@$IP:$REL_P?security=reality&sni=$SNI&fp=chrome&pbk=$REL_B&sid=$REL_S&flow=xtls-rprx-vision&type=tcp#Rel-Server"
    echo -e "Reality: $link"
    qrencode -t ANSIUTF8 "$link"
fi

}

main_menu() {
    clear
    echo -e "${CYAN}====================================${NC}"
    echo -e "${CYAN}   Sing-Box 官方驱动管理脚本 (2026)  ${NC}"
    echo -e "${CYAN}   ✅ 统一 SNI | ✅ BBR 加速         ${NC}"
    echo -e "${CYAN}====================================${NC}"
    echo "1. 安装 Hysteria2 + Reality"
    echo "2. 单独安装 Hysteria2"
    echo "3. 单独安装 Reality (VLESS)"
    echo "------------------------------------"
    echo "4. 查看当前配置/二维码"
    echo "5. 查看实时日志"
    echo "6. 卸载 Sing-box"
    echo "0. 退出"
    read -p "请选择: " opt
    case $opt in
        1) install_deps; enable_bbr; install_core; generate_config "all"; setup_service; show_info ;;
        2) install_deps; enable_bbr; install_core; generate_config "hy2"; setup_service; show_info ;;
        3) install_deps; enable_bbr; install_core; generate_config "reality"; setup_service; show_info ;;
        4) show_info ;;
        5) journalctl -u sing-box -f -n 50 ;;
        6) systemctl disable --now sing-box; rm -rf "$SINGBOX_BIN" "$CONF_DIR" /etc/systemd/system/sing-box.service; systemctl daemon-reload; success "卸载完成" ;;
        *) exit ;;
    esac
}

[[ "$(id -u)" -ne 0 ]] && error "请用 root 运行"
main_menu
