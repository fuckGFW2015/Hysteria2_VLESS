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
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q 'bbr'; then
        success "BBR 已启用"
        return
    fi
    echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
    echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
    success "BBR 已成功启用"
}

# --- 1. 环境准备与依赖安装 ---
install_deps() {
    info "安装必要依赖..."
    local deps=("curl" "wget" "jq" "openssl" "tar" "qrencode")
    if command -v apt &>/dev/null; then
        apt update && apt install -y "${deps[@]}"
    elif command -v dnf &>/dev/null; then
        dnf install -y "${deps[@]}"
    fi
}

# --- 2. 自动放行防火墙 ---
open_ports() {
    for port in "$@"; do
        if command -v ufw &>/dev/null; then
            ufw allow "$port"/tcp >/dev/null; ufw allow "$port"/udp >/dev/null
        elif command -v firewall-cmd &>/dev/null; then
            firewall-cmd --permanent --add-port="$port"/{tcp,udp} >/dev/null; firewall-cmd --reload >/dev/null
        else
            iptables -I INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null
            iptables -I INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null
        fi
        echo -e "  - 已放行端口: $port"
    done
}

# --- 3. 下载核心 ---
install_core() {
    info "下载 Sing-box 最新 Beta 核心..."
    local api_url="https://api.github.com/repos/SagerNet/sing-box/releases"
    TAG=$(curl -s "$api_url" | jq -r 'map(select(.prerelease == true)) | first | .tag_name')
    VERSION=${TAG#v}
    ARCH=$(uname -m)
    [[ "$ARCH" == "x86_64" ]] && SARCH="linux-amd64" || SARCH="linux-arm64"
    
    URL="https://github.com/SagerNet/sing-box/releases/download/${TAG}/sing-box-${VERSION}-${SARCH}.tar.gz"
    wget -qO- "$URL" | tar -xz -C /tmp
    mv /tmp/sing-box-*/sing-box "$SINGBOX_BIN"
    chmod +x "$SINGBOX_BIN"
    mkdir -p "$CONF_DIR" "$CERT_DIR"
    success "Sing-box $TAG 安装成功"
}

# --- 4. 配置生成 ---
generate_config() {
    read -p "请输入伪装域名 (SNI, 默认 www.cloudflare.com): " sni_domain
    sni_domain=${sni_domain:-www.cloudflare.com}
    
    read -p "Hysteria2 端口 (默认 8443): " hy2_p; hy2_p=${hy2_p:-8443}
    read -p "TUIC v5 端口 (默认 8444): " tuic_p; tuic_p=${tuic_p:-8444}
    read -p "Reality 端口 (默认 443): " rel_p; rel_p=${rel_p:-443}

    open_ports "$hy2_p" "$tuic_p" "$rel_p"

    local uuid=$($SINGBOX_BIN generate uuid)
    local tuic_uuid=$($SINGBOX_BIN generate uuid)
    local keypair=$($SINGBOX_BIN generate reality-keypair)
    local pk=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
    local pub=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
    local sid=$(openssl rand -hex 4)
    local hy2_pass=$(openssl rand -hex 16)
    local ip=$(curl -s https://api.ipify.org)

    # 生成自签名证书 (Hy2 & TUIC 使用)
    openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/private.key"
    openssl req -new -x509 -days 3650 -nodes -key "$CERT_DIR/private.key" \
        -out "$CERT_DIR/cert.pem" -subj "/CN=$sni_domain"

    # 构建 JSON
    hy2_in=$(jq -n --arg p "$hy2_p" --arg pass "$hy2_pass" --arg cert "$CERT_DIR/cert.pem" --arg key "$CERT_DIR/private.key" \
        '{"type":"hysteria2","tag":"hy2-in","listen":"::","listen_port":($p|tonumber),"users":[{"password":$pass}],"tls":{"enabled":true,"certificate_path":$cert,"key_path":$key}}')
    
    tuic_in=$(jq -n --arg p "$tuic_p" --arg uuid "$tuic_uuid" --arg cert "$CERT_DIR/cert.pem" --arg key "$CERT_DIR/private.key" \
        '{"type":"tuic","tag":"tuic-in","listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$uuid}],"tls":{"enabled":true,"certificate_path":$cert,"key_path":$key,"alpn":["h3"]},"congestion_control":"bbr"}')

    rel_in=$(jq -n --arg p "$rel_p" --arg uuid "$uuid" --arg pk "$pk" --arg sid "$sid" --arg sni "$sni_domain" \
        '{"type":"vless","tag":"vless-in","listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$uuid,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":$sni,"reality":{"enabled":true,"handshake":{"server":$sni,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}')

    jq -n --argjson hy2 "$hy2_in" --argjson tuic "$tuic_in" --argjson rel "$rel_in" \
        '{"log":{"level":"info","timestamp":true},"inbounds":[$hy2, $tuic, $rel],"outbounds":[{"type":"direct","tag":"direct"}]}' > "$CONF_FILE"

    # 保存数据
    echo -e "IP=\"$ip\"\nHY2_P=\"$hy2_p\"\nHY2_K=\"$hy2_pass\"\nTUIC_P=\"$tuic_p\"\nTUIC_U=\"$tuic_uuid\"\nREL_P=\"$rel_p\"\nREL_U=\"$uuid\"\nREL_B=\"$pub\"\nREL_S=\"$sid\"\nSNI=\"$sni_domain\"" > "$DB_FILE"
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
    systemctl daemon-reload && systemctl enable --now sing-box
    success "服务已启动"
}

# --- 查看配置信息 ---
show_info() {
    source "$DB_FILE"
    echo -e "\n${GREEN}======= 节点配置列表 =======${NC}"
    
    # Hy2
    local hy2_link="hy2://$HY2_K@$IP:$HY2_P?insecure=1&sni=$SNI&alpn=h3#Hy2-$IP"
    echo -e "${CYAN}[Hysteria2]${NC}\n$hy2_link\n"

    # TUIC v5
    local tuic_link="tuic://$TUIC_U@$IP:$TUIC_P?sni=$SNI&congestion_control=bbr&alpn=h3&allow_insecure=1#TUIC-$IP"
    echo -e "${CYAN}[TUIC v5]${NC}\n$tuic_link\n"

    # Reality
    local rel_link="vless://$REL_U@$IP:$REL_P?security=reality&sni=$SNI&fp=chrome&pbk=$REL_B&sid=$REL_S&flow=xtls-rprx-vision&type=tcp#Reality-$IP"
    echo -e "${CYAN}[Reality]${NC}\n$rel_link\n"
    
    warn "注意：Hy2 和 TUIC 使用自签名证书，客户端请开启 '允许不安全连接 (Insecure)'"
}

# --- 主菜单 ---
main_menu() {
    clear
    echo -e "${CYAN}Sing-Box 2026 增强版管理脚本${NC}"
    echo "1. 安装/重装 (Hy2 + TUIC + Reality)"
    echo "2. 查看当前配置链接"
    echo "3. 卸载"
    echo "0. 退出"
    read -p "选择: " opt
    case $opt in
        1) install_deps; enable_bbr; install_core; generate_config; setup_service; show_info ;;
        2) show_info ;;
        3) systemctl disable --now sing-box; rm -rf "$SINGBOX_BIN" "$CONF_DIR"; success "已卸载" ;;
        *) exit ;;
    esac
}

[[ "$(id -u)" -ne 0 ]] && error "请用 root 运行"
main_menu
