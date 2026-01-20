cat << 'EOF' > Hy2_Vless_Final.sh
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

# --- 核心辅助函数 (必须定义在脚本最上方) ---
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# --- 1. 环境准备 ---
install_deps() {
    info "安装必要依赖..."
    local deps=("curl" "wget" "jq" "openssl" "tar" "qrencode" "socat")
    apt update && apt install -y "${deps[@]}"
}

enable_bbr() {
    info "检测 BBR..."
    if ! sysctl net.ipv4.tcp_congestion_control | grep -q 'bbr'; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
    fi
    success "BBR 已就绪"
}

# --- 2. 安装核心 ---
install_core() {
    if [[ ! -x "$SINGBOX_BIN" ]]; then
        info "正在下载 Sing-box..."
        TAG=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r 'map(select(.prerelease == true)) | first | .tag_name')
        VERSION=${TAG#v}
        wget -qO- "https://github.com/SagerNet/sing-box/releases/download/${TAG}/sing-box-${VERSION}-linux-amd64.tar.gz" | tar -xz -C /tmp
        mv /tmp/sing-box-*/sing-box "$SINGBOX_BIN"
        chmod +x "$SINGBOX_BIN"
    fi
    mkdir -p "$CONF_DIR" "$CERT_DIR"
}

# --- 3. 配置生成 (Reality/Hy2) ---
generate_config() {
    local mode=$1
    read -p "伪装域名 (SNI) [www.bing.com]: " sni; sni=${sni:-"www.bing.com"}
    read -p "Hy2 端口 [8443]: " hy_p; hy_p=${hy_p:-8443}
    read -p "Reality 端口 [443]: " rel_p; rel_p=${rel_p:-443}

    local uuid=$($SINGBOX_BIN generate uuid)
    local keypair=$($SINGBOX_BIN generate reality-keypair)
    local pk=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
    local pub=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
    local sid=$(openssl rand -hex 4)
    local pass=$(openssl rand -hex 16)
    local ip=$(curl -s https://api.ipify.org)

    openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/hy2.key"
    openssl req -new -x509 -days 3650 -nodes -key "$CERT_DIR/hy2.key" -out "$CERT_DIR/hy2.pem" -subj "/CN=$sni" >/dev/null 2>&1

    jq -n --arg hp "$hy_p" --arg pass "$pass" --arg rp "$rel_p" --arg uuid "$uuid" --arg pk "$pk" --arg sid "$sid" --arg sni "$sni" --arg cert "$CERT_DIR/hy2.pem" --arg key "$CERT_DIR/hy2.key" \
    '{"log":{"level":"info"},"inbounds":[{"type":"hysteria2","tag":"hy2-in","listen":"0.0.0.0","listen_port":($hp|tonumber),"users":[{"password":$pass}],"tls":{"enabled":true,"certificate_path":$cert,"key_path":$key}},{"type":"vless","tag":"vless-in","listen":"0.0.0.0","listen_port":($rp|tonumber),"users":[{"uuid":$uuid,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":$sni,"reality":{"enabled":true,"handshake":{"server":$sni,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}],"outbounds":[{"type":"direct"}]}' > "$CONF_FILE"

    echo -e "MODE=\"all\"\nIP=\"$ip\"\nHY_PASS=\"$pass\"\nHY_PORT=\"$hy_p\"\nSNI=\"$sni\"\nREL_UUID=\"$uuid\"\nREL_PORT=\"$rel_p\"\nREL_PUB=\"$pub\"\nREL_SID=\"$sid\"" > "$DB_FILE"
}

# --- 4. Hy2 + VLESS-WS ---
generate_hy2_ws() {
    read -p "请输入解析好的域名: " domain
    [[ -z "$domain" ]] && error "必须输入域名"
    local ip=$(curl -s https://api.ipify.org)
    local uuid=$($SINGBOX_BIN generate uuid)
    local path="/$(openssl rand -hex 4)"
    local pass=$(openssl rand -hex 12)

    info "证书申请中 (需要确保80端口空闲)..."
    if [ ! -d "$HOME/.acme.sh" ]; then curl -s https://get.acme.sh | sh; fi
    ~/.acme.sh/acme.sh --issue -d "$domain" --standalone --force
    ~/.acme.sh/acme.sh --install-cert -d "$domain" --fullchain-file "$CERT_DIR/ws.pem" --key-file "$CERT_DIR/ws.key"

    jq -n --arg hp "8443" --arg pass "$pass" --arg wp "443" --arg uuid "$uuid" --arg domain "$domain" --arg path "$path" --arg cert "$CERT_DIR/ws.pem" --arg key "$CERT_DIR/ws.key" \
    '{"log":{"level":"info"},"inbounds":[{"type":"hysteria2","tag":"hy2-in","listen":"0.0.0.0","listen_port":($hp|tonumber),"users":[{"password":$pass}],"tls":{"enabled":true,"certificate_path":$cert,"key_path":$key}},{"type":"vless","tag":"ws-in","listen":"0.0.0.0","listen_port":($wp|tonumber),"users":[{"uuid":$uuid}],"tls":{"enabled":true,"certificate_path":$cert,"key_path":$key},"transport":{"type":"ws","path":$path}}],"outbounds":[{"type":"direct"}]}' > "$CONF_FILE"

    echo -e "MODE=\"hy2_ws\"\nIP=\"$ip\"\nHY_PASS=\"$pass\"\nHY_PORT=\"8443\"\nHY_SNI=\"$domain\"\nWS_UUID=\"$uuid\"\nWS_PORT=\"443\"\nWS_DOMAIN=\"$domain\"\nWS_PATH=\"$path\"" > "$DB_FILE"
}

# --- 5. 展示信息 ---
show_info() {
    [[ ! -f "$DB_FILE" ]] && return
    source "$DB_FILE"
    echo -e "\n${GREEN}======= 节点信息与二维码 =======${NC}"
    if [[ "$MODE" == "hy2_ws" ]]; then
        local l1="hy2://$HY_PASS@$IP:$HY_PORT?insecure=1&sni=$HY_SNI#Hy2"
        local l2="vless://$WS_UUID@$IP:$WS_PORT?encryption=none&security=tls&type=ws&host=$WS_DOMAIN&path=$WS_PATH#VLESS-WS"
        echo -e "Hy2: $l1\nWS: $l2"
        qrencode -t ansiutf8 "$l1"; qrencode -t ansiutf8 "$l2"
    else
        local l1="hy2://$HY_PASS@$IP:$HY_PORT?insecure=1&sni=$SNI#Hy2"
        local l2="vless://$REL_UUID@$IP:$REL_PORT?security=reality&sni=$SNI&fp=chrome&pbk=$REL_PUB&sid=$REL_SID&flow=xtls-rprx-vision&type=tcp#Reality"
        echo -e "Hy2: $l1\nReality: $l2"
        qrencode -t ansiutf8 "$l1"; qrencode -t ansiutf8 "$l2"
    fi
}

# --- 菜单 ---
main_menu() {
    clear
    echo "1. 安装 Hysteria2 + Reality"
    echo "2. 单独安装 Hysteria2"
    echo "3. 单独安装 Reality (VLESS)"
    echo "4. 安装 VLESS + WebSocket + TLS"
    echo "5. 安装 Hysteria2 + VLESS-WS"
    echo "------------------------------------"
    echo "6. 查看当前配置/二维码"
    echo "7. 查看实时日志"
    echo "8. 卸载 Sing-box"
    echo "0. 退出"
    read -p "选择: " opt
    case $opt in
        1|2|3) install_deps; enable_bbr; install_core; generate_config "all" ;;
        4|5) install_deps; enable_bbr; install_core; generate_hy2_ws ;;
        6) show_info; exit 0 ;;
        7) journalctl -u sing-box -f ;;
        8) systemctl disable --now sing-box; rm -rf "$CONF_DIR" "$SINGBOX_BIN"; success "卸载完成"; exit 0 ;;
        *) exit 0 ;;
    esac

    # 部署服务
    cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box
After=network.target
[Service]
ExecStart=$SINGBOX_BIN run -c $CONF_FILE
Restart=always
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl enable --now sing-box
    show_info
}

main_menu
EOF
chmod +x Hy2_Vless_Final.sh
./Hy2_Vless_Final.sh
