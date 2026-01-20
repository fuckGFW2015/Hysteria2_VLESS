cat << 'EOF' > Hy2_Vless_Final.sh
#!/bin/bash

# --- 路徑與常量配置 ---
SINGBOX_BIN="/usr/local/bin/sing-box"
CONF_DIR="/etc/sing-box"
CONF_FILE="${CONF_DIR}/config.json"
CERT_DIR="${CONF_DIR}/certs"
DB_FILE="${CONF_DIR}/.script_data.db"

# 顏色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 核心輔助函數 ---
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# --- 啟用 BBR 加速 ---
enable_bbr() {
    info "正在檢測並啟用 BBR 加速..."
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q 'bbr'; then
        success "BBR 已啟用"
        return
    fi
    echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
    echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
    success "BBR 已開啟"
}

# --- 1. 環境準備與依賴安裝 ---
install_deps() {
    info "檢查並安裝必要依賴..."
    local deps=("curl" "wget" "jq" "openssl" "tar" "qrencode" "socat" "iptables-persistent")
    if command -v apt &>/dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        echo iptables-persistent select true | debconf-set-selections
        apt update && apt install -y "${deps[@]}"
    elif command -v dnf &>/dev/null; then
        dnf install -y epel-release && dnf install -y "${deps[@]}"
    elif command -v yum &>/dev/null; then
        yum install -y epel-release && yum install -y "${deps[@]}"
    fi
}

# --- 2. 自動放行防火牆 ---
open_ports() {
    info "配置系統防火牆策略..."
    if command -v iptables &>/dev/null; then
        iptables -P INPUT ACCEPT
        iptables -F
    fi
    for p in "$@"; do
        local port_num=$p
        local proto="tcp"
        [[ "$p" == *"/"* ]] && { port_num=${p%/*}; proto=${p##*/}; }
        iptables -I INPUT -p "$proto" --dport "$port_num" -j ACCEPT 2>/dev/null
    done
    [[ -x "$(command -v netfilter-persistent)" ]] && netfilter-persistent save >/dev/null 2>&1
}

# --- 3. 安裝核心 ---
install_core() {
    [[ -x "$SINGBOX_BIN" ]] && return
    info "獲取 Sing-box 核心..."
    TAG=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r 'map(select(.prerelease == true)) | first | .tag_name // empty')
    [[ -z "$TAG" ]] && error "獲取版本失敗"
    VERSION=${TAG#v}
    URL="https://github.com/SagerNet/sing-box/releases/download/${TAG}/sing-box-${VERSION}-linux-amd64.tar.gz"
    wget -qO- "$URL" | tar -xz -C /tmp
    mv /tmp/sing-box-*/sing-box "$SINGBOX_BIN"
    chmod +x "$SINGBOX_BIN"
    mkdir -p "$CONF_DIR" "$CERT_DIR"
}

# --- 4. 配置生成 (Reality/Hy2) ---
generate_config() {
    local mode=$1
    read -p "請輸入偽裝域名 (SNI): " sni_domain; sni_domain=${sni_domain:-"www.cloudflare.com"}
    read -p "Hysteria2 端口 (默認8443): " hy2_port; hy2_port=${hy2_port:-8443}
    read -p "Reality 端口 (默認443): " rel_port; rel_port=${rel_port:-443}
    
    [[ "$mode" == "all" ]] && open_ports "$hy2_port/udp" "$rel_port/tcp"
    [[ "$mode" == "hy2" ]] && open_ports "$hy2_port/udp"
    [[ "$mode" == "reality" ]] && open_ports "$rel_port/tcp"

    local uuid=$($SINGBOX_BIN generate uuid)
    local keypair=$($SINGBOX_BIN generate reality-keypair)
    local pk=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
    local pub=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
    local sid=$(openssl rand -hex 4)
    local pass=$(openssl rand -hex 16)
    local ip=$(curl -s https://api.ipify.org)
    
    local hy2_in="null"; local rel_in="null"
    if [[ "$mode" == "all" || "$mode" == "hy2" ]]; then
        openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/private.key"
        openssl req -new -x509 -days 3650 -nodes -key "$CERT_DIR/private.key" -out "$CERT_DIR/cert.pem" -subj "/CN=$sni_domain" >/dev/null 2>&1
        hy2_in=$(jq -n --arg port "$hy2_port" --arg pass "$pass" --arg cert "$CERT_DIR/cert.pem" --arg key "$CERT_DIR/private.key" \
        '{"type":"hysteria2","tag":"hy2-in","listen":"0.0.0.0","listen_port":($port|tonumber),"users":[{"password":$pass}],"tls":{"enabled":true,"certificate_path":$cert,"key_path":$key}}')
    fi
    if [[ "$mode" == "all" || "$mode" == "reality" ]]; then
        rel_in=$(jq -n --arg port "$rel_port" --arg uuid "$uuid" --arg pk "$pk" --arg sid "$sid" --arg sni "$sni_domain" \
        '{"type":"vless","tag":"vless-in","listen":"0.0.0.0","listen_port":($port|tonumber),"users":[{"uuid":$uuid,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":$sni,"reality":{"enabled":true,"handshake":{"server":$sni,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}')
    fi
    jq -n --argjson hy2 "$hy2_in" --argjson rel "$rel_in" '{"log":{"level":"info"},"inbounds":([$hy2, $rel]|map(select(.!=null))),"outbounds":[{"type":"direct"}]}' > "$CONF_FILE"
    echo -e "MODE=\"reality_hy2\"\nIP=\"$ip\"\nHY_PASS=\"$pass\"\nHY_PORT=\"$hy2_port\"\nSNI=\"$sni_domain\"\nREL_UUID=\"$uuid\"\nREL_PORT=\"$rel_port\"\nREL_PK=\"$pk\"\nREL_SID=\"$sid\"" > "$DB_FILE"
}

# --- 5. Hy2 + VLESS-WS (修復版) ---
generate_hy2_and_vless_ws() {
    read -p "Hy2 SNI (默認 www.bing.com): " hy_sni; hy_sni=${hy_sni:-"www.bing.com"}
    read -p "Hy2 端口 (默認 8443): " hy_port; hy_port=${hy_port:-8443}
    read -p "VLESS-WS 域名: " ws_domain
    [[ -z "$ws_domain" ]] && error "域名不能為空"
    read -p "VLESS-WS 端口 (默認 443): " ws_port; ws_port=${ws_port:-443}

    open_ports "$hy_port/udp" "$ws_port/tcp" "80/tcp"
    systemctl stop nginx apache2 httpd 2>/dev/null || true

    if [ ! -d "$HOME/.acme.sh" ]; then
        curl -s https://get.acme.sh | sh -s email=admin@${ws_domain} >/dev/null
    fi
    rm -rf ~/.acme.sh/ca
    ~/.acme.sh/acme.sh --register-account -m "admin@${ws_domain}" --server letsencrypt --force

    openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/hy2.key"
    openssl req -new -x509 -days 3650 -nodes -key "$CERT_DIR/hy2.key" -out "$CERT_DIR/hy2.pem" -subj "/CN=$hy_sni" >/dev/null 2>&1
    local hy_pass=$(openssl rand -hex 16)

    local ws_cert=""
    local ws_key=""
    info "正在向 Let's Encrypt 申請正式證書..."
    if ~/.acme.sh/acme.sh --issue -d "$ws_domain" --standalone --server letsencrypt --force --accountemail "admin@${ws_domain}"; then
        ~/.acme.sh/acme.sh --install-cert -d "$ws_domain" --cert-file "$CERT_DIR/ws.pem" --key-file "$CERT_DIR/ws.key" --fullchain-file "$CERT_DIR/ws-fullchain.pem"
        ws_cert="$CERT_DIR/ws-fullchain.pem"; ws_key="$CERT_DIR/ws.key"
        success "證書申請成功！"
    else
        warn "申請失敗，切換自簽名"
        openssl req -new -x509 -days 365 -nodes -subj "/CN=$ws_domain" -out "$CERT_DIR/ws.pem" -keyout "$CERT_DIR/ws.key" >/dev/null 2>&1
        ws_cert="$CERT_DIR/ws.pem"; ws_key="$CERT_DIR/ws.key"
    fi

    local ws_uuid=$($SINGBOX_BIN generate uuid)
    local ws_path="/$(openssl rand -hex 6)"
    local ip=$(curl -s https://api.ipify.org)

    local hy_in=$(jq -n --arg port "$hy_port" --arg pass "$hy_pass" --arg cert "$CERT_DIR/hy2.pem" --arg key "$CERT_DIR/hy2.key" \
        '{"type":"hysteria2","tag":"hy2-in","listen":"0.0.0.0","listen_port":($port|tonumber),"users":[{"password":$pass}],"tls":{"enabled":true,"certificate_path":$cert,"key_path":$key}}')
    local ws_in=$(jq -n --arg port "$ws_port" --arg uuid "$ws_uuid" --arg cert "$ws_cert" --arg key "$ws_key" --arg domain "$ws_domain" --arg path "$ws_path" \
        '{"type":"vless","tag":"vless-ws-in","listen":"0.0.0.0","listen_port":($port|tonumber),"users":[{"uuid":$uuid}],"tls":{"enabled":true,"certificate_path":$cert,"key_path":$key},"transport":{"type":"ws","path":$path,"headers":{"Host":$domain}}}')

    jq -n --argjson hy "$hy_in" --argjson ws "$ws_in" '{"log":{"level":"info"},"inbounds":[$hy, $ws],"outbounds":[{"type":"direct"}]}' > "$CONF_FILE"
    echo -e "MODE=\"hy2_ws\"\nIP=\"$ip\"\nHY_PASS=\"$hy_pass\"\nHY_PORT=\"$hy_port\"\nHY_SNI=\"$hy_sni\"\nWS_UUID=\"$ws_uuid\"\nWS_PORT=\"$ws_port\"\nWS_DOMAIN=\"$ws_domain\"\nWS_PATH=\"$ws_path\"" > "$DB_FILE"
}

# --- 服務部署 ---
setup_service() {
    $SINGBOX_BIN check -c "$CONF_FILE" || error "配置校驗失敗"
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
    success "Sing-box 運行中"
}

# --- 6. 查看信息與二維碼 ---
show_info() {
    [[ ! -f "$DB_FILE" ]] && { warn "未找到配置記錄"; return; }
    source "$DB_FILE"
    echo -e "\n${GREEN}======= 節點鏈接 =======${NC}"
    if [[ "$MODE" == "hy2_ws" ]]; then
        local hy2_link="hy2://$HY_PASS@$IP:$HY_PORT?insecure=1&sni=$HY_SNI#Hy2"
        local ws_link="vless://$WS_UUID@$IP:$WS_PORT?encryption=none&security=tls&type=ws&host=$WS_DOMAIN&path=$WS_PATH#VLESS-WS"
        echo -e "Hysteria2: ${CYAN}$hy2_link${NC}"
        qrencode -t ansiutf8 "$hy2_link"
        echo -e "\nVLESS-WS: ${CYAN}$ws_link${NC}"
        qrencode -t ansiutf8 "$ws_link"
    else
        local hy2_link="hy2://$HY_PASS@$IP:$HY_PORT?insecure=1&sni=$SNI#Hy2"
        local rel_link="vless://$REL_UUID@$IP:$REL_PORT?security=reality&sni=$SNI&fp=chrome&pbk=$REL_PK&sid=$REL_SID&flow=xtls-rprx-vision&type=tcp#Reality"
        echo -e "Hysteria2: ${CYAN}$hy2_link${NC}"
        qrencode -t ansiutf8 "$hy2_link"
        echo -e "\nReality: ${CYAN}$rel_link${NC}"
        qrencode -t ansiutf8 "$rel_link"
    fi
}

# --- 菜單 ---
main_menu() {
    clear
    echo -e "${CYAN}====================================${NC}"
    echo -e "${CYAN}   Sing-Box 管理腳本 (完整修復版)   ${NC}"
    echo -e "${CYAN}====================================${NC}"
    echo "1. 安裝 Hysteria2 + Reality"
    echo "2. 單獨安裝 Hysteria2"
    echo "3. 單獨安裝 Reality (VLESS)"
    echo "4. 安裝 VLESS + WebSocket + TLS"
    echo "5. 安裝 Hysteria2 + VLESS-WS"
    echo "------------------------------------"
    echo "6. 查看當前配置/二維碼"
    echo "7. 查看實時日誌"
    echo "8. 卸載 Sing-box"
    echo "0. 退出"
    read -p "選擇: " opt
    case $opt in
        1) install_deps; enable_bbr; install_core; generate_config "all"; setup_service; show_info ;;
        2) install_deps; enable_bbr; install_core; generate_config "hy2"; setup_service; show_info ;;
        3) install_deps; enable_bbr; install_core; generate_config "reality"; setup_service; show_info ;;
        4|5) install_deps; enable_bbr; install_core; generate_hy2_and_vless_ws; setup_service; show_info ;;
        6) show_info ;;
        7) journalctl -u sing-box -f -n 50 ;;
        8) systemctl disable --now sing-box; rm -rf "$SINGBOX_BIN" "$CONF_DIR"; success "卸載完成" ;;
        *) exit ;;
    esac
}

[[ "$(id -u)" -ne 0 ]] && error "請用 root 運行"
main_menu
EOF

chmod +x Hy2_Vless_Final.sh
./Hy2_Vless_Final.sh
