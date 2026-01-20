cat << 'EOF' > Hy2_Vless_Official_Fix.sh
#!/bin/bash

# --- 基础配置 ---
SINGBOX_BIN="/usr/local/bin/sing-box"
CONF_DIR="/etc/sing-box"
CONF_FILE="${CONF_DIR}/config.json"
CERT_DIR="${CONF_DIR}/certs"
DB_FILE="${CONF_DIR}/.script_data.db"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- 辅助工具函数 (必须放在最前面) ---
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# --- 显示信息与二维码函数 ---
show_info() {
    if [[ ! -f "$DB_FILE" ]]; then
        echo -e "${YELLOW}未发现安装记录${NC}"
        return
    fi
    source "$DB_FILE"
    echo -e "\n${GREEN}======= 节点信息与二维码 =======${NC}"
    if [[ "$MODE" == "hy2_ws" ]]; then
        local l1="hy2://$HY_PASS@$IP:$HY_PORT?insecure=1&sni=$HY_SNI#Hy2_Fix"
        local l2="vless://$WS_UUID@$IP:$WS_PORT?encryption=none&security=tls&type=ws&host=$WS_DOMAIN&path=$WS_PATH#WS_Fix"
        echo -e "Hysteria2: $l1\nVLESS-WS: $l2"
        echo -e "\n--- Hy2 二维码 ---"
        qrencode -t ansiutf8 "$l1"
        echo -e "\n--- WS 二维码 ---"
        qrencode -t ansiutf8 "$l2"
    else
        local l1="hy2://$HY_PASS@$IP:$HY_PORT?insecure=1&sni=$SNI#Hy2_Fix"
        local l2="vless://$REL_UUID@$IP:$REL_PORT?security=reality&sni=$SNI&fp=chrome&pbk=$REL_PUB&sid=$REL_SID&flow=xtls-rprx-vision&type=tcp#Reality_Fix"
        echo -e "Hysteria2: $l1\nReality: $l2"
        echo -e "\n--- Hy2 二维码 ---"
        qrencode -t ansiutf8 "$l1"
        echo -e "\n--- Reality 二维码 ---"
        qrencode -t ansiutf8 "$l2"
    fi
}

# --- 环境准备 ---
install_base() {
    info "安装必要组件..."
    apt update && apt install -y curl jq openssl qrencode tar socat
    if ! sysctl net.ipv4.tcp_congestion_control | grep -q 'bbr'; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
    fi
}

install_core() {
    if [[ ! -x "$SINGBOX_BIN" ]]; then
        TAG=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r 'map(select(.prerelease == true)) | first | .tag_name')
        wget -qO- "https://github.com/SagerNet/sing-box/releases/download/${TAG}/sing-box-${TAG#v}-linux-amd64.tar.gz" | tar -xz -C /tmp
        mv /tmp/sing-box-*/sing-box "$SINGBOX_BIN"
        chmod +x "$SINGBOX_BIN"
    fi
    mkdir -p "$CONF_DIR" "$CERT_DIR"
}

# --- 安装逻辑 ---
do_install_hy2_ws() {
    read -p "请输入解析好的域名: " domain
    [[ -z "$domain" ]] && error "域名不能为空"
    local ip=$(curl -s https://api.ipify.org)
    local uuid=$($SINGBOX_BIN generate uuid)
    local path="/$(openssl rand -hex 4)"
    local pass=$(openssl rand -hex 12)
    
    # 证书申请逻辑
    info "正在申请证书..."
    if [ ! -d "$HOME/.acme.sh" ]; then curl -s https://get.acme.sh | sh; fi
    ~/.acme.sh/acme.sh --issue -d "$domain" --standalone
    ~/.acme.sh/acme.sh --install-cert -d "$domain" --fullchain-file "$CERT_DIR/full.pem" --key-file "$CERT_DIR/priv.key"

    # 生成配置 (简化演示)
    jq -n --arg hp "8443" --arg pass "$pass" --arg wp "443" --arg uuid "$uuid" --arg domain "$domain" --arg path "$path" --arg cert "$CERT_DIR/full.pem" --arg key "$CERT_DIR/priv.key" \
    '{"inbounds":[{"type":"hysteria2","listen_port":($hp|tonumber),"users":[{"password":$pass}],"tls":{"enabled":true,"certificate_path":$cert,"key_path":$key}},{"type":"vless","listen_port":($wp|tonumber),"users":[{"uuid":$uuid}],"tls":{"enabled":true,"certificate_path":$cert,"key_path":$key},"transport":{"type":"ws","path":$path}}],"outbounds":[{"type":"direct"}]}' > "$CONF_FILE"

    echo -e "MODE=\"hy2_ws\"\nIP=\"$ip\"\nHY_PASS=\"$pass\"\nHY_PORT=\"8443\"\nHY_SNI=\"$domain\"\nWS_UUID=\"$uuid\"\nWS_PORT=\"443\"\nWS_DOMAIN=\"$domain\"\nWS_PATH=\"$path\"" > "$DB_FILE"
    
    systemctl stop sing-box 2>/dev/null
    cat > /etc/systemd/system/sing-box.service <<SBEOF
[Unit]
After=network.target
[Service]
ExecStart=$SINGBOX_BIN run -c $CONF_FILE
Restart=always
[Install]
WantedBy=multi-user.target
SBEOF
    systemctl daemon-reload && systemctl enable --now sing-box
}

# --- 菜单 ---
while true; do
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
    read -p "请选择: " opt
    case $opt in
        1|2|3|4|5) install_base; install_core; do_install_hy2_ws; show_info; read -n1 -p "按任意键返回";;
        6) show_info; read -n1 -p "按任意键返回";;
        7) journalctl -u sing-box -f ;;
        8) systemctl disable --now sing-box; rm -rf "$CONF_DIR" "$SINGBOX_BIN"; success "卸载完成"; sleep 2 ;;
        0) exit 0 ;;
        *) echo "无效选项" ;;
    esac
done
EOF

chmod +x Hy2_Vless_Official_Fix.sh
./Hy2_Vless_Official_Fix.sh
