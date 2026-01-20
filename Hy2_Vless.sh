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
    success "BBR 已开启"
}

# --- 1. 环境准备与依赖安装 ---
install_deps() {
    info "检查并安装必要依赖..."
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

# --- 2. 自动放行防火墙 (已解决冲突逻辑) ---
open_ports() {
    info "配置系统防火墙策略..."
    if command -v iptables &>/dev/null; then
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        iptables -F
    fi

    for p in "$@"; do
        local port_num=$p
        local proto="tcp"
        if [[ "$p" == *"/"* ]]; then
            port_num=${p%/*}
            proto=${p##*/}
        fi

        if command -v ufw &>/dev/null; then
            ufw allow "$port_num"/"$proto" >/dev/null 2>&1
        fi
        if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
            firewall-cmd --permanent --add-port="$port_num"/"$proto" >/dev/null 2>&1
            firewall-cmd --reload >/dev/null 2>&1
        fi
        iptables -I INPUT -p "$proto" --dport "$port_num" -j ACCEPT 2>/dev/null
        echo -e "  - 放行端口: $port_num ($proto)"
    done

    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save >/dev/null 2>&1
    fi
}

# --- 3. 下载核心 ---
install_core() {
    [[ -x "$SINGBOX_BIN" ]] && return
    info "从 GitHub 获取最新官方 Beta 核心..."
    local api_url="https://api.github.com/repos/SagerNet/sing-box/releases"
    TAG=$(curl -s "$api_url" | jq -r 'map(select(.prerelease == true)) | first | .tag_name // empty')
    [[ -z "$TAG" ]] && error "获取版本失败"
    VERSION=${TAG#v}
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) SARCH="linux-amd64" ;;
        aarch64) SARCH="linux-arm64" ;;
        *) error "不支持的架构" ;;
    esac
    URL="https://github.com/SagerNet/sing-box/releases/download/${TAG}/sing-box-${VERSION}-${SARCH}.tar.gz"
    wget -qO- "$URL" | tar -xz -C /tmp
    mv /tmp/sing-box-*/sing-box "$SINGBOX_BIN"
    chmod +x "$SINGBOX_BIN"
    mkdir -p "$CONF_DIR" "$CERT_DIR"
}

# --- 4. 配置生成 (Reality/Hy2) ---
generate_config() {
    local mode=$1
    read -p "请输入伪装域名 (SNI): " sni_domain
    sni_domain=${sni_domain:-"www.cloudflare.com"}
    read -p "Hysteria2 端口 (默认8443): " hy2_port; hy2_port=${hy2_port:-8443}
    read -p "Reality 端口 (默认443): " rel_port; rel_port=${rel_port:-443}
    
    [[ "$mode" == "all" ]] && open_ports "$hy2_port/udp" "$rel_port/tcp"
    [[ "$mode" == "hy2" ]] && open_ports "$hy2_port/udp"
    [[ "$mode" == "reality" ]] && open_ports "$rel_port/tcp"

    local uuid=$($SINGBOX_BIN generate uuid)
    local keypair=$($SINGBOX_BIN generate reality-keypair)
    local pk=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
    local pub=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
    local sid=$(openssl rand -hex 4)
    local pass=$(openssl rand -hex 16)
    
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
    jq -n --argjson hy2 "$hy2_in" --argjson rel "$rel_in" '{"log":{"level":"info","timestamp":true},"inbounds":([$hy2, $rel]|map(select(.!=null))),"outbounds":[{"type":"direct","tag":"direct"}]}' > "$CONF_FILE"
    echo -e "MODE=\"$mode\"\nIP=\"$(curl -s https://api.ipify.org)\"\nHY2_P=\"$hy2_port\"\nHY2_K=\"$pass\"\nREL_P=\"$rel_port\"\nREL_U=\"$uuid\"\nREL_B=\"$pub\"\nREL_S=\"$sid\"\nSNI=\"$sni_domain\"" > "$DB_FILE"
}

# --- 5. VLESS + WS + TLS (仅使用 Let's Encrypt) ---
generate_vless_ws_tls() {
    read -p "请输入域名: " domain
    [[ -z "$domain" ]] && error "域名不能为空"
    read -p "端口 (默认 443): " port; port=${port:-443}

    open_ports 80/tcp "$port/tcp"
    systemctl stop nginx apache2 httpd 2>/dev/null || true
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        curl -s https://get.acme.sh | sh -s email=my@example.com >/dev/null
    fi

    local ws_cert=""
    local ws_key=""
    # 强制指定 Let's Encrypt 服务器
    if ~/.acme.sh/acme.sh --issue -d "$domain" --standalone --server letsencrypt --force; then
        ~/.acme.sh/acme.sh --install-cert -d "$domain" --cert-file "$CERT_DIR/cert.pem" --key-file "$CERT_DIR/private.key" --fullchain-file "$CERT_DIR/fullchain.pem"
        ws_cert="$CERT_DIR/fullchain.pem"
        ws_key="$CERT_DIR/private.key"
    else
        warn "申请失败，回退自签名"
        openssl req -new -x509 -days 365 -nodes -subj "/CN=$domain" -out "$CERT_DIR/cert.pem" -keyout "$CERT_DIR/private.key" >/dev/null 2>&1
        ws_cert="$CERT_DIR/cert.pem"
        ws_key="$CERT_DIR/private.key"
    fi

    local uuid=$($SINGBOX_BIN generate uuid)
    local ws_path="/$(openssl rand -hex 6)"
    jq -n --arg port "$port" --arg uuid "$uuid" --arg cert "$ws_cert" --arg key "$ws_key" --arg domain "$domain" --arg path "$ws_path" \
        '{"log":{"level":"info"},"inbounds":[{"type":"vless","tag":"ws-in","listen":"0.0.0.0","listen_port":($port|tonumber),"users":[{"uuid":$uuid}],"tls":{"enabled":true,"certificate_path":$cert,"key_path":$key},"transport":{"type":"ws","path":$path,"headers":{"Host":$domain}}}],"outbounds":[{"type":"direct"}]}' > "$CONF_FILE"
    echo -e "MODE=\"vless-ws\"\nIP=\"$(curl -s https://api.ipify.org)\"\nPORT=\"$port\"\nUUID=\"$uuid\"\nDOMAIN=\"$domain\"\nPATH=\"$ws_path\"" > "$DB_FILE"
}

# --- 6. Hy2 + VLESS-WS (仅使用 Let's Encrypt) ---
generate_hy2_and_vless_ws() {
    read -p "Hy2 SNI (默认 www.bing.com): " hy_sni; hy_sni=${hy_sni:-"www.bing.com"}
    read -p "Hy2 端口 (默认 8443): " hy_port; hy_port=${hy_port:-8443}
    read -p "VLESS-WS 域名: " ws_domain
    [[ -z "$ws_domain" ]] && error "域名不能为空"
    read -p "VLESS-WS 端口 (默认 443): " ws_port; ws_port=${ws_port:-443}

    open_ports "$hy_port/udp" "$ws_port/tcp" "80/tcp"
    systemctl stop nginx apache2 httpd 2>/dev/null || true

    # Hy2 证书 (保持自签名，因为 SNI 通常是伪装的)
    openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/hy2.key"
    openssl req -new -x509 -days 3650 -nodes -key "$CERT_DIR/hy2.key" -out "$CERT_DIR/hy2.pem" -subj "/CN=$hy_sni" >/dev/null 2>&1
    local hy_pass=$(openssl rand -hex 16)

    # WS 证书 (强制 Let's Encrypt)
    local ws_cert=""
    local ws_key=""
    if ~/.acme.sh/acme.sh --issue -d "$ws_domain" --standalone --server letsencrypt --force; then
        ~/.acme.sh/acme.sh --install-cert -d "$ws_domain" --cert-file "$CERT_DIR/ws.pem" --key-file "$CERT_DIR/ws.key" --fullchain-file "$CERT_DIR/ws-fullchain.pem"
        ws_cert="$CERT_DIR/ws-fullchain.pem"
        ws_key="$CERT_DIR/ws.key"
        success "Let's Encrypt 证书签发成功"
    else
        warn "签发失败，切换自签名"
        openssl req -new -x509 -days 365 -nodes -subj "/CN=$ws_domain" -out "$CERT_DIR/ws.pem" -keyout "$CERT_DIR/ws.key" >/dev/null 2>&1
        ws_cert="$CERT_DIR/ws.pem"
        ws_key="$CERT_DIR/ws.key"
    fi

    local ws_uuid=$($SINGBOX_BIN generate uuid)
    local ws_path="/$(openssl rand -hex 6)"
    local hy_in=$(jq -n --arg port "$hy_port" --arg pass "$hy_pass" --arg cert "$CERT_DIR/hy2.pem" --arg key "$CERT_DIR/hy2.key" \
        '{"type":"hysteria2","tag":"hy2-in","listen":"0.0.0.0","listen_port":($port|tonumber),"users":[{"password":$pass}],"tls":{"enabled":true,"certificate_path":$cert,"key_path":$key}}')
    local ws_in=$(jq -n --arg port "$ws_port" --arg uuid "$ws_uuid" --arg cert "$ws_cert" --arg key "$ws_key" --arg domain "$ws_domain" --arg path "$ws_path" \
        '{"type":"vless","tag":"vless-ws-in","listen":"0.0.0.0","listen_port":($port|tonumber),"users":[{"uuid":$uuid}],"tls":{"enabled":true,"certificate_path":$cert,"key_path":$key},"transport":{"type":"ws","path":$path,"headers":{"Host":$domain}}}')

    jq -n --argjson hy "$hy_in" --argjson ws "$ws_in" '{"log":{"level":"info"},"inbounds":[$hy, $ws],"outbounds":[{"type":"direct"}]}' > "$CONF_FILE"
    echo -e "MODE=\"hy2+vless-ws\"\nIP=\"$(curl -s https://api.ipify.org)\"\nHY_PORT=\"$hy_port\"\nHY_PASS=\"$hy_pass\"\nHY_SNI=\"$hy_sni\"\nWS_PORT=\"$ws_port\"\nWS_UUID=\"$ws_uuid\"\nWS_DOMAIN=\"$ws_domain\"\nWS_PATH=\"$ws_path\"" > "$DB_FILE"
}

# --- 7. 服务部署 ---
setup_service() {
    $SINGBOX_BIN check -c "$CONF_FILE" || error "配置校验失败"
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
    success "Sing-box 已启动"
}

# --- 8. 显示信息 ---
show_info() {
    [[ ! -f "$DB_FILE" ]] && return
    source "$DB_FILE"
    echo -e "\n${GREEN}======= 节点信息 =======${NC}"
    if [[ "$MODE" == "hy2+vless-ws" ]]; then
        echo -e "Hy2: hy2://$HY_PASS@$IP:$HY_PORT?insecure=1&sni=$HY_SNI#Hy2"
        echo -e "WS: vless://$WS_UUID@$IP:$WS_PORT?encryption=none&security=tls&type=ws&host=$WS_DOMAIN&path=$WS_PATH#VLESS-WS"
    elif [[ "$MODE" == "vless-ws" ]]; then
        echo -e "WS: vless://$UUID@$IP:$PORT?encryption=none&security=tls&type=ws&host=$DOMAIN&path=$PATH#VLESS-WS"
    else
        [[ "$MODE" == "all" || "$MODE" == "hy2" ]] && echo -e "Hy2: hy2://$HY2_K@$IP:$HY2_P?insecure=1&sni=$SNI#Hy2"
        [[ "$MODE" == "all" || "$MODE" == "reality" ]] && echo -e "Reality: vless://$REL_U@$IP:$REL_P?security=reality&sni=$SNI&fp=chrome&pbk=$REL_B&sid=$REL_S&flow=xtls-rprx-vision&type=tcp#Reality"
    fi
}

# --- 主菜单 ---
main_menu() {
    clear
    echo -e "${CYAN}====================================${NC}"
    echo -e "${CYAN}   Sing-Box 管理脚本 (Let's Encrypt版) ${NC}"
    echo -e "${CYAN}====================================${NC}"
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
        1) install_deps; enable_bbr; install_core; generate_config "all"; setup_service; show_info ;;
        2) install_deps; enable_bbr; install_core; generate_config "hy2"; setup_service; show_info ;;
        3) install_deps; enable_bbr; install_core; generate_config "reality"; setup_service; show_info ;;
        4) install_deps; enable_bbr; install_core; generate_vless_ws_tls; setup_service; show_info ;;
        5) install_deps; enable_bbr; install_core; generate_hy2_and_vless_ws; setup_service; show_info ;;
        6) show_info ;;
        7) journalctl -u sing-box -f -n 50 ;;
        8) systemctl disable --now sing-box; rm -rf "$SINGBOX_BIN" "$CONF_DIR" /etc/systemd/system/sing-box.service; success "卸载完成" ;;
        *) exit ;;
    esac
}

[[ "$(id -u)" -ne 0 ]] && error "请用 root 运行"
main_menu
