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
    kernel_version=$(uname -r | awk -F. '{print ($1 * 1000) + $2}')
    if [[ $kernel_version -lt 4009 ]]; then
        warn "内核版本过低（需 >= 4.9），跳过 BBR 启用"
        return
    fi
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q 'bbr'; then
        success "BBR 已启用"
        return
    fi
    echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
    echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q 'bbr'; then
        success "BBR 已成功启用"
    else
        warn "BBR 启用失败（可能系统不支持或需重启生效）"
    fi
}

# --- 1. 环境准备与依赖安装 ---
install_deps() {
    info "检查并安装必要依赖..."
    local deps=("curl" "wget" "jq" "openssl" "tar" "qrencode" "socat")
    if command -v apt &>/dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt update && apt install -y "${deps[@]}"
    elif command -v dnf &>/dev/null; then
        dnf install -y "${deps[@]}"
    elif command -v yum &>/dev/null; then
        yum install -y epel-release && yum install -y "${deps[@]}"
    fi
}

# --- 2. 自动放行防火墙 ---
open_ports() {
    info "配置系统防火墙策略..."
    local handled=false
    local p

    for p in "$@"; do
        if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
            ufw allow "$p"/tcp >/dev/null 2>&1
            echo -e "  - UFW 已放行端口: $p (TCP)"
            handled=true
        elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
            firewall-cmd --permanent --add-port="$p"/tcp >/dev/null 2>&1
            firewall-cmd --reload >/dev/null 2>&1
            echo -e "  - Firewalld 已放行端口: $p (TCP)"
            handled=true
        fi
    done

    if ! $handled; then
        for p in "$@"; do
            iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || \
                iptables -I INPUT -p tcp --dport "$p" -j ACCEPT
            echo -e "  - iptables 已放行端口: $p (TCP)"
        done
        if command -v iptables-save &>/dev/null; then
            if command -v apt &>/dev/null; then
                apt install -y iptables-persistent 2>/dev/null && netfilter-persistent save
            elif command -v dnf &>/dev/null; then
                dnf install -y iptables-services 2>/dev/null && service iptables save
            fi
        fi
    fi
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

# --- 4. 原有配置生成（Reality/Hy2）---
generate_config() {
    local mode=$1
    read -p "请输入统一的伪装域名 (SNI): " sni_domain
    [[ -z "$sni_domain" ]] && { sni_domain="www.cloudflare.com"; warn "使用默认 SNI: $sni_domain"; }

    read -p "Hysteria2 端口 (默认8443): " hy2_port; hy2_port=${hy2_port:-8443}
    read -p "Reality 端口 (默认443): " rel_port; rel_port=${rel_port:-443}
    
    [[ "$mode" == "all" ]] && open_ports "$hy2_port" "$rel_port"
    [[ "$mode" == "hy2" ]] && open_ports "$hy2_port"
    [[ "$mode" == "reality" ]] && open_ports "$rel_port"

    [[ ! -x "$SINGBOX_BIN" ]] && error "Sing-box 未安装"

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
        openssl req -new -x509 -days 3650 -nodes -key "$CERT_DIR/private.key" \
            -out "$CERT_DIR/cert.pem" -subj "/CN=$sni_domain"
        hy2_in=$(jq -n --arg port "$hy2_port" --arg pass "$pass" --arg cert "$CERT_DIR/cert.pem" --arg key "$CERT_DIR/private.key" \
            '{"type":"hysteria2","tag":"hy2-in","listen":"::","listen_port":($port|tonumber),"users":[{"password":$pass}],"tls":{"enabled":true,"certificate_path":$cert,"key_path":$key}}')
    fi

    if [[ "$mode" == "all" || "$mode" == "reality" ]]; then
        rel_in=$(jq -n --arg port "$rel_port" --arg uuid "$uuid" --arg pk "$pk" --arg sid "$sid" --arg sni "$sni_domain" \
            '{"type":"vless","tag":"vless-in","listen":"::","listen_port":($port|tonumber),"users":[{"uuid":$uuid,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":$sni,"reality":{"enabled":true,"handshake":{"server":$sni,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}')
    fi

    jq -n --argjson hy2 "$hy2_in" --argjson rel "$rel_in" \
        '{"log":{"level":"info","timestamp":true},"inbounds":([$hy2, $rel]|map(select(.!=null))),"outbounds":[{"type":"direct","tag":"direct"}]}' > "$CONF_FILE"

    echo -e "MODE=\"$mode\"\nIP=\"$ip\"\nHY2_P=\"$hy2_port\"\nHY2_K=\"$pass\"\nREL_P=\"$rel_port\"\nREL_U=\"$uuid\"\nREL_B=\"$pub\"\nREL_S=\"$sid\"\nSNI=\"$sni_domain\"" > "$DB_FILE"
}

# --- 5. 新增：VLESS + WebSocket + TLS ---
generate_vless_ws_tls() {
    read -p "请输入你的域名 (必须已解析到本机 IP): " domain
    [[ -z "$domain" ]] && error "域名不能为空"

    read -p "请输入端口 (默认 443): " port
    port=${port:-443}

    read -p "是否使用现有证书？(y/n，默认 n): " use_cert
    if [[ "$use_cert" =~ ^[Yy]$ ]]; then
        read -p "证书文件路径 (fullchain.pem): " cert_path
        read -p "私钥文件路径 (privkey.pem): " key_path
        [[ ! -f "$cert_path" ]] && error "证书文件不存在: $cert_path"
        [[ ! -f "$key_path" ]] && error "私钥文件不存在: $key_path"
    else
        info "正在尝试自动申请 Let's Encrypt 证书..."
        install_deps
        open_ports 80

        # 停止占用 80 的服务
        systemctl stop nginx apache2 httpd 2>/dev/null || true

        if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
            curl -s https://get.acme.sh | sh -s email=my@example.com
        fi

        if ~/.acme.sh/acme.sh --issue -d "$domain" --standalone --force; then
            mkdir -p "$CERT_DIR"
            ～/.acme.sh/acme.sh --install-cert -d "$domain" \
                --cert-file "$CERT_DIR/cert.pem" \
                --key-file "$CERT_DIR/private.key" \
                --fullchain-file "$CERT_DIR/fullchain.pem"
            cert_path="$CERT_DIR/fullchain.pem"
            key_path="$CERT_DIR/private.key"
            success "Let's Encrypt 证书申请成功"
        else
            warn "自动申请失败，使用自签名证书（仅测试）"
            mkdir -p "$CERT_DIR"
            openssl req -new -x509 -days 365 -nodes -subj "/CN=$domain" \
                -out "$CERT_DIR/cert.pem" -keyout "$CERT_DIR/private.key" >/dev/null 2>&1
            cert_path="$CERT_DIR/cert.pem"
            key_path="$CERT_DIR/private.key"
        fi
    fi

    open_ports "$port"
    local uuid=$($SINGBOX_BIN generate uuid)
    local ip=$(curl -s https://api.ipify.org)
    local ws_path="/$(openssl rand -hex 6)"

    local inbound=$(jq -n \
        --arg port "$port" \
        --arg uuid "$uuid" \
        --arg cert "$cert_path" \
        --arg key "$key_path" \
        --arg domain "$domain" \
        --arg path "$ws_path" \
        '{
            "type": "vless",
            "tag": "vless-ws-in",
            "listen": "::",
            "listen_port": ($port | tonumber),
            "users": [{"uuid": $uuid}],
            "tls": {
                "enabled": true,
                "certificate_path": $cert,
                "key_path": $key
            },
            "transport": {
                "type": "ws",
                "path": $path,
                "headers": {"Host": $domain}
            }
        }')

    jq -n --argjson in "$inbound" \
        '{"log":{"level":"info","timestamp":true},"inbounds":[$in],"outbounds":[{"type":"direct","tag":"direct"}]}' > "$CONF_FILE"

    echo -e "MODE=\"vless-ws\"\nIP=\"$ip\"\nPORT=\"$port\"\nUUID=\"$uuid\"\nDOMAIN=\"$domain\"\nPATH=\"$ws_path\"\nCERT=\"$cert_path\"\nKEY=\"$key_path\"" > "$DB_FILE"
    success "VLESS + WS + TLS 配置生成成功（域名: $domain）"
}

# --- 6. 服务部署 ---
setup_service() {
    cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-Box Service
After=network.target

[Service]
ExecStart=$SINGBOX_BIN run -c $CONF_FILE
Restart=on-failure
User=root
LimitNOFILE=500000

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now sing-box
    success "服务已启动"
}

# --- 7. 显示信息 ---
show_info() {
    [[ ! -f "$DB_FILE" ]] && { warn "未找到记录"; return; }
    MODE=$(grep '^MODE=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    if [[ "$MODE" == "vless-ws" ]]; then
        show_vless_ws_info
        return
    fi

    IP=$(grep '^IP=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    HY2_P=$(grep '^HY2_P=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    HY2_K=$(grep '^HY2_K=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    REL_P=$(grep '^REL_P=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    REL_U=$(grep '^REL_U=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    REL_B=$(grep '^REL_B=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    REL_S=$(grep '^REL_S=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    SNI=$(grep '^SNI=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')

    echo -e "\n${GREEN}======= 配置详情 =======${NC}"
    if [[ "$MODE" == "all" || "$MODE" == "hy2" ]]; then
        local link="hy2://$HY2_K@$IP:$HY2_P?insecure=1&sni=$SNI&alpn=h3#Hy2-VPS"
        echo -e "Hysteria2: $link"
        qrencode -t ANSIUTF8 "$link"
    fi
    if [[ "$MODE" == "all" || "$MODE" == "reality" ]]; then
        local link="vless://$REL_U@$IP:$REL_P?security=reality&sni=$SNI&fp=chrome&pbk=$REL_B&sid=$REL_S&flow=xtls-rprx-vision&type=tcp#Rel-Server"
        echo -e "Reality: $link"
        qrencode -t ANSIUTF8 "$link"
    fi
    echo -e "\n${YELLOW}⚠️  请确保云服务器安全组已放行相应端口${NC}"
}

show_vless_ws_info() {
    IP=$(grep '^IP=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    PORT=$(grep '^PORT=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    UUID=$(grep '^UUID=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    DOMAIN=$(grep '^DOMAIN=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')
    PATH=$(grep '^PATH=' "$DB_FILE" | cut -d'=' -f2 | tr -d '"')

    echo -e "\n${GREEN}======= VLESS + WS + TLS =======${NC}"
    local link="vless://${UUID}@${IP}:${PORT}?encryption=none&security=tls&type=ws&host=${DOMAIN}&path=${PATH}&fp=chrome#VLESS-WS"
    echo -e "链接: $link"
    qrencode -t ANSIUTF8 "$link"
    echo -e "\n${YELLOW}⚠️  注意：\n- 域名 ${DOMAIN} 必须解析到 ${IP}\n- 安全组需放行 ${PORT}/TCP\n- 生产环境建议使用有效证书${NC}"
}

# --- 主菜单 ---
main_menu() {
    clear
    echo -e "${CYAN}====================================${NC}"
    echo -e "${CYAN}   Sing-Box 多协议管理脚本 (2026)   ${NC}"
    echo -e "${CYAN}   ✅ Reality | Hy2 | VLESS-WS-TLS  ${NC}"
    echo -e "${CYAN}====================================${NC}"
    echo "1. 安装 Hysteria2 + Reality"
    echo "2. 单独安装 Hysteria2"
    echo "3. 单独安装 Reality (VLESS)"
    echo "4. 安装 VLESS + WebSocket + TLS"   # ← 你的需求
    echo "------------------------------------"
    echo "5. 查看当前配置/二维码"
    echo "6. 查看实时日志"
    echo "7. 卸载 Sing-box"
    echo "0. 退出"
    read -p "请选择: " opt
    case $opt in
        1) install_deps; enable_bbr; install_core; generate_config "all"; setup_service; show_info ;;
        2) install_deps; enable_bbr; install_core; generate_config "hy2"; setup_service; show_info ;;
        3) install_deps; enable_bbr; install_core; generate_config "reality"; setup_service; show_info ;;
        4) install_deps; enable_bbr; install_core; generate_vless_ws_tls; setup_service; show_vless_ws_info ;;
        5) show_info ;;
        6) journalctl -u sing-box -f -n 50 ;;
        7) systemctl disable --now sing-box; rm -rf "$SINGBOX_BIN" "$CONF_DIR" /etc/systemd/system/sing-box.service; systemctl daemon-reload; success "卸载完成" ;;
        *) exit ;;
    esac
}

[[ "$(id -u)" -ne 0 ]] && error "请用 root 运行"
main_menu
