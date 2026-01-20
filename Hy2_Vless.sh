cat << 'EOF' > Hy2_Vless_Official_Fix.sh
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

# --- 核心辅助函数 (必须定义在最前) ---
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# --- 1. 环境准备与依赖安装 ---
install_deps() {
    info "正在安装必要依赖 (curl, wget, jq, openssl, tar, qrencode, socat)..."
    local deps=("curl" "wget" "jq" "openssl" "tar" "qrencode" "socat")
    if command -v apt &>/dev/null; then
        apt update && apt install -y "${deps[@]}" || error "apt 安装依赖失败"
    elif command -v dnf &>/dev/null; then
        dnf install -y epel-release && dnf install -y "${deps[@]}" || error "dnf 安装依赖失败"
    else
        warn "未检测到 apt 或 dnf，跳过依赖安装（请确保已手动安装所需工具）"
    fi
}

enable_bbr() {
    info "开启 BBR 加速..."
    if ! sysctl net.ipv4.tcp_congestion_control | grep -q 'bbr'; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1 || warn "sysctl -p 执行失败，但 BBR 可能仍已启用"
    fi
}

install_core() {
    if [[ ! -x "$SINGBOX_BIN" ]]; then
        info "正在下载 Sing-box 核心..."
        local releases_json
        releases_json=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases")
        if [[ $? -ne 0 ]] || [[ -z "$releases_json" ]]; then
            error "无法连接 GitHub 获取版本信息，请检查网络或代理设置"
        fi
        TAG=$(echo "$releases_json" | jq -r 'map(select(.prerelease == false and .draft == false)) | first | .tag_name')
        [[ -z "$TAG" ]] && error "无法获取最新稳定版 Sing-box（可能 API 限流或无发布版本）"
        VERSION=${TAG#v}
        URL="https://github.com/SagerNet/sing-box/releases/download/${TAG}/sing-box-${VERSION}-linux-amd64.tar.gz"
        info "下载地址: $URL"
        wget -qO- "$URL" | tar -xz -C /tmp || error "下载或解压 Sing-box 失败"
        mv /tmp/sing-box-*/sing-box "$SINGBOX_BIN" || error "移动 sing-box 二进制文件失败"
        chmod +x "$SINGBOX_BIN"
        success "Sing-box 安装完成"
    else
        info "Sing-box 已存在，跳过安装"
    fi
    mkdir -p "$CONF_DIR" "$CERT_DIR"
}

# --- 2. 展示信息与二维码 ---
show_info() {
    if [[ ! -f "$DB_FILE" ]]; then
        warn "未找到配置记录，请先安装节点"
        return
    fi

    # 安全加载 DB（避免执行任意代码）
    declare -A CONFIG
    while IFS='=' read -r key value; do
        [[ -n "$key" && "$key" != "#"* ]] && CONFIG["$key"]="${value#\"}"
    done < <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$DB_FILE")

    # 必要字段校验
    for field in MODE IP; do
        [[ -z "${CONFIG[$field]}" ]] && { error "配置文件缺失字段: $field"; }
    done

    echo -e "\n${GREEN}======= 节点链接与二维码 =======${NC}"

    if [[ "${CONFIG[MODE]}" == "hy2_ws" ]]; then
        local l1="hy2://${CONFIG[HY_PASS]}@${CONFIG[IP]}:${CONFIG[HY_PORT]}?insecure=1&sni=${CONFIG[HY_SNI]}#Hy2"
        local l2="vless://${CONFIG[WS_UUID]}@${CONFIG[IP]}:${CONFIG[WS_PORT]}?encryption=none&security=tls&type=ws&host=${CONFIG[WS_DOMAIN]}&path=${CONFIG[WS_PATH]}#VLESS-WS"
        echo -e "Hysteria2: ${CYAN}$l1${NC}"
        qrencode -t ansiutf8 "$l1"
        echo -e "\nVLESS-WS: ${CYAN}$l2${NC}"
        qrencode -t ansiutf8 "$l2"
    else
        local l1="hy2://${CONFIG[HY_PASS]}@${CONFIG[IP]}:${CONFIG[HY_PORT]}?insecure=1&sni=${CONFIG[SNI]}#Hy2"
        local l2="vless://${CONFIG[REL_UUID]}@${CONFIG[IP]}:${CONFIG[REL_PORT]}?security=reality&sni=${CONFIG[SNI]}&fp=chrome&pbk=${CONFIG[REL_PUB]}&sid=${CONFIG[REL_SID]}&flow=xtls-rprx-vision&type=tcp#Reality"
        echo -e "Hysteria2: ${CYAN}$l1${NC}"
        qrencode -t ansiutf8 "$l1"
        echo -e "\nReality: ${CYAN}$l2${NC}"
        qrencode -t ansiutf8 "$l2"
    fi

    # 检查服务状态
    if systemctl is-active --quiet sing-box; then
        success "Sing-box 服务正在运行"
    else
        warn "Sing-box 服务未运行！请运行 'journalctl -u sing-box -n 50' 查看错误日志"
    fi
}

# --- 3. 配置生成逻辑 ---
generate_config() {
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
    [[ -z "$ip" ]] && error "无法获取公网 IP，请检查网络连接"

    info "生成自签名证书用于 Hysteria2（仅测试用，生产环境建议使用可信证书）"
    openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/hy2.key"
    openssl req -new -x509 -days 3650 -nodes -key "$CERT_DIR/hy2.key" -out "$CERT_DIR/hy2.pem" -subj "/CN=$sni" >/dev/null 2>&1

    jq -n --arg hp "$hy_p" --arg pass "$pass" --arg rp "$rel_p" --arg uuid "$uuid" --arg pk "$pk" --arg sid "$sid" --arg sni "$sni" --arg cert "$CERT_DIR/hy2.pem" --arg key "$CERT_DIR/hy2.key" \
    '{"log":{"level":"info"},"inbounds":[{"type":"hysteria2","tag":"hy2-in","listen":"0.0.0.0","listen_port":($hp|tonumber),"users":[{"password":$pass}],"tls":{"enabled":true,"certificate_path":$cert,"key_path":$key}},{"type":"vless","tag":"vless-in","listen":"0.0.0.0","listen_port":($rp|tonumber),"users":[{"uuid":$uuid,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":$sni,"reality":{"enabled":true,"handshake":{"server":$sni,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}],"outbounds":[{"type":"direct"}]}' > "$CONF_FILE"

    {
        echo "MODE=\"all\""
        echo "IP=\"$ip\""
        echo "HY_PASS=\"$pass\""
        echo "HY_PORT=\"$hy_p\""
        echo "SNI=\"$sni\""
        echo "REL_UUID=\"$uuid\""
        echo "REL_PORT=\"$rel_p\""
        echo "REL_PUB=\"$pub\""
        echo "REL_SID=\"$sid\""
    } > "$DB_FILE"
    success "配置文件已生成"
}

generate_hy2_ws() {
    read -p "请输入解析好的域名: " domain
    [[ -z "$domain" ]] && error "域名不能为空"
    local ip=$(curl -s https://api.ipify.org)
    [[ -z "$ip" ]] && error "无法获取公网 IP"

    local uuid=$($SINGBOX_BIN generate uuid)
    local path="/$(openssl rand -hex 6)"
    local pass=$(openssl rand -hex 12)

    info "正在通过 acme.sh 申请正式证书（需临时开放 80 端口）..."
    if [ ! -d "$HOME/.acme.sh" ]; then
        curl -s https://get.acme.sh | sh || error "acme.sh 安装失败"
    fi

    if ! ~/.acme.sh/acme.sh --issue -d "$domain" --standalone --force; then
        error "证书申请失败！请确保：
  1. 域名已正确解析到本机 IP
  2. 防火墙已开放 80 端口
  3. 无其他程序占用 80 端口（如 nginx、apache）"
    fi

    if ! ～/.acme.sh/acme.sh --install-cert -d "$domain" \
        --fullchain-file "$CERT_DIR/ws.pem" \
        --key-file "$CERT_DIR/ws.key"; then
        error "证书安装失败"
    fi

    jq -n --arg hp "8443" --arg pass "$pass" --arg wp "443" --arg uuid "$uuid" --arg domain "$domain" --arg path "$path" --arg cert "$CERT_DIR/ws.pem" --arg key "$CERT_DIR/ws.key" \
    '{"log":{"level":"info"},"inbounds":[{"type":"hysteria2","tag":"hy2-in","listen":"0.0.0.0","listen_port":($hp|tonumber),"users":[{"password":$pass}],"tls":{"enabled":true,"certificate_path":$cert,"key_path":$key}},{"type":"vless","tag":"ws-in","listen":"0.0.0.0","listen_port":($wp|tonumber),"users":[{"uuid":$uuid}],"tls":{"enabled":true,"certificate_path":$cert,"key_path":$key},"transport":{"type":"ws","path":$path}}],"outbounds":[{"type":"direct"}]}' > "$CONF_FILE"

    {
        echo "MODE=\"hy2_ws\""
        echo "IP=\"$ip\""
        echo "HY_PASS=\"$pass\""
        echo "HY_PORT=\"8443\""
        echo "HY_SNI=\"$domain\""
        echo "WS_UUID=\"$uuid\""
        echo "WS_PORT=\"443\""
        echo "WS_DOMAIN=\"$domain\""
        echo "WS_PATH=\"$path\""
    } > "$DB_FILE"
    success "Hy2 + VLESS-WS 配置已生成"
}

# --- 4. 主菜单 ---
main_menu() {
    clear
    echo -e "${CYAN}====================================${NC}"
    echo -e "${CYAN}   Sing-Box 管理脚本 (官方修复版)  ${NC}"
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
        1|2|3)
            install_deps
            enable_bbr
            install_core
            generate_config
            # 安装或重启服务
            if systemctl is-active --quiet sing-box; then
                systemctl restart sing-box
            else
                cat > /etc/systemd/system/sing-box.service <<SBEOF
[Unit]
Description=sing-box
After=network.target
[Service]
ExecStart=$SINGBOX_BIN run -c $CONF_FILE
Restart=always
User=root
[Install]
WantedBy=multi-user.target
SBEOF
                systemctl daemon-reload
                systemctl enable --now sing-box
            fi
            show_info
            ;;
        4|5)
            install_deps
            enable_bbr
            install_core
            generate_hy2_ws
            systemctl restart sing-box
            show_info
            ;;
        6) show_info ;;
        7) journalctl -u sing-box -f ;;
        8)
            systemctl disable --now sing-box 2>/dev/null
            rm -rf "$CONF_DIR" "$SINGBOX_BIN" /etc/systemd/system/sing-box.service
            systemctl daemon-reload
            success "Sing-box 已完全卸载"
            ;;
        0|*) exit 0 ;;
    esac
}

main_menu
EOF

chmod +x Hy2_Vless_Official_Fix.sh
./Hy2_Vless_Official_Fix.sh
