#!/bin/bash

# --- 路径与常量配置 ---
SINGBOX_BIN="/usr/local/bin/sing-box"
CONF_DIR="/etc/sing-box"
CONF_FILE="${CONF_DIR}/config.json"
CERT_DIR="${CONF_DIR}/certs"
DB_FILE="${CONF_DIR}/.script_data.json"

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

# --- 网络请求带重试 ---
fetch_with_retry() {
    local url="$1" max_retries=3 delay=2
    for i in $(seq 1 $max_retries); do
        if response=$(curl -fsSL --connect-timeout 10 --retry 2 "$url" 2>/dev/null); then
            echo "$response"
            return 0
        fi
        sleep $delay
    done
    error "多次尝试后仍无法访问: $url"
}

# --- 获取公网 IP（多源 fallback）---
get_public_ip() {
    for api in "https://api.ipify.org" "https://ipv4.icanhazip.com" "https://ident.me"; do
        ip=$(curl -s --max-time 5 "$api" 2>/dev/null)
        if [[ $ip =～ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    warn "无法自动获取公网 IP，请手动填写"
    read -p "请输入服务器公网 IP: " ip
    echo "$ip"
}

# --- 检查端口是否被占用 ---
check_port_free() {
    local port=$1
    if ss -ltn | grep -q ":$port\b" || ss -lun | grep -q ":$port\b"; then
        error "端口 $port 已被占用，请更换！"
    fi
}

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

# --- 1. 安装依赖 ---
install_deps() {
    info "检查并安装必要依赖 (curl, jq, openssl, qrencode, etc.)..."
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
    local handled=false

    for port in "${ports[@]}"; do
        if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
            ufw allow "$port"/tcp >/dev/null 2>&1
            ufw allow "$port"/udp >/dev/null 2>&1
            echo -e "  - UFW 已放行端口: $port"
            handled=true
        elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
            firewall-cmd --permanent --add-port="$port"/{tcp,udp} >/dev/null 2>&1
            firewall-cmd --reload >/dev/null 2>&1
            echo -e "  - Firewalld 已放行端口: $port"
            handled=true
        fi
    done

    if ! $handled; then
        for port in "${ports[@]}"; do
            iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || \
                iptables -I INPUT -p tcp --dport "$port" -j ACCEPT
            iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || \
                iptables -I INPUT -p udp --dport "$port" -j ACCEPT
            echo -e "  - iptables 已放行端口: $port"
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
    response=$(fetch_with_retry "$api_url")
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
    trap 'rm -rf "$tmp_dir"' EXIT

    if ! wget -qO- "$URL" | tar -xz -C "$tmp_dir"; then
        error "下载或解压失败"
    fi
    mv "$tmp_dir"/sing-box-*/sing-box "$SINGBOX_BIN"
    chmod +x "$SINGBOX_BIN"
    mkdir -p "$CONF_DIR" "$CERT_DIR"
    success "Sing-box $TAG 安装成功"
}

# --- 创建专用服务用户 ---
create_service_user() {
    if ! id "singbox" &>/dev/null; then
        useradd -r -s /sbin/nologin -d "$CONF_DIR" singbox
    fi
    chown -R singbox:singbox "$CONF_DIR"
}

# --- 4. 配置生成 ---
generate_config() {
    local mode=$1

    read -p "请输入统一的伪装域名 (SNI, 例如: cdn.example.com): " sni_domain
    if [[ -z "$sni_domain" ]]; then
        sni_domain="www.cloudflare.com"
        warn "未指定域名，使用默认伪装域名: $sni_domain"
    fi

    read -p "Hysteria2 端口 (默认8443): " hy2_port
    hy2_port=${hy2_port:-8443}
    check_port_free "$hy2_port"

    read -p "Reality 端口 (默认443): " rel_port
    rel_port=${rel_port:-443}
    check_port_free "$rel_port"

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
    local ip=$(get_public_ip)

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

    # 保存为 JSON（更可靠）
    jq -n \
        --arg mode "$mode" \
        --arg ip "$ip" \
        --arg hy2_p "$hy2_port" \
        --arg hy2_k "$pass" \
        --arg rel_p "$rel_port" \
        --arg rel_u "$uuid" \
        --arg rel_b "$pub" \
        --arg rel_s "$sid" \
        --arg sni "$sni_domain" \
        '{
            mode: $mode,
            ip: $ip,
            hy2_port: $hy2_p,
            hy2_password: $hy2_k,
            reality_port: $rel_p,
            reality_uuid: $rel_u,
            reality_public_key: $rel_b,
            reality_short_id: $rel_s,
            sni: $sni
        }' > "$DB_FILE"

    chown singbox:singbox "$DB_FILE"
}

# --- 5. 服务部署 ---
setup_service() {
    create_service_user

    cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-Box Service
After=network.target

[Service]
ExecStart=$SINGBOX_BIN run -c $CONF_FILE
Restart=on-failure
User=singbox
Group=singbox
WorkingDirectory=$CONF_DIR

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now sing-box
    success "服务已启动（以 singbox 用户运行）"
}

# --- 查看配置信息 ---
show_info() {
    [[ ! -f "$DB_FILE" ]] && { warn "未找到配置记录"; return; }

    MODE=$(jq -r '.mode // empty' "$DB_FILE")
    IP=$(jq -r '.ip // empty' "$DB_FILE")
    HY2_P=$(jq -r '.hy2_port // empty' "$DB_FILE")
    HY2_K=$(jq -r '.hy2_password // empty' "$DB_FILE")
    REL_P=$(jq -r '.reality_port // empty' "$DB_FILE")
    REL_U=$(jq -r '.reality_uuid // empty' "$DB_FILE")
    REL_B=$(jq -r '.reality_public_key // empty' "$DB_FILE")
    REL_S=$(jq -r '.reality_short_id // empty' "$DB_FILE")
    SNI=$(jq -r '.sni // empty' "$DB_FILE")

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

    echo -e "\n${RED}❗ 阿里云/腾讯云用户：务必在【云控制台】的安全组中放行以下端口！${NC}"
    echo -e "${YELLOW}仅系统防火墙放行是不够的！${NC}"
    echo -e "${CYAN}→ Hysteria2: ${HY2_P} (TCP + UDP)${NC}"
    echo -e "${CYAN}→ Reality: ${REL_P} (TCP)${NC}"
}

# --- 主菜单 ---
main_menu() {
    clear
    echo -e "${CYAN}====================================${NC}"
    echo -e "${CYAN}   Sing-Box 官方驱动管理脚本 (2026)  ${NC}"
    echo -e "${CYAN}   ✅ 统一 SNI | ✅ BBR | ✅ 非 root 运行 ${NC}"
    echo -e "${CYAN}====================================${NC}"
    echo "1. 安装 Hysteria2 + Reality"
    echo "2. 单独安装 Hysteria2"
    echo "3. 单独安装 Reality (VLESS)"
    echo "------------------------------------"
    echo "4. 查看当前配置/二维码"
    echo "5. 查看实时日志（按 Ctrl+C 退出）"
    echo "6. 卸载 Sing-box"
    echo "0. 退出"
    read -p "请选择: " opt
    case $opt in
        1) install_deps; enable_bbr; install_core; generate_config "all"; setup_service; show_info ;;
        2) install_deps; enable_bbr; install_core; generate_config "hy2"; setup_service; show_info ;;
        3) install_deps; enable_bbr; install_core; generate_config "reality"; setup_service; show_info ;;
        4) show_info ;;
        5) echo -e "${YELLOW}按 Ctrl+C 退出日志查看${NC}"; journalctl -u sing-box -f -n 50 ;;
        6)
            systemctl disable --now sing-box >/dev/null 2>&1
            rm -rf "$SINGBOX_BIN" "$CONF_DIR" /etc/systemd/system/sing-box.service
            userdel -r singbox 2>/dev/null || true
            systemctl daemon-reload
            success "卸载完成"
            ;;
        *) exit ;;
    esac
}

[[ "$(id -u)" -ne 0 ]] && error "请用 root 运行"
main_menu
