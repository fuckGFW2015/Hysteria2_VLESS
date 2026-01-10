# Sing-Box Hysteria2 & Reality 快速配置脚本

## 更新后的特性
一键安装 Sing-Box (beta 版)
自动从官方 GitHub Releases 下载并安装最新 beta 版本的 Sing-Box。
多种安装模式
同时安装 Hysteria2 + Reality (VLESS)，实现双协议共存
单独安装 Hysteria2
单独安装 Reality (VLESS)
自动化配置
Hysteria2：自动生成自签名 TLS 证书、URL 安全的十六进制密码（避免链接解析失败）
Reality (VLESS)：自动生成 UUID、Reality 密钥对（私钥/公钥）、随机 short_id
自动填充所有凭证到 /etc/sing-box/config.json
支持用户交互式输入：监听端口、伪装域名（SNI）、是否启用 BBR 等
网络性能优化
✅ 自动检测并启用 BBR 拥塞控制算法（提升吞吐量与抗丢包能力）
若内核 ≥ 4.9 且未启用 BBR，脚本将自动配置并重启网络栈生效
防火墙自动适配与端口放行
✅ 自动识别系统防火墙类型（ufw / firewalld / iptables）
✅ 根据所选协议自动放行所需端口：
Hysteria2：开放 TCP + UDP 监听端口（如 8443）
Reality：开放 TCP 监听端口（如 443）
✅ 云服务器友好：同时提示用户检查 云平台安全组（阿里云/腾讯云等）
导入信息与二维码
安装完成后，自动显示标准客户端链接（含 alpn=h3 提高兼容性）
若系统已安装 qrencode，直接在终端渲染 ANSI 二维码
支持随时通过菜单选项 重新查看配置与二维码
依赖自动处理
自动检测并安装核心依赖：curl, openssl, jq
可选依赖 qrencode 缺失时仅跳过二维码生成，不影响主流程
兼容主流发行版：Ubuntu/Debian（apt）、CentOS/Rocky（yum/dnf）
系统服务集成
自动生成 /etc/systemd/system/sing-box.service
自动启用开机自启并启动服务
提供日志查看、卸载清理等便捷操作
## 环境要求

*   Linux (x86_64 / amd64, aarch64 / arm64 架构理论上支持，未全面测试)
*   root 权限 (脚本内操作需要 sudo)
*   核心依赖: `curl`, `openssl`, `jq` (脚本会尝试自动安装)
*   可选依赖: `qrencode` (用于显示二维码，脚本会尝试自动安装)

## 使用方法

### 1. 下载并运行脚本


```bash
bash <(curl -sSL https://raw.githubusercontent.com/fuckGFW2015/Hysteria2_VLESS/refs/heads/main/Hy2_Vless.sh)
```

### 2. 再次运行脚本

```bash
sudo bash Hy2_Vless.sh
```

脚本将以 root 权限运行，并显示主菜单。

### 3. 菜单选项说明

脚本启动后，你会看到类似如下的菜单：

安装选项:
1. 安装 Hysteria2 + Reality
2. 单独安装 Hysteria2
3. 单独安装 Reality (VLESS)
------------------------------------
4. 查看当前配置/二维码
5. 查看实时日志
6. 卸载 Sing-box
0. 退出

================================================
根据提示输入数字选择相应功能即可。

## 个人推荐选项内容：
请输入统一的伪装域名 (SNI, 例如: cdn.example.com): www.microsoft.com
Hysteria2 端口 (默认8443): 回车键，直接默认
Reality 端口 (默认443): 2096




。
