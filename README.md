# Sing-Box Hysteria2 & Reality 快速配置脚本

## 更新后的特性
*   一键安装 Sing-Box (beta 版)
  
** 自动从官方 GitHub Releases 下载并安装最新 beta 版本的 Sing-Box。

*   **脚本所有功能**
  ```
✅ 支持 VLESS + WebSocket + TLS（使用你的自定义域名）
✅ 自动申请 Let's Encrypt 证书（或手动指定已有证书）
✅ 兼容原有 Reality / Hysteria2 模式
✅ 防火墙自动放行、BBR 加速、服务管理、二维码生成
✅ 使用 acme.sh 轻量申请证书（不依赖 Nginx）
```


## 环境要求

*   Linux (x86_64 / amd64, aarch64 / arm64 架构理论上支持，未全面测试)
*   root 权限 (脚本内操作需要 sudo)
*   核心依赖: `curl`, `openssl`, `jq` (脚本会尝试自动安装)
*   可选依赖: `qrencode` (用于显示二维码，脚本会尝试自动安装)

## 使用方法

### 1. 下载并运行脚本(或者再次运行脚本)

```bash
bash <(curl -sSL https://raw.githubusercontent.com/fuckGFW2015/Hysteria2_VLESS/refs/heads/main/Hy2_Vless.sh)
```
脚本将以 root 权限运行，并显示主菜单。

### 3. 菜单选项说明

脚本启动后，你会看到类似如下的菜单：

安装选项:
1. 安装 Hysteria2 + Reality
2. 单独安装 Hysteria2
3. 单独安装 Reality (VLESS)
4. 安装 VLESS + WebSocket + TLS"
------------------------------------
5. 查看当前配置/二维码
6. 查看实时日志
7. 卸载 Sing-box
0. 退出

=======根据提示输入数字选择相应功能即可=======


## 个人推荐选项内容：

请输入统一的伪装域名 (SNI, 例如: cdn.example.com): www.microsoft.com

Hysteria2 端口 (默认8443): 回车键，直接默认

Reality 端口 (默认443): 2096

## 验证BBR是否开启
```
sysctl net.ipv4.tcp_congestion_control | grep -i bbr

或

cat /proc/sys/net/ipv4/tcp_congestion_control

```
## 禁用 BBR 命令

```
# 1. 临时禁用（立即生效）
sysctl -w net.ipv4.tcp_congestion_control=cubic
sysctl -w net.core.default_qdisc=pfifo_fast

# 2. 永久移除 BBR 配置（防止重启后自动启用）
sed -i '/net\.core\.default_qdisc.*fq/d' /etc/sysctl.conf
sed -i '/net\.ipv4\.tcp_congestion_control.*bbr/d' /etc/sysctl.conf

# 3. 重新加载 sysctl 配置
sysctl -p

```
## 完全卸载整个 Sing-Box（包括 Hysteria2 + REALITY）
* 重复第一步，直接使用脚本自带的 卸载功能：
  在脚本菜单中选择：
  ```
  6. 卸载 Sing-box
```
。
