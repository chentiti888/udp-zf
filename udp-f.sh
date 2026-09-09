#!/usr/bin/env bash
set -Eeuo pipefail

# UDP DNAT 转发一键交互式脚本
# 用法：
#   chmod +x udp-forward.sh
#   sudo ./udp-forward.sh
#
# 说明：
#   - 中转端口和落地端口可以不同
#   - 重复运行相同任务不会重复添加规则
#   - 规则写入 iptables-persistent，重启后自动恢复
#   - 默认不修改 SSH/TCP 规则，只处理 IPv4 UDP 转发

RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
CYAN='\033[36m'
RESET='\033[0m'

log()  { echo -e "${GREEN}[+]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
die()  { echo -e "${RED}[x]${RESET} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "请使用 root 运行：sudo bash $0"

echo
echo "=============================================="
echo "          UDP DNAT 转发一键配置工具"
echo "=============================================="
echo

read -r -p "请输入落地服务器 IP: " BACKEND_IP
[[ "$BACKEND_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "IP 格式不正确：$BACKEND_IP"

IFS='.' read -r o1 o2 o3 o4 <<< "$BACKEND_IP"
for o in "$o1" "$o2" "$o3" "$o4"; do
    (( o <= 255 )) || die "IP 地址不正确：$BACKEND_IP"
done

read -r -p "请输入落地服务器 UDP 端口: " BACKEND_PORT
[[ "$BACKEND_PORT" =~ ^[0-9]+$ ]] || die "端口必须是数字"
(( BACKEND_PORT >= 1 && BACKEND_PORT <= 65535 )) || die "端口范围必须是 1-65535"

read -r -p "请输入中转服务器监听 UDP 端口: " FRONT_PORT
[[ "$FRONT_PORT" =~ ^[0-9]+$ ]] || die "端口必须是数字"
(( FRONT_PORT >= 1 && FRONT_PORT <= 65535 )) || die "端口范围必须是 1-65535"

echo
echo "----------------------------------------------"
echo "中转端口 : ${FRONT_PORT}/UDP"
echo "落地地址 : ${BACKEND_IP}:${BACKEND_PORT}/UDP"
echo "----------------------------------------------"
read -r -p "确认配置？[Y/n]: " CONFIRM
[[ -z "$CONFIRM" || "$CONFIRM" =~ ^[Yy]$ ]] || { echo "已取消。"; exit 0; }

# 检测发行版并安装 iptables
install_iptables() {
    if command -v iptables >/dev/null 2>&1; then
        return
    fi

    log "正在安装 iptables..."
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y
        apt-get install -y iptables iptables-persistent
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y iptables
    elif command -v yum >/dev/null 2>&1; then
        yum install -y iptables
    else
        die "无法识别包管理器，请手动安装 iptables 后重新运行。"
    fi
}

install_iptables

# 开启 IPv4 forwarding，并持久化
log "正在开启 IPv4 转发..."
cat >/etc/sysctl.d/99-udp-forward.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
sysctl --system >/dev/null
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# 检查目标是否可路由
if ! ip route get "$BACKEND_IP" >/dev/null 2>&1; then
    warn "当前服务器没有到 $BACKEND_IP 的有效路由，继续配置可能无法工作。"
fi

# 获取默认出口网卡
OUT_IF="$(ip route get "$BACKEND_IP" 2>/dev/null | awk '
    {
        for (i=1; i<=NF; i++)
            if ($i=="dev") { print $(i+1); exit }
    }')"

[[ -n "$OUT_IF" ]] || OUT_IF="$(ip route show default | awk '/default/ {print $5; exit}')"
[[ -n "$OUT_IF" ]] || die "无法确定出口网卡。"

log "检测到出口网卡：$OUT_IF"

# 确保 NAT/FORWARD 所需链存在（iptables 一般默认存在）
iptables -t nat -N UDP_FORWARD_DNAT 2>/dev/null || true
iptables -N UDP_FORWARD_ACCEPT 2>/dev/null || true

# 添加自定义链跳转，仅添加一次
iptables -t nat -C PREROUTING -p udp --dport "$FRONT_PORT" -j UDP_FORWARD_DNAT 2>/dev/null ||
    iptables -t nat -A PREROUTING -p udp --dport "$FRONT_PORT" -j UDP_FORWARD_DNAT

iptables -C FORWARD -p udp -d "$BACKEND_IP" --dport "$BACKEND_PORT" -j UDP_FORWARD_ACCEPT 2>/dev/null ||
    iptables -A FORWARD -p udp -d "$BACKEND_IP" --dport "$BACKEND_PORT" -j UDP_FORWARD_ACCEPT

# DNAT：中转端口 -> 落地 IP:端口
iptables -t nat -C UDP_FORWARD_DNAT -p udp --dport "$FRONT_PORT" \
    -j DNAT --to-destination "${BACKEND_IP}:${BACKEND_PORT}" 2>/dev/null ||
    iptables -t nat -A UDP_FORWARD_DNAT -p udp --dport "$FRONT_PORT" \
    -j DNAT --to-destination "${BACKEND_IP}:${BACKEND_PORT}"

# FORWARD 放行去程
iptables -C UDP_FORWARD_ACCEPT -p udp -d "$BACKEND_IP" --dport "$BACKEND_PORT" \
    -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null ||
    iptables -A UDP_FORWARD_ACCEPT -p udp -d "$BACKEND_IP" --dport "$BACKEND_PORT" \
    -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

# 回程放行
iptables -C UDP_FORWARD_ACCEPT -p udp -s "$BACKEND_IP" \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null ||
    iptables -A UDP_FORWARD_ACCEPT -p udp -s "$BACKEND_IP" \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# MASQUERADE：保证落地机能把回包正确返回中转机
iptables -t nat -C POSTROUTING -o "$OUT_IF" -p udp -d "$BACKEND_IP" --dport "$BACKEND_PORT" \
    -j MASQUERADE 2>/dev/null ||
    iptables -t nat -A POSTROUTING -o "$OUT_IF" -p udp -d "$BACKEND_IP" --dport "$BACKEND_PORT" \
    -j MASQUERADE

# 保存规则
log "正在保存 iptables 规则..."
if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null
elif command -v iptables-save >/dev/null 2>&1; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
fi

# 尝试启用持久化服务
if systemctl list-unit-files 2>/dev/null | grep -q '^netfilter-persistent.service'; then
    systemctl enable netfilter-persistent >/dev/null 2>&1 || true
fi

echo
echo "=============================================="
echo -e "             ${GREEN}配置完成${RESET}"
echo "=============================================="
echo
echo "中转服务器：$(hostname -I 2>/dev/null | awk '{print $1}')"
echo "中转端口  ：${FRONT_PORT}/UDP"
echo "落地服务器：${BACKEND_IP}:${BACKEND_PORT}/UDP"
echo "出口网卡  ：${OUT_IF}"
echo "IPv4 转发 ：$(sysctl -n net.ipv4.ip_forward)"
echo
echo "DNAT 规则："
iptables -t nat -S UDP_FORWARD_DNAT
echo
echo "FORWARD 规则："
iptables -S UDP_FORWARD_ACCEPT
echo
echo "MASQUERADE 规则："
iptables -t nat -S POSTROUTING | grep -F -- "$BACKEND_IP" || true
echo
echo "查看全部规则："
echo "  iptables -t nat -vnL"
echo "  iptables -vnL FORWARD"
echo
log "重复运行相同配置不会重复添加相同规则。"
