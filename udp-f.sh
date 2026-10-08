#!/usr/bin/env bash
set -Eeuo pipefail

# TCP/UDP DNAT 端口转发一键交互式脚本
# 用法：
#   chmod +x port-forward.sh
#   sudo ./port-forward.sh
#
# 说明：
#   - 支持 TCP+UDP / 仅 UDP / 仅 TCP 三种模式（默认 TCP+UDP）
#   - 中转端口和落地端口可以不同
#   - 重复运行相同任务不会重复添加规则
#   - 规则写入 iptables-persistent，重启后自动恢复
#   - 只处理 IPv4 转发，不修改 SSH 等其他规则
#   - 注意：中转端口不要与本机 SSH 等已有服务端口冲突

RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
RESET='\033[0m'

log()  { echo -e "${GREEN}[+]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
die()  { echo -e "${RED}[x]${RESET} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "请使用 root 运行：sudo bash $0"

DNAT_CHAIN="PORT_FWD_DNAT"
ACCEPT_CHAIN="PORT_FWD_ACCEPT"

echo
echo "=============================================="
echo "        TCP/UDP DNAT 转发一键配置工具"
echo "=============================================="
echo

read -r -p "请输入落地服务器 IP: " BACKEND_IP
[[ "$BACKEND_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "IP 格式不正确：$BACKEND_IP"

IFS='.' read -r o1 o2 o3 o4 <<< "$BACKEND_IP"
for o in "$o1" "$o2" "$o3" "$o4"; do
    (( 10#$o <= 255 )) || die "IP 地址不正确：$BACKEND_IP"
done

read -r -p "请输入落地服务器端口: " BACKEND_PORT
[[ "$BACKEND_PORT" =~ ^[0-9]+$ ]] || die "端口必须是数字"
(( BACKEND_PORT >= 1 && BACKEND_PORT <= 65535 )) || die "端口范围必须是 1-65535"

read -r -p "请输入中转服务器监听端口: " FRONT_PORT
[[ "$FRONT_PORT" =~ ^[0-9]+$ ]] || die "端口必须是数字"
(( FRONT_PORT >= 1 && FRONT_PORT <= 65535 )) || die "端口范围必须是 1-65535"

echo
echo "转发协议："
echo "  1) TCP + UDP（默认）"
echo "  2) 仅 UDP"
echo "  3) 仅 TCP"
read -r -p "请选择 [1-3]: " PROTO_CHOICE
case "${PROTO_CHOICE:-1}" in
    1) PROTOS=(tcp udp); PROTO_DESC="TCP+UDP" ;;
    2) PROTOS=(udp);     PROTO_DESC="UDP" ;;
    3) PROTOS=(tcp);     PROTO_DESC="TCP" ;;
    *) die "无效选择：$PROTO_CHOICE" ;;
esac

echo
echo "----------------------------------------------"
echo "转发协议 : ${PROTO_DESC}"
echo "中转端口 : ${FRONT_PORT}"
echo "落地地址 : ${BACKEND_IP}:${BACKEND_PORT}"
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

# 幂等添加规则：已存在则跳过
# 用法：ensure [-t table] CHAIN rule...
ensure() {
    local tbl=()
    if [[ "$1" == "-t" ]]; then
        tbl=(-t "$2")
        shift 2
    fi
    local chain="$1"
    shift
    iptables ${tbl[@]+"${tbl[@]}"} -C "$chain" "$@" 2>/dev/null ||
        iptables ${tbl[@]+"${tbl[@]}"} -A "$chain" "$@"
}

# 开启 IPv4 forwarding，并持久化
log "正在开启 IPv4 转发..."
cat >/etc/sysctl.d/99-port-forward.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
sysctl --system >/dev/null
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# 检查目标是否可路由
if ! ip route get "$BACKEND_IP" >/dev/null 2>&1; then
    warn "当前服务器没有到 $BACKEND_IP 的有效路由，继续配置可能无法工作。"
fi

# 获取出口网卡
OUT_IF="$(ip route get "$BACKEND_IP" 2>/dev/null | awk '
    {
        for (i=1; i<=NF; i++)
            if ($i=="dev") { print $(i+1); exit }
    }')"

[[ -n "$OUT_IF" ]] || OUT_IF="$(ip route show default | awk '/default/ {print $5; exit}')"
[[ -n "$OUT_IF" ]] || die "无法确定出口网卡。"

log "检测到出口网卡：$OUT_IF"

# 创建自定义链
iptables -t nat -N "$DNAT_CHAIN" 2>/dev/null || true
iptables -N "$ACCEPT_CHAIN" 2>/dev/null || true

for PROTO in "${PROTOS[@]}"; do
    log "正在配置 ${PROTO^^} 转发..."

    # 链跳转（仅添加一次）
    ensure -t nat PREROUTING -p "$PROTO" --dport "$FRONT_PORT" -j "$DNAT_CHAIN"
    ensure FORWARD -p "$PROTO" -d "$BACKEND_IP" --dport "$BACKEND_PORT" -j "$ACCEPT_CHAIN"

    # DNAT：中转端口 -> 落地 IP:端口
    ensure -t nat "$DNAT_CHAIN" -p "$PROTO" --dport "$FRONT_PORT" \
        -j DNAT --to-destination "${BACKEND_IP}:${BACKEND_PORT}"

    # FORWARD 放行去程
    ensure "$ACCEPT_CHAIN" -p "$PROTO" -d "$BACKEND_IP" --dport "$BACKEND_PORT" \
        -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

    # 回程放行
    ensure "$ACCEPT_CHAIN" -p "$PROTO" -s "$BACKEND_IP" --sport "$BACKEND_PORT" \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # MASQUERADE：保证落地机把回包正确返回中转机
    ensure -t nat POSTROUTING -o "$OUT_IF" -p "$PROTO" -d "$BACKEND_IP" --dport "$BACKEND_PORT" \
        -j MASQUERADE
done

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
echo "转发协议  ：${PROTO_DESC}"
echo "中转端口  ：${FRONT_PORT}"
echo "落地服务器：${BACKEND_IP}:${BACKEND_PORT}"
echo "出口网卡  ：${OUT_IF}"
echo "IPv4 转发 ：$(sysctl -n net.ipv4.ip_forward)"
echo
echo "DNAT 规则："
iptables -t nat -S "$DNAT_CHAIN"
echo
echo "FORWARD 规则："
iptables -S "$ACCEPT_CHAIN"
echo
echo "MASQUERADE 规则："
iptables -t nat -S POSTROUTING | grep -F -- "$BACKEND_IP" || true
echo
echo "查看全部规则："
echo "  iptables -t nat -vnL"
echo "  iptables -vnL FORWARD"
echo
log "重复运行相同配置不会重复添加相同规则。"
