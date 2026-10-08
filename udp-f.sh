#!/usr/bin/env bash
set -Eeuo pipefail

# TCP/UDP DNAT 端口转发管理脚本（添加 / 删除 / 查看 / 清空）
# 用法：
#   chmod +x port-forward.sh
#   sudo ./port-forward.sh
#
# 说明：
#   - 支持 TCP+UDP / 仅 UDP / 仅 TCP 三种模式（默认 TCP+UDP）
#   - 中转端口和落地端口可以不同
#   - 重复添加相同转发不会重复写入规则
#   - 规则写入 iptables-persistent，重启后自动恢复
#   - 只处理 IPv4 转发，不修改 SSH 等其他规则
#   - 同时识别并可删除旧版 UDP 脚本创建的 UDP_FORWARD_* 规则

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
LEGACY_DNAT_CHAIN="UDP_FORWARD_DNAT"
LEGACY_ACCEPT_CHAIN="UDP_FORWARD_ACCEPT"

RULES=()

# ---------------------------------------------------------------- 通用函数

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

need_iptables() {
    command -v iptables >/dev/null 2>&1 || die "未安装 iptables，没有可操作的规则。"
}

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

# 按正则筛选并删除规则
# 用法：purge TABLE CHAIN REGEX...   （REGEX 以 ! 开头表示"不匹配"）
purge() {
    local table="$1" chain="$2"
    shift 2
    local out line re
    local a=()
    out="$(iptables -t "$table" -S "$chain" 2>/dev/null | grep '^-A' || true)"
    for re in "$@"; do
        if [[ "$re" == '!'* ]]; then
            out="$(grep -Ev -- "${re:1}" <<< "$out" || true)"
        else
            out="$(grep -E -- "$re" <<< "$out" || true)"
        fi
    done
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        read -ra a <<< "$line"
        a[0]="-D"
        iptables -t "$table" "${a[@]}" 2>/dev/null || true
    done <<< "$out"
}

save_rules() {
    log "正在保存 iptables 规则..."
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null
    elif command -v iptables-save >/dev/null 2>&1; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
    fi

    if systemctl list-unit-files 2>/dev/null | grep -q '^netfilter-persistent.service'; then
        systemctl enable netfilter-persistent >/dev/null 2>&1 || true
    fi
}

# 读取当前所有转发规则到 RULES 数组
# 每项格式：chain|proto|前端端口|落地IP|落地端口
collect_rules() {
    RULES=()
    local chain line proto front dest i
    local f=()
    for chain in "$DNAT_CHAIN" "$LEGACY_DNAT_CHAIN"; do
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            read -ra f <<< "$line"
            proto=""; front=""; dest=""
            for ((i = 0; i < ${#f[@]}; i++)); do
                case "${f[i]}" in
                    -p)               proto="${f[i+1]:-}" ;;
                    --dport)          front="${f[i+1]:-}" ;;
                    --to-destination) dest="${f[i+1]:-}" ;;
                esac
            done
            if [[ -n "$proto" && -n "$front" && -n "$dest" ]]; then
                RULES+=("${chain}|${proto}|${front}|${dest%:*}|${dest##*:}")
            fi
        done < <(iptables -t nat -S "$chain" 2>/dev/null | grep '^-A' || true)
    done
}

# 统计匹配的规则数，参数可用 * 作通配：count_rules proto front ip port
count_rules() {
    local n=0 r chain proto front ip port
    for r in ${RULES[@]+"${RULES[@]}"}; do
        IFS='|' read -r chain proto front ip port <<< "$r"
        # shellcheck disable=SC2053
        if [[ "$proto" == $1 && "$front" == $2 && "$ip" == $3 && "$port" == $4 ]]; then
            n=$((n + 1))
        fi
    done
    echo "$n"
}

# 打印规则列表，返回规则数量到 RULE_COUNT
print_rules() {
    collect_rules
    RULE_COUNT=${#RULES[@]}
    if (( RULE_COUNT == 0 )); then
        echo "  （当前没有转发规则）"
        return
    fi
    printf "  %-4s %-6s %-10s %-24s %s\n" "编号" "协议" "中转端口" "落地地址" "来源"
    local i=1 r chain proto front ip port src
    for r in "${RULES[@]}"; do
        IFS='|' read -r chain proto front ip port <<< "$r"
        src="当前版本"
        [[ "$chain" == "$LEGACY_DNAT_CHAIN" ]] && src="旧版UDP脚本"
        printf "  %-6s %-6s %-12s %-24s %s\n" "$i" "${proto^^}" "$front" "${ip}:${port}" "$src"
        i=$((i + 1))
    done
}

# ---------------------------------------------------------------- 添加转发

do_add() {
    local BACKEND_IP BACKEND_PORT FRONT_PORT PROTO_CHOICE CONFIRM
    local PROTOS=() PROTO_DESC="" PROTO OUT_IF o o1 o2 o3 o4

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
    [[ -z "$CONFIRM" || "$CONFIRM" =~ ^[Yy]$ ]] || { echo "已取消。"; return; }

    install_iptables

    log "正在开启 IPv4 转发..."
    cat >/etc/sysctl.d/99-port-forward.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
    sysctl --system >/dev/null
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    if ! ip route get "$BACKEND_IP" >/dev/null 2>&1; then
        warn "当前服务器没有到 $BACKEND_IP 的有效路由，继续配置可能无法工作。"
    fi

    OUT_IF="$(ip route get "$BACKEND_IP" 2>/dev/null | awk '
        {
            for (i=1; i<=NF; i++)
                if ($i=="dev") { print $(i+1); exit }
        }')"
    [[ -n "$OUT_IF" ]] || OUT_IF="$(ip route show default | awk '/default/ {print $5; exit}')"
    [[ -n "$OUT_IF" ]] || die "无法确定出口网卡。"
    log "检测到出口网卡：$OUT_IF"

    iptables -t nat -N "$DNAT_CHAIN" 2>/dev/null || true
    iptables -N "$ACCEPT_CHAIN" 2>/dev/null || true

    for PROTO in "${PROTOS[@]}"; do
        log "正在配置 ${PROTO^^} 转发..."

        ensure -t nat PREROUTING -p "$PROTO" --dport "$FRONT_PORT" -j "$DNAT_CHAIN"
        ensure FORWARD -p "$PROTO" -d "$BACKEND_IP" --dport "$BACKEND_PORT" -j "$ACCEPT_CHAIN"

        ensure -t nat "$DNAT_CHAIN" -p "$PROTO" --dport "$FRONT_PORT" \
            -j DNAT --to-destination "${BACKEND_IP}:${BACKEND_PORT}"

        ensure "$ACCEPT_CHAIN" -p "$PROTO" -d "$BACKEND_IP" --dport "$BACKEND_PORT" \
            -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

        ensure "$ACCEPT_CHAIN" -p "$PROTO" -s "$BACKEND_IP" --sport "$BACKEND_PORT" \
            -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

        ensure -t nat POSTROUTING -o "$OUT_IF" -p "$PROTO" -d "$BACKEND_IP" --dport "$BACKEND_PORT" \
            -j MASQUERADE
    done

    save_rules

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
    echo "当前转发规则："
    print_rules
    echo
    log "重复添加相同配置不会重复写入相同规则。"
}

# ---------------------------------------------------------------- 删除转发

# 删除单条转发（参数：chain|proto|前端端口|落地IP|落地端口）
delete_forward() {
    local entry="$1"
    local chain proto front ip port acc_chain ip_re
    IFS='|' read -r chain proto front ip port <<< "$entry"
    ip_re="${ip//./\\.}"

    acc_chain="$ACCEPT_CHAIN"
    [[ "$chain" == "$LEGACY_DNAT_CHAIN" ]] && acc_chain="$LEGACY_ACCEPT_CHAIN"

    # 1. 删除 DNAT 规则
    iptables -t nat -D "$chain" -p "$proto" --dport "$front" \
        -j DNAT --to-destination "${ip}:${port}" 2>/dev/null || true

    collect_rules

    # 2. 没有其他规则使用该前端端口，则删除 PREROUTING 跳转
    if [[ "$(count_rules "$proto" "$front" '*' '*')" == "0" ]]; then
        purge nat PREROUTING "-p ${proto} " "--dport ${front} " \
            "-j (${DNAT_CHAIN}|${LEGACY_DNAT_CHAIN})\$"
    fi

    # 3. 没有其他规则使用该落地目标，则删除放行与 MASQUERADE
    if [[ "$(count_rules "$proto" '*' "$ip" "$port")" == "0" ]]; then
        purge filter FORWARD "-p ${proto} " "-d ${ip_re}/32 " "--dport ${port} " \
            "-j (${ACCEPT_CHAIN}|${LEGACY_ACCEPT_CHAIN})\$"
        purge filter "$acc_chain" "-p ${proto} " "-d ${ip_re}/32 " "--dport ${port} "
        purge filter "$acc_chain" "-p ${proto} " "-s ${ip_re}/32 " "--sport ${port} "
        purge nat POSTROUTING "-p ${proto} " "-d ${ip_re}/32 " "--dport ${port} " "-j MASQUERADE\$"
    fi

    # 4. 旧版回程规则（不带 --sport），该 IP+协议下已无转发才删除
    if [[ "$(count_rules "$proto" '*' "$ip" '*')" == "0" ]]; then
        purge filter "$acc_chain" "-p ${proto} " "-s ${ip_re}/32 " "!--sport"
    fi

    log "已删除：${proto^^} ${front} -> ${ip}:${port}"
}

do_delete() {
    need_iptables
    echo
    echo "当前转发规则："
    print_rules
    (( RULE_COUNT > 0 )) || return

    echo
    local sel idx
    local picks=() entries=()
    read -r -p "请输入要删除的编号（可多个，空格分隔；直接回车取消）: " sel
    [[ -n "$sel" ]] || { echo "已取消。"; return; }

    for idx in $sel; do
        [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= RULE_COUNT )) || die "无效编号：$idx"
        entries+=("${RULES[idx-1]}")
    done

    local CONFIRM
    read -r -p "确认删除选中的 ${#entries[@]} 条规则？[y/N]: " CONFIRM
    [[ "$CONFIRM" =~ ^[Yy]$ ]] || { echo "已取消。"; return; }

    local e
    for e in "${entries[@]}"; do
        delete_forward "$e"
    done

    save_rules
    echo
    echo "剩余转发规则："
    print_rules
}

do_clear_all() {
    need_iptables
    echo
    echo "当前转发规则："
    print_rules
    (( RULE_COUNT > 0 )) || { warn "没有规则，仍会清理残留的自定义链。"; }

    echo
    local CONFIRM
    read -r -p "确认清空全部转发规则（含旧版 UDP 脚本规则）？[y/N]: " CONFIRM
    [[ "$CONFIRM" =~ ^[Yy]$ ]] || { echo "已取消。"; return; }

    local r chain proto front ip port ip_re c
    collect_rules
    for r in ${RULES[@]+"${RULES[@]}"}; do
        IFS='|' read -r chain proto front ip port <<< "$r"
        ip_re="${ip//./\\.}"
        purge nat POSTROUTING "-p ${proto} " "-d ${ip_re}/32 " "--dport ${port} " "-j MASQUERADE\$"
    done

    purge nat PREROUTING "-j (${DNAT_CHAIN}|${LEGACY_DNAT_CHAIN})\$"
    purge filter FORWARD "-j (${ACCEPT_CHAIN}|${LEGACY_ACCEPT_CHAIN})\$"

    for c in "$DNAT_CHAIN" "$LEGACY_DNAT_CHAIN"; do
        iptables -t nat -F "$c" 2>/dev/null || true
        iptables -t nat -X "$c" 2>/dev/null || true
    done
    for c in "$ACCEPT_CHAIN" "$LEGACY_ACCEPT_CHAIN"; do
        iptables -F "$c" 2>/dev/null || true
        iptables -X "$c" 2>/dev/null || true
    done

    save_rules
    log "已清空全部转发规则。"
}

do_list() {
    need_iptables
    echo
    echo "当前转发规则："
    print_rules
    echo
    echo "详细规则查看："
    echo "  iptables -t nat -vnL"
    echo "  iptables -vnL FORWARD"
}

# ---------------------------------------------------------------- 主菜单

while true; do
    echo
    echo "=============================================="
    echo "        TCP/UDP DNAT 端口转发管理工具"
    echo "=============================================="
    echo "  1) 添加转发"
    echo "  2) 删除指定转发"
    echo "  3) 清空全部转发规则"
    echo "  4) 查看当前转发规则"
    echo "  0) 退出"
    echo "----------------------------------------------"
    read -r -p "请选择 [0-4]: " CHOICE
    case "$CHOICE" in
        1) do_add ;;
        2) do_delete ;;
        3) do_clear_all ;;
        4) do_list ;;
        0|q|Q) echo "已退出。"; exit 0 ;;
        *) warn "无效选择：$CHOICE" ;;
    esac
done
