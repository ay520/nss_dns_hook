#!/bin/bash
#
# nss_dns_hook 自动化部署脚本
#
# 用法:
#   sudo ./deploy.sh install        编译 + 安装模块 + 配置 nsswitch + 部署配置文件
#   sudo ./deploy.sh uninstall      卸载模块 + 还原 nsswitch + 删除配置文件
#   sudo ./deploy.sh status         查看当前安装状态
#   sudo ./deploy.sh test           冒烟测试(白名单/劫持/通配符/日志)
#   sudo ./deploy.sh setup-logs     配置 rsyslog 日志分文件(/var/log/nss_hs.log)
#   sudo ./deploy.sh teardown-logs  删除 rsyslog 分文件配置
#

set -euo pipefail

# ===== 配置常量 =====
WHITELIST_SRC="nss_whitelist.conf"
PRIVATE_NETWORKS_SRC="nss_private_networks.conf"
WHITELIST_DST="/etc/nss_whitelist.conf"
PRIVATE_NETWORKS_DST="/etc/nss_private_networks.conf"
NSSWITCH_FILE="/etc/nsswitch.conf"
NSSWITCH_BAK="/etc/nsswitch.conf.bak.nss_hs"
RSYSLOG_CONF="/etc/rsyslog.d/nss_hs.conf"
LIB_PATH="/lib64"
MODULE_NAME="libnss_hs.so.2"
LOG_IDENT="nss_hs"

# ===== 颜色输出 =====
if [[ -t 1 ]]; then
    C_INFO='\033[32m'; C_WARN='\033[33m'; C_ERR='\033[31m'; C_RESET='\033[0m'
else
    C_INFO=''; C_WARN=''; C_ERR=''; C_RESET=''
fi

info()  { echo -e "${C_INFO}[INFO]${C_RESET} $*"; }
warn()  { echo -e "${C_WARN}[WARN]${C_RESET} $*"; }
error() { echo -e "${C_ERR}[ERROR]${C_RESET} $*" >&2; }
die()   { error "$*"; exit 1; }

# ===== 前置检查 =====
check_root() {
    [[ $EUID -eq 0 ]] || die "需要 root 权限执行(用 sudo)"
}

check_repo() {
    [[ -f "Makefile" && -f "nss_module.c" ]] || die "请在 nss_dns_hook 仓库根目录执行"
}

# ===== install =====
do_install() {
    info "开始安装 nss_dns_hook..."
    check_root
    check_repo

    # 1. 编译
    info "编译模块..."
    make clean >/dev/null 2>&1 || true
    make >/dev/null 2>&1 || die "编译失败(用 make 手动编译查看详情)"
    [[ -f "$MODULE_NAME" ]] || die "编译失败: $MODULE_NAME 未生成"
    info "编译成功"

    # 2. 安装 .so
    info "安装 $MODULE_NAME 到 $LIB_PATH/..."
    make install >/dev/null 2>&1
    ldconfig
    ldconfig -p | grep -q "$MODULE_NAME" || die "ldconfig 未识别到 $MODULE_NAME"
    info "模块已注册"

    # 3. 部署配置文件
    deploy_config "$WHITELIST_SRC" "$WHITELIST_DST"
    deploy_config "$PRIVATE_NETWORKS_SRC" "$PRIVATE_NETWORKS_DST"

    # 4. 配置 nsswitch.conf
    setup_nsswitch

    # 5. 完成
    echo ""
    info "安装完成。建议执行 './deploy.sh test' 验证功能。"
}

deploy_config() {
    local src="$1" dst="$2"
    if [[ -f "$dst" ]]; then
        local bak="${dst}.bak.$(date +%s)"
        cp "$dst" "$bak"
        info "已备份现有 $dst -> $bak"
    fi
    cp "$src" "$dst"
    info "部署 $dst"
}

setup_nsswitch() {
    info "配置 $NSSWITCH_FILE ..."
    local hosts_line
    hosts_line=$(grep "^hosts:" "$NSSWITCH_FILE" 2>/dev/null || true)
    if [[ -z "$hosts_line" ]]; then
        die "$NSSWITCH_FILE 中找不到 hosts: 行,请手动配置"
    fi

    if echo "$hosts_line" | grep -qw "hs"; then
        info "nsswitch 已包含 hs 模块,无需修改"
        return
    fi

    # 备份
    cp "$NSSWITCH_FILE" "$NSSWITCH_BAK"
    info "已备份 $NSSWITCH_FILE -> $NSSWITCH_BAK"

    # 在 hosts: 行的 files 后面插入 hs
    # 例: "hosts: files dns myhostname" -> "hosts: files hs dns myhostname"
    if echo "$hosts_line" | grep -qw "files"; then
        sed -i -E 's/^(hosts:[[:space:]]+)files/\1files hs/' "$NSSWITCH_FILE"
    else
        # 没有 files,在 hosts: 后直接加 hs
        sed -i -E 's/^(hosts:[[:space:]]+)/\1hs /' "$NSSWITCH_FILE"
    fi

    info "nsswitch 已更新: $(grep '^hosts:' "$NSSWITCH_FILE")"
}

# ===== uninstall =====
do_uninstall() {
    info "开始卸载 nss_dns_hook..."
    check_root

    # 1. 还原 nsswitch
    if [[ -f "$NSSWITCH_BAK" ]]; then
        cp "$NSSWITCH_BAK" "$NSSWITCH_FILE"
        info "已还原 $NSSWITCH_FILE(从备份)"
        rm -f "$NSSWITCH_BAK"
    else
        # 只删 hs
        sed -i -E 's/^(hosts:[[:space:]]+.*)[[:space:]]+hs\b/\1/' "$NSSWITCH_FILE"
        info "已从 nsswitch 移除 hs: $(grep '^hosts:' "$NSSWITCH_FILE")"
    fi

    # 2. 卸载 .so
    if [[ -f "$LIB_PATH/$MODULE_NAME" ]]; then
        rm -f "$LIB_PATH/$MODULE_NAME"
        ldconfig
        info "模块已卸载"
    else
        info "模块未安装,跳过"
    fi

    # 3. 配置文件(保留,用户可能还要用)
    warn "配置文件保留: $WHITELIST_DST $PRIVATE_NETWORKS_DST"
    warn "如需删除: rm -f $WHITELIST_DST $PRIVATE_NETWORKS_DST"

    echo ""
    info "卸载完成"
}

# ===== status =====
do_status() {
    echo "=== nss_dns_hook 安装状态 ==="

    # 模块
    if ldconfig -p | grep -q "$MODULE_NAME"; then
        local path
        path=$(ldconfig -p | grep "$MODULE_NAME" | awk '{print $NF}')
        info "模块: 已安装 ($path)"
    else
        warn "模块: 未安装"
    fi

    # nsswitch
    local hosts_line
    hosts_line=$(grep "^hosts:" "$NSSWITCH_FILE" 2>/dev/null || true)
    if [[ -n "$hosts_line" ]]; then
        if echo "$hosts_line" | grep -qw "hs"; then
            info "nsswitch: 已配置 hs"
        else
            warn "nsswitch: 未配置 hs"
        fi
        echo "    当前: $hosts_line"
    else
        warn "nsswitch: 找不到 hosts: 行"
    fi

    # 配置文件
    for f in "$WHITELIST_DST" "$PRIVATE_NETWORKS_DST"; do
        if [[ -f "$f" ]]; then
            local lines
            lines=$(grep -cv '^[[:space:]]*\(#\|$\)' "$f" 2>/dev/null || echo 0)
            info "$f: 存在 ($lines 条配置)"
        else
            warn "$f: 不存在"
        fi
    done

    # rsyslog
    if [[ -f "$RSYSLOG_CONF" ]]; then
        info "rsyslog 分文件: 已配置 ($RSYSLOG_CONF)"
    else
        info "rsyslog 分文件: 未配置(日志走默认 messages)"
    fi

    echo ""
}

# ===== test =====
do_test() {
    echo "=== 冒烟测试 ==="

    local pass=0 fail=0

    # 测试 1: DNS 能解析(不挂)
    if getent hosts www.baidu.com >/dev/null 2>&1; then
        info "PASS: DNS 解析正常(getent 不挂)"
        pass=$((pass+1))
    else
        error "FAIL: DNS 解析异常(getent 返回非零)"
        fail=$((fail+1))
    fi

    # 测试 2: 白名单内域名返回真实 IP(非 127.0.0.1/::1)
    local out
    out=$(getent hosts www.baidu.com 2>&1) || true
    if echo "$out" | grep -qvE '127\.0\.0\.1|::1'; then
        info "PASS: 白名单域名放行(www.baidu.com 返回真实 IP)"
        pass=$((pass+1))
    else
        error "FAIL: 白名单域名应放行,实际: $out"
        fail=$((fail+1))
    fi

    # 测试 3: 非白名单公网域名被劫持到 localhost
    out=$(getent hosts example.com 2>&1) || true
    if echo "$out" | grep -qE '127\.0\.0\.1|::1'; then
        info "PASS: 非白名单域名劫持到 localhost(example.com)"
        pass=$((pass+1))
    else
        error "FAIL: 非白名单域名应劫持,实际: $out"
        fail=$((fail+1))
    fi

    # 测试 4: 通配符匹配(pan.baidu.com 应匹配 *.baidu.com,放行)
    out=$(getent hosts pan.baidu.com 2>&1) || true
    if echo "$out" | grep -qvE '127\.0\.0\.1|::1'; then
        info "PASS: 通配符匹配(pan.baidu.com 匹配 *.baidu.com)"
        pass=$((pass+1))
    else
        error "FAIL: 通配符匹配异常,实际: $out"
        fail=$((fail+1))
    fi

    # 测试 5: 日志能输出
    out=$(journalctl -t "$LOG_IDENT" --since '1 min ago' --no-pager 2>/dev/null | head -1 || true)
    if [[ -z "$out" ]]; then
        out=$(grep "$LOG_IDENT" /var/log/messages 2>/dev/null | tail -1 || true)
    fi
    if [[ -n "$out" ]]; then
        info "PASS: syslog 日志输出正常"
        pass=$((pass+1))
    else
        warn "SKIP: 未找到 syslog 日志(可能刚安装还没查询,或 rsyslog/journald 配置不同)"
    fi

    echo ""
    info "测试结果: $pass 通过, $fail 失败"
    [[ $fail -eq 0 ]] || die "有测试失败"
}

# ===== setup-logs / teardown-logs =====
do_setup_logs() {
    info "配置 rsyslog 将 nss_hs 日志分到 /var/log/nss_hs.log..."
    check_root

    mkdir -p "$(dirname "$RSYSLOG_CONF")"
    cat > "$RSYSLOG_CONF" <<'EOF'
# nss_dns_hook 日志路由
local0.*    /var/log/nss_hs.log
& stop
EOF

    systemctl restart rsyslog 2>/dev/null || true
    info "rsyslog 已配置: $RSYSLOG_CONF"
    info "日志文件: /var/log/nss_hs.log"
    info "查看: tail -f /var/log/nss_hs.log"
}

do_teardown_logs() {
    info "删除 rsyslog 分文件配置..."
    check_root
    rm -f "$RSYSLOG_CONF"
    systemctl restart rsyslog 2>/dev/null || true
    info "已删除,日志恢复走默认 messages"
}

# ===== main =====
case "${1:-}" in
    install)        do_install ;;
    uninstall)      do_uninstall ;;
    status)         do_status ;;
    test)           do_test ;;
    setup-logs)     do_setup_logs ;;
    teardown-logs)  do_teardown_logs ;;
    "")
        echo "用法: sudo $0 {install|uninstall|status|test|setup-logs|teardown-logs}"
        echo ""
        echo "命令:"
        echo "  install        编译 + 安装模块 + 配置 nsswitch + 部署配置文件"
        echo "  uninstall      卸载模块 + 还原 nsswitch + 保留配置文件"
        echo "  status         查看当前安装状态"
        echo "  test           冒烟测试(白名单/劫持/通配符/日志)"
        echo "  setup-logs     配置 rsyslog 日志分文件(/var/log/nss_hs.log)"
        echo "  teardown-logs  删除 rsyslog 分文件配置"
        exit 1
        ;;
    *)
        die "未知命令: $1 (用 $0 不带参数查看用法)"
        ;;
esac
