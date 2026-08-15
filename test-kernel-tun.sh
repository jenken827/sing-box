#!/bin/bash
# ============================================================================
# kernel_tun (路线A) 集成测试脚本 — 需要 root 权限
#
# 用法:
#   sudo bash test-kernel-tun.sh              # 常规测试, 结束后自动恢复服务
#   sudo bash test-kernel-tun.sh --keep       # 测试后保留统一二进制运行(手动排查)
#   sudo bash test-kernel-tun.sh --no-confirm # 跳过确认提示
#
# 可选环境变量:
#   TEST_DOMAIN=xxx.xxx      管理端下发的自定义域名(测试隧道内 DNS 解析, 强烈建议)
#   TEST_IPERF_PEER=100.x.x  iperf3 对端 overlay IP(可选, 需对端已装 iperf3 -s)
#
# 测试流程:
#   1. 环境预检 + 快照(规则/服务/resolv.conf)
#   2. 停止系统 netbird + sing-box 服务
#   3. 用现有 netbird 身份(PrivateKey)启动统一二进制(kernel_tun)
#   4. 验证: wt0 / ip rule 2000 / table 10021 / resolv.conf 未变 / 隧道 DNS / docker / 外网
#   5. 清理: 停二进制 → 删路由 → 恢复系统服务 → 复查
# 注意: 若你当前 SSH 会话走的是 netbird 隧道, 第 2 步会断连!
# ============================================================================
set -u

TESTDIR=/tmp/sing-netbird-test
BIN=$TESTDIR/sing-netbird
LOGDIR=$TESTDIR/log
SB_CONFIG=$TESTDIR/sing-box-test.json
NB_CONFIG=$TESTDIR/netbird-config.json
SB_LOG=$LOGDIR/sing-box.log
RUN_LOG=$LOGDIR/run-all.log
STATE_DIR=$TESTDIR/nb-state
RESOLV_MD5_BEFORE=""
KEEP=0
NO_CONFIRM=0
BIN_PID=""
PASS=0
FAIL=0

for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    --no-confirm) NO_CONFIRM=1 ;;
  esac
done

log() { echo "[$(date +%H:%M:%S)] $*"; }
ok()  { echo "    [PASS] $*"; PASS=$((PASS+1)); }
bad() { echo "    [FAIL] $*"; FAIL=$((FAIL+1)); }
info(){ echo "    [INFO] $*"; }

mkdir -p "$LOGDIR"

# ---------- 0. 预检 ----------
log "=== 0. 环境预检 ==="
if [ "$(id -u)" != "0" ]; then
  echo "需要 root: 请用 sudo bash $0 执行"
  exit 1
fi
[ -x "$BIN" ] && ok "二进制存在: $BIN" || { bad "二进制缺失: $BIN (需先编译)"; exit 1; }
command -v python3 >/dev/null && ok "python3 可用" || { bad "python3 缺失"; exit 1; }
command -v dig >/dev/null || command -v nslookup >/dev/null || { bad "dig/nslookup 均缺失"; exit 1; }
if ! sudo -n true 2>/dev/null && [ "$(id -u)" != "0" ]; then
  echo "需要免密 sudo 或直接以 root 运行"
  exit 1
fi
# 用 python3 读取 netbird 配置字段 (不打印值)
nb_get() { python3 -c "import json,sys; d=json.load(open('/etc/netbird/config.json')); print(d.get(sys.argv[1],''))" "$1" 2>/dev/null; }
# 凭据来源: 1) /etc/netbird/config.json  2) $TESTDIR/netbird-credentials.json  3) 无凭据 → Mode B 机制测试
CREDS_MODE="config"
if [ ! -r /etc/netbird/config.json ]; then
  if [ -r "$TESTDIR/netbird-credentials.json" ]; then
    CREDS_MODE="file"
    ok "凭据来源: 用户文件 $TESTDIR/netbird-credentials.json"
    ok "格式: {\"private_key\":\"...\",\"management_url\":\"...\"} 或 {\"setup_key\":\"...\",\"management_url\":\"...\"}"
  else
    CREDS_MODE="none"
    info "无 netbird 凭据 → 将执行 Mode B (内核路由机制测试, 不建真实隧道, 不动系统服务)"
  fi
fi
if [ "$CREDS_MODE" = "config" ]; then
  # 校验现有配置含 PrivateKey + ManagementURL
  if [ -z "$(nb_get PrivateKey)" ]; then
    bad "/etc/netbird/config.json 缺少 PrivateKey 字段"
    exit 1
  fi
  if [ -z "$(nb_get ManagementURL)" ]; then
    bad "/etc/netbird/config.json 缺少 ManagementURL 字段"
    exit 1
  fi
  ok "现有 netbird 配置含 PrivateKey + ManagementURL"
fi

# ---------- 1. 快照 ----------
log "=== 1. 环境快照 ==="
{
  echo "===== $(date) ====="
  echo "--- services ---"
  systemctl is-active netbird sing-box 2>&1
  echo "--- ip rule ---"
  ip rule show
  echo "--- wt0 ---"
  ip -br addr show wt0 2>&1
  echo "--- resolv.conf md5 ---"
  md5sum /etc/resolv.conf
  echo "--- docker containers ---"
  docker ps -q 2>&1 | wc -l
  echo "--- tun devices ---"
  ip -br link show type tun 2>&1
} > "$LOGDIR/before.txt" 2>&1
RESOLV_MD5_BEFORE=$(md5sum /etc/resolv.conf | awk '{print $1}')
info "快照已存: $LOGDIR/before.txt"

# ========== Mode B: 无凭据 → 内核路由机制测试 (不碰系统服务) ==========
mode_b() {
  log "=== Mode B: 内核路由机制测试 ==="
  [ -x "$TESTDIR/test-kernel-route" ] || { bad "harness 缺失: $TESTDIR/test-kernel-route"; return 1; }
  if ip -br addr show wt0 >/dev/null 2>&1; then
    info "检测到真实 wt0 (系统 netbird 在跑) — 规则将短暂指向真实隧道, 15s 后自动清理, 不影响现有隧道"
  fi
  # 模拟 wt0 (若不存在)
  if ! ip link show wt0 >/dev/null 2>&1; then
    ip link add wt0 type dummy 2>&1 && info "dummy wt0 已创建"
    ip addr add 100.121.254.26/16 dev wt0 2>/dev/null
    ip link set wt0 up
    DUMMY_CREATED=1
  else
    DUMMY_CREATED=0
  fi
  # 运行 harness (15s 后自动清理)
  "$TESTDIR/test-kernel-route" 100.121.0.0/16 > "$LOGDIR/harness.log" 2>&1 &
  HPID=$!
  sleep 4
  if ip rule show | grep -q "2000:.*lookup 10021"; then
    ok "ip rule 2000 → table 10021 已安装"
  else
    bad "ip rule 2000 未安装: $(ip rule show | head -6)"
  fi
  if ip route show table 10021 2>/dev/null | grep -q "dev wt0"; then
    ok "table 10021 路由指向 wt0"
  else
    bad "table 10021 路由缺失"
  fi
  R2000=$(ip rule show | awk '$1=="2000:"{print NR; exit}')
  R9000=$(ip rule show | awk '$1=="9000:"{print NR; exit}')
  info "规则顺序: 2000 在第 ${R2000:-无} 条, sing-tun 默认 9000 在第 ${R9000:-无} 条"
  if [ -n "$R2000" ] && { [ -z "$R9000" ] || [ "$R2000" -lt "$R9000" ]; }; then
    ok "优先级正确: 2000 先于 9000"
  else
    bad "优先级异常 (2000 应数值最小=最先匹配)"
  fi
  # 等待 harness 自动清理
  wait "$HPID" 2>/dev/null
  if grep -q CLEANUP_OK "$LOGDIR/harness.log"; then
    ok "harness 清理完成 (CLEANUP_OK)"
  else
    bad "harness 清理异常:"; tail -5 "$LOGDIR/harness.log"
  fi
  sleep 1
  if ip rule show | grep -q "lookup 10021"; then
    bad "清理后 rule 10021 残留"
  else
    ok "rule 10021 已清理"
  fi
  if ip route show table 10021 2>/dev/null | grep -q wt0; then
    bad "清理后 table 10021 路由残留"
  else
    ok "table 10021 路由已清理"
  fi
  if [ "$DUMMY_CREATED" = "1" ]; then
    ip link del wt0 2>/dev/null && ok "dummy wt0 已删除"
  fi
  # 确认系统 netbird 规则未被碰
  if ip rule show | grep -qE "^(105|110):"; then
    ok "系统 netbird 规则 (105/110) 完好"
  else
    info "系统 netbird 规则 105/110 不存在 (守护进程未在跑或规则不同)"
  fi
}

# ---------- 危险提示 (仅真实隧道模式) ----------
if [ "$CREDS_MODE" = "none" ]; then
  mode_b
  log "=== Mode B 汇总: PASS=$PASS FAIL=$FAIL ==="
  [ "$FAIL" = "0" ] && echo ">>> Mode B 全部通过 <<<" || echo ">>> Mode B 存在失败项, 日志: $LOGDIR/ <<<"
  exit 0
fi

log "即将停止系统服务: netbird.service, sing-box.service"
log "并短暂接管 netbird 身份(复用 PrivateKey) + 全流量 TUN(gvisor)"
if [ "$NO_CONFIRM" != "1" ]; then
  read -r -p "确认继续? (yes/no): " ans
  [ "$ans" = "yes" ] || { echo "已取消"; exit 0; }
fi

# ---------- 2. 停止系统服务 ----------
log "=== 2. 停止系统服务 ==="
systemctl stop netbird 2>&1; info "netbird stop rc=$?"
systemctl stop sing-box 2>&1; info "sing-box stop rc=$?"
sleep 3
if ip -br addr show wt0 >/dev/null 2>&1; then
  bad "netbird 停止后 wt0 仍存在"
else
  ok "netbird 停止后 wt0 已消失"
fi
# netbird 停止后若残留 rule 105/110, 手动清理(防止 suppress_prefixlength 干扰测试)
for prio in 105 110; do
  if ip rule show | grep -q "^$prio:"; then
    ip rule del priority $prio 2>&1 && info "清理残留 rule $prio"
  fi
done
ok "系统服务已停止, 规则已就绪"

# ---------- 3. 准备配置 + 启动 ----------
log "=== 3. 启动统一二进制 (kernel_tun) ==="
NB_PKEY=""; NB_SETUP=""; NB_MGMT=""
if [ "$CREDS_MODE" = "config" ]; then
  NB_PKEY=$(nb_get PrivateKey)
  NB_MGMT=$(nb_get ManagementURL)
elif [ "$CREDS_MODE" = "file" ]; then
  cred_get() { python3 -c "import json,sys; d=json.load(open('$TESTDIR/netbird-credentials.json')); print(d.get(sys.argv[1],''))" "$1" 2>/dev/null; }
  NB_PKEY=$(cred_get private_key)
  NB_SETUP=$(cred_get setup_key)
  NB_MGMT=$(cred_get management_url)
  if [ -z "$NB_PKEY" ] && [ -z "$NB_SETUP" ]; then
    bad "凭据文件缺少 private_key 或 setup_key"
    exit 1
  fi
  if [ -z "$NB_MGMT" ]; then
    bad "凭据文件缺少 management_url"
    exit 1
  fi
fi
if [ -n "$NB_PKEY" ]; then
  CRED_JSON="  \"private_key\": \"$NB_PKEY\","
elif [ -n "$NB_SETUP" ]; then
  CRED_JSON="  \"setup_key\": \"$NB_SETUP\","
else
  CRED_JSON=""
fi
cat > "$NB_CONFIG" <<EOF
{
  "device_name": "sing-netbird-kerneltun-test",
$CRED_JSON
  "management_url": "$NB_MGMT",
  "log_level": "debug",
  "kernel_tun": true
}
EOF
chmod 600 "$NB_CONFIG"
info "netbird-config.json 已生成 (凭据已写入, 不显示)"

cat > "$SB_CONFIG" <<'EOF'
{
  "log": {"level": "info", "output": "/tmp/sing-netbird-test/log/sing-box.log"},
  "dns": {"servers": [{"tag": "dns-direct", "address": "223.5.5.5"}]},
  "inbounds": [
    {"type": "tun", "tag": "tun-in", "interface_name": "tun0",
     "stack": "gvisor", "auto_route": true, "mtu": 1500}
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"final": "direct"}
}
EOF
info "sing-box 测试配置已生成 (tun gvisor + auto_route)"

cd "$TESTDIR"
"$BIN" run-all -c "$SB_CONFIG" --netbird-config "$NB_CONFIG" --enable-netbird \
  > "$RUN_LOG" 2>&1 &
BIN_PID=$!
info "统一二进制 PID=$BIN_PID, 日志: $RUN_LOG"

# 等待就绪: 最多 150s, 盯关键标记
READY=0
for i in $(seq 1 50); do
  sleep 3
  if ! kill -0 "$BIN_PID" 2>/dev/null; then
    bad "统一二进制提前退出"
    tail -30 "$RUN_LOG"
    break
  fi
  if grep -q "netbird kernel route installed" "$RUN_LOG" && \
     grep -q "sing-box started" "$RUN_LOG"; then
    READY=1; ok "统一二进制就绪 (等待 $((i*3))s)"
    break
  fi
  if grep -qE "panic|fatal" "$RUN_LOG"; then
    bad "检测到 panic/fatal"
    tail -30 "$RUN_LOG"
    break
  fi
done
[ "$READY" = "1" ] || bad "150s 内未就绪, 日志尾部:"
[ "$READY" = "1" ] || tail -40 "$RUN_LOG"
[ "$READY" = "1" ] || { echo "就绪失败, 清理退出"; FAIL=$((FAIL+1)); exit 1; }

# ---------- 4. 验证 ----------
log "=== 4. 验证 ==="

# 4a. wt0 + overlay IP
if W0_IP=$(ip -4 -br addr show wt0 2>/dev/null | awk '{print $3}' | cut -d/ -f1); then
  ok "wt0 存在, overlay IP=$W0_IP"
else
  bad "wt0 不存在"
fi

# 4b. ip rule 2000 + 优先级
if ip rule show | grep -q "2000:.*lookup 10021"; then
  ok "ip rule 2000 → table 10021 存在"
else
  bad "ip rule 2000 缺失: $(ip rule show | head -8)"
fi

# 4c. table 10021 路由 → wt0
if ip route show table 10021 2>/dev/null | grep -q "dev wt0"; then
  ok "table 10021 路由指向 wt0"
  ip route show table 10021
else
  bad "table 10021 无 wt0 路由"
fi

# 4d. resolv.conf 未变
RESOLV_MD5_NOW=$(md5sum /etc/resolv.conf | awk '{print $1}')
if [ "$RESOLV_MD5_NOW" = "$RESOLV_MD5_BEFORE" ]; then
  ok "resolv.conf 未被修改"
else
  bad "resolv.conf 被修改! (测试后需恢复)"
fi

# 4e. overlay 可达性 (ICMP — 隧道 DNS 可能不回 ping, 仅参考)
TUNNEL_DNS=""
if [ -n "${W0_IP:-}" ]; then
  TUNNEL_DNS=$(python3 - "$W0_IP" <<'PYEOF'
import ipaddress, sys
ip = ipaddress.IPv4Address(sys.argv[1])
net = ipaddress.ip_network(f"{ip}/16", strict=False)
print(str(net.broadcast_address - 1))
PYEOF
)
  info "隧道 DNS 按 /16 推算: $TUNNEL_DNS"
fi
if [ -n "$TUNNEL_DNS" ]; then
  if ping -c 2 -W 2 "$TUNNEL_DNS" >/dev/null 2>&1; then
    ok "overlay ping 通 ($TUNNEL_DNS)"
  else
    info "overlay ping 无响应 (隧道 DNS 可能不回 ICMP, 以 dig 为准)"
  fi
fi

# 4f. 隧道内 DNS (核心测试: 有响应即证明内核路由 + wt0 通)
if [ -n "$TUNNEL_DNS" ]; then
  if dig +time=3 +tries=1 "@$TUNNEL_DNS" example.com 2>&1 | grep -q "timed out"; then
    bad "隧道 DNS 超时 — 内核路由或 wt0 不通"
  else
    ok "隧道 DNS 可达 ($TUNNEL_DNS:53 有响应)"
  fi
  if [ -n "${TEST_DOMAIN:-}" ]; then
    DIG_OUT=$(dig +time=4 +tries=1 "@$TUNNEL_DNS" "$TEST_DOMAIN" 2>&1)
    if echo "$DIG_OUT" | grep -q "ANSWER: [1-9]"; then
      ok "自定义域名 $TEST_DOMAIN 经隧道解析成功:"
      echo "$DIG_OUT" | grep -A2 "ANSWER SECTION" || true
    else
      bad "自定义域名 $TEST_DOMAIN 隧道解析失败:"
      echo "$DIG_OUT" | grep -E "status:|timed out" || true
    fi
  else
    info "未设置 TEST_DOMAIN, 跳过自定义域名解析测试 (建议补测)"
  fi
fi

# 4g. docker 正常
if docker ps >/dev/null 2>&1; then
  ok "docker daemon 正常"
  CNT=$(docker ps -q | wc -l)
  info "运行中容器数: $CNT"
  FIRST=$(docker ps -q | head -1)
  if [ -n "$FIRST" ]; then
    if docker exec "$FIRST" ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
      ok "容器内网络正常 (ping 8.8.8.8)"
    else
      info "容器内 ping 8.8.8.8 不通 (可能容器策略限制, 不判失败)"
    fi
  fi
else
  bad "docker daemon 异常"
fi

# 4h. 外网 (走 sing-box tun 全隧道)
if curl -m 8 -sI https://www.baidu.com >/dev/null 2>&1; then
  ok "外网连通 (curl baidu, 经 tun 全隧道)"
else
  bad "外网连通失败"
fi

# 4i. iperf3 (可选)
if [ -n "${TEST_IPERF_PEER:-}" ]; then
  if command -v iperf3 >/dev/null 2>&1; then
    log "iperf3 测试: 对端 $TEST_IPERF_PEER (10s 上传)"
    iperf3 -c "$TEST_IPERF_PEER" -t 10 2>&1 | grep -E "SUM|receiver|sender" | tail -4 || \
      bad "iperf3 失败"
  else
    info "iperf3 未安装, 跳过 (apt install iperf3 后可补测)"
  fi
else
  info "未设置 TEST_IPERF_PEER, 跳过 iperf3 吞吐测试"
fi

# ---------- 5. 清理 ----------
CLEANED=0
cleanup() {
  [ "$CLEANED" = "1" ] && return
  CLEANED=1
  log "=== 5. 清理 ==="
  if [ "$KEEP" = "1" ]; then
    info "--keep 模式: 保留统一二进制运行 (PID=$BIN_PID, 日志 $RUN_LOG)"
    info "手动停止: kill $BIN_PID; 恢复服务: systemctl start netbird sing-box"
    return
  fi
  if [ -n "$BIN_PID" ] && kill -0 "$BIN_PID" 2>/dev/null; then
    kill -TERM "$BIN_PID"
    for i in $(seq 1 5); do
      sleep 1
      kill -0 "$BIN_PID" 2>/dev/null || break
    done
    if kill -0 "$BIN_PID" 2>/dev/null; then
      info "15s 内未优雅退出, SIGKILL"
      kill -9 "$BIN_PID"
    fi
    wait "$BIN_PID" 2>/dev/null
    info "统一二进制已停止"
  fi
  sleep 2
  if ip rule show | grep -q "lookup 10021"; then
    bad "清理后 ip rule 10021 仍存在"
  else
    ok "ip rule 2000/table 10021 已清理"
  fi
  if ip -br addr show wt0 >/dev/null 2>&1; then
    bad "清理后 wt0 仍存在"
  else
    ok "wt0 已消失"
  fi
  # 恢复系统服务
  systemctl start netbird 2>&1; info "netbird 恢复 rc=$?"
  systemctl start sing-box 2>&1; info "sing-box 恢复 rc=$?"
  sleep 5
  if ip -br addr show wt0 >/dev/null 2>&1 && ip rule show | grep -q "105:"; then
    ok "系统 netbird 恢复 (wt0 + rule 105 回来)"
  else
    bad "系统 netbird 恢复异常, 请检查: systemctl status netbird"
  fi
  if [ "$(md5sum /etc/resolv.conf | awk '{print $1}')" = "$RESOLV_MD5_BEFORE" ]; then
    ok "resolv.conf 恢复确认"
  else
    bad "resolv.conf 与测试前不一致!"
  fi
}
trap cleanup EXIT

# 正常路径: 先清理, 再汇总
cleanup

# ---------- 汇总 ----------
log "=== 测试汇总: PASS=$PASS FAIL=$FAIL ==="
[ "$FAIL" = "0" ] && echo ">>> 全部通过 <<<" || echo ">>> 存在失败项, 关键日志: $LOGDIR/ <<<"
