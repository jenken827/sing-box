#!/bin/bash
# 网络诊断：conntrack + TCP 状态 + 路由检查
# 输出到 /tmp/diag_net.log

OUT=/tmp/diag_net.log
echo "=== conntrack -S ===" > $OUT
sudo conntrack -S >> $OUT 2>&1

echo -e "\n=== conntrack -C (当前条目数) ===" >> $OUT
sudo conntrack -C >> $OUT 2>&1

echo -e "\n=== conntrack 最大数 ===" >> $OUT
sysctl net.netfilter.nf_conntrack_max >> $OUT 2>&1

echo -e "\n=== conntrack 超时设置 ===" >> $OUT
for t in time_wait close_wait fin_wait established last_ack; do
    key="net.netfilter.nf_conntrack_tcp_timeout_${t}"
    echo "$key = $(sysctl -n $key 2>/dev/null)" >> $OUT
done

echo -e "\n=== TCP 连接状态分布 ===" >> $OUT
ss -t state all | awk '{print $1}' | sort | uniq -c | sort -rn >> $OUT

echo -e "\n=== UDP 连接状态 ===" >> $OUT
ss -u state all | awk '{print $1}' | sort | uniq -c | sort -rn >> $OUT

echo -e "\n=== 各网卡 RX/TX 错误 + drop ===" >> $OUT
ip -s link | grep -E '^[0-9]|RX:|TX:|errors|dropped' >> $OUT

echo -e "\n=== 路由策略 ===" >> $OUT
ip rule show >> $OUT 2>&1

echo -e "\n=== 当前默认路由 ===" >> $OUT
ip route show default >> $OUT 2>&1

echo -e "\n=== ARP 表 ===" >> $OUT
ip neigh show >> $OUT 2>&1

echo -e "\n=== dmesg 网络相关错误（最近）===" >> $OUT
sudo dmesg --level=err,warn 2>/dev/null | grep -iE '(net|conntrack|nf_|ipt|nft|fw|drop|timeout)' | tail -30 >> $OUT

echo -e "\n=== WiFi 信号状态 ===" >> $OUT
iwconfig wlp7s0 2>/dev/null | grep -E 'ESSID|Signal|Link|Bit' >> $OUT

echo "保存到 $OUT"
wc -l $OUT
