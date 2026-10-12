#!/usr/bin/env bash
# Field Network isolation tests on simulated radios.
#
#   tests/hwsim/run.sh OUT_DIR [SCENARIO...]
#
# Real NetworkManager 1.36, wpa_supplicant and dnsmasq drive Linux
# mac80211_hwsim radios. Each radio lives in its own network-isolated
# container (`--network none`):
#
#   ap   NetworkManager + LabLink. wlan0 (radio), up0 (simulated Ethernet
#        uplink with the default route, managed by NetworkManager), lan0
#        (simulated lab LAN), wg0 (a real WireGuard VPN, added by scenarios)
#   c1   hotspot client (wpa_supplicant + dhclient)
#   c2   second hotspot client
#   wan  the networks behind the host: uplink 192.0.2.1, "internet"
#        198.51.100.1 / 2001:db8:ff::1, lab LAN 10.20.0.1, VPN 100.64.0.1,
#        a DNS server. Its raw-table counters count every probe packet that
#        reaches it, so a one-way leak (no reply) is still seen.
#
# The ap container is set up to forward as permissively as possible:
# net.ipv4.ip_forward=1, net.ipv6.conf.all.forwarding=1, FORWARD policy
# ACCEPT plus an explicit ACCEPT-everything rule at the top of FORWARD,
# and routes back to the hotspot subnet on the far side. Isolation that
# holds here does not depend on the firewall.
#
# Host changes: loads mac80211_hwsim (and wireguard if absent) through a
# privileged helper container, moves only mac80211_hwsim phys (checked by
# sysfs path) into the containers, and unloads the modules at the end. It
# never touches a physical interface. A host snapshot is taken before and
# after and diffed (OUT_DIR/host-*.txt).
set -euo pipefail

OUT=${1:?usage: run.sh OUT_DIR [SCENARIO...]}
shift || true
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
IMG=${LABLINK_HWSIM_IMAGE:-lablink-hwsim:22.04-iso}
LABLINK_BIN=${LABLINK_BIN:-${CARGO_TARGET_DIR:-$ROOT/target}/debug/lablink}
P=llhw
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
LOG="$OUT/run.log"
: >"$LOG"

say() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$LOG" >&2; }
in_() { local c=$1; shift; docker exec -i "$P-$c" bash -c "$*"; }
helper() {
    docker run --rm --privileged --net=host --pid=host \
        -v /lib/modules:/lib/modules:ro "$IMG" bash -c "$*"
}

host_snapshot() {
    local f="$OUT/host-$1.txt"
    {
        echo "## links"; ip -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | sort
        echo "## nm active"; nmcli -t -f NAME,UUID,DEVICE connection show --active | sort
        echo "## routes4"; ip -4 route show table all | grep -v -E '^(local|broadcast) ' | sort
        echo "## routes6"; ip -6 route show table all | grep -v -E '^(local|anycast|multicast) ' | sort
        echo "## rules4"; ip -4 rule
        echo "## rules6"; ip -6 rule
        echo "## ip_forward"; cat /proc/sys/net/ipv4/ip_forward
        echo "## ipv6 forwarding"; cat /proc/sys/net/ipv6/conf/all/forwarding
        echo "## phys"; for p in /sys/class/ieee80211/*; do echo "$(basename "$p") $(readlink -f "$p/device")"; done
        echo "## modules"; lsmod | awk '{print $1}' | grep -E '^(mac80211_hwsim|wireguard)$' || true
    } >"$f" 2>&1
}

setup() {
    say "host snapshot (before)"
    host_snapshot before
    WG_LOADED=$(lsmod | awk '$1=="wireguard"{print 1}')
    echo "${WG_LOADED:-0}" >"$OUT/.wg-preloaded"
    say "starting containers"
    for c in ap c1 c2 wan; do
        docker rm -f "$P-$c" >/dev/null 2>&1 || true
        # Mount the binary only when it exists: docker would create a
        # root-owned directory in its place.
        local mount=() b
        if [ "$c" = ap ]; then
            for b in "$LABLINK_BIN" "$(dirname "$LABLINK_BIN")/lablinkd"; do
                [ -f "$b" ] && mount+=(-v "$b:/usr/local/bin/$(basename "$b"):ro")
            done
            mount+=(-v "$ROOT/packaging/networkmanager/90-lablink-field-filter:/opt/lablink/90-lablink-field-filter:ro")
        fi
        docker run -d --name "$P-$c" --hostname "$c" --network none --privileged \
            "${mount[@]}" "$IMG" sleep infinity >/dev/null
    done
    local pid_ap pid_c1 pid_c2 pid_wan
    pid_ap=$(docker inspect -f '{{.State.Pid}}' $P-ap)
    pid_c1=$(docker inspect -f '{{.State.Pid}}' $P-c1)
    pid_c2=$(docker inspect -f '{{.State.Pid}}' $P-c2)
    pid_wan=$(docker inspect -f '{{.State.Pid}}' $P-wan)
    say "loading mac80211_hwsim (3 radios) and moving them into the containers"
    helper "
        set -e
        lsmod | grep -q '^mac80211_hwsim ' && { echo 'mac80211_hwsim already loaded; refusing'; exit 1; }
        modprobe wireguard
        modprobe mac80211_hwsim radios=3
        phys=()
        for p in /sys/class/ieee80211/*; do
            case \$(readlink -f \$p/device) in
                */mac80211_hwsim/*) phys+=(\$(basename \$p));;
            esac
        done
        [ \${#phys[@]} -eq 3 ] || { echo \"expected 3 hwsim phys, got \${phys[*]}\"; exit 1; }
        iw phy \${phys[0]} set netns $pid_ap
        iw phy \${phys[1]} set netns $pid_c1
        iw phy \${phys[2]} set netns $pid_c2
        # veths are created directly inside the container namespaces.
        ip link add up0 netns $pid_ap type veth peer name dn0 netns $pid_wan
        ip link add lan0 netns $pid_ap type veth peer name lan1 netns $pid_wan
    " 2>&1 | tee -a "$LOG"
    for c in ap c1 c2; do
        in_ $c 'w=$(ls /sys/class/net | grep -E "^wlan" | head -1); [ "$w" = wlan0 ] || ip link set "$w" name wlan0'
    done
    say "configuring wan"
    in_ wan '
        set -e
        sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0
        ip link set lo up; ip link set dn0 up; ip link set lan1 up
        ip addr add 192.0.2.1/24 dev dn0; ip -6 addr add 2001:db8:1::1/64 dev dn0 nodad
        ip addr add 10.20.0.1/24 dev lan1; ip -6 addr add 2001:db8:20::1/64 dev lan1 nodad
        ip link add inet0 type dummy; ip link set inet0 up
        ip addr add 198.51.100.1/24 dev inet0; ip -6 addr add 2001:db8:ff::1/64 dev inet0 nodad
        # Routes back to the hotspot, so forwarded traffic could even get replies.
        ip route add 10.77.0.0/16 via 192.0.2.2
        ip -6 route add 2001:db8:77::/48 via 2001:db8:1::2
        # Count every probe that reaches any of these networks (UDP/TCP
        # 7000-7999, ICMP echo), before anything else can drop it.
        for t in iptables ip6tables; do
            $t -t raw -N PROBE
            $t -t raw -A PREROUTING -j PROBE
            $t -t raw -A PROBE -p udp --dport 7000:7999 -j RETURN
            $t -t raw -A PROBE -p tcp --dport 7000:7999 -j RETURN
        done
        iptables -t raw -A PROBE -p icmp --icmp-type echo-request -j RETURN
        ip6tables -t raw -A PROBE -p ipv6-icmp --icmpv6-type echo-request -j RETURN
        # Listeners that answer, for bidirectional checks.
        for a in 192.0.2.1 198.51.100.1 10.20.0.1; do
            socat -T2 TCP4-LISTEN:7080,bind=$a,fork,reuseaddr SYSTEM:"echo reached-$a" >/dev/null 2>&1 &
        done
        for a in 2001:db8:1::1 2001:db8:ff::1 2001:db8:20::1; do
            socat -T2 TCP6-LISTEN:7080,bind=[$a],fork,reuseaddr SYSTEM:"echo reached-$a" >/dev/null 2>&1 &
        done
        # A DNS server "on the internet" that the host forwards to.
        dnsmasq --no-resolv --no-hosts --listen-address=192.0.2.1 --bind-interfaces \
            --address=/internet.test/198.51.100.1 --pid-file=/run/wan-dns.pid
    ' 2>&1 | tee -a "$LOG"
    say "configuring ap (NetworkManager)"
    in_ ap '
        set -e
        mkdir -p /run/dbus /etc/NetworkManager/conf.d /run/wpa_supplicant
        printf "[main]\nplugins=keyfile\ndns=default\nno-auto-default=*\n" >/etc/NetworkManager/NetworkManager.conf
        : >/etc/NetworkManager/conf.d/10-globally-managed-devices.conf
        echo "nameserver 192.0.2.1" >/etc/resolv.conf.wan
        ip link set lo up
        # There is no udev here. With /sys read-only NetworkManager runs in
        # its container mode and does not wait for udev to initialise links.
        mount -o remount,ro /sys
        # Mirror the workstation: forwarding already on (Docker and others),
        # loose reverse-path filtering. Then make the firewall forward
        # everything, so only LabLink'"'"'s rule can stop it.
        sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 \
            net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.default.rp_filter=2
        iptables -P FORWARD ACCEPT; ip6tables -P FORWARD ACCEPT
        dbus-daemon --system --fork 2>/dev/null
        /usr/libexec/polkitd --no-debug >/tmp/polkitd.log 2>&1 &
        wpa_supplicant -u -s -O /run/wpa_supplicant >/tmp/wpas.log 2>&1 &
        sleep 1
        NetworkManager --debug >/tmp/nm.log 2>&1 &
        for i in $(seq 1 30); do nmcli -t general status >/dev/null 2>&1 && break; sleep 0.5; done
        # veth devices are unmanaged by default; the simulated wired links are not.
        nmcli device set up0 managed yes; nmcli device set lan0 managed yes
        for i in $(seq 1 40); do
            [ "$(nmcli -t -f DEVICE,STATE device | grep -cE "^(up0|lan0):(disconnected|connected)")" = 2 ] && break; sleep 0.25
        done
        nmcli -t -f DEVICE,TYPE,STATE device
        nmcli connection add type ethernet ifname up0 con-name "Wired uplink" \
            ipv4.method manual ipv4.addresses 192.0.2.2/24 ipv4.gateway 192.0.2.1 \
            ipv4.dns 192.0.2.1 ipv6.method manual ipv6.addresses 2001:db8:1::2/64 \
            ipv6.gateway 2001:db8:1::1 >/dev/null
        nmcli connection add type ethernet ifname lan0 con-name "Lab LAN" \
            ipv4.method manual ipv4.addresses 10.20.0.2/24 ipv4.never-default yes \
            ipv6.method manual ipv6.addresses 2001:db8:20::2/64 ipv6.never-default yes >/dev/null
        nmcli --wait 20 connection up "Wired uplink" >/dev/null
        nmcli --wait 20 connection up "Lab LAN" >/dev/null
        # The DNS relay test needs the host resolver to point at "the internet".
        cp /etc/resolv.conf.wan /etc/resolv.conf
        # A host service clients may reach.
        socat -T2 TCP4-LISTEN:2222,fork,reuseaddr SYSTEM:"echo host-service" >/dev/null 2>&1 &
        nmcli -t device
        ip -4 route; ip -6 route | grep -v fe80
    ' 2>&1 | tee -a "$LOG"
    in_ ap 'iptables -I FORWARD 1 -j ACCEPT; ip6tables -I FORWARD 1 -j ACCEPT'
    for c in c1 c2; do
        in_ $c 'ip link set lo up; mkdir -p /run/wpa_supplicant
            sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0 net.ipv6.conf.wlan0.disable_ipv6=0
            sysctl -qw net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0 net.ipv6.conf.wlan0.accept_dad=0'
    done
}

teardown() {
    say "teardown: unloading mac80211_hwsim, removing containers"
    local wg_pre
    wg_pre=$(cat "$OUT/.wg-preloaded" 2>/dev/null || echo 1)
    # Unload first: the radios are destroyed wherever they are, so they
    # never return to the host namespace when the containers go away.
    helper "rmmod mac80211_hwsim 2>/dev/null || true" 2>&1 | tee -a "$LOG" || true
    for c in ap c1 c2 wan; do docker rm -f "$P-$c" >/dev/null 2>&1 || true; done
    if [ "$wg_pre" = 0 ]; then helper "rmmod wireguard 2>/dev/null || true" || true; fi
    rm -f "$OUT/.wg-preloaded"
    say "host snapshot (after)"
    host_snapshot after
    if diff -u "$OUT/host-before.txt" "$OUT/host-after.txt" >"$OUT/host-diff.txt"; then
        say "host state identical before and after"
    else
        say "HOST STATE DIFFERS: see $OUT/host-diff.txt"
    fi
}

# --- helpers used by scenarios -------------------------------------------

AP_MAC() { in_ ap 'cat /sys/class/net/wlan0/address'; }

counters() { # total probe packets that reached wan, v4+v6
    in_ wan 'a=$(iptables -t raw -L PROBE -v -n -x | awk "/RETURN/ {s+=\$1} END {print s+0}");
             b=$(ip6tables -t raw -L PROBE -v -n -x | awk "/RETURN/ {s+=\$1} END {print s+0}");
             echo $((a+b))'
}
counters_detail() {
    in_ wan 'echo "v4:"; iptables -t raw -L PROBE -v -n -x | tail -n +3; echo "v6:"; ip6tables -t raw -L PROBE -v -n -x | tail -n +3'
}
zero_counters() { in_ wan 'iptables -t raw -Z PROBE; ip6tables -t raw -Z PROBE'; }

client_join() { # client ssid psk [static-ip]
    local c=$1 ssid=$2 psk=$3 static=${4:-}
    in_ $c "pkill wpa_supplicant 2>/dev/null; pkill dhclient 2>/dev/null; sleep 0.3
        ip -4 addr flush dev wlan0; ip -6 addr flush dev wlan0 scope global; ip link set wlan0 down; ip link set wlan0 up
        umask 077; printf 'ctrl_interface=/run/wpa_supplicant\nnetwork={\n ssid=\"%s\"\n psk=\"%s\"\n key_mgmt=WPA-PSK SAE\n ieee80211w=1\n}\n' '$ssid' '$psk' >/tmp/wpa.conf
        wpa_supplicant -B -i wlan0 -c /tmp/wpa.conf -f /tmp/wpa.log
        for i in \$(seq 1 60); do wpa_cli -i wlan0 status 2>/dev/null | grep -q wpa_state=COMPLETED && break; sleep 0.5; done
        rm -f /tmp/wpa.conf
        wpa_cli -i wlan0 status | grep -E '^(wpa_state|ssid|key_mgmt)='
        if [ -n '$static' ]; then ip addr add '$static' dev wlan0; else timeout 30 dhclient -1 -v wlan0 2>&1 | grep -E 'DHCPACK|bound' | tail -1; fi
        ip -4 -o addr show dev wlan0 | awk '{print \$4}'"
}

client_leave() { in_ "$1" 'pkill dhclient 2>/dev/null; pkill wpa_supplicant 2>/dev/null; ip -4 addr flush dev wlan0; ip -6 addr flush dev wlan0 scope global; true'; }

# Try every way out from a client: v4 and v6, UDP, TCP and ICMP, to the
# uplink, the internet, the lab LAN and the VPN, with the host as gateway.
probe_out() { # client label
    local c=$1 label=$2 apmac
    apmac=$(AP_MAC)
    zero_counters
    in_ $c "
        ip route replace default via 10.77.0.1 dev wlan0 2>/dev/null || true
        for net in 192.0.2.0/24 198.51.100.0/24 10.20.0.0/24 100.64.0.0/10; do ip route replace \$net via 10.77.0.1 dev wlan0; done
        # IPv6: the host has no IPv6 on the hotspot, so aim straight at its MAC.
        ip -6 addr add 2001:db8:77::50/64 dev wlan0 nodad 2>/dev/null || true
        ip -6 neigh replace fe80::77 lladdr $apmac dev wlan0 nud permanent
        ip -6 route replace default via fe80::77 dev wlan0
        n=0
        for d in 192.0.2.1 198.51.100.1 10.20.0.1 100.64.0.1; do
            for p in 7001 7002 7003; do echo x | socat -u - UDP4-SENDTO:\$d:\$p 2>/dev/null; done
            r=\$(timeout 3 socat -T2 - TCP4:\$d:7080,connect-timeout=2 2>&1 </dev/null | head -1)
            echo \"tcp4 \$d:7080 -> \${r:-no answer}\"
            ping -c 2 -W 1 -q \$d >/dev/null 2>&1 && echo \"icmp4 \$d -> REPLY\" || echo \"icmp4 \$d -> no reply\"
        done
        for d in 2001:db8:1::1 2001:db8:ff::1 2001:db8:20::1; do
            for p in 7011 7012; do echo x | socat -u - UDP6-SENDTO:[\$d]:\$p 2>/dev/null; done
            r=\$(timeout 3 socat -T2 - TCP6:[\$d]:7080,connect-timeout=2 2>&1 </dev/null | head -1)
            echo \"tcp6 \$d:7080 -> \${r:-no answer}\"
            ping -6 -c 2 -W 1 -q \$d >/dev/null 2>&1 && echo \"icmp6 \$d -> REPLY\" || echo \"icmp6 \$d -> no reply\"
        done
    " 2>&1
    local n
    n=$(counters)
    echo "$label: probe packets that reached the networks behind the host: $n"
    [ "$n" = 0 ] || counters_detail
}

probe_host() { # client
    in_ "$1" '
        ping -c 2 -W 1 -q 10.77.0.1 >/dev/null && echo "icmp to host 10.77.0.1 -> REPLY" || echo "icmp to host 10.77.0.1 -> no reply"
        r=$(timeout 3 socat -T2 - TCP4:10.77.0.1:2222,connect-timeout=2 2>&1 </dev/null | head -1); echo "tcp to host 10.77.0.1:2222 -> ${r:-no answer}"
        r=$(timeout 3 socat -T2 - TCP4:192.0.2.2:2222,connect-timeout=2 2>&1 </dev/null | head -1); echo "tcp to host'"'"'s uplink address 192.0.2.2:2222 -> ${r:-no answer}"'
}

probe_c2c() {
    local ip2
    ip2=$(in_ c2 "ip -4 -o addr show dev wlan0 | awk '{print \$4}' | cut -d/ -f1")
    in_ c2 'pkill -x socat 2>/dev/null; sleep 0.2; socat -u UDP4-RECV:7900 OPEN:/tmp/udp.txt,creat,trunc >/dev/null 2>&1 &
            socat -T2 TCP4-LISTEN:7901,reuseaddr,fork SYSTEM:"echo c2-tcp" >/dev/null 2>&1 & sleep 0.3'
    in_ c1 "ping -c 2 -W 1 -q $ip2 >/dev/null && echo 'c1 -> c2 icmp: REPLY' || echo 'c1 -> c2 icmp: no reply'
            echo c2c-udp | socat -u - UDP4-SENDTO:$ip2:7900
            r=\$(timeout 3 socat -T2 - TCP4:$ip2:7901 </dev/null 2>&1 | head -1); echo \"c1 -> c2 tcp: \${r:-no answer}\""
    sleep 0.5
    in_ c2 'echo "c2 received udp: $(cat /tmp/udp.txt 2>/dev/null)"'
    local ll2
    ll2=$(in_ c2 "ip -6 -o addr show dev wlan0 scope link | awk '{print \$4}' | cut -d/ -f1")
    in_ c1 "ping -6 -c 2 -W 1 -q $ll2%wlan0 >/dev/null && echo 'c1 -> c2 icmp6 link-local: REPLY' || echo 'c1 -> c2 icmp6 link-local: no reply'"
}

ap_state() {
    in_ ap 'echo "rules4:"; ip -4 rule; echo "rules6:"; ip -6 rule
            echo "ip_forward=$(cat /proc/sys/net/ipv4/ip_forward) wlan0.forwarding=$(cat /proc/sys/net/ipv4/conf/wlan0/forwarding) wlan0.disable_ipv6=$(cat /proc/sys/net/ipv6/conf/wlan0/disable_ipv6) v6.all.forwarding=$(cat /proc/sys/net/ipv6/conf/all/forwarding)"
            echo "nat:"; iptables -t nat -L POSTROUTING -v -n -x | grep -i masq || true'
}

scenario_file() { echo "$OUT/$1.txt"; }

# Scenarios are defined in scenarios.sh so they can be read on their own.
# shellcheck source=tests/hwsim/scenarios.sh
. "$HERE/scenarios.sh"

trap teardown EXIT
setup
if [ $# -eq 0 ]; then set -- $(all_scenarios); fi
for s in "$@"; do
    say "=== scenario $s"
    (set +e; "scenario_$s") 2>&1 | tee "$(scenario_file "$s")" | tee -a "$LOG" >/dev/null || say "scenario $s exited non-zero"
done
