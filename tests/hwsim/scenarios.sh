# Scenarios for tests/hwsim/run.sh (sourced, not run directly).
#
# raw_*      use plain nmcli profiles to measure the kernel and
#            NetworkManager behaviour LabLink relies on.
# lablink_*  drive the real `lablink hotspot` commands.
#
# Every scenario leaves the hotspot down and the clients disconnected.

all_scenarios() {
    echo raw_control raw_isolated raw_late_changes raw_nm_restart raw_window raw_dns \
        raw_filter_events lablink_isolated lablink_monitor lablink_permissions lablink_leak
}

PSK=fieldtest-passphrase
RULES='ipv4.routing-rules "priority 0 iif wlan0 prohibit" ipv6.routing-rules "priority 0 iif wlan0 prohibit"'

raw_profile() { # name extra-nmcli-settings
    in_ ap "nmcli connection delete '$1' >/dev/null 2>&1
        nmcli connection add type wifi ifname wlan0 con-name '$1' autoconnect no ssid LLTEST \
            802-11-wireless.mode ap 802-11-wireless.band bg 802-11-wireless.channel 6 \
            802-11-wireless.ap-isolation 0 \
            wifi-sec.key-mgmt wpa-psk wifi-sec.proto rsn wifi-sec.pairwise ccmp wifi-sec.group ccmp \
            wifi-sec.pmf 1 wifi-sec.psk $PSK \
            ipv4.method shared ipv4.addresses 10.77.0.1/24 ipv6.method disabled $2 >/dev/null
        nmcli -t -f ipv4.method,ipv4.routing-rules,ipv6.method,ipv6.routing-rules connection show '$1'"
}
raw_up() { in_ ap "nmcli --wait 45 connection up '$1' >/dev/null && echo 'hotspot $1 active'"; }
raw_down() {
    client_leave c1; client_leave c2
    in_ ap "nmcli connection down '$1' >/dev/null 2>&1; nmcli connection delete '$1' >/dev/null 2>&1; true"
}

# --- raw NetworkManager: the mechanism -------------------------------------

scenario_raw_control() {
    echo "# Positive control: shared mode WITHOUT the isolation rule."
    echo "# Expected: probes reach the networks behind the host (proves the harness can see a leak)."
    raw_profile Field ""
    raw_up Field
    ap_state
    client_join c1 LLTEST $PSK
    probe_out c1 "control (no rule)"
    echo "## IPv6 control: re-enable IPv6 on the hotspot interface, still no rule"
    in_ ap 'sysctl -qw net.ipv6.conf.wlan0.disable_ipv6=0; echo "wlan0.disable_ipv6=$(cat /proc/sys/net/ipv6/conf/wlan0/disable_ipv6)"'
    probe_out c1 "control, IPv6 enabled (no rule)"
    raw_down Field
}

scenario_raw_isolated() {
    echo "# Shared mode WITH 'priority 0 iif wlan0 prohibit' (v4 and v6), ipv6.method disabled."
    echo "# Expected: host reachable, client-to-client works, zero probes reach any other network."
    raw_profile Field "$RULES"
    raw_up Field
    ap_state
    client_join c1 LLTEST $PSK
    client_join c2 LLTEST $PSK
    probe_host c1
    probe_c2c
    probe_out c1 "isolated"
    echo "# after deactivation, the rules are gone:"
    in_ ap "nmcli connection down Field >/dev/null; ip -4 rule; ip -6 rule"
    raw_down Field
}

scenario_raw_late_changes() {
    echo "# Isolated hotspot running, then the host's networking changes underneath it."
    raw_profile Field "$RULES"
    raw_up Field
    client_join c1 LLTEST $PSK
    probe_out c1 "baseline"

    echo; echo "## 1. a VPN appears after activation (WireGuard + Tailscale-style policy rule)"
    in_ wan 'wg genkey >/tmp/wan.key; wg pubkey </tmp/wan.key >/tmp/wan.pub'
    in_ ap 'wg genkey >/tmp/ap.key; wg pubkey </tmp/ap.key >/tmp/ap.pub'
    local wanpub appub
    wanpub=$(in_ wan 'cat /tmp/wan.pub'); appub=$(in_ ap 'cat /tmp/ap.pub')
    in_ wan "ip link add wg0 type wireguard; wg set wg0 listen-port 51820 private-key /tmp/wan.key \
             peer $appub allowed-ips 100.64.0.0/10,10.77.0.0/16 endpoint 192.0.2.2:51820
             ip addr add 100.64.0.1/10 dev wg0; ip link set wg0 up
             socat -T2 TCP4-LISTEN:7080,bind=100.64.0.1,fork,reuseaddr SYSTEM:'echo reached-vpn' >/dev/null 2>&1 &"
    in_ ap "ip link add wg0 type wireguard; wg set wg0 listen-port 51820 private-key /tmp/ap.key \
             peer $wanpub allowed-ips 0.0.0.0/0 endpoint 192.0.2.1:51820
             ip addr add 100.64.0.2/32 dev wg0; ip link set wg0 up
             ip route add 100.64.0.0/10 dev wg0 table 52
             ip rule add pref 5270 lookup 52
             ping -c1 -W2 -q 100.64.0.1 >/dev/null && echo 'host reaches VPN peer: yes' || echo 'host reaches VPN peer: NO'"
    probe_out c1 "after VPN"

    echo; echo "## 2. new routes after activation (more specific, other table, new default)"
    in_ ap 'ip route add 198.51.100.0/24 via 10.20.0.1 dev lan0
            ip route add 0.0.0.0/1 via 192.0.2.1; ip route add 128.0.0.0/1 via 192.0.2.1
            ip route add default via 192.0.2.1 table 100; ip rule add pref 100 lookup 100
            ip -6 route add 2001:db8:ff::/64 via 2001:db8:20::1 dev lan0'
    probe_out c1 "after new routes"

    echo; echo "## 3. hostile rules added after activation, at priority 0"
    in_ ap 'ip rule add pref 0 iif wlan0 lookup main; ip rule add pref 0 from 10.77.0.0/24 lookup main
            ip -6 rule add pref 0 iif wlan0 lookup main
            echo "rules4:"; ip -4 rule | head -5; echo "rules6:"; ip -6 rule | head -4'
    probe_out c1 "after hostile pref-0 rules"
    in_ ap 'ip rule del pref 0 iif wlan0 lookup main; ip rule del pref 0 from 10.77.0.0/24 lookup main
            ip -6 rule del pref 0 iif wlan0 lookup main'

    echo; echo "## 4. forwarding sysctls toggled; IPv6 re-enabled on the hotspot interface"
    in_ ap 'sysctl -qw net.ipv4.ip_forward=0; sysctl -qw net.ipv4.ip_forward=1
            sysctl -qw net.ipv4.conf.wlan0.forwarding=1 net.ipv4.conf.all.forwarding=1
            sysctl -qw net.ipv6.conf.all.forwarding=0; sysctl -qw net.ipv6.conf.all.forwarding=1
            sysctl -qw net.ipv6.conf.wlan0.disable_ipv6=0 net.ipv6.conf.wlan0.forwarding=1
            ip -6 addr add 2001:db8:77::1/64 dev wlan0 nodad
            echo "wlan0: disable_ipv6=$(cat /proc/sys/net/ipv6/conf/wlan0/disable_ipv6) v4fwd=$(cat /proc/sys/net/ipv4/conf/wlan0/forwarding)"'
    probe_out c1 "after sysctl toggles + IPv6 on wlan0"

    echo; echo "## 5. firewall: NAT for everything"
    in_ ap 'iptables -t nat -A POSTROUTING -j MASQUERADE; ip6tables -t nat -A POSTROUTING -j MASQUERADE 2>/dev/null || true'
    probe_out c1 "after blanket MASQUERADE"
    probe_host c1

    echo; echo "## 6. negative control: delete the rules by hand (what lablinkd's monitor must catch)"
    in_ ap 'ip rule del pref 0 iif wlan0 prohibit; ip -6 rule del pref 0 iif wlan0 prohibit; ip -4 rule | head -3'
    probe_out c1 "rule removed by root"

    in_ ap 'ip rule del pref 5270 lookup 52; ip rule del pref 100 lookup 100; ip link del wg0
            ip route del 198.51.100.0/24 via 10.20.0.1 dev lan0; ip route del 0.0.0.0/1; ip route del 128.0.0.0/1
            ip -6 route del 2001:db8:ff::/64 via 2001:db8:20::1 dev lan0
            iptables -t nat -D POSTROUTING -j MASQUERADE; ip6tables -t nat -D POSTROUTING -j MASQUERADE 2>/dev/null; true'
    in_ wan 'ip link del wg0; pkill -f "bind=100.64.0.1"; true'
    raw_down Field
}

scenario_raw_nm_restart() {
    echo "# NetworkManager stopped, killed and restarted while the isolated hotspot runs."
    raw_profile Field "$RULES"
    raw_up Field
    client_join c1 LLTEST $PSK
    for sig in TERM KILL; do
        echo; echo "## NetworkManager SIG$sig"
        in_ ap "pkill -$sig -x NetworkManager; sleep 2; pgrep -x NetworkManager || echo 'NetworkManager not running'
                ip -4 rule | head -3; ip -6 rule | head -3
                iw dev wlan0 info | grep -E 'type|ssid' || true
                echo 'wlan0 IPv4:' \$(ip -4 -o addr show dev wlan0 | awk '{print \$4}')
                echo 'ip_forward:' \$(cat /proc/sys/net/ipv4/ip_forward)
                echo 'still running:'; pgrep -a dnsmasq; pgrep -a wpa_supplicant
                timeout 45 tcpdump -lni wlan0 -c 40 'tcp port 7080 or icmp' >/tmp/td-$sig.txt 2>/dev/null &"
        in_ c1 'wpa_cli -i wlan0 status | grep -E "wpa_state|bssid"'
        probe_out c1 "NetworkManager down after SIG$sig"
        in_ ap "sleep 1; pkill tcpdump; echo 'hotspot traffic the host saw while NetworkManager was down:'; head -8 /tmp/td-$sig.txt"
        in_ ap 'NetworkManager --debug >>/tmp/nm.log 2>&1 &
                for i in $(seq 1 40); do nmcli -t general status >/dev/null 2>&1 && break; sleep 0.5; done; sleep 8
                nmcli -t -f NAME,DEVICE,STATE connection show --active
                ip -4 rule | head -3; ip -6 rule | head -3'
        probe_out c1 "after NetworkManager restart (SIG$sig)"
        in_ ap "echo 'dnsmasq after the restart:'; pgrep -a dnsmasq
                nmcli connection show --active | grep -q '^Field ' || nmcli --wait 45 connection up Field >/dev/null || {
                    echo 'reactivation failed; NetworkManager log:'; grep -E 'dnsmasq|shared|reserve' /tmp/nm.log | tail -6; }"
        client_join c1 LLTEST $PSK >/dev/null
    done
    raw_down Field
}

# The rule is part of the connection's layer-3 configuration, so NetworkManager
# installs it in activation stage 3. The radio accepts clients after stage 2.
# A client that already knows the passphrase, has a static address and the
# host's MAC, and sends continuously is the worst case for that window.
scenario_raw_window() {
    local runs=${WINDOW_RUNS:-8} profile=${WINDOW_PROFILE:-isolated}
    echo "# Activation window: $runs activations of the '$profile' profile while a client floods."
    if [ "$profile" = isolated ]; then raw_profile Field "$RULES"; else raw_profile Field ""; fi
    # The AP's MAC while it runs: idle, NetworkManager gives the adapter a
    # random scanning MAC.
    local apmac
    raw_up Field >/dev/null
    apmac=$(AP_MAC)
    in_ ap 'for t in iptables ip6tables; do $t -t raw -N ARRIVE 2>/dev/null; $t -t raw -F ARRIVE
                $t -t raw -D PREROUTING -i wlan0 -j ARRIVE 2>/dev/null; $t -t raw -I PREROUTING -i wlan0 -j ARRIVE; done
            iptables -t raw -A ARRIVE -s 10.77.0.50 -j RETURN; ip6tables -t raw -A ARRIVE -s 2001:db8:77::50 -j RETURN'
    in_ c1 "pkill wpa_supplicant; pkill dhclient; for i in \$(seq 1 30); do pgrep -x wpa_supplicant >/dev/null || break; sleep 0.1; done
        ip -4 addr flush dev wlan0; ip -6 addr flush dev wlan0 scope global; ip link set wlan0 up
        ip addr add 10.77.0.50/24 dev wlan0
        ip neigh replace 10.77.0.1 lladdr $apmac dev wlan0 nud permanent
        for n in 192.0.2.0/24 198.51.100.0/24 10.20.0.0/24; do ip route replace \$n via 10.77.0.1 dev wlan0 onlink; done
        ip -6 addr add 2001:db8:77::50/64 dev wlan0 nodad
        ip -6 neigh replace fe80::77 lladdr $apmac dev wlan0 nud permanent
        ip -6 route replace default via fe80::77 dev wlan0 onlink
        # Scan only the hotspot's channel, and rescan at once whenever idle
        # (a scan request while authenticating would abort the attempt).
        umask 077; printf 'ctrl_interface=/run/wpa_supplicant\nnetwork={\n ssid=\"LLTEST\"\n psk=\"$PSK\"\n key_mgmt=WPA-PSK\n ieee80211w=1\n scan_freq=$freq\n freq_list=$freq\n}\n' >/tmp/wpa.conf
        wpa_supplicant -B -i wlan0 -c /tmp/wpa.conf -f /tmp/wpa.log -t || echo 'wpa_supplicant did not start'
        nohup bash -c 'while :; do case \$(wpa_cli -i wlan0 status | sed -n s/^wpa_state=//p) in DISCONNECTED|INACTIVE) wpa_cli -i wlan0 scan >/dev/null;; esac; sleep 0.05; done' >/dev/null 2>&1 &
        for d in 198.51.100.1 192.0.2.1 10.20.0.1; do nohup ping -q -i 0.005 \$d >/dev/null 2>&1 & done
        nohup ping -6 -q -i 0.005 2001:db8:ff::1 >/dev/null 2>&1 &
        echo 'client c1: static 10.77.0.50, static neighbour for the host, flooding v4+v6 at 200 pkt/s per target'"
    local i total_leak=0 total_arrived=0
    for i in $(seq 1 "$runs"); do
        in_ ap "nmcli connection down Field >/dev/null 2>&1; true"
        sleep 2
        zero_counters
        in_ ap 'iptables -t raw -Z ARRIVE; ip6tables -t raw -Z ARRIVE
            # Trace the activation: rule present?, ip_forward, FORWARD rules, packets arrived from the client.
            ( end=$((SECONDS+40)); while [ $SECONDS -lt $end ]; do
                printf "%s r4=%s r6=%s fwd=%s acc=%s arr4=%s arr6=%s\n" "$(date +%s.%N | cut -c1-14)" \
                  "$(ip -4 rule | grep -c "iif wlan0 prohibit")" "$(ip -6 rule | grep -c "iif wlan0 prohibit")" \
                  "$(cat /proc/sys/net/ipv4/ip_forward)" "$(iptables -S FORWARD | grep -c wlan0)" \
                  "$(iptables -t raw -L ARRIVE -v -n -x | awk "/RETURN/{print \$1}")" \
                  "$(ip6tables -t raw -L ARRIVE -v -n -x | awk "/RETURN/{print \$1}")"
                sleep 0.01; done ) >/tmp/trace.txt 2>&1 &
            echo $! >/tmp/trace.pid
            date +%s.%N | cut -c1-14 >/tmp/t0
            nmcli --wait 45 connection up Field >/dev/null && echo up-ok || echo up-FAILED
            date +%s.%N | cut -c1-14 >/tmp/t1
            # Wait for the client (up to 20 s) so every run is a real attempt.
            for w in $(seq 1 100); do
                [ "$(iptables -t raw -L ARRIVE -v -n -x | awk "/RETURN/{print \$1}")" -gt 0 ] && break; sleep 0.2; done
            sleep 1; kill $(cat /tmp/trace.pid) 2>/dev/null' | tr '\n' ' '
        local leak arrived first_arr first_rule
        leak=$(counters)
        arrived=$(in_ ap 'a=$(iptables -t raw -L ARRIVE -v -n -x | awk "/RETURN/{s+=\$1} END{print s+0}"); b=$(ip6tables -t raw -L ARRIVE -v -n -x | awk "/RETURN/{s+=\$1} END{print s+0}"); echo $((a+b))')
        first_arr=$(in_ ap 'awk "{split(\$6,a,\"=\"); split(\$7,b,\"=\"); if (a[2]+b[2]>0) {print \$1; exit}}" /tmp/trace.txt')
        first_rule=$(in_ ap 'awk "{split(\$2,a,\"=\"); split(\$3,b,\"=\"); if (a[2]>0 && b[2]>0) {print \$1; exit}}" /tmp/trace.txt')
        # When NetworkManager moved the adapter through activation (the radio
        # accepts clients once "config" ends).
        nm_t=$(in_ ap 't0=$(cat /tmp/t0); grep -E "device \(wlan0\): state change: (prepare|config|ip-config|ip-check) ->" /tmp/nm.log |
            sed -E "s/.*\[([0-9]+\.[0-9]+)\].*state change: ([a-z-]+ -> [a-z-]+).*/\1 \2/" | awk -v t0="$t0" "\$1 >= t0" | tr "\n" ";"')
        echo "run $i: client packets that arrived at the host: $arrived; reached other networks: $leak; rule installed at ${first_rule:-never}, first client packet at ${first_arr:-never}; NetworkManager: $nm_t"
        [ "$arrived" -gt 0 ] || {
            in_ c1 'echo "  client: $(wpa_cli -i wlan0 status 2>&1 | grep wpa_state); pings running: $(pgrep -c ping)"; ip -4 addr show dev wlan0 | grep inet | sed "s/^/  /"; ip route | sed "s/^/  /"; ip neigh | sed "s/^/  /"'
            in_ ap 'echo "  host sees on wlan0:"; timeout 2 tcpdump -lnei wlan0 -c 4 2>/dev/null | sed "s/^/  /"; iptables -t raw -S PREROUTING | sed "s/^/  /"'
        }
        in_ ap "cp /tmp/trace.txt /tmp/trace-$i.txt"
        total_leak=$((total_leak + leak)); total_arrived=$((total_arrived + arrived))
    done
    echo "TOTAL over $runs activations: arrived at host $total_arrived, reached other networks $total_leak"
    echo "# trace of run 1 (first 3 lines, lines around the first arrival, last line):"
    in_ ap 'head -3 /tmp/trace-1.txt; awk "{split(\$6,a,\"=\"); if (a[2]>0) {print; n++} if (n>=3) exit}" /tmp/trace-1.txt; tail -1 /tmp/trace-1.txt'
    in_ c1 'pkill ping; pkill -f "wpa_cli -i wlan[0]"; pkill wpa_supplicant; ip -6 route flush dev wlan0; ip route flush dev wlan0; ip neigh flush dev wlan0; ip -4 addr flush dev wlan0; ip -6 addr flush dev wlan0 scope global; true'
    in_ ap 'iptables -t raw -D PREROUTING -i wlan0 -j ARRIVE; ip6tables -t raw -D PREROUTING -i wlan0 -j ARRIVE; true'
    raw_down Field
}

scenario_raw_dns() {
    echo "# DNS: NetworkManager's shared-mode dnsmasq forwards client queries to the host's upstream resolvers."
    raw_profile Field "$RULES"
    raw_up Field
    client_join c1 LLTEST $PSK
    in_ ap 'echo "dnsmasq command line:"; tr "\0" " " </proc/$(pgrep -f "dnsmasq.*wlan0" | head -1)/cmdline; echo'
    echo "## without a drop-in"
    in_ c1 'r=$(dig +time=2 +tries=1 +short @10.77.0.1 internet.test); echo "client asks the host for internet.test -> ${r:-no answer}"'
    echo "## with /etc/NetworkManager/dnsmasq-shared.d/lablink-no-upstream.conf = no-resolv"
    in_ ap 'mkdir -p /etc/NetworkManager/dnsmasq-shared.d; echo no-resolv >/etc/NetworkManager/dnsmasq-shared.d/lablink-no-upstream.conf
            nmcli connection down Field >/dev/null; nmcli --wait 45 connection up Field >/dev/null; echo reactivated'
    client_join c1 LLTEST $PSK >/dev/null
    in_ c1 'r=$(dig +time=2 +tries=1 @10.77.0.1 internet.test | grep -E "status:|^internet.test"); echo "client asks the host for internet.test -> ${r:-no answer}"
            r=$(dig +time=2 +tries=1 +short @10.77.0.1 -x 10.77.0.1); echo "host still answers local names: ${r:-none}"'
    in_ ap 'rm -f /etc/NetworkManager/dnsmasq-shared.d/lablink-no-upstream.conf'
    raw_down Field
}

# --- lablink: the real commands, as an unprivileged user ---------------------

# The narrow grant a site admin installs (polkit 0.105 .pkla). The
# container has no logind, so every subject is "any": ResultAny stands in
# for the desktop's active session, where the first three are already yes.
PKLA=/etc/polkit-1/localauthority/50-local.d/50-lablink-field-network.pkla
NM_ACTIONS="network-control settings.modify.own wifi.share.protected checkpoint-rollback"

polkit_restart() {
    in_ ap 'pkill -x polkitd; for i in $(seq 1 20); do pgrep -x polkitd >/dev/null || break; sleep 0.1; done
            /usr/libexec/polkitd --no-debug >>/tmp/polkitd.log 2>&1 &
            for i in $(seq 1 40); do busctl --system status org.freedesktop.PolicyKit1 >/dev/null 2>&1 && break; sleep 0.25; done'
}
grant() {
    in_ ap "mkdir -p \$(dirname $PKLA); printf '%s\n' \
        '[LabLink Field Network for fielduser]' \
        'Identity=unix-user:fielduser' \
        'Action=$(for a in $NM_ACTIONS; do printf 'org.freedesktop.NetworkManager.%s;' $a; done | sed 's/;$//')' \
        'ResultAny=yes' 'ResultInactive=yes' 'ResultActive=yes' >$PKLA; cat $PKLA"
    polkit_restart
}
revoke() { in_ ap "rm -f $PKLA"; polkit_restart; }
perms() { # user
    in_ ap "runuser -u $1 -- nmcli -t general permissions | grep -E '\.($(echo $NM_ACTIONS | tr ' ' '|'))\:'"
}

# One unprivileged user who runs LabLink, one who does not.
lablink_user() {
    # The one root step: the field filter.
    install_filter
    in_ ap '
        id fielduser >/dev/null 2>&1 || useradd -m -s /bin/bash fielduser
        id otheruser >/dev/null 2>&1 || useradd -m -s /bin/bash otheruser
        u=$(id -u fielduser)
        install -d -o fielduser -m 700 /run/user/$u
        printf "%s\n" "#!/bin/sh" \
            "exec runuser -u fielduser -- env HOME=/home/fielduser USER=fielduser LOGNAME=fielduser XDG_RUNTIME_DIR=/run/user/$u \"\$@\"" \
            >/usr/local/bin/fu
        chmod 755 /usr/local/bin/fu
        fu lablink feature enable field-network >/dev/null
        echo "lablink $(fu lablink --version 2>&1 | head -1) as $(fu id -un)"'
}
fu_start() { # extra flags
    in_ ap "echo $PSK | fu lablink hotspot start --ssid LLTEST --password-stdin --no-site --yes --json $* >/tmp/start.json; rc=\$?
            echo \"start exit \$rc\"
            jq -e .started /tmp/start.json >/dev/null 2>&1 && jq -c '.started | {isolated, isolation: .isolation.verified, filter: .isolation.filter.state, problems: .isolation.problems, checkpoint, ip_forward_before}' /tmp/start.json 2>/dev/null || cat /tmp/start.json"
}
fu_stop() { in_ ap 'fu lablink hotspot stop --json >/dev/null 2>&1; echo "stop exit $?"'; }
fu_status() { in_ ap "fu lablink hotspot status --json | jq -c '.status | {active, out_of_sync, verified: .isolation.verified, filter: .isolation.filter.state, problems: .isolation.problems}'"; }
hotspot_up() { in_ ap "nmcli -t -f NAME connection show --active | grep -qx 'LabLink Field Network'"; }

scenario_lablink_permissions() {
    echo "# What an unprivileged user needs, proven against real NetworkManager and polkit 0.105."
    lablink_user
    echo "## no grant (the container has no session, so the policy's 'any' defaults apply)"
    revoke
    perms fielduser
    in_ ap 'fu lablink hotspot preflight --ssid LLTEST --json >/tmp/pf.json; echo "preflight exit $?"
            jq -r ".preflight.findings[] | select(.level==\"block\") | \"BLOCK \(.code): \(.message)\"" /tmp/pf.json'
    echo "## the narrow grant: four NetworkManager actions, one user"
    grant
    perms fielduser
    in_ ap 'fu lablink hotspot preflight --ssid LLTEST --json >/tmp/pf.json; echo "preflight exit $?"
            jq -r ".preflight.findings[] | \"\(.level) \(.code)\"" /tmp/pf.json | sort | uniq | tr "\n" " "; echo'
    fu_start
    echo "## another user, without the grant, cannot see or stop it"
    perms otheruser
    in_ ap 'runuser -u otheruser -- nmcli -t -f NAME connection show | grep -c "LabLink Field Network" | sed "s/^/profiles otheruser can see: /"
            runuser -u otheruser -- nmcli connection down id "LabLink Field Network" 2>&1 | head -1'
    hotspot_up && echo "hotspot still up after otheruser's attempt" || echo "hotspot DOWN after otheruser's attempt"
    fu_stop
    in_ ap 'fu lablink hotspot forget --yes 2>&1 | tail -1; echo "forget exit ${PIPESTATUS[0]}"
            nmcli -t -f NAME connection show | grep -c "LabLink Field Network" | sed "s/^/LabLink profiles left: /"'
}

scenario_lablink_isolated() {
    echo "# lablink hotspot start (isolated, the default) as fielduser, then everything the raw tests probe."
    lablink_user
    grant
    fu_start
    in_ ap 'nmcli -t -f ipv4.method,ipv4.routing-rules,ipv6.method,ipv6.routing-rules,connection.permissions connection show "LabLink Field Network"'
    ap_state
    client_join c1 LLTEST $PSK
    client_join c2 LLTEST $PSK
    probe_host c1
    probe_c2c
    probe_out c1 "lablink isolated"
    echo "## DNS: refused by the field filter"
    in_ c1 'r=$(dig +time=2 +tries=1 @10.77.0.1 internet.test A 2>&1 | grep -E "status:|^internet.test|failed" | head -1); echo "client asks the host for internet.test -> ${r:-no answer}"'
    echo "## a VPN and new routes appear after the start"
    in_ ap 'ip link add vpn0 type dummy; ip link set vpn0 up; ip addr add 100.64.0.2/10 dev vpn0
            ip route add 198.51.100.0/24 via 10.20.0.1 dev lan0; ip route add default via 192.0.2.1 table 100
            ip rule add pref 100 lookup 100; ip rule add pref 0 iif wlan0 lookup main'
    probe_out c1 "lablink isolated, after late routes and a hostile pref-0 rule"
    fu_status
    in_ ap 'ip rule del pref 0 iif wlan0 lookup main; ip rule del pref 100 lookup 100
            ip route del default via 192.0.2.1 table 100; ip route del 198.51.100.0/24 via 10.20.0.1 dev lan0; ip link del vpn0'
    echo "## internet sharing is a separate, explicit mode (positive control through LabLink)"
    client_leave c1; client_leave c2
    fu_stop
    fu_start --allow-internet-sharing
    in_ ap 'echo "rules4:"; ip -4 rule | head -3'
    client_join c1 LLTEST $PSK
    probe_out c1 "lablink --allow-internet-sharing"
    client_leave c1
    fu_stop
    in_ ap 'echo "after stop:"; ip -4 rule | grep -c prohibit | sed "s/^/prohibit rules left: /"; nmcli -t -f DEVICE,STATE device | grep ^wlan0'
}

scenario_lablink_monitor() {
    echo "# lablinkd's watchdog: isolation is re-checked every 2 s and the hotspot stopped when it fails."
    lablink_user
    grant
    in_ ap 'fu lablinkd --no-mdns --no-netlink --no-startup-discovery --no-color --log info >/tmp/lablinkd.log 2>&1 &
            for i in $(seq 1 40); do grep -q "lablinkd ready" /tmp/lablinkd.log && break; sleep 0.25; done
            grep -c "lablinkd ready" /tmp/lablinkd.log | sed "s/^/lablinkd ready: /"'
    local case
    for case in rule4 rule6 ingress; do
        echo; echo "## case $case"
        fu_start
        in_ ap 'for i in $(seq 1 40); do grep -q "isolation verified" /tmp/lablinkd.log && break; sleep 0.25; done
                grep -c "isolation verified" /tmp/lablinkd.log | sed "s/^/watchdog verified (cumulative): /"'
        client_join c1 LLTEST $PSK
        probe_out c1 "$case: before"
        # Flood outbound for 8 s while the breach happens, then count what got out.
        zero_counters
        in_ c1 'ip route replace 192.0.2.0/24 via 10.77.0.1 dev wlan0
                ( end=$(( $(date +%s) + 8 )); while [ $(date +%s) -lt $end ]; do echo x | socat -u - UDP4-SENDTO:192.0.2.1:7001 2>/dev/null; sleep 0.01; done ) >/dev/null 2>&1 &'
        sleep 1
        local t0
        t0=$(date +%s.%N)
        case $case in
            rule4) in_ ap 'ip rule del pref 0 iif wlan0 prohibit' ;;
            rule6) in_ ap 'ip -6 rule del pref 0 iif wlan0 prohibit' ;;
            ingress) in_ ap 'tc qdisc add dev wlan0 ingress' ;;
        esac
        local i
        for i in $(seq 1 100); do hotspot_up || break; sleep 0.1; done
        if hotspot_up; then echo "$case: hotspot STILL UP 10 s after the breach"; else
            echo "$case: hotspot down $(echo "$(date +%s.%N) - $t0" | bc | cut -c1-4) s after the breach"; fi
        sleep 8
        echo "$case: flood packets that reached the uplink: $(counters)"
        in_ ap 'grep -E "isolation failed" /tmp/lablinkd.log | tail -1 | cut -c1-300'
        fu_status
        client_leave c1
        in_ ap 'tc qdisc del dev wlan0 ingress 2>/dev/null; true'
        fu_stop
    done
    in_ ap 'pkill -x lablinkd; true'
}

# --- the field filter (packaging/networkmanager/90-lablink-field-filter) ----

FILTER=/etc/NetworkManager/dispatcher.d/90-lablink-field-filter
install_filter() {
    in_ ap "install -o root -g root -m 755 /opt/lablink/90-lablink-field-filter $FILTER
        ln -sf ../90-lablink-field-filter /etc/NetworkManager/dispatcher.d/pre-up.d/
        ln -sf ../90-lablink-field-filter /etc/NetworkManager/dispatcher.d/pre-down.d/
        $FILTER load; echo \"filter load exit \$?\""
}
remove_filter() {
    in_ ap "$FILTER unload; rm -f $FILTER /etc/NetworkManager/dispatcher.d/pre-up.d/90-lablink-field-filter /etc/NetworkManager/dispatcher.d/pre-down.d/90-lablink-field-filter"
}
open_set() { in_ ap "nft -j list set inet lablink_field open 2>/dev/null | jq -c '[.nftables[].set? | select(.) | .elem // [] | .[]]' || echo absent"; }

# An ordinary Wi-Fi network for the host to be a client of ("Carebear 1" on
# the workstation): c2 runs it as a WPA2 access point (wpa_supplicant AP
# mode) with a static address; the host joins with a static address too.
uplink_wifi_up() {
    in_ c2 'pkill wpa_supplicant; pkill dhclient; sleep 0.3; ip -4 addr flush dev wlan0; ip link set wlan0 up
        ip addr add 192.168.8.1/24 dev wlan0
        printf "ctrl_interface=/run/wpa_supplicant\nap_scan=2\nnetwork={\n ssid=\"Carebear\"\n mode=2\n frequency=2412\n key_mgmt=WPA-PSK\n proto=RSN\n pairwise=CCMP\n group=CCMP\n psk=\"carebear-pass\"\n}\n" >/tmp/cb.conf
        wpa_supplicant -B -i wlan0 -c /tmp/cb.conf -f /tmp/cb.log; sleep 1; echo "c2 runs Carebear: $(wpa_cli -i wlan0 status | grep -E "^(mode|ssid)=" | tr "\n" " ")"'
    in_ ap 'nmcli connection delete "Carebear 1" >/dev/null 2>&1
        nmcli connection add type wifi ifname wlan0 con-name "Carebear 1" autoconnect no ssid Carebear \
            wifi-sec.key-mgmt wpa-psk wifi-sec.psk carebear-pass ipv4.method manual \
            ipv4.addresses 192.168.8.168/24 ipv4.never-default yes ipv6.method disabled >/dev/null
        nmcli --wait 45 connection up "Carebear 1" >/dev/null && echo "host joined Carebear 1 as a client" || echo "Carebear 1 FAILED"'
}
uplink_wifi_down() {
    in_ ap 'nmcli connection down "Carebear 1" >/dev/null 2>&1; nmcli connection delete "Carebear 1" >/dev/null 2>&1; true'
    in_ c2 'pkill wpa_supplicant; ip -4 addr flush dev wlan0; true'
}

scenario_raw_filter_events() {
    echo "# Field filter state across NetworkManager events (raw nmcli profiles)."
    install_filter
    echo "open set after load, no connection on wlan0: $(open_set)"
    in_ ap 'ls -l /etc/NetworkManager/dispatcher.d/ /etc/NetworkManager/dispatcher.d/pre-up.d/ | grep lablink'
    uplink_wifi_up
    echo "open set with Carebear 1 (ordinary client connection): $(open_set)"
    in_ ap 'ping -c1 -W1 -q 192.168.8.1 >/dev/null && echo "host reaches Carebear AP: yes" || echo "host reaches Carebear AP: NO"'
    raw_profile Field "$RULES"
    # Trace: the open set, the radio mode, NetworkManager's device state.
    in_ ap '( end=$((SECONDS+30)); while [ $SECONDS -lt $end ]; do
            printf "%s open=%s type=%s\n" "$(date +%s.%N | cut -c1-14)" \
              "$(nft list set inet lablink_field open | grep -c "elements = { \"wlan0\" }")" \
              "$(iw dev wlan0 info | awk "/type/{print \$2}")"; sleep 0.01; done ) >/tmp/ftrace.txt 2>&1 & echo $! >/tmp/ftrace.pid'
    raw_up Field
    echo "open set with the isolated hotspot up: $(open_set)"
    in_ ap 'kill $(cat /tmp/ftrace.pid)
        echo "trace samples: $(wc -l </tmp/ftrace.txt)"
        echo "first AP sample:   $(grep -m1 "type=AP" /tmp/ftrace.txt)"
        echo "AP samples while open=1: $(grep -c "open=1 type=AP" /tmp/ftrace.txt)"
        echo "last open=1 sample: $(grep "open=1" /tmp/ftrace.txt | tail -1)"'
    in_ ap 'nmcli connection down Field >/dev/null; echo "open set after the hotspot went down: $(nft list set inet lablink_field open | grep -c wlan0) (0 = armed)"
        ip -br link show wlan0'
    in_ ap 'nmcli --wait 45 connection up "Carebear 1" >/dev/null && echo "Carebear 1 back"'
    echo "open set with Carebear 1 back: $(open_set)"
    echo "## device disconnect: is wlan0 still up, and armed?"
    in_ ap 'nmcli --wait 20 device disconnect wlan0 >/dev/null; ip -br link show wlan0; nmcli -t -f DEVICE,STATE device | grep ^wlan0'
    echo "open set after disconnect: $(open_set)"
    echo "## a shared hotspot WITHOUT the isolation rule (internet sharing) opens the interface"
    raw_profile Share ""
    raw_up Share
    echo "open set with the sharing hotspot: $(open_set)"
    raw_down Share
    echo "open set after it: $(open_set)"
    uplink_wifi_down
    raw_down Field
    remove_filter
    in_ ap 'nft list tables'
}

# --- continuous traffic: leakage measured, not inferred ----------------------
#
# c1 knows the passphrase, has a static address and the host's MAC, and
# sends continuously to every network behind the host (ICMP, UDP, TCP, v4
# and v6) while it re-associates as soon as the hotspot exists. wan sends
# continuously towards c1 through the host. Every phase below runs with
# that traffic and reports, from counters taken before and after it:
#   wan      client packets that reached the networks behind the host
#   inject   wan packets that reached the client
#   docker   client packets that reached a Docker-style container (bridge
#            plus a published-port DNAT rule) on the host
#   arrived  client packets that reached the host's Wi-Fi interface (proof
#            the client was sending through the phase)
# tcpdump on wan and c1 (inbound only) gives an independent per-phase count.

leak_counts() {
    local w i d a
    w=$(counters)
    i=$(in_ c1 'iptables -t raw -L INJECT -v -n -x | awk "/RETURN/{s+=\$1} END{print s+0}"')
    d=$(in_ ap 'ip netns exec dk1 iptables -t raw -L PROBE -v -n -x | awk "/RETURN/{s+=\$1} END{print s+0}"')
    a=$(in_ ap 'a=$(iptables -t raw -L ARRIVE -v -n -x | awk "/RETURN/{s+=\$1} END{print s+0}"); b=$(ip6tables -t raw -L ARRIVE -v -n -x | awk "/RETURN/{s+=\$1} END{print s+0}"); echo $((a+b))')
    echo "$w $i $d $a"
}

leak_phase() { # name dwell-seconds action
    local name=$1 dwell=$2 action=$3 b a t0 t1 up
    echo; echo "## phase $name"
    b=$(leak_counts)
    t0=$(date +%s.%N)
    if [ -n "$action" ]; then eval "$action"; fi
    sleep "$dwell"
    t1=$(date +%s.%N)
    a=$(leak_counts)
    if hotspot_up; then up=up; else up=down; fi
    # shellcheck disable=SC2086
    set -- $b $a
    printf '%s\t%s\t%s\t%.1f\t%d\t%d\t%d\t%d\t%s\n' "$name" "$t0" "$t1" "$(echo "$t1 - $t0" | bc)" \
        $(($5 - $1)) $(($6 - $2)) $(($7 - $3)) $(($8 - $4)) "$up" >>"$OUT/leak-phases.tsv"
    printf 'RESULT %-22s %6.1f s  wan %d  inject %d  docker %d  arrived %d  hotspot %s\n' "$name" \
        "$(echo "$t1 - $t0" | bc)" $(($5 - $1)) $(($6 - $2)) $(($7 - $3)) $(($8 - $4)) "$up"
}

leak_lablinkd() { # how many "ready" lines the log has once this one is up
    in_ ap "fu lablinkd --no-mdns --no-netlink --no-startup-discovery --no-color --log info >>/tmp/lablinkd.log 2>&1 &
            for i in \$(seq 1 40); do [ \$(grep -c 'lablinkd ready' /tmp/lablinkd.log) -ge $1 ] && break; sleep 0.25; done
            echo \"lablinkd running: \$(pgrep -x lablinkd | wc -l)\""
}
leak_wait_client() { # until the client's packets reach the host again (it re-associates after every start)
    in_ ap 'n0=$(iptables -t raw -L ARRIVE -v -n -x | awk "/RETURN/{s+=\$1} END{print s+0}"); t0=$SECONDS
        while [ $((SECONDS - t0)) -lt 40 ]; do
            sleep 0.2; n=$(iptables -t raw -L ARRIVE -v -n -x | awk "/RETURN/{s+=\$1} END{print s+0}")
            [ "$n" -gt $((n0 + 20)) ] && { echo "client sending after $((SECONDS - t0)) s"; exit 0; }
        done; echo "CLIENT NOT SENDING after 40 s"'
}
leak_recover() { # start again if the hotspot is down (after a phase that stopped it)
    hotspot_up && return 0
    in_ ap 'pgrep -x dnsmasq >/dev/null && { echo "orphan dnsmasq: $(pgrep -a dnsmasq | cut -c1-80)"; pkill -x dnsmasq; sleep 1; }; true'
    fu_start
}

exposure_checks() { # c2 joins with DHCP, then probes this machine
    echo "### exposure: what a hotspot client reaches on the host"
    client_join c2 LLTEST $PSK
    in_ c2 'ip neigh show 10.77.0.1 | sed "s/^/c2 neighbour (ARP): /"
        for n in 192.0.2.0/24 172.17.0.0/16; do ip route replace $n via 10.77.0.1 dev wlan0; done
        t() { r=$(timeout 4 socat -T2 - TCP4:$1,connect-timeout=2 2>&1 </dev/null | head -1); echo "tcp $1 -> ${r:-no answer}"; }
        t 10.77.0.1:22; t 10.77.0.1:2222; t 10.77.0.1:8080; t 10.77.0.1:53; t 192.0.2.2:22; t 192.0.2.2:2222; t 172.17.0.2:7080
        r=$(dig +time=2 +tries=1 @10.77.0.1 internet.test A 2>&1 | grep -E "status:|^internet.test|connection refused|timed out|unreachable" | head -1); echo "dns udp 10.77.0.1:53 -> ${r:-no answer}"
        ping -c2 -W1 -q 10.77.0.1 >/dev/null && echo "icmp 10.77.0.1 -> REPLY" || echo "icmp 10.77.0.1 -> no reply"
        ping -c2 -W1 -q 192.0.2.2 >/dev/null && echo "icmp 192.0.2.2 (host uplink address) -> REPLY" || echo "icmp 192.0.2.2 (host uplink address) -> no reply"'
    echo "### positive control from wan: the published port works from the uplink"
    in_ wan 'r=$(timeout 4 socat -T2 - TCP4:192.0.2.2:8080,connect-timeout=2 2>&1 </dev/null | head -1); echo "wan tcp 192.0.2.2:8080 -> ${r:-no answer}"
             r=$(timeout 4 socat -T2 - TCP4:192.0.2.2:2222,connect-timeout=2 2>&1 </dev/null | head -1); echo "wan tcp 192.0.2.2:2222 -> ${r:-no answer}"'
    echo "### multicast and DDS-style traffic (mDNS 5353, SPDP 239.255.0.1:7400, unicast 7410)"
    local ip2
    ip2=$(in_ c2 "ip -4 -o addr show dev wlan0 | awk '{print \$4}' | cut -d/ -f1")
    in_ ap 'rm -f /tmp/mc-*.txt
        socat -u UDP4-RECV:5353,ip-add-membership=224.0.0.251:wlan0,reuseaddr OPEN:/tmp/mc-mdns.txt,creat,append >/dev/null 2>&1 &
        socat -u UDP4-RECV:7400,ip-add-membership=239.255.0.1:wlan0,reuseaddr OPEN:/tmp/mc-spdp.txt,creat,append >/dev/null 2>&1 &
        socat -u UDP4-RECV:7410,reuseaddr OPEN:/tmp/mc-uni.txt,creat,append >/dev/null 2>&1 &'
    in_ c1 'rm -f /tmp/mc-*.txt
        socat -u UDP4-RECV:5353,ip-add-membership=224.0.0.251:wlan0,reuseaddr OPEN:/tmp/mc-mdns.txt,creat,append >/dev/null 2>&1 &
        socat -u UDP4-RECV:7400,ip-add-membership=239.255.0.1:wlan0,reuseaddr OPEN:/tmp/mc-spdp.txt,creat,append >/dev/null 2>&1 &'
    in_ c2 'rm -f /tmp/mc-*.txt; socat -u UDP4-RECV:7411,reuseaddr OPEN:/tmp/mc-uni.txt,creat,append >/dev/null 2>&1 &'
    sleep 1
    in_ c2 "for i in 1 2 3; do
        echo mdns-from-c2 | socat -u - UDP4-DATAGRAM:224.0.0.251:5353,ip-multicast-if=$ip2,ip-multicast-ttl=255
        echo spdp-from-c2 | socat -u - UDP4-DATAGRAM:239.255.0.1:7400,ip-multicast-if=$ip2
        echo dds-unicast-from-c2 | socat -u - UDP4-SENDTO:10.77.0.1:7410; sleep 0.2; done"
    in_ ap "echo dds-unicast-from-host | socat -u - UDP4-SENDTO:$ip2:7411"
    sleep 1
    in_ ap 'echo "host received: mdns=$(grep -c mdns-from-c2 /tmp/mc-mdns.txt 2>/dev/null) spdp=$(grep -c spdp-from-c2 /tmp/mc-spdp.txt 2>/dev/null) unicast=$(grep -c dds-unicast /tmp/mc-uni.txt 2>/dev/null) (of 3 each)"
            pkill -x socat; socat -T2 TCP4-LISTEN:2222,fork,reuseaddr SYSTEM:"echo host-service" >/dev/null 2>&1 &
            socat -T2 TCP4-LISTEN:22,fork,reuseaddr SYSTEM:"echo host-ssh" >/dev/null 2>&1 &
            ip netns exec dk1 socat -T2 TCP4-LISTEN:7080,fork,reuseaddr SYSTEM:"echo container" >/dev/null 2>&1 &'
    in_ c1 'echo "c1 received: mdns=$(grep -c mdns-from-c2 /tmp/mc-mdns.txt 2>/dev/null) spdp=$(grep -c spdp-from-c2 /tmp/mc-spdp.txt 2>/dev/null) (of 3 each)"; pkill -x socat; true'
    in_ c2 'echo "c2 received from the host: $(grep -c dds-unicast-from-host /tmp/mc-uni.txt 2>/dev/null) (of 1)"; pkill -x socat; true'
    probe_c2c
    in_ ap 'echo "filter counters:"; nft list table inet lablink_field | grep -E "counter packets [1-9]" | sed "s/^\s*/  /"'
    client_leave c2
}

scenario_lablink_leak() {
    echo "# Continuous traffic through every phase of the hotspot's life; leakage counted per phase."
    : >"$OUT/leak-phases.tsv"
    in_ ap ': >/tmp/lablinkd.log'
    lablink_user
    grant
    echo "## host services: SSH-like listener on 22 (allowed), another on 2222 (not allowed)"
    in_ ap 'pkill -x socat; socat -T2 TCP4-LISTEN:2222,fork,reuseaddr SYSTEM:"echo host-service" >/dev/null 2>&1 &
            socat -T2 TCP4-LISTEN:22,fork,reuseaddr SYSTEM:"echo host-ssh" >/dev/null 2>&1 &'
    echo "## a Docker-style network: bridge 172.17.0.1/16, a container 172.17.0.2, published port 8080 (DNAT)"
    in_ ap 'ip link add br-dk type bridge; ip addr add 172.17.0.1/16 dev br-dk; ip link set br-dk up
        ip netns add dk1; ip link add vdk0 type veth peer name vdk1 netns dk1; ip link set vdk0 master br-dk up
        ip -n dk1 link set lo up; ip -n dk1 addr add 172.17.0.2/16 dev vdk1; ip -n dk1 link set vdk1 up
        ip -n dk1 route add default via 172.17.0.1
        ip netns exec dk1 iptables -t raw -N PROBE; ip netns exec dk1 iptables -t raw -A PREROUTING -j PROBE
        ip netns exec dk1 iptables -t raw -A PROBE ! -s 192.0.2.0/24 -p icmp --icmp-type echo-request -j RETURN
        ip netns exec dk1 iptables -t raw -A PROBE ! -s 192.0.2.0/24 -p tcp --dport 7080 -j RETURN
        ip netns exec dk1 socat -T2 TCP4-LISTEN:7080,fork,reuseaddr SYSTEM:"echo container" >/dev/null 2>&1 &
        iptables -t nat -A PREROUTING -m addrtype --dst-type LOCAL -p tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:7080
        iptables -t nat -A OUTPUT -m addrtype --dst-type LOCAL -p tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:7080
        r=$(timeout 3 socat -T2 - TCP4:172.17.0.2:7080 </dev/null 2>&1 | head -1); echo "host reaches the container: ${r:-no}"'
    echo "## an existing policy-routing configuration, present throughout: a full-tunnel VPN as wg-quick sets it up"
    echo "## (main for anything more specific than a default, then table 200 with a default via the uplink)"
    in_ ap 'ip route add default via 192.0.2.1 dev up0 table 200
            ip rule add pref 49 lookup main suppress_prefixlength 0; ip rule add pref 50 not fwmark 0xca6c lookup 200; ip -4 rule'
    echo "## first start (to learn the access point's MAC), then stop"
    fu_start
    local apmac freq
    apmac=$(AP_MAC)
    freq=$(in_ ap "iw dev wlan0 info | sed -nE 's/.*channel [0-9]+ \(([0-9]+) MHz.*/\1/p'")
    echo "AP MAC $apmac, $freq MHz"
    fu_stop
    leak_lablinkd 1
    echo "## counters on the host's Wi-Fi interface, the client and wan; packet captures"
    in_ ap 'for t in iptables ip6tables; do $t -t raw -N ARRIVE 2>/dev/null; $t -t raw -F ARRIVE
                $t -t raw -D PREROUTING -i wlan0 -j ARRIVE 2>/dev/null; $t -t raw -I PREROUTING -i wlan0 -j ARRIVE; done
            iptables -t raw -A ARRIVE -s 10.77.0.50 -j RETURN; ip6tables -t raw -A ARRIVE -s 2001:db8:77::50 -j RETURN'
    # wan's own packets towards the client come back to it while the hotspot
    # is down (the host routes 10.77.0.0/24 by its default route then): not
    # client traffic, so not counted.
    in_ wan 'iptables -t raw -I PROBE 1 -d 10.77.0.0/16 -j ACCEPT; rm -f /tmp/leak-*.pcap
        for i in dn0 lan1; do nohup tcpdump -U -Q in -ni $i -w /tmp/leak-$i.pcap "not dst net 10.77.0.0/16 and ((udp and dst portrange 7000-7999) or (tcp and dst portrange 7000-7999) or icmp[icmptype]==icmp-echo or (icmp6 and ip6[40]==128))" >/dev/null 2>&1 & done'
    in_ c1 "rm -f /tmp/leak-*.pcap
        pkill wpa_supplicant; pkill dhclient; for i in \$(seq 1 30); do pgrep -x wpa_supplicant >/dev/null || break; sleep 0.1; done
        ip -4 addr flush dev wlan0; ip -6 addr flush dev wlan0 scope global; ip link set wlan0 up
        ip addr add 10.77.0.50/24 dev wlan0
        ip neigh replace 10.77.0.1 lladdr $apmac dev wlan0 nud permanent
        for n in 192.0.2.0/24 198.51.100.0/24 10.20.0.0/24 100.64.0.0/10 172.17.0.0/16 203.0.113.0/24; do ip route replace \$n via 10.77.0.1 dev wlan0 onlink; done
        ip -6 addr add 2001:db8:77::50/64 dev wlan0 nodad
        ip -6 neigh replace fe80::77 lladdr $apmac dev wlan0 nud permanent
        ip -6 route replace default via fe80::77 dev wlan0 onlink
        iptables -t raw -N INJECT 2>/dev/null; iptables -t raw -F INJECT
        iptables -t raw -D PREROUTING -i wlan0 -j INJECT 2>/dev/null; iptables -t raw -I PREROUTING -i wlan0 -j INJECT
        for n in 192.0.2.0/24 198.51.100.0/24 10.20.0.0/24; do iptables -t raw -A INJECT -s \$n -j RETURN; done
        nohup tcpdump -U -Q in -ni wlan0 -w /tmp/leak-c1.pcap 'src net 192.0.2.0/24 or src net 198.51.100.0/24 or src net 10.20.0.0/24' >/dev/null 2>&1 &
        umask 077; printf 'ctrl_interface=/run/wpa_supplicant\nnetwork={\n ssid=\"LLTEST\"\n psk=\"$PSK\"\n key_mgmt=WPA-PSK\n ieee80211w=1\n scan_freq=$freq\n freq_list=$freq\n}\n' >/tmp/wpa.conf
        wpa_supplicant -B -i wlan0 -c /tmp/wpa.conf -f /tmp/wpa.log -t || echo 'wpa_supplicant did not start'
        nohup bash -c 'while :; do case \$(wpa_cli -i wlan0 status | sed -n s/^wpa_state=//p) in DISCONNECTED|INACTIVE) wpa_cli -i wlan0 scan >/dev/null;; esac; sleep 0.05; done' >/dev/null 2>&1 &
        for d in 198.51.100.1 192.0.2.1 10.20.0.1 100.64.0.1 172.17.0.2 203.0.113.9; do nohup ping -q -i 0.01 \$d >/dev/null 2>&1 & done
        nohup ping -6 -q -i 0.01 2001:db8:ff::1 >/dev/null 2>&1 &
        nohup bash -c 'while :; do for t in 192.0.2.1/7001 198.51.100.1/7002 10.20.0.1/7003; do echo x >/dev/udp/\${t%/*}/\${t#*/}; done 2>/dev/null; sleep 0.01; done' >/dev/null 2>&1 &
        nohup bash -c 'while :; do timeout 0.3 bash -c \"exec 3<>/dev/tcp/192.0.2.1/7080\" 2>/dev/null; timeout 0.3 bash -c \"exec 3<>/dev/tcp/10.77.0.1/8080\" 2>/dev/null; sleep 0.05; done' >/dev/null 2>&1 &
        echo 'c1 floods: 6 v4 + 1 v6 ping targets at 100/s each, UDP to 3 networks, TCP connects to wan and to the published Docker port'"
    in_ wan 'nohup ping -q -i 0.01 10.77.0.50 >/dev/null 2>&1 &
        nohup bash -c "while :; do echo y >/dev/udp/10.77.0.50/7500; sleep 0.01; done" >/dev/null 2>&1 &
        echo "wan floods towards the client: ping 100/s + UDP 7500"'

    leak_phase armed-idle 6 ""
    leak_phase activation 4 "fu_start"
    leak_phase operation 4 ""
    leak_phase operation-exposure 1 "exposure_checks"
    leak_phase operation-steady 20 ""
    leak_phase rejoin 0 "leak_wait_client"
    leak_phase restart 4 "in_ ap 'fu lablink hotspot restart --json >/dev/null 2>&1; echo \"restart exit \$?\"'"
    leak_phase rejoin 0 "leak_wait_client"
    leak_phase rules-deleted 8 "in_ ap 'ip rule del pref 0 iif wlan0 prohibit; ip -6 rule del pref 0 iif wlan0 prohibit; echo rules deleted'"
    in_ ap 'grep "isolation failed" /tmp/lablinkd.log | tail -1 | cut -c1-240'
    leak_phase recovery-1 4 "leak_recover"
    leak_phase rejoin 0 "leak_wait_client"
    leak_phase filter-unloaded 8 "in_ ap '$FILTER unload; echo filter unloaded'"
    in_ ap 'grep "isolation failed" /tmp/lablinkd.log | tail -1 | cut -c1-240'
    leak_phase recovery-2 4 "in_ ap '$FILTER load; echo filter reloaded'; leak_recover"
    leak_phase rejoin 0 "leak_wait_client"
    leak_phase no-pref-rule+new-if 10 "in_ ap 'ip link add new0 type dummy; sysctl -qw net.ipv6.conf.new0.disable_ipv6=1; ip link set new0 up; ip addr add 203.0.113.1/24 dev new0
            ip route add default via 192.0.2.1 dev up0 table 51820; ip rule add not fwmark 0xca6d lookup 51820; ip rule add lookup main suppress_prefixlength 0
            echo \"rules after wg-quick-style rules without a priority:\"; ip -4 rule | head -5; echo \"new0 tx before: \$(cat /sys/class/net/new0/statistics/tx_packets)\"'"
    in_ ap 'echo "new0 tx after: $(cat /sys/class/net/new0/statistics/tx_packets)"; ip rule del not fwmark 0xca6d lookup 51820; ip rule del lookup main suppress_prefixlength 0; ip route flush table 51820; ip link del new0'
    fu_status
    leak_phase if-state-change 10 "in_ ap 'nmcli device disconnect lan0 >/dev/null; ip link set up0 down; sleep 2; ip link set up0 up; nmcli --wait 20 connection up \"Lab LAN\" >/dev/null; nmcli --wait 20 connection up \"Wired uplink\" >/dev/null; nmcli -t -f DEVICE,STATE device'"
    fu_status
    leak_phase rejoin 0 "leak_wait_client"
    leak_phase lablinkd-killed 8 "in_ ap 'pkill -KILL -x lablinkd; echo lablinkd killed'"
    leak_phase user-procs-killed 6 "in_ ap 'pkill -KILL -u fielduser; echo all fielduser processes killed (no logind here: the nearest stand-in for a logout)'"
    leak_lablinkd 2
    leak_phase rejoin 0 "leak_wait_client"
    leak_phase nm-sigterm 10 "in_ ap 'pkill -TERM -x NetworkManager; sleep 1; pgrep -x NetworkManager || echo NetworkManager stopped; iw dev wlan0 info | grep type'"
    leak_phase nm-restart-1 12 "in_ ap 'NetworkManager --debug >>/tmp/nm.log 2>&1 & for i in \$(seq 1 40); do nmcli -t general status >/dev/null 2>&1 && break; sleep 0.5; done; echo NetworkManager back'"
    in_ ap 'nmcli -t -f NAME,DEVICE,STATE connection show --active; iw dev wlan0 info | grep type'
    leak_phase recovery-3 4 "leak_recover"
    leak_phase rejoin 0 "leak_wait_client"
    leak_phase nm-sigkill 10 "in_ ap 'pkill -KILL -x NetworkManager; sleep 1; pgrep -x NetworkManager || echo NetworkManager killed; iw dev wlan0 info | grep type; pgrep -a dnsmasq | cut -c1-60'"
    leak_phase nm-restart-2 12 "in_ ap 'NetworkManager --debug >>/tmp/nm.log 2>&1 & for i in \$(seq 1 40); do nmcli -t general status >/dev/null 2>&1 && break; sleep 0.5; done; echo NetworkManager back'"
    in_ ap 'nmcli -t -f NAME,DEVICE,STATE connection show --active; iw dev wlan0 info | grep type'
    leak_phase recovery-4 4 "leak_recover"
    leak_phase stop-during-start 10 "fu_stop; in_ ap 'echo $PSK | fu lablink hotspot start --ssid LLTEST --password-stdin --no-site --yes --json >/tmp/start2.json 2>&1 & t0=\$(date +%s.%N); sleep 1.5; t1=\$(date +%s.%N); fu lablink hotspot stop --json >/tmp/stop2.json 2>&1; echo \"stop exit \$? (sent at +\$(echo \$t1 - \$t0 | bc | cut -c1-4) s, done at +\$(echo \$(date +%s.%N) - \$t0 | bc | cut -c1-4) s): \$(jq -c . /tmp/stop2.json | cut -c1-300)\"; wait; echo \"start finished at +\$(echo \$(date +%s.%N) - \$t0 | bc | cut -c1-4) s: \$(jq -c \"{started: (.started != null), error}\" /tmp/start2.json 2>/dev/null || head -c 300 /tmp/start2.json)\"; nmcli -t -f NAME,STATE connection show --active | grep -i lablink || echo \"no LabLink connection active\"'"
    in_ ap 'nmcli connection down id "LabLink Field Network" >/dev/null 2>&1; true'
    leak_phase recovery-5 4 "leak_recover"
    leak_phase rejoin 0 "leak_wait_client"
    leak_phase NEGATIVE-CONTROL 8 "in_ ap 'ip rule del pref 0 iif wlan0 prohibit; ip -6 rule del pref 0 iif wlan0 prohibit; $FILTER unload; echo rules deleted AND filter unloaded'"
    in_ ap 'grep "isolation failed" /tmp/lablinkd.log | tail -1 | cut -c1-240'
    leak_phase recovery-6 4 "in_ ap '$FILTER load'; leak_recover"
    leak_phase rejoin 0 "leak_wait_client"
    leak_phase shutdown 6 "fu_stop"
    leak_phase armed-idle-after 6 ""

    echo; echo "## stop traffic and captures"
    in_ c1 'pkill -x ping; pkill -f "dev/[u]dp"; pkill -f "dev/[t]cp"; pkill -f "wpa_cli -i wlan[0]"; pkill wpa_supplicant; pkill -x tcpdump; true'
    in_ wan 'pkill -x ping; pkill -f "dev/[u]dp"; pkill -x tcpdump; iptables -t raw -D PROBE -d 10.77.0.0/16 -j ACCEPT; true'
    sleep 1
    docker cp "$P-wan:/tmp/leak-dn0.pcap" "$OUT/" 2>/dev/null; docker cp "$P-wan:/tmp/leak-lan1.pcap" "$OUT/" 2>/dev/null
    docker cp "$P-c1:/tmp/leak-c1.pcap" "$OUT/" 2>/dev/null
    echo "## per-phase packets in the captures (wan dn0 + lan1 inbound; c1 inbound from wan)"
    local f
    for f in dn0 lan1 c1; do
        docker run --rm -v "$OUT:/o:ro" "$IMG" tcpdump -tt -nr "/o/leak-$f.pcap" 2>/dev/null | awk '{print $1}' >"$OUT/leak-$f.times" || true
    done
    while IFS=$'\t' read -r name t0 t1 dur _ _ _ _ _; do
        n_dn0=$(awk -v a="$t0" -v b="$t1" '$1>=a && $1<b' "$OUT/leak-dn0.times" | wc -l)
        n_lan1=$(awk -v a="$t0" -v b="$t1" '$1>=a && $1<b' "$OUT/leak-lan1.times" | wc -l)
        n_c1=$(awk -v a="$t0" -v b="$t1" '$1>=a && $1<b' "$OUT/leak-c1.times" | wc -l)
        printf 'PCAP %-22s %6s s  dn0 %d  lan1 %d  c1 %d\n' "$name" "$dur" "$n_dn0" "$n_lan1" "$n_c1"
    done <"$OUT/leak-phases.tsv"
    echo "## totals"
    awk -F'\t' '{d+=$4; w+=$5; i+=$6; k+=$7; a+=$8} END {printf "phases %d, %.1f s, wan %d, inject %d, docker %d, arrived %d\n", NR, d, w, i, k, a}' "$OUT/leak-phases.tsv"
    echo "pcap packets: dn0 $(wc -l <"$OUT/leak-dn0.times"), lan1 $(wc -l <"$OUT/leak-lan1.times"), c1 $(wc -l <"$OUT/leak-c1.times")"
    in_ ap 'cp /tmp/lablinkd.log /tmp/leak-lablinkd.log; grep -cE "isolation (verified|failed)" /tmp/lablinkd.log | sed "s/^/watchdog log lines: /"'
    docker cp "$P-ap:/tmp/lablinkd.log" "$OUT/leak-lablinkd.log" 2>/dev/null
    in_ ap 'pkill -x lablinkd; iptables -t nat -F PREROUTING; iptables -t nat -F OUTPUT; ip netns del dk1; ip link del br-dk; ip rule del pref 50 not fwmark 0xca6c lookup 200; ip rule del pref 49 lookup main suppress_prefixlength 0; ip route flush table 200
            for t in iptables ip6tables; do $t -t raw -D PREROUTING -i wlan0 -j ARRIVE; done; true'
    in_ c1 'iptables -t raw -D PREROUTING -i wlan0 -j INJECT; ip -6 route flush dev wlan0; ip route flush dev wlan0; ip neigh flush dev wlan0; ip -4 addr flush dev wlan0; ip -6 addr flush dev wlan0 scope global; true'
}
