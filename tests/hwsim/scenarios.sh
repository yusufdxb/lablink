# Scenarios for tests/hwsim/run.sh (sourced, not run directly).
#
# raw_*      use plain nmcli profiles to measure the kernel and
#            NetworkManager behaviour LabLink relies on.
# lablink_*  drive the real `lablink hotspot` commands.
#
# Every scenario leaves the hotspot down and the clients disconnected.

all_scenarios() {
    echo raw_control raw_isolated raw_late_changes raw_nm_restart raw_window raw_dns \
        lablink_isolated lablink_monitor lablink_permissions
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
        umask 077; printf 'ctrl_interface=/run/wpa_supplicant\nnetwork={\n ssid=\"LLTEST\"\n psk=\"$PSK\"\n key_mgmt=WPA-PSK\n ieee80211w=1\n scan_freq=2437\n freq_list=2437\n}\n' >/tmp/wpa.conf
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
    in_ ap '
        id fielduser >/dev/null 2>&1 || useradd -m -s /bin/bash fielduser
        id otheruser >/dev/null 2>&1 || useradd -m -s /bin/bash otheruser
        u=$(id -u fielduser)
        install -d -o fielduser -m 700 /run/user/$u
        printf "%s\n" "#!/bin/sh" \
            "exec runuser -u fielduser -- env HOME=/home/fielduser USER=fielduser LOGNAME=fielduser XDG_RUNTIME_DIR=/run/user/$u \"\$@\"" \
            >/usr/local/bin/fu
        chmod 755 /usr/local/bin/fu
        # The one root step: stop the hotspot DNS server forwarding upstream.
        mkdir -p /etc/NetworkManager/dnsmasq-shared.d
        echo no-resolv >/etc/NetworkManager/dnsmasq-shared.d/lablink-no-upstream.conf
        fu lablink feature enable field-network >/dev/null
        echo "lablink $(fu lablink --version 2>&1 | head -1) as $(fu id -un)"'
}
fu_start() { # extra flags
    in_ ap "echo $PSK | fu lablink hotspot start --ssid LLTEST --password-stdin --no-site --yes --json $* >/tmp/start.json; rc=\$?
            echo \"start exit \$rc\"
            jq -e .started /tmp/start.json >/dev/null 2>&1 && jq -c '.started | {isolated, isolation: .isolation.verified, problems: .isolation.problems, dns: .dns_relay.state, checkpoint, ip_forward_before}' /tmp/start.json 2>/dev/null || cat /tmp/start.json"
}
fu_stop() { in_ ap 'fu lablink hotspot stop --json >/dev/null 2>&1; echo "stop exit $?"'; }
fu_status() { in_ ap "fu lablink hotspot status --json | jq -c '.status | {active, out_of_sync, isolation, dns: .dns_relay.state}'"; }
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
    echo "## DNS: the drop-in is in place"
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
