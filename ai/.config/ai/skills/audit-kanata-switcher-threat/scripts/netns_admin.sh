#!/usr/bin/env bash
# Root-only helper for the privileged network audit.
#
# The audit runs the target in a dedicated network namespace connected by a
# veth pair to a second "capture" namespace. There is deliberately no NAT and
# no route to the real network: every packet the target emits stays on the
# veth, where tcpdump records it and the sinkhole answers it. This makes the
# network look real enough for a payload to attempt egress while keeping the
# host isolated.
#
# This script is invoked through sudo by run_dynamic_network_audit.sh and
# run_gnome_extension_audit.sh. It must run as root.
#
# Subcommands:
#   setup <daemon-ns> <capture-ns> <daemon-if> <capture-if>
#         <daemon-ip4/cidr> <capture-ip4/cidr> <daemon-ip6/cidr> <capture-ip6/cidr> <out>
#   teardown <daemon-ns> <capture-ns>
#   run-as <ns> <uid> <gid> -- <command...>
#   capture-start <capture-ns> <iface> <pcap> <log>
#   capture-stop <pidfile>
#   sinkhole-start <capture-ns> <uid> <gid> <script> <pidfile> <log> -- <args...>
#   system-monitor-start <log> <pidfile>
#   stop-pid <pidfile>

set -euo pipefail

usage() {
    sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# Help must work without root: only the mutating subcommands need privileges.
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
    usage
    exit 0
fi

if [[ ${EUID} -ne 0 ]]; then
    echo "error: netns_admin.sh must run as root" >&2
    exit 2
fi

# Namespace names become `/etc/netns/<name>` paths under root. Reject anything
# that is not a plain identifier so a mistyped or hostile argument can never
# make teardown's `rm -rf` escape the netns directory.
valid_ns_name() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]]
}

ns_exists() {
    ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$1"
}

link_exists() {
    ip link show "$1" >/dev/null 2>&1
}

teardown() {
    local dns="${1:-}" cns="${2:-}" ns
    [[ -n "$dns" && -n "$cns" ]] || return 0
    if ! valid_ns_name "$dns" || ! valid_ns_name "$cns"; then
        echo "error: refusing to tear down invalid namespace name(s): '$dns' '$cns'" >&2
        return 2
    fi
    for ns in "$dns" "$cns"; do
        if ns_exists "$ns"; then
            ip netns pids "$ns" 2>/dev/null | xargs -r kill -TERM 2>/dev/null || true
        fi
    done
    sleep 0.2
    for ns in "$dns" "$cns"; do
        if ns_exists "$ns"; then
            ip netns pids "$ns" 2>/dev/null | xargs -r kill -KILL 2>/dev/null || true
            ip netns del "$ns" 2>/dev/null || true
        fi
    done
    # `ip netns exec` bind-mounts /etc/netns/<name>/resolv.conf over
    # /etc/resolv.conf. Remove our per-namespace copies on teardown.
    rm -rf -- "/etc/netns/${dns:?}" "/etc/netns/${cns:?}"
}

setup() {
    if [[ $# -ne 9 ]]; then
        echo "error: setup expects 9 arguments" >&2
        exit 2
    fi
    local dns="$1" cns="$2" dif="$3" cif="$4"
    local dip="$5" cip="$6" dip6="$7" cip6="$8" out="$9"
    local gw4="${cip%%/*}"
    local gw6="${cip6%%/*}"

    if ! valid_ns_name "$dns" || ! valid_ns_name "$cns"; then
        echo "error: invalid namespace name(s): '$dns' '$cns'" >&2
        exit 2
    fi
    if [[ ! "$dif" =~ ^[A-Za-z0-9_.-]{1,15}$ || ! "$cif" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; then
        echo "error: invalid interface name(s): '$dif' '$cif'" >&2
        exit 2
    fi

    mkdir -p "$out/net"
    teardown "$dns" "$cns"
    if link_exists "$dif"; then ip link del "$dif" 2>/dev/null || true; fi
    if link_exists "$cif"; then ip link del "$cif" 2>/dev/null || true; fi

    ip netns add "$dns"
    ip netns add "$cns"
    ip link add "$dif" type veth peer name "$cif"
    ip link set "$dif" netns "$dns"
    ip link set "$cif" netns "$cns"

    # Keep the kernel from generating IPv6 link-local/router-solicitation noise.
    # Any IPv6 packet in the capture is then attributable to the target.
    ip netns exec "$dns" sysctl -qw "net.ipv6.conf.${dif}.addr_gen_mode=1" 2>/dev/null || true
    ip netns exec "$cns" sysctl -qw "net.ipv6.conf.${cif}.addr_gen_mode=1" 2>/dev/null || true

    ip -n "$dns" link set lo up
    ip -n "$cns" link set lo up
    ip -n "$dns" link set "$dif" up
    ip -n "$cns" link set "$cif" up

    ip -n "$dns" addr add "$dip" dev "$dif"
    ip -n "$cns" addr add "$cip" dev "$cif"
    ip -n "$dns" -6 addr add "$dip6" dev "$dif" nodad
    ip -n "$cns" -6 addr add "$cip6" dev "$cif" nodad

    ip -n "$dns" route add default via "$gw4" dev "$dif"
    ip -n "$dns" -6 route add default via "$gw6" dev "$dif"

    # `ip netns exec` bind-mounts /etc/netns/<name>/resolv.conf over the host
    # resolver configuration. Point both namespaces at the sinkhole so DNS
    # queries are answered and logged instead of failing against a host stub
    # (127.0.0.53) that is unreachable inside the namespace.
    mkdir -p "/etc/netns/$dns" "/etc/netns/$cns"
    printf 'nameserver %s\nnameserver %s\noptions timeout:1 attempts:1\n' \
        "$gw4" "$gw6" > "/etc/netns/$dns/resolv.conf"
    printf 'nameserver %s\nnameserver %s\noptions timeout:1 attempts:1\n' \
        "$gw4" "$gw6" > "/etc/netns/$cns/resolv.conf"

    # No forwarding in either namespace. The capture namespace has no default
    # route, so a packet that leaves the daemon namespace can only reach the
    # capture namespace or be dropped.
    ip netns exec "$dns" sysctl -qw net.ipv4.ip_forward=0
    ip netns exec "$cns" sysctl -qw net.ipv4.ip_forward=0
    ip netns exec "$dns" sysctl -qw net.ipv6.conf.all.forwarding=0
    ip netns exec "$cns" sysctl -qw net.ipv6.conf.all.forwarding=0
    ip netns exec "$dns" sysctl -qw "net.ipv6.conf.${dif}.autoconf=0" 2>/dev/null || true
    ip netns exec "$dns" sysctl -qw "net.ipv6.conf.${dif}.accept_ra=0" 2>/dev/null || true
    ip netns exec "$dns" sysctl -qw "net.ipv6.conf.${dif}.router_solicitations=0" 2>/dev/null || true
    ip netns exec "$dns" sysctl -qw "net.ipv6.conf.${dif}.dad_transmits=0" 2>/dev/null || true
    ip netns exec "$cns" sysctl -qw "net.ipv6.conf.${cif}.autoconf=0" 2>/dev/null || true
    ip netns exec "$cns" sysctl -qw "net.ipv6.conf.${cif}.accept_ra=0" 2>/dev/null || true
    ip netns exec "$cns" sysctl -qw "net.ipv6.conf.${cif}.router_solicitations=0" 2>/dev/null || true

    # Let the unprivileged sinkhole bind port 53 inside the capture namespace.
    ip netns exec "$dns" sysctl -qw net.ipv4.ip_unprivileged_port_start=0 2>/dev/null || true
    ip netns exec "$cns" sysctl -qw net.ipv4.ip_unprivileged_port_start=0 2>/dev/null || true

    ip netns exec "$dns" cat "/sys/class/net/${dif}/address" > "$out/net/daemon.mac"
    ip netns exec "$cns" cat "/sys/class/net/${cif}/address" > "$out/net/capture.mac"

    {
        printf 'DAEMON_NS=%s\n' "$dns"
        printf 'CAPTURE_NS=%s\n' "$cns"
        printf 'DAEMON_IF=%s\n' "$dif"
        printf 'CAPTURE_IF=%s\n' "$cif"
        printf 'DAEMON_IP4=%s\n' "$dip"
        printf 'CAPTURE_IP4=%s\n' "$cip"
        printf 'DAEMON_IP6=%s\n' "$dip6"
        printf 'CAPTURE_IP6=%s\n' "$cip6"
        printf 'GATEWAY_IP4=%s\n' "$gw4"
        printf 'GATEWAY_IP6=%s\n' "$gw6"
    } > "$out/net/topology.env"
}

run_as() {
    if [[ $# -lt 4 ]]; then
        echo "error: run-as expects <ns> <uid> <gid> -- <command...>" >&2
        exit 2
    fi
    local ns="$1" uid="$2" gid="$3"
    shift 3
    if [[ "${1:-}" == "--" ]]; then
        shift
    fi
    ip netns exec "$ns" setpriv --reuid="$uid" --regid="$gid" --init-groups -- "$@"
}

capture_start() {
    if [[ $# -ne 4 ]]; then
        echo "error: capture-start expects <capture-ns> <iface> <pcap> <log>" >&2
        exit 2
    fi
    local ns="$1" iface="$2" pcap="$3" log="$4"
    : > "$pcap"
    : > "$log"
    ip netns exec "$ns" tcpdump -i "$iface" -nn -s 0 -U -w "$pcap" >"$log" 2>&1 &
    local pid=$!
    printf '%s\n' "$pid" > "${pcap}.pid"
    sleep 0.3
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "error: tcpdump failed to start; see $log" >&2
        cat "$log" >&2 || true
        return 2
    fi
}

capture_stop() {
    local pidfile="$1" pid
    [[ -f "$pidfile" ]] || return 0
    pid="$(cat "$pidfile")"
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 50); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    kill -KILL "$pid" 2>/dev/null || true
    rm -f "$pidfile"
}

sinkhole_start() {
    if [[ $# -lt 7 ]]; then
        echo "error: sinkhole-start expects <ns> <uid> <gid> <script> <pidfile> <log> -- <args...>" >&2
        exit 2
    fi
    local ns="$1" uid="$2" gid="$3" script="$4" pidfile="$5" log="$6"
    shift 6
    if [[ "${1:-}" == "--" ]]; then
        shift
    fi
    : > "$log"
    ip netns exec "$ns" setpriv --reuid="$uid" --regid="$gid" --init-groups -- \
        python3 "$script" "$@" >"$log" 2>&1 &
    printf '%s\n' "$!" > "$pidfile"
}

system_monitor_start() {
    if [[ $# -ne 2 ]]; then
        echo "error: system-monitor-start expects <log> <pidfile>" >&2
        exit 2
    fi
    local log="$1" pidfile="$2"
    : > "$log"
    dbus-monitor --system >"$log" 2>&1 &
    printf '%s\n' "$!" > "$pidfile"
    sleep 0.5
    if ! kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        echo "error: dbus-monitor --system failed; see $log" >&2
        cat "$log" >&2 || true
        return 2
    fi
}

stop_pid() {
    local pidfile="$1" pid
    [[ -f "$pidfile" ]] || return 0
    pid="$(cat "$pidfile")"
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 50); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    kill -KILL "$pid" 2>/dev/null || true
    rm -f "$pidfile"
}

case "${1:-}" in
    setup) shift; setup "$@" ;;
    teardown) shift; teardown "$@" ;;
    run-as) shift; run_as "$@" ;;
    capture-start) shift; capture_start "$@" ;;
    capture-stop) shift; capture_stop "$@" ;;
    sinkhole-start) shift; sinkhole_start "$@" ;;
    system-monitor-start) shift; system_monitor_start "$@" ;;
    stop-pid) shift; stop_pid "$@" ;;
    -h|--help|help) usage ;;
    *) usage >&2; exit 2 ;;
esac
