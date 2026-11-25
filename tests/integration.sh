#!/usr/bin/env bash
# Run as root on Linux with systemd, wg, ip, nft and Python. The test uses only
# temporary network namespaces and uniquely named service units.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
repo=$PWD
suffix=$(python3 -c 'import secrets; print(secrets.token_hex(3))')
vps="test-v-$suffix"
home="test-h-$suffix"
lab=$(mktemp -d /tmp/rwg-test.XXXXXXXX)
state_created=no
if [[ ! -e /etc/residential-wg-tunnel ]]; then state_created=yes; fi
jobs=()

in_ns() { ip netns exec "$@"; }
manage() { local namespace=$1; shift; in_ns "$namespace" "$repo/residential-wg-tunnel.sh" --instance "$namespace" "$@"; }
traffic() { in_ns "$1" python3 "$repo/tests/traffic.py" "${@:2}"; }

cleanup() {
    local rc=$?
    trap - EXIT
    if (( rc != 0 )); then
        for ns in "$vps" "$home"; do
            in_ns "$ns" wg show rwgtest latest-handshakes 2>/dev/null || true
            in_ns "$ns" nft list ruleset 2>/dev/null || true
            journalctl -u "residential-wg-tunnel-$ns.service" -n 12 --no-pager -o cat || true
        done
    fi
    for p in "${jobs[@]}"; do kill "$p" 2>/dev/null || true; done
    for p in "${jobs[@]}"; do wait "$p" 2>/dev/null || true; done
    for ns in "$vps" "$home"; do
        if ip netns exec "$ns" true 2>/dev/null; then
            manage "$ns" uninstall --purge-key > /dev/null 2>&1 || rc=1
            ip netns del "$ns" || rc=1
        fi
        dropin="/etc/systemd/system/residential-wg-tunnel-$ns.service.d"
        if [[ -f "$dropin/90-rwg-test.conf" ]]; then rm -f -- "$dropin/90-rwg-test.conf"; rmdir -- "$dropin" || rc=1; fi
        if [[ -e "/etc/systemd/system/residential-wg-tunnel-$ns.service" ]]; then rc=1; fi
    done
    if [[ "$state_created" == yes && -d /etc/residential-wg-tunnel ]] &&
       [[ "$(find /etc/residential-wg-tunnel -mindepth 1 -maxdepth 1 -printf '%f\n')" == .lock ]]; then
        rm -f /etc/residential-wg-tunnel/.lock
        rmdir /etc/residential-wg-tunnel || rc=1
    fi
    systemctl daemon-reload
    rm -rf -- "$lab"
    exit "$rc"
}
trap cleanup EXIT

ip netns add "$vps"
ip netns add "$home"
ip -n "$vps" link add uplink type veth peer name uplink netns "$home"
for ns in "$vps" "$home"; do
    ip -n "$ns" link set lo up
    ip -n "$ns" link set uplink up
    in_ns "$ns" sysctl -qw net.ipv4.ip_forward=0
    in_ns "$ns" sysctl -qw net.ipv6.conf.all.forwarding=0
    in_ns "$ns" nft add table inet existing_marker
    dropin="/etc/systemd/system/residential-wg-tunnel-$ns.service.d"
    mkdir -- "$dropin"
    printf '[Service]\nNetworkNamespacePath=/run/netns/%s\n' "$ns" > "$dropin/90-rwg-test.conf"
done
ip -n "$vps" address add 198.51.100.1/30 dev uplink
ip -n "$home" address add 198.51.100.2/30 dev uplink
ip -n "$vps" -6 address add 2001:db8:996::1/64 dev uplink nodad
ip -n "$home" -6 address add 2001:db8:996::2/64 dev uplink nodad

vps_key=$(manage "$vps" keygen)
home_key=$(manage "$home" keygen)
test "$(manage "$vps" keygen)" = "$vps_key"

cat > "$lab/vps.json" <<EOF
{
  "role":"vps","interface":"rwgtest",
  "tunnel":{"ipv4":"10.204.54.1","ipv6":"fd42:3791:2::1"},
  "peer":{"public_key":"$home_key","ipv4":"10.204.54.2","ipv6":"fd42:3791:2::2"},
  "public":{"ipv4":"198.51.100.1","ipv6":"2001:db8:996::1"},
  "wireguard_port":51891,"wireguard_sources":["198.51.100.2/32"],
  "ports":[
    {"listen":18443,"target":14443,"protocols":["tcp","udp"],"source_policy":"none","udp_security":"authenticated"},
    {"listen":18444,"target":14444,"protocols":["tcp","udp"],"source_policy":"acl","allow":["198.51.100.2/32"],"udp_security":"allowlist"},
    {"listen":18445,"target":14443,"target_family":"ipv4","protocols":["tcp","udp"],"source_policy":"none","udp_security":"authenticated"}
  ]
}
EOF
cat > "$lab/home.json" <<EOF
{
  "role":"home","interface":"rwgtest",
  "tunnel":{"ipv4":"10.204.54.2","ipv6":"fd42:3791:2::2"},
  "peer":{"public_key":"$vps_key","ipv4":"10.204.54.1","ipv6":"fd42:3791:2::1","endpoint":{"host":"198.51.100.1","port":51891},"keepalive":1},
  "ports":[
    {"listen":14443,"protocols":["tcp","udp"]},
    {"listen":14444,"protocols":["tcp","udp"],"loopback":{"ipv4":{"host":"127.0.0.1","port":14445},"ipv6":{"host":"::1","port":14445}}}
  ]
}
EOF

launch_echo() {
    ip netns exec "$1" python3 "$repo/tests/traffic.py" serve "$2" "$3" &
    jobs+=("$!")
}
launch_echo "$home" 0.0.0.0 14443
launch_echo "$home" :: 14443
launch_echo "$home" 127.0.0.1 14445
launch_echo "$home" ::1 14445
launch_echo "$vps" 198.51.100.1 18446
sleep .5
for p in "${jobs[@]}"; do kill -0 "$p"; done
wait_handshake() {
    for attempt in $(seq 1 15); do
        if in_ns "$vps" wg show rwgtest latest-handshakes | awk '$2 > 0 {ok=1} END {exit !ok}'; then
            return
        fi
        sleep 1
    done
    echo "VPS has no WireGuard handshake" >&2
    return 1
}
manage "$vps" check "$lab/vps.json"
manage "$home" check "$lab/home.json"
manage "$vps" install "$lab/vps.json"
manage "$home" install "$lab/home.json"
manage "$home" status
manage "$vps" install "$lab/vps.json"
wait_handshake
for port in 18443 18445; do
    traffic "$home" pass 198.51.100.1 "$port"
    traffic "$home" pass 2001:db8:996::1 "$port"
done
traffic "$home" pass 198.51.100.1 18444
traffic "$home" blocked 2001:db8:996::1 18444
in_ns "$vps" test "$(in_ns "$vps" sysctl -n net.ipv6.conf.all.forwarding)" = 0
manage "$home" stop
traffic "$home" blocked 198.51.100.1 18443
traffic "$home" blocked 2001:db8:996::1 18443
manage "$home" start
sleep 1
traffic "$home" pass 198.51.100.1 18443
sed 's/18443/18446/g' "$lab/vps.json" > "$lab/conflict.json"
if manage "$vps" update "$lab/conflict.json"; then echo "Conflicting update unexpectedly succeeded" >&2; exit 1; fi
wait_handshake
traffic "$home" pass 198.51.100.1 18443
sed 's/18443/18447/g' "$lab/vps.json" > "$lab/updated.json"
manage "$vps" update "$lab/updated.json"
wait_handshake
traffic "$home" pass 2001:db8:996::1 18447
traffic "$home" blocked 198.51.100.1 18443
for ns in "$home" "$vps"; do
    manage "$ns" uninstall --purge-key
    if ip -n "$ns" link show rwgtest >/dev/null 2>&1; then exit 1; fi
    if in_ns "$ns" nft list tables | grep -q rwg_; then exit 1; fi
    in_ns "$ns" nft list table inet existing_marker >/dev/null
    test ! -e "/etc/residential-wg-tunnel/$ns"
done
echo 'Verified real WireGuard, TCP/UDP dual-stack, ACLs, loopback handoff, stop/recovery, update/rollback and uninstall.'
