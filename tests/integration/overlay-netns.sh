#!/usr/bin/env bash
# Privileged end-to-end VPN tests: actual mqvpn binaries, QUIC, TUN, VXLAN / FRR.
set -Eeuo pipefail
mode="${1:-}"
[[ "$mode" == vxlan || "$mode" == bgp || "$mode" == tcp || "$mode" == udp || "$mode" == voip ]] || {
  echo "usage: $0 vxlan|bgp|tcp|udp|voip" >&2; exit 2;
}
[[ "$EUID" == 0 ]] || { echo "run as root with CAP_NET_ADMIN" >&2; exit 2; }
root="$(cd "$(dirname "$0")/../.." && pwd)"
for tool in ip ping openssl sha256sum timeout; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }
done
for binary in "$root/bin/mqvpn-server" "$root/bin/mqvpn-client"; do
  [[ -x "$binary" ]] || { echo "make release first: $binary" >&2; exit 2; }
done
if [[ "$mode" == tcp || "$mode" == udp || "$mode" == voip ]]; then
  command -v python3 >/dev/null || { echo "missing python3" >&2; exit 2; }
fi
if [[ "$mode" == bgp ]]; then
  for binary in /usr/lib/frr/zebra /usr/lib/frr/bgpd /usr/bin/vtysh; do
    [[ -x "$binary" ]] || { echo "missing official FRR stable deb: $binary" >&2; exit 2; }
  done
fi
work="$(mktemp -d)"
server_ns="mqvs$$"
client_ns="mqvc$$"
server_veth="vs$$"
client_veth="vc$$"
frr_server="frs$$"
frr_client="frc$$"
pids=""

fail() { echo "FAIL: $*" >&2; exit 1; }
cleanup() {
  status="$?"
  trap - EXIT INT TERM
  if (( status != 0 )); then
    for file in "$work"/*.log; do
      [[ -e "$file" ]] || continue
      echo "---- $(basename "$file") ----" >&2
      tail -80 "$file" >&2 || true
    done
    ip -n "$server_ns" route 2>/dev/null >&2 || true
    ip -n "$client_ns" route 2>/dev/null >&2 || true
  fi
  for pid in $pids; do kill "$pid" 2>/dev/null || true; done
  for pid in $pids; do wait "$pid" 2>/dev/null || true; done
  for ns in "$server_ns" "$client_ns"; do
    if ip netns list | grep -q "^$ns "; then
      while read -r pid; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
      done < <(ip netns pids "$ns" || true)
      ip netns del "$ns" 2>/dev/null || true
    fi
  done
  if [[ "$mode" == bgp ]]; then rm -rf "/run/frr/$frr_server" "/run/frr/$frr_client"; fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT INT TERM

# Separate network namespaces isolate the underlay, so both daemons must
# exchange real encrypted QUIC packets through the veth WAN.
ip netns add "$server_ns"
ip netns add "$client_ns"
ip link add "$server_veth" type veth peer name "$client_veth"
ip link set "$server_veth" netns "$server_ns" name wan0
ip link set "$client_veth" netns "$client_ns" name wan0
for ns in "$server_ns" "$client_ns"; do
  ip -n "$ns" link set lo up
  ip -n "$ns" link set wan0 up
done
ip -n "$server_ns" addr add 192.0.2.1/30 dev wan0
ip -n "$client_ns" addr add 192.0.2.2/30 dev wan0

bash "$root/scripts/gen-dev-certs.sh" "$work/certs" vpn.ci.example >"$work/certs.log" 2>&1
cert="$work/certs"
fingerprint="$(openssl x509 -in "$cert/client.crt" -outform DER | sha256sum | awk '{print $1}')"
cat >"$work/peers.yaml" <<EOF
peers:
  - id: ci-client
    certificate_sha256: "$fingerprint"
    routes:
      - 10.77.0.2/32
      - 198.18.202.1/32
EOF
cat >"$work/server.yaml" <<EOF
listen: "192.0.2.1:8443"
instances:
  - name: lab
    server_name: vpn.ci.example
    tun: mq0
    address: 10.77.0.1/30
    mtu: 1500
    max_frame: 1514
    peers: "$work/peers.yaml"
    cert: "$cert/server.crt"
    key: "$cert/server.key"
    client_ca: "$cert/ca.crt"
    tc:
      mode: off
EOF
"$root/bin/mqvpn-server" validate --config "$work/server.yaml" >"$work/validate.log" 2>&1 ||
  fail "mqvpn-server configuration validation"
ip netns exec "$server_ns" "$root/bin/mqvpn-server" \
  --config "$work/server.yaml" --reload-interval 0 >"$work/server.log" 2>&1 &
pids="$pids $!"
# The server's UDP/8443 listener is ready once the TUN exists.
for attempt in $(seq 1 60); do
  ip -n "$server_ns" link show mq0 >/dev/null 2>&1 && break
  sleep 0.2
done
ip -n "$server_ns" link show mq0 >/dev/null || fail "server failed to create mq0"
ip netns exec "$client_ns" "$root/bin/mqvpn-client" \
  --server vpn.ci.example:8443 --connect-ip 192.0.2.1 \
  --tun mq0 --tun-address 10.77.0.2/30 \
  --tun-mtu 1500 --max-frame 1514 \
  --source-ip 192.0.2.2 --source-interface wan0 \
  --ca "$cert/ca.crt" --cert "$cert/client.crt" --key "$cert/client.key" \
  --tc-mode off --transport quic --reconnect=false \
  >"$work/client.log" 2>&1 &
pids="$pids $!"

ready=0
for attempt in $(seq 1 90); do
  for pid in $pids; do kill -0 "$pid" 2>/dev/null || fail "early VPN process exit ($pid)"; done
  if ip -n "$client_ns" link show mq0 >/dev/null 2>&1 &&
     ip netns exec "$server_ns" ping -n -c 1 -W 1 10.77.0.2 >/dev/null 2>&1 &&
     ip netns exec "$client_ns" ping -n -c 1 -W 1 10.77.0.1 >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.2
done
(( ready )) || fail "authenticated QUIC/TUN forwarding did not come up"
ip -n "$server_ns" -o link show mq0 | grep -q 'mtu 1500' || fail "server TUN MTU"
ip -n "$client_ns" -o link show mq0 | grep -q 'mtu 1500' || fail "client TUN MTU"
echo "PASS actual mTLS QUIC+TUN peer connectivity, MTU 1500"

if [[ "$mode" == vxlan ]]; then
  ip -n "$server_ns" link add vx100 type vxlan id 100 dev mq0 local 10.77.0.1 remote 10.77.0.2 dstport 4789
  ip -n "$client_ns" link add vx100 type vxlan id 100 dev mq0 local 10.77.0.2 remote 10.77.0.1 dstport 4789
  ip -n "$server_ns" addr add 172.30.100.1/24 dev vx100
  ip -n "$client_ns" addr add 172.30.100.2/24 dev vx100
  # Standard IPv4 VXLAN overhead is 50 bytes, leaving 1450-byte
  # inner Ethernet payload on a 1500-byte mqvpn TUN interface.
  ip -n "$server_ns" link set vx100 mtu 1450
  ip -n "$client_ns" link set vx100 mtu 1450
  ip -n "$server_ns" link set vx100 up
  ip -n "$client_ns" link set vx100 up
  ip -n "$server_ns" -o link show vx100 | grep -q 'mtu 1450' ||
    fail "server VXLAN MTU != 1450"
  ip -n "$client_ns" -o link show vx100 | grep -q 'mtu 1450' ||
    fail "client VXLAN MTU != 1450"
  ip netns exec "$server_ns" ping -n -c 3 -W 2 172.30.100.2 || fail "VXLAN server -> client"
  ip netns exec "$client_ns" ping -n -c 3 -W 2 172.30.100.1 || fail "VXLAN client -> server"
  # 1422 ICMP data + 8 ICMP + 20 inner IPv4 = 1450-byte inner IP.
  # Adding 50 bytes of IPv4 VXLAN overhead yields a 1500-byte TUN IP
  # packet; frag-v1 must fit it into the QUIC DATAGRAM budget.
  ip netns exec "$server_ns" ping -n -M do -s 1422 -c 2 -W 2 172.30.100.2 ||
    fail "VXLAN MTU 1450 DF packet server -> client"
  ip netns exec "$client_ns" ping -n -M do -s 1422 -c 2 -W 2 172.30.100.1 ||
    fail "VXLAN MTU 1450 DF packet client -> server"
  ip -n "$server_ns" neigh show dev vx100 | grep -q 172.30.100.2 ||
    fail "VXLAN L2 neighbor resolution"
  echo "PASS VXLAN VNI 100, MTU 1450: L2 ARP, bidirectional IP, 1500-byte outer TUN IP DF packets"
  exit 0
fi

# Each test runs against the same authenticated QUIC/TUN topology.
# A fresh listener marker prevents startup races; a failure in either
# namespace fails the entire CI test instead of silently losing packets.
run_probe() {
  local proto="$1" listen_ns="$2" send_ns="$3" listen_ip="$4" send_ip="$5" label="$6"
  local marker="$work/${proto}-${label}.ready"
  ip netns exec "$listen_ns" python3 "$root/tests/integration/transport_probe.py" \
    listen "$proto" "$listen_ip" "$send_ip" "$marker" \
    >"$work/${proto}-${label}-listener.log" 2>&1 &
  local probe_pid="$!"
  pids="$pids $probe_pid"
  local active=0
  for attempt in $(seq 1 100); do
    if [[ -f "$marker" ]]; then active=1; break; fi
    kill -0 "$probe_pid" 2>/dev/null || fail "$proto $label listener exited early"
    sleep 0.05
  done
  (( active )) || fail "$proto $label listener never became ready"
  timeout 40s ip netns exec "$send_ns" python3 "$root/tests/integration/transport_probe.py" \
    send "$proto" "$send_ip" "$listen_ip" "$marker" \
    >"$work/${proto}-${label}-sender.log" 2>&1 ||
    fail "$proto $label sender failed"
  wait "$probe_pid" || fail "$proto $label listener failed"
  cat "$work/${proto}-${label}-listener.log"
  cat "$work/${proto}-${label}-sender.log"
}

if [[ "$mode" == tcp || "$mode" == udp ]]; then
  # Both endpoints must accept real connections and carry both data flows.
  run_probe "$mode" "$server_ns" "$client_ns" 10.77.0.1 10.77.0.2 s2c
  run_probe "$mode" "$client_ns" "$server_ns" 10.77.0.2 10.77.0.1 c2s
  echo "PASS $mode: both VPN peers served as endpoints"
  exit 0
fi
if [[ "$mode" == voip ]]; then
  # SIP initiator on the Client, then reverse it. Both simulate a full
  # duplex 20ms G.711 RTP call with EF marking and RTCP reports.
  run_probe voip "$server_ns" "$client_ns" 10.77.0.1 10.77.0.2 s2c
  run_probe voip "$client_ns" "$server_ns" 10.77.0.2 10.77.0.1 c2s
  echo "PASS VoIP: two full-duplex SIP/RTP/RTCP sessions over QUIC TUN"
  exit 0
fi

ip -n "$server_ns" addr add 198.18.101.1/32 dev lo
ip -n "$client_ns" addr add 198.18.202.1/32 dev lo
# FRR 10.7 stable daemons drop privileges to frr, which is in frrvty.
# Keep certificate private keys root-owned; only generated daemon configs
# and dedicated runtime directories are accessible to the FRR account.
install -d -m 0750 -o frr -g frr "/run/frr/$frr_server" "/run/frr/$frr_client"
chgrp frr "$work"
chmod 0750 "$work"
for side in server client; do
  if [[ "$side" == server ]]; then
    asn=65001; peer_asn=65002; local_ip=10.77.0.1; peer_ip=10.77.0.2
    prefix=198.18.101.1/32
  else
    asn=65002; peer_asn=65001; local_ip=10.77.0.2; peer_ip=10.77.0.1
    prefix=198.18.202.1/32
  fi
  cat >"$work/$side-zebra.conf" <<EOF
hostname $side-zebra
log stdout
!
EOF
  cat >"$work/$side-bgpd.conf" <<EOF
hostname $side-bgpd
log stdout
router bgp $asn
 bgp router-id $local_ip
 no bgp ebgp-requires-policy
 no bgp network import-check
 neighbor $peer_ip remote-as $peer_asn
 neighbor $peer_ip timers 3 9
 address-family ipv4 unicast
  network $prefix
  neighbor $peer_ip activate
 exit-address-family
!
EOF
done
# The default FRR service user must be a member of frrvty.
# Never bypass this protection by forcing -u root.
id frr
chown frr:frr "$work"/{server,client}-{zebra,bgpd}.conf
chmod 0640 "$work"/{server,client}-{zebra,bgpd}.conf
for side in server client; do
  if [[ "$side" == server ]]; then ns="$server_ns"; space="$frr_server"; else ns="$client_ns"; space="$frr_client"; fi
  ip netns exec "$ns" /usr/lib/frr/zebra -N "$space" -u frr -g frr \
    -f "$work/$side-zebra.conf" -A 127.0.0.1 -P 0 >"$work/$side-zebra.log" 2>&1 &
  pids="$pids $!"
done
for attempt in $(seq 1 60); do
  [[ -S "/run/frr/$frr_server/zserv.api" && -S "/run/frr/$frr_client/zserv.api" ]] && break
  sleep 0.2
done
[[ -S "/run/frr/$frr_server/zserv.api" && -S "/run/frr/$frr_client/zserv.api" ]] ||
  fail "FRR zebra ZAPI socket not created"
for side in server client; do
  if [[ "$side" == server ]]; then ns="$server_ns"; space="$frr_server"; else ns="$client_ns"; space="$frr_client"; fi
  ip netns exec "$ns" /usr/lib/frr/bgpd -N "$space" -u frr -g frr \
    -f "$work/$side-bgpd.conf" -A 127.0.0.1 -P 0 >"$work/$side-bgpd.log" 2>&1 &
  pids="$pids $!"
done
# No static route to remote loopbacks exists: these MUST be learned via
# BGP over TCP/179 in mq0, installed by FRR zebra in each namespace.
converged=0
for attempt in $(seq 1 120); do
  if ip -n "$server_ns" -4 route show 198.18.202.1/32 | grep -Eq 'via 10\.77\.0\.2 dev mq0' &&
     ip -n "$client_ns" -4 route show 198.18.101.1/32 | grep -Eq 'via 10\.77\.0\.1 dev mq0'; then
    converged=1
    break
  fi
  sleep 0.5
done
(( converged )) || fail "FRR BGP peers did not converge and install routes on mq0"
ip netns exec "$server_ns" vtysh -N "$frr_server" -c "show bgp ipv4 unicast summary" ||
  fail "server FRR BGP summary"
ip netns exec "$client_ns" vtysh -N "$frr_client" -c "show bgp ipv4 unicast summary" ||
  fail "client FRR BGP summary"
ip netns exec "$server_ns" ping -n -I 198.18.101.1 -c 3 -W 2 198.18.202.1 ||
  fail "forwarding server -> client over BGP learned route"
ip netns exec "$client_ns" ping -n -I 198.18.202.1 -c 3 -W 2 198.18.101.1 ||
  fail "forwarding client -> server over BGP learned route"
echo "PASS official FRR stable eBGP: neighbor convergence, Linux FIB and bidirectional traffic over TUN"
