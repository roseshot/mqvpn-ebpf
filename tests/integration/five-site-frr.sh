#!/usr/bin/env bash
# Five real Linux namespaces: one mqvpn P2MP hub, four authenticated Clients.
# FRRouting exchanges BGP or OSPF routes across their QUIC/TUN sessions.
# No static routes to any remote site's 198.18.20x.1/32 loopback are installed.
set -euo pipefail
mode="${1:-}"
[[ "$mode" == bgp || "$mode" == ospf ]] || { echo "usage: $0 bgp|ospf" >&2; exit 2; }
(( EUID == 0 )) || { echo "CAP_NET_ADMIN/root required" >&2; exit 2; }
for command in ip ping openssl sha256sum timeout sysctl; do
  command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 2; }
done
for daemon in zebra bgpd ospfd; do
  [[ -x "/usr/lib/frr/$daemon" ]] || { echo "missing official FRR daemon $daemon" >&2; exit 2; }
done
root="$(cd "$(dirname "$0")/../.." && pwd)"
for binary in mqvpn-server mqvpn-client; do
  [[ -x "$root/bin/$binary" ]] || { echo "run make release before $0" >&2; exit 2; }
done

work="$(mktemp -d)"
nodes=("mq5s$$" "mq5c1$$" "mq5c2$$" "mq5c3$$" "mq5c4$$")
spaces=("mq5f0$$" "mq5f1$$" "mq5f2$$" "mq5f3$$" "mq5f4$$")
underlay_server=(192.0.2.1 198.51.100.1 203.0.113.1 192.0.2.5)
underlay_client=(192.0.2.2 198.51.100.2 203.0.113.2 192.0.2.6)
tunnel=(10.77.0.1 10.77.0.2 10.77.0.3 10.77.0.4 10.77.0.5)
loopback=(198.18.200.1 198.18.201.1 198.18.202.1 198.18.203.1 198.18.204.1)
pids=()
fail() { echo "FAIL five-site $mode: $*" >&2; exit 1; }
cleanup() {
  status="$?"
  trap - EXIT INT TERM
  if (( status != 0 )); then
    for log in "$work"/*.log; do
      [[ -f "$log" ]] || continue
      echo "---- $(basename "$log") ----" >&2
      tail -50 "$log" >&2 || true
    done
    for node in "${nodes[@]}"; do
      ip -n "$node" -4 route 2>/dev/null >&2 || true
    done
  fi
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  for node in "${nodes[@]}"; do
    if ip netns list | grep -q "^$node "; then
      while read -r pid; do
        [[ -z "$pid" ]] || kill "$pid" 2>/dev/null || true
      done < <(ip netns pids "$node" 2>/dev/null || true)
      ip netns del "$node" 2>/dev/null || true
    fi
  done
  for space in "${spaces[@]}"; do rm -rf "/run/frr/$space"; done
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT INT TERM

for node in "${nodes[@]}"; do
  ip netns add "$node"
  ip -n "$node" link set lo up
done
# Independent /30 underlays; no direct client-to-client physical link.
for i in 1 2 3 4; do
  offset=$((i - 1))
  ip link add "m5s$i$$" type veth peer name "m5c$i$$"
  ip link set "m5s$i$$" netns "${nodes[0]}" name "wan$i"
  ip link set "m5c$i$$" netns "${nodes[i]}" name wan0
  ip -n "${nodes[0]}" addr add "${underlay_server[offset]}/30" dev "wan$i"
  ip -n "${nodes[i]}" addr add "${underlay_client[offset]}/30" dev wan0
  ip -n "${nodes[0]}" link set "wan$i" up
  ip -n "${nodes[i]}" link set wan0 up
done

# Allow the hub kernel to hairpin cross-site IP packets from mq0 back to mq0.
# The daemon itself never installs or fabricates routing-protocol routes.
ip netns exec "${nodes[0]}" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "${nodes[0]}" sysctl -qw net.ipv4.conf.all.send_redirects=0
for node in "${nodes[@]}"; do
  ip netns exec "$node" sysctl -qw net.ipv4.conf.all.rp_filter=0
  ip netns exec "$node" sysctl -qw net.ipv4.conf.default.rp_filter=0
done

cert="$work/certs"
bash "$root/scripts/gen-dev-certs.sh" "$cert" vpn.ci.example >"$work/certs.log" 2>&1
mv "$cert/client.crt" "$cert/site1.crt"
mv "$cert/client.key" "$cert/site1.key"
for i in 2 3 4; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$cert/site$i.key" -out "$cert/site$i.csr" \
    -subj "/CN=mqvpn-site$i" >>"$work/certs.log" 2>&1
  printf 'extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\n' >"$cert/site$i.ext"
  openssl x509 -req -in "$cert/site$i.csr" -CA "$cert/ca.crt" \
    -CAkey "$cert/ca.key" -CAcreateserial -out "$cert/site$i.crt" \
    -days 7 -extfile "$cert/site$i.ext" >>"$work/certs.log" 2>&1
done
{
  echo "peers:"
  for i in 1 2 3 4; do
    fingerprint="$(openssl x509 -in "$cert/site$i.crt" -outform DER | sha256sum | awk '{print $1}')"
    printf '  - id: site%d\n    certificate_sha256: "%s"\n    routes:\n      - %s/32\n      - %s/32\n' \
      "$i" "$fingerprint" "${tunnel[i]}" "${loopback[i]}"
  done
} >"$work/peers.yaml"

cat >"$work/server.yaml" <<EOF
listen: "0.0.0.0:8443"
instances:
  - name: five-site
    server_name: vpn.ci.example
    tun: mq0
    address: 10.77.0.1/24
    mtu: 1500
    max_frame: 1514
    peers: "$work/peers.yaml"
    cert: "$cert/server.crt"
    key: "$cert/server.key"
    client_ca: "$cert/ca.crt"
    tc:
      mode: off
EOF
"$root/bin/mqvpn-server" validate --config "$work/server.yaml" >"$work/validate.log" 2>&1 || fail "server config"
ip netns exec "${nodes[0]}" "$root/bin/mqvpn-server" \
  --config "$work/server.yaml" --reload-interval 0 >"$work/server.log" 2>&1 &
pids+=("$!")
for attempt in $(seq 1 80); do
  ip -n "${nodes[0]}" link show mq0 >/dev/null 2>&1 && break
  sleep 0.1
done
ip -n "${nodes[0]}" link show mq0 >/dev/null 2>&1 || fail "Server TUN missing"
ip netns exec "${nodes[0]}" sysctl -qw net.ipv4.conf.mq0.rp_filter=0
ip netns exec "${nodes[0]}" sysctl -qw net.ipv4.conf.mq0.send_redirects=0
for i in 1 2 3 4; do
  offset=$((i - 1))
  ip netns exec "${nodes[i]}" "$root/bin/mqvpn-client" \
    --server vpn.ci.example:8443 --connect-ip "${underlay_server[offset]}" \
    --source-ip "${underlay_client[offset]}" --source-interface wan0 \
    --tun mq0 --tun-address "${tunnel[i]}/24" \
    --tun-mtu 1500 --max-frame 1514 \
    --ca "$cert/ca.crt" --cert "$cert/site$i.crt" --key "$cert/site$i.key" \
    --tc-mode off --transport quic --reconnect=false \
    >"$work/site$i-client.log" 2>&1 &
  pids+=("$!")
done

connected=0
for attempt in $(seq 1 120); do
  ready=1
  for i in 1 2 3 4; do
    if ! ip -n "${nodes[i]}" link show mq0 >/dev/null 2>&1 ||
       ! ip netns exec "${nodes[i]}" ping -n -c 1 -W 1 "${tunnel[0]}" >/dev/null 2>&1 ||
       ! ip netns exec "${nodes[0]}" ping -n -c 1 -W 1 "${tunnel[i]}" >/dev/null 2>&1; then
      ready=0
      break
    fi
  done
  if (( ready )); then connected=1; break; fi
  for pid in "${pids[@]}"; do kill -0 "$pid" 2>/dev/null || fail "VPN process exited before all sites connected"; done
  sleep 0.25
done
(( connected )) || fail "five authenticated Client/Server TUN sessions not reachable"
echo "PASS five-site $mode: four distinct mTLS Client peers via one Server/UDP listener"
for i in 0 1 2 3 4; do
  ip -n "${nodes[i]}" addr add "${loopback[i]}/32" dev lo
  ip netns exec "${nodes[i]}" sysctl -qw net.ipv4.conf.mq0.rp_filter=0
done

# FRR daemons run unprivileged under the signed frr-stable package.
id frr >/dev/null || fail "FRR system user missing"
chgrp frr "$work"
chmod 0750 "$work"
for i in 0 1 2 3 4; do
  space="${spaces[i]}"
  install -d -m 0750 -o frr -g frr "/run/frr/$space"
  cat >"$work/site$i-zebra.conf" <<EOF
hostname site$i-zebra
log stdout
!
EOF
  if [[ "$mode" == bgp ]]; then
    if (( i == 0 )); then asn=65000; else asn=$((65100 + i)); fi
    {
      echo "hostname site$i-bgpd"
      echo "log stdout"
      echo "router bgp $asn"
      echo " bgp router-id ${tunnel[i]}"
      echo " no bgp ebgp-requires-policy"
      echo " no bgp network import-check"
      if (( i == 0 )); then
        for peer in 1 2 3 4; do
          echo " neighbor ${tunnel[peer]} remote-as $((65100 + peer))"
          echo " neighbor ${tunnel[peer]} timers 3 9"
        done
      else
        echo " neighbor ${tunnel[0]} remote-as 65000"
        echo " neighbor ${tunnel[0]} timers 3 9"
      fi
      echo " address-family ipv4 unicast"
      echo "  network ${loopback[i]}/32"
      if (( i == 0 )); then
        for peer in 1 2 3 4; do
          echo "  neighbor ${tunnel[peer]} activate"
          echo "  neighbor ${tunnel[peer]} next-hop-self"
        done
      else
        echo "  neighbor ${tunnel[0]} activate"
      fi
      echo " exit-address-family"
      echo "!"
    } >"$work/site$i-bgpd.conf"
  else
    cat >"$work/site$i-ospfd.conf" <<EOF
hostname site$i-ospfd
log stdout
interface mq0
 ip ospf network point-to-multipoint
 ip ospf hello-interval 1
 ip ospf dead-interval 4
!
router ospf
 ospf router-id ${tunnel[i]}
 network 10.77.0.0/24 area 0
 network ${loopback[i]}/32 area 0
!
EOF
  fi
done
chown frr:frr "$work"/site*-{zebra,bgpd,ospfd}.conf 2>/dev/null || {
  # The shell glob includes only the active routing protocol.
  chown frr:frr "$work"/site*-zebra.conf "$work"/site*-"$mode"d.conf
}
chmod 0640 "$work"/site*.conf

for i in 0 1 2 3 4; do
  ip netns exec "${nodes[i]}" /usr/lib/frr/zebra -N "${spaces[i]}" \
    -u frr -g frr -f "$work/site$i-zebra.conf" -A 127.0.0.1 -P 0 \
    >"$work/site$i-zebra.log" 2>&1 &
  pids+=("$!")
done
zebra_ready=0
for attempt in $(seq 1 80); do
  ready=1
  for space in "${spaces[@]}"; do
    [[ -S "/run/frr/$space/zserv.api" ]] || ready=0
  done
  if (( ready )); then zebra_ready=1; break; fi
  sleep 0.2
done
(( zebra_ready )) || fail "five zebra ZAPI sockets did not initialize"

for i in 0 1 2 3 4; do
  ip netns exec "${nodes[i]}" "/usr/lib/frr/${mode}d" -N "${spaces[i]}" \
    -u frr -g frr -f "$work/site$i-${mode}d.conf" -A 127.0.0.1 -P 0 \
    >"$work/site$i-${mode}d.log" 2>&1 &
  pids+=("$!")
done

# Every one of 20 remote /32 destinations must come from the selected
# routing daemon (no static FIB routes are used), not merely ping reachability.
converged=0
for attempt in $(seq 1 180); do
  missing=0
  for i in 0 1 2 3 4; do
    for j in 0 1 2 3 4; do
      (( i == j )) && continue
      route="$(ip -n "${nodes[i]}" -4 route show "${loopback[j]}/32")"
      if [[ "$route" != *"proto $mode"* || "$route" != *"dev mq0"* ]]; then
        missing=$((missing + 1))
      fi
    done
  done
  if (( missing == 0 )); then converged=1; break; fi
  for pid in "${pids[@]}"; do kill -0 "$pid" 2>/dev/null || fail "VPN or FRR daemon exited during convergence"; done
  sleep 0.5
done
(( converged )) || fail "20 remote loopback routes not installed by $mode (missing=$missing)"
echo "PASS five-site $mode: 20/20 remote prefixes installed in Linux FIB by FRR"

for i in 0 1 2 3 4; do
  if [[ "$mode" == bgp ]]; then
    ip netns exec "${nodes[i]}" vtysh -N "${spaces[i]}" \
      -c "show bgp ipv4 unicast summary" >"$work/site$i-summary.log" ||
      fail "BGP summary unavailable at site$i"
  else
    ip netns exec "${nodes[i]}" vtysh -N "${spaces[i]}" \
      -c "show ip ospf neighbor" >"$work/site$i-summary.log" ||
      fail "OSPF neighbor summary unavailable at site$i"
  fi
  [[ -s "$work/site$i-summary.log" ]] || fail "site$i routing summary empty"
done

# Cross-site traffic must pass through the real Server TUN forwarding path;
# there are no Client↔Client physical WAN links.
for i in 0 1 2 3 4; do
  for j in 0 1 2 3 4; do
    (( i == j )) && continue
    ip netns exec "${nodes[i]}" ping -n -I "${loopback[i]}" \
      -c 2 -W 2 "${loopback[j]}" >"$work/ping-$i-$j.log" 2>&1 ||
      fail "site$i to site$j forwarding over $mode learned route"
  done
done
echo "PASS five-site $mode: 20/20 directed loopback-to-loopback ping tests over encrypted P2MP TUN"
