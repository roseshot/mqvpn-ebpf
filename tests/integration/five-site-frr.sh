#!/usr/bin/env bash
# Five real Linux namespaces: one mqvpn P2MP hub, four authenticated Clients.
# FRRouting exchanges BGP and OSPF routes across their QUIC/TUN sessions.
# No static routes to any remote site's 198.18.20x.1/32 loopback are installed.
set -euo pipefail
mode="${1:-}"
[[ "$mode" == bgp || "$mode" == ospf || "$mode" == scenario ]] || { echo "usage: $0 scenario|bgp|ospf" >&2; exit 2; }
routing_modes=("$mode")
if [[ "$mode" == scenario ]]; then routing_modes=(bgp ospf); fi
(( EUID == 0 )) || { echo "CAP_NET_ADMIN/root required" >&2; exit 2; }
for command in ip bridge ping openssl sha256sum python3 timeout sysctl; do
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
# Eight distinct Server underlays; each Client chooses a reproducible random
# count (1..8) and a random subset of the available WAN indices.
# The seed is logged so a failed CI run can be replayed locally.
WAN_SEED="${WAN_SEED:-20261115}"
[[ "$WAN_SEED" =~ ^[0-9]+$ ]] || { echo "WAN_SEED must be an integer" >&2; exit 2; }
mapfile -t site_selection < <(python3 - "$WAN_SEED" "$mode" <<'PY'
import random
import sys
rng = random.Random(f"{sys.argv[1]}:{sys.argv[2]}")
for count in rng.sample(range(1, 9), 4):
    indices = rng.sample(range(8), count)
    print(" ".join(str(i) for i in indices))
PY
)
(( ${#site_selection[@]} == 4 )) || { echo "WAN random sample failed" >&2; exit 2; }
echo "WAN_SEED=$WAN_SEED protocol=$mode (reproduce with WAN_SEED=$WAN_SEED)"
bridges=()
tunnel=(10.77.0.1 10.77.0.2 10.77.0.3 10.77.0.4 10.77.0.5)
loopback=(198.18.200.1 198.18.201.1 198.18.202.1 198.18.203.1 198.18.204.1)
# Unique OSPF prefixes prevent one routing protocol masking the other.
ospf_loopback=(198.18.210.1 198.18.211.1 198.18.212.1 198.18.213.1 198.18.214.1)
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
  for bridge_name in "${bridges[@]}"; do ip link del "$bridge_name" 2>/dev/null || true; done
  for space in "${spaces[@]}"; do
    rm -rf "/run/frr/$space"
    # Only the process-unique test namespace, never /etc/frr itself.
    rm -rf "/etc/frr/$space"
  done
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT INT TERM

for node in "${nodes[@]}"; do
  ip netns add "$node"
  ip -n "$node" link set lo up
done
# Eight separate underlay switches let the Server share WAN0..WAN7
# while each Client selects an arbitrary 1..8 WAN subset. Bridge port
# isolation prevents Client-to-Client L2 bypass of the P2MP Server.
for wan in 0 1 2 3 4 5 6 7; do
  bridge_name="m5b${wan}$$"
  bridges+=("$bridge_name")
  ip link add "$bridge_name" type bridge
  ip link set "$bridge_name" up
  ip link add "m5s${wan}$$" type veth peer name "m5h${wan}$$"
  ip link set "m5s${wan}$$" netns "${nodes[0]}" name "wan$wan"
  ip link set "m5h${wan}$$" master "$bridge_name"
  ip link set "m5h${wan}$$" up
  ip -n "${nodes[0]}" addr add "172.20.$wan.1/24" dev "wan$wan"
  ip -n "${nodes[0]}" link set "wan$wan" up
done
for i in 1 2 3 4; do
  read -r -a chosen < <(printf '%s\n' "${site_selection[i-1]}")
  (( ${#chosen[@]} >= 1 && ${#chosen[@]} <= 8 )) ||
    fail "invalid sampled path count for site$i"
  echo "site$i WAN_COUNT=${#chosen[@]} WAN_INDICES=${chosen[*]}"
  for wan in "${chosen[@]}"; do
    root_end="m5c${i}${wan}$$"
    ns_end="m5n${i}${wan}$$"
    ip link add "$root_end" type veth peer name "$ns_end"
    ip link set "$ns_end" netns "${nodes[i]}" name "wan$wan"
    ip link set "$root_end" master "${bridges[wan]}"
    bridge link set dev "$root_end" isolated on
    ip link set "$root_end" up
    ip -n "${nodes[i]}" addr add "172.20.$wan.$((i + 1))/24" dev "wan$wan"
    ip -n "${nodes[i]}" link set "wan$wan" up
  done
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
# Generate four distinct Client certificates with CNs matching the
# explicitly authorized Peer identities. The generic demo client cert has
# CN=mqvpn-client and must never masquerade as Site 1.
for i in 1 2 3 4; do
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
    printf '  - id: site%d\n    certificate_cn: mqvpn-site%d\n    routes:\n      - %s/32\n      - %s/32\n' \
      "$i" "$i" "${tunnel[i]}" "${loopback[i]}"
    if [[ "$mode" == scenario ]]; then
      printf '      - %s/32\n' "${ospf_loopback[i]}"
    fi
  done
} >"$work/peers.yaml"

{
  echo 'listen: "0.0.0.0:8443"'
  echo 'wans:'
  for wan in 0 1 2 3 4 5 6 7; do
    printf '  - interface: wan%d\n    ip: 172.20.%d.1\n' "$wan" "$wan"
  done
  cat <<EOF
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
} >"$work/server.yaml"
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
  read -r -a chosen < <(printf '%s\n' "${site_selection[i-1]}")
  client_wan_flags=()
  for wan in "${chosen[@]}"; do
    client_wan_flags+=(--wan "172.20.$wan.$((i + 1))@wan$wan=172.20.$wan.1")
  done
  primary_wan="${chosen[0]}"
  ip netns exec "${nodes[i]}" "$root/bin/mqvpn-client" \
    --server vpn.ci.example:8443 --connect-ip "172.20.$primary_wan.1" \
    "${client_wan_flags[@]}" \
    --tun mq0 --tun-address "${tunnel[i]}/24" \
    --tun-mtu 1500 --max-frame 1514 \
    --ca "$cert/ca.crt" --cert "$cert/site$i.crt" --key "$cert/site$i.key" \
    --tc-mode off --transport quic --reconnect=false \
    >"$work/site$i-client.log" 2>&1 &
  pids+=("$!")
done

connected=0
for attempt in $(seq 1 160); do
  ready=1
  for i in 1 2 3 4; do
    read -r -a chosen < <(printf '%s\n' "${site_selection[i-1]}")
    expected_extra=$(( ${#chosen[@]} - 1 ))
    validated="$(grep -c 'QUIC WAN path validated' "$work/site$i-client.log" || true)"
    if (( validated < expected_extra )) ||
       ! ip -n "${nodes[i]}" link show mq0 >/dev/null 2>&1 ||
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
for i in 1 2 3 4; do
  read -r -a chosen < <(printf '%s\n' "${site_selection[i-1]}")
  validated="$(grep -c 'QUIC WAN path validated' "$work/site$i-client.log" || true)"
  echo "PASS site$i: ${#chosen[@]} configured WANs, $validated additional QUIC paths validated"
done
echo "PASS five-site $mode: four distinct mTLS Client peers via eight Server WANs and one UDP listener"
for i in 0 1 2 3 4; do
  ip -n "${nodes[i]}" addr add "${loopback[i]}/32" dev lo
  if [[ "$mode" == scenario ]]; then
    ip -n "${nodes[i]}" addr add "${ospf_loopback[i]}/32" dev lo
  fi
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
  if [[ "$mode" == bgp || "$mode" == scenario ]]; then
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
  fi
  if [[ "$mode" == ospf || "$mode" == scenario ]]; then
    ospf_prefix="${loopback[i]}"
    if [[ "$mode" == scenario ]]; then ospf_prefix="${ospf_loopback[i]}"; fi
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
 network ${ospf_prefix}/32 area 0
!
EOF
  fi
done
chown frr:frr "$work"/site*.conf
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

# Daemons were started with explicit per-daemon -f files. Only create the
# vtysh configuration namespace AFTER they have loaded those configs:
# if frr.conf existed before startup, FRR could ignore -f and start
# without BGP/OSPF settings. Empty, FRR-valid comments avoid the
# misleading "Can't open vtysh.conf" / "frr.conf processing failure: 11"
# messages without hiding stderr or changing the running configuration.
for space in "${spaces[@]}"; do
  install -d -m 0750 -o frr -g frr "/etc/frr/$space"
  printf '!\n' >"/etc/frr/$space/vtysh.conf"
  printf '!\n' >"/etc/frr/$space/frr.conf"
  chown frr:frr "/etc/frr/$space/vtysh.conf" "/etc/frr/$space/frr.conf"
  chmod 0640 "/etc/frr/$space/vtysh.conf" "/etc/frr/$space/frr.conf"
done

# Query live daemon state as JSON and assert each expected neighbor
# individually. A nonempty summary/zero vtysh exit code alone could mask
# an Idle BGP peer or a 2-Way/Exchange OSPF adjacency.
for i in 0 1 2 3 4; do
  neighbors=()
  if (( i == 0 )); then
    neighbors=("${tunnel[@]:1}")
  else
    neighbors=("${tunnel[0]}")
  fi
  if [[ "$mode" == bgp ]]; then
    command="show bgp ipv4 unicast summary json"
  else
    command="show ip ospf neighbor json"
  fi
  if ! ip netns exec "${nodes[i]}" vtysh -N "${spaces[i]}" \
      -c "$command" >"$work/site$i-neighbors.json" 2>"$work/site$i-vtysh.log"; then
    fail "$mode live neighbor query failed at site$i"
  fi
  # Even warnings indicate that vtysh configuration is incomplete; never
  # discard them just to make an integration check appear green.
  [[ ! -s "$work/site$i-vtysh.log" ]] || fail "$mode vtysh configuration warning at site$i"
  python3 "$root/tests/integration/check_frr_neighbors.py" "$mode" \
    "$work/site$i-neighbors.json" "${neighbors[@]}" ||
    fail "$mode neighbor state assertion at site$i"
done
echo "PASS five-site $mode: all 8 expected bidirectional FRR adjacencies are Established/Full with clean vtysh configuration"

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
