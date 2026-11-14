#!/usr/bin/env bash
# Real mTLS + QUIC + TUN failover across two independent Server daemons.
# Tests client-managed active_standby: primary dies, Client safely reconnects
# to standby without changing the TLS name or reusing an old TUN session.
set -euo pipefail
(( EUID == 0 )) || { echo "root/CAP_NET_ADMIN required" >&2; exit 2; }
for tool in ip ping openssl sha256sum timeout; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }
done
root="$(cd "$(dirname "$0")/../.." && pwd)"
[[ -x "$root/bin/mqvpn-server" && -x "$root/bin/mqvpn-client" ]] || {
  echo "build with make release first" >&2
  exit 2
}
work="$(mktemp -d)"
primary="mqhas1$$"
standby="mqhas2$$"
client="mqhac$$"
pids=()
cleanup() {
  code=$?
  trap - EXIT INT TERM
  if (( code != 0 )); then
    for log in "$work"/*.log; do
      [[ -f "$log" ]] || continue
      echo "---- $(basename "$log") ----" >&2
      tail -60 "$log" >&2 || true
    done
  fi
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  for node in "$client" "$primary" "$standby"; do
    if ip netns list | grep -q "^$node "; then
      while read -r pid; do [[ -z "$pid" ]] || kill "$pid" 2>/dev/null || true; done \
        < <(ip netns pids "$node" 2>/dev/null || true)
      ip netns del "$node" 2>/dev/null || true
    fi
  done
  rm -rf "$work"
  exit "$code"
}
trap cleanup EXIT INT TERM
fail() { echo "FAIL native HA: $*" >&2; exit 1; }

for node in "$client" "$primary" "$standby"; do
  ip netns add "$node"
  ip -n "$node" link set lo up
done
for n in 1 2; do
  if (( n == 1 )); then server="$primary"; else server="$standby"; fi
  ip link add "has$n$$" type veth peer name "hac$n$$"
  ip link set "has$n$$" netns "$server" name wan0
  ip link set "hac$n$$" netns "$client" name "wan$((n-1))"
  ip -n "$server" addr add "172.29.$n.1/30" dev wan0
  ip -n "$client" addr add "172.29.$n.2/30" dev "wan$((n-1))"
  ip -n "$server" link set wan0 up
  ip -n "$client" link set "wan$((n-1))" up
done
bash "$root/scripts/gen-dev-certs.sh" "$work/certs" vpn.ci.example \
  >"$work/certs.log" 2>&1
fingerprint="$(openssl x509 -in "$work/certs/client.crt" -outform DER |
  sha256sum | awk '{print $1}')"
cat >"$work/peers.yaml" <<EOF
peers:
  - id: site1
    certificate_sha256: "$fingerprint"
    routes: [10.77.0.2/32]
EOF
cat >"$work/server.yaml" <<EOF
listen: "0.0.0.0:8443"
instances:
  - name: shared-tenant
    server_name: vpn.ci.example
    tun: mq0
    address: 10.77.0.1/30
    mtu: 1400
    max_frame: 1414
    peers: "$work/peers.yaml"
    cert: "$work/certs/server.crt"
    key: "$work/certs/server.key"
    client_ca: "$work/certs/ca.crt"
    tc:
      mode: off
EOF
"$root/bin/mqvpn-server" validate --config "$work/server.yaml" \
  >"$work/validate.log" 2>&1 || fail "Server config validation"
for server in "$primary" "$standby"; do
  ip netns exec "$server" "$root/bin/mqvpn-server" \
    --config "$work/server.yaml" --reload-interval 0 \
    >"$work/$server.log" 2>&1 &
  pids+=("$!")
done
for attempt in $(seq 1 100); do
  if ip -n "$primary" link show mq0 >/dev/null 2>&1 &&
     ip -n "$standby" link show mq0 >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
ip -n "$primary" link show mq0 >/dev/null 2>&1 || fail "primary TUN not ready"
ip -n "$standby" link show mq0 >/dev/null 2>&1 || fail "standby TUN not ready"

cat >"$work/client.yaml" <<EOF
server: vpn.ci.example:8443
address: 10.77.0.2/30
transport: quic
reconnect: true
ca: "$work/certs/ca.crt"
cert: "$work/certs/client.crt"
key: "$work/certs/client.key"
tc:
  mode: off
ha:
  mode: active_standby
  controller: client
  backends: [172.29.1.1, 172.29.2.1]
EOF
ip netns exec "$client" "$root/bin/mqvpn-client" \
  --config "$work/client.yaml" >"$work/client.log" 2>&1 &
client_pid="$!"
pids+=("$client_pid")
ready=0
for attempt in $(seq 1 100); do
  if grep -q 'backend_index=1' "$work/client.log" &&
     ip netns exec "$client" ping -n -c 1 -W 1 10.77.0.1 >/dev/null 2>&1; then
    ready=1
    break
  fi
  kill -0 "$client_pid" 2>/dev/null || fail "Client exited before primary connected"
  sleep 0.2
done
(( ready )) || fail "Client could not establish a usable primary QUIC/TUN"
echo "PASS native HA: first Server tunnel established with authenticated tenant identity"

# Simulate a Server host failure, not a graceful Client reconnect.
kill "${pids[0]}" 2>/dev/null || true
wait "${pids[0]}" 2>/dev/null || true
recovered=0
# QUIC idle timeout is 30s; allow time for actual session expiry, cleanup,
# reconnect backoff and the backup TLS/CONNECT handshake on loaded CI hosts.
for attempt in $(seq 1 180); do
  if grep -q 'backend_index=2' "$work/client.log" &&
     ip netns exec "$client" ping -n -c 1 -W 1 10.77.0.1 >/dev/null 2>&1; then
    recovered=1
    break
  fi
  kill -0 "$client_pid" 2>/dev/null || fail "Client exited rather than recovering"
  sleep 0.5
done
(( recovered )) || fail "standby session not established after primary failed"
echo "PASS native HA: Server death caused a clean Client reconnect to backup QUIC/TUN"
