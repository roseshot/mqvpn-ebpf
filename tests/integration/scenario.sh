#!/usr/bin/env bash
# One reproducible, fail-fast Linux VPN integration scenario.
# Focused legacy probes retain isolated network fixtures for WAN impairment,
# while the final five-site stage shares one TUN/QUIC topology for BGP, OSPF,
# TCP, UDP and voice traffic. No test uses fake VPN packet devices.
set -Eeuo pipefail
(( EUID == 0 )) || { echo "run this scenario as root (CAP_NET_ADMIN required)" >&2; exit 2; }
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
WAN_SEED="${WAN_SEED:-20261115}"
[[ "$WAN_SEED" =~ ^[0-9]+$ ]] || { echo "WAN_SEED must be numeric" >&2; exit 2; }
export WAN_SEED

phase="preflight"
trap 'printf "FAIL unified VPN integration scenario: phase=%s WAN_SEED=%s\n" "$phase" "$WAN_SEED" >&2' ERR

run_phase() {
  phase="$1"
  shift
  echo "::group::$phase"
  printf '=== Integration phase: %s (WAN_SEED=%s) ===\n' "$phase" "$WAN_SEED"
  "$@"
  echo "::endgroup::"
}
for tool in go make clang git ip ping modprobe python3 openssl timeout \
            tc ss iperf3 tcpdump tshark haproxy; do
  command -v "$tool" >/dev/null || { echo "missing dependency: $tool" >&2; exit 2; }
done
for daemon in zebra bgpd ospfd; do
  [[ -x "/usr/lib/frr/$daemon" ]] || { echo "missing FRRouting daemon: $daemon" >&2; exit 2; }
done

run_phase "Prepare kernel TUN/VXLAN modules" bash -c '
  modprobe tun || true
  modprobe vxlan || true
  test -c /dev/net/tun
'
for script in tests/integration/overlay-netns.sh tests/integration/five-site-frr.sh \
              tests/integration/scenario.sh scripts/mqvpn-ready.sh; do
  run_phase "Shell syntax: $script" bash -n "$script"
done
run_phase "Python syntax" python3 -m py_compile \
  tests/integration/transport_probe.py tests/integration/wan_probe.py \
  tests/integration/wire_crypto_probe.py tests/integration/verify_wire_crypto.py \
  tests/integration/verify_sticky_wire.py tests/integration/check_frr_neighbors.py \
  tests/integration/test_frr_neighbors.py
run_phase "FRR neighbor parser regressions" python3 -m unittest discover \
  -s tests/integration -p test_frr_neighbors.py -v
run_phase "HAProxy TCP ingress configuration validation" bash -c '
  haproxy -c -f configs/haproxy-mqvpn-active-active-tcp.cfg
  haproxy -c -f configs/haproxy-mqvpn-active-standby-tcp.cfg
'

run_phase "Build embedded XDP and TCX eBPF objects" make bpf
run_phase "Compare regenerated ELF objects to repository" git diff --exit-code -- \
  internal/tcebpf/objects/tun_tc.o internal/xdp/objects/xdp_mqvpn.o
run_phase "Kernel TCX MSS rewrite and checksums" env CGO_ENABLED=0 \
  go test -mod=readonly -tags bpf_integration -run '^TestKernel' -v ./internal/tcebpf
run_phase "Kernel TUN connected routes" env CGO_ENABLED=0 \
  go test -mod=readonly -tags tun_integration -run '^TestIntegration' -v ./internal/tun
run_phase "Build Server and Client from the tested eBPF objects" make release

# The legacy two-site probes are focused security, WAN-impairment and
# encapsulation phases of this ONE integration scenario, not separate CI
# scenario invocations. Every child tears down its own namespace fixture.
overlay_modes=(
  crypto-wan4 crypto-tcp wan4 wan4-latency wan4-sticky
  vxlan tcp udp voip mixed wan-regional wan-poor
)
for mode in "${overlay_modes[@]}"; do
  run_phase "Two-site $mode" bash tests/integration/overlay-netns.sh "$mode"
done

# The final five-site phase is ONE persistent VPN fixture: four independent
# mTLS peers, randomized 1..8 WANs, concurrent BGP and OSPF with disjoint
# destination prefixes, and Client-to-Client TCP/UDP/VoIP payload checks.
run_phase "Five-site unified BGP+OSPF multi-WAN TCP/UDP/VoIP" \
  bash tests/integration/five-site-frr.sh scenario

phase="complete"
echo "PASS unified VPN integration scenario: WAN_SEED=$WAN_SEED"
