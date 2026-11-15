#!/bin/sh
# Keepalived/VRRP health probe: 0 = Server is ready for new sessions.
# Expects server.yaml: ha: {readiness_listen: '127.0.0.1:9090'}
# Never curl the public VPN service address or call reload from here.
set -eu
exec curl --noproxy '*' --fail --silent --show-error \
  --connect-timeout 1 --max-time 1 \
  --output /dev/null http://127.0.0.1:9090/readyz
