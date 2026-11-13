#!/usr/bin/env bash
# Test-only CA. Do not reuse these keys or certs for a real VPN deployment.
set -euo pipefail
OUT="$1"
SERVER_NAME="$2"
: "$OUT"
: "$SERVER_NAME"
mkdir -p "$OUT"
umask 077
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$OUT/ca.key" -out "$OUT/ca.crt" -days 7 \
  -subj "/CN=mqvpn-dev-CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$OUT/server.key" -out "$OUT/server.csr" -subj "/CN=$SERVER_NAME"
printf 'subjectAltName=DNS:%s,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\n' "$SERVER_NAME" > "$OUT/server.ext"
openssl x509 -req -in "$OUT/server.csr" -CA "$OUT/ca.crt" \
  -CAkey "$OUT/ca.key" -CAcreateserial -out "$OUT/server.crt" \
  -days 7 -extfile "$OUT/server.ext"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$OUT/client.key" -out "$OUT/client.csr" -subj "/CN=mqvpn-client"
printf 'extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\n' > "$OUT/client.ext"
openssl x509 -req -in "$OUT/client.csr" -CA "$OUT/ca.crt" \
  -CAkey "$OUT/ca.key" -CAcreateserial -out "$OUT/client.crt" \
  -days 7 -extfile "$OUT/client.ext"
rm -f "$OUT/server.csr" "$OUT/client.csr" "$OUT/server.ext" "$OUT/client.ext"
echo "TEST-ONLY certificates generated in $OUT"
