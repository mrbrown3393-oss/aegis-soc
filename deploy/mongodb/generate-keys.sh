#!/usr/bin/env bash
# Generate the WiredTiger encryption keyfile and self-signed TLS material
# for DEVELOPMENT/TESTING. Production: use your CA / KMIP, never self-signed.
set -euo pipefail

KEY_DIR="${1:-./keys}"
TLS_DIR="${2:-./tls}"
mkdir -p "$KEY_DIR" "$TLS_DIR"

# 1) WiredTiger encryption keyfile (base64 key material, 0600)
if [ ! -f "$KEY_DIR/mongodb-keyfile" ]; then
  openssl rand -base64 756 > "$KEY_DIR/mongodb-keyfile"
  chmod 400 "$KEY_DIR/mongodb-keyfile"
  echo "[+] Encryption keyfile: $KEY_DIR/mongodb-keyfile (store in secrets manager, DELETE local copy in prod)"
fi

# 2) TLS material for dev/test only
if [ ! -f "$TLS_DIR/mongodb.pem" ]; then
  openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
    -keyout "$TLS_DIR/ca.key" -out "$TLS_DIR/ca.pem" \
    -subj "/CN=AegisDevCA/O=Aegis SOC Dev"
  openssl req -newkey rsa:4096 -nodes \
    -keyout "$TLS_DIR/mongodb.key" -out "$TLS_DIR/mongodb.csr" \
    -subj "/CN=mongodb/O=Aegis SOC Dev"
  openssl x509 -req -in "$TLS_DIR/mongodb.csr" -days 365 -sha256 \
    -CA "$TLS_DIR/ca.pem" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
    -out "$TLS_DIR/mongodb.crt"
  cat "$TLS_DIR/mongodb.key" "$TLS_DIR/mongodb.crt" > "$TLS_DIR/mongodb.pem"
  chmod 400 "$TLS_DIR"/*.key "$TLS_DIR/mongodb.pem"
  echo "[+] Dev TLS material in $TLS_DIR (ca.pem, mongodb.pem)"
fi

echo "Next: point mongod at deploy/mongodb/mongod.conf and set MONGO_URL with tls=true&tlsCAFile=..."
