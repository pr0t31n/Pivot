#!/usr/bin/env bash
# =============================================================================
# tools/gen_certs.sh
#
# Generates a self-signed CA and TLS certificates for the Pivot agent.
# Optionally generates a client certificate for mTLS.
#
# Usage:
#   sudo bash tools/gen_certs.sh [OUTPUT_DIR] [AGENT_CN] [AGENT_IP]
#
# Defaults:
#   OUTPUT_DIR  = /etc/pivot/certs
#   AGENT_CN    = pivot-agent
#   AGENT_IP    = 192.168.1.5   (added as IP SAN so hostname verification works)
#
# Requirements: openssl (any modern version)
# =============================================================================

set -euo pipefail

# --- Configuration -----------------------------------------------------------
OUTPUT_DIR="${1:-/etc/pivot/certs}"
AGENT_CN="${2:-pivot-agent}"
AGENT_IP="${3:-192.168.1.5}"
DAYS_CA=3650       # 10 years for the CA
DAYS_LEAF=825      # ~2.25 years for leaf certs (Apple/browser limit)
KEY_BITS=4096

# --- Helpers -----------------------------------------------------------------
info()  { echo "[INFO]  $*"; }
warn()  { echo "[WARN]  $*" >&2; }
die()   { echo "[ERROR] $*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || die "openssl not found in PATH"

# --- Create output directory -------------------------------------------------
mkdir -p "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"
info "Output directory: $OUTPUT_DIR"

# --- 1. Generate CA key and self-signed certificate --------------------------
info "Generating CA key (${KEY_BITS}-bit RSA)..."
openssl genrsa -out "$OUTPUT_DIR/ca.key" "$KEY_BITS" 2>/dev/null

info "Generating CA certificate (valid ${DAYS_CA} days)..."
openssl req -new -x509 \
    -key  "$OUTPUT_DIR/ca.key" \
    -out  "$OUTPUT_DIR/ca.crt" \
    -days "$DAYS_CA" \
    -subj "/CN=Pivot CA/O=pivot/OU=PKI"

# --- 2. Generate agent (server) key and certificate signed by CA -------------
info "Generating agent key..."
openssl genrsa -out "$OUTPUT_DIR/agent.key" "$KEY_BITS" 2>/dev/null
chmod 600 "$OUTPUT_DIR/agent.key"

info "Generating agent CSR..."
openssl req -new \
    -key  "$OUTPUT_DIR/agent.key" \
    -out  "$OUTPUT_DIR/agent.csr" \
    -subj "/CN=${AGENT_CN}/O=pivot/OU=Agent"

# Build a SAN extension file so the cert works with hostname verification.
SAN_FILE="$(mktemp)"
cat > "$SAN_FILE" <<EOF
[req]
req_extensions = v3_req
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${AGENT_CN}
IP.1  = ${AGENT_IP}
EOF

info "Signing agent certificate (valid ${DAYS_LEAF} days, SAN=${AGENT_CN} / ${AGENT_IP})..."
openssl x509 -req \
    -in              "$OUTPUT_DIR/agent.csr" \
    -CA              "$OUTPUT_DIR/ca.crt" \
    -CAkey           "$OUTPUT_DIR/ca.key" \
    -CAcreateserial \
    -out             "$OUTPUT_DIR/agent.crt" \
    -days            "$DAYS_LEAF" \
    -extfile         "$SAN_FILE" \
    -extensions      v3_req 2>/dev/null

rm -f "$SAN_FILE" "$OUTPUT_DIR/agent.csr"

# --- 3. (Optional) Generate a client certificate for mTLS -------------------
info "Generating client key and certificate (for optional mTLS)..."
openssl genrsa -out "$OUTPUT_DIR/client.key" "$KEY_BITS" 2>/dev/null
chmod 600 "$OUTPUT_DIR/client.key"

openssl req -new \
    -key  "$OUTPUT_DIR/client.key" \
    -out  "$OUTPUT_DIR/client.csr" \
    -subj "/CN=pivot-client/O=pivot/OU=Client"

openssl x509 -req \
    -in              "$OUTPUT_DIR/client.csr" \
    -CA              "$OUTPUT_DIR/ca.crt" \
    -CAkey           "$OUTPUT_DIR/ca.key" \
    -CAcreateserial \
    -out             "$OUTPUT_DIR/client.crt" \
    -days            "$DAYS_LEAF" 2>/dev/null

rm -f "$OUTPUT_DIR/client.csr"

# --- 4. Print summary --------------------------------------------------------
info ""
info "Certificates generated successfully:"
info "  CA cert:      $OUTPUT_DIR/ca.crt"
info "  Agent cert:   $OUTPUT_DIR/agent.crt"
info "  Agent key:    $OUTPUT_DIR/agent.key  (keep secret!)"
info "  Client cert:  $OUTPUT_DIR/client.crt  (for mTLS; copy to scanner)"
info "  Client key:   $OUTPUT_DIR/client.key  (keep secret!)"
info ""
info "Distribution checklist:"
info "  Relay agent machine  -> ca.crt, agent.crt, agent.key"
info "  Scanner machine(s)   -> ca.crt  (+ client.crt/client.key if mTLS enabled)"
info ""
warn "The CA private key (ca.key) is not needed at runtime."
warn "Store it securely offline after certificate generation."
