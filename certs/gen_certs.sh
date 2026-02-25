#!/usr/bin/env bash
# gen_certs.sh — Generates all certificates needed for the mTLS lab
# Run from the project root: bash certs/gen_certs.sh
set -euo pipefail

CERTS_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> [1/6] Generating CA private key..."
openssl genrsa -out "${CERTS_DIR}/ca.key" 4096

echo "==> [2/6] Generating self-signed CA certificate (10-year validity)..."
openssl req \
  -new -x509 \
  -days 3650 \
  -key  "${CERTS_DIR}/ca.key" \
  -out  "${CERTS_DIR}/ca.crt" \
  -config "${CERTS_DIR}/ca.cnf"

echo "==> [3/6] Generating server private key and CSR..."
openssl genrsa -out "${CERTS_DIR}/server.key" 2048
openssl req \
  -new \
  -key    "${CERTS_DIR}/server.key" \
  -out    "${CERTS_DIR}/server.csr" \
  -config "${CERTS_DIR}/server.cnf"

echo "==> [4/6] Signing server certificate with CA (serverAuth EKU + SAN)..."
openssl x509 \
  -req \
  -days 365 \
  -in   "${CERTS_DIR}/server.csr" \
  -CA   "${CERTS_DIR}/ca.crt" \
  -CAkey "${CERTS_DIR}/ca.key" \
  -CAcreateserial \
  -out  "${CERTS_DIR}/server.crt" \
  -extensions v3_server \
  -extfile "${CERTS_DIR}/server.cnf"

echo "==> [5/6] Generating client private key and CSR..."
openssl genrsa -out "${CERTS_DIR}/client.key" 2048
openssl req \
  -new \
  -key    "${CERTS_DIR}/client.key" \
  -out    "${CERTS_DIR}/client.csr" \
  -config "${CERTS_DIR}/client.cnf"

echo "==> [6/6] Signing client certificate with CA (clientAuth EKU)..."
openssl x509 \
  -req \
  -days 365 \
  -in   "${CERTS_DIR}/client.csr" \
  -CA   "${CERTS_DIR}/ca.crt" \
  -CAkey "${CERTS_DIR}/ca.key" \
  -CAcreateserial \
  -out  "${CERTS_DIR}/client.crt" \
  -extensions v3_client \
  -extfile "${CERTS_DIR}/client.cnf"

echo ""
echo "==> Certificate generation complete. Files created:"
ls -1 "${CERTS_DIR}"/*.{crt,key,csr} 2>/dev/null

echo ""
echo "==> Verifying server certificate chain..."
openssl verify -CAfile "${CERTS_DIR}/ca.crt" "${CERTS_DIR}/server.crt"

echo "==> Verifying client certificate chain..."
openssl verify -CAfile "${CERTS_DIR}/ca.crt" "${CERTS_DIR}/client.crt"

echo ""
echo "All certificates generated and verified successfully."
