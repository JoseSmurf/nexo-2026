#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CERT_DIR="${ROOT_DIR}/staging/certs"

mkdir -p "${CERT_DIR}"
rm -f "${CERT_DIR}"/*.crt "${CERT_DIR}"/*.key "${CERT_DIR}"/*.csr "${CERT_DIR}"/*.srl

openssl req -x509 -nodes -newkey rsa:4096 \
  -keyout "${CERT_DIR}/ca.key" \
  -out "${CERT_DIR}/ca.crt" \
  -days 3650 \
  -subj "/CN=nexo-staging-ca"

openssl req -nodes -newkey rsa:2048 \
  -keyout "${CERT_DIR}/server.key" \
  -out "${CERT_DIR}/server.csr" \
  -subj "/CN=localhost"

openssl x509 -req \
  -in "${CERT_DIR}/server.csr" \
  -CA "${CERT_DIR}/ca.crt" \
  -CAkey "${CERT_DIR}/ca.key" \
  -CAcreateserial \
  -out "${CERT_DIR}/server.crt" \
  -days 825 \
  -sha256

openssl req -nodes -newkey rsa:2048 \
  -keyout "${CERT_DIR}/client.key" \
  -out "${CERT_DIR}/client.csr" \
  -subj "/CN=client-a"

openssl x509 -req \
  -in "${CERT_DIR}/client.csr" \
  -CA "${CERT_DIR}/ca.crt" \
  -CAkey "${CERT_DIR}/ca.key" \
  -CAcreateserial \
  -out "${CERT_DIR}/client.crt" \
  -days 825 \
  -sha256

echo "Certificates generated under ${CERT_DIR}"
