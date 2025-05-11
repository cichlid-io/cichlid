#!/bin/bash

set -e

CERT_DIR="./config"
CERT_PATH="$CERT_DIR/cert.pem"
KEY_PATH="$CERT_DIR/key.pem"

mkdir -p "$CERT_DIR"

echo "Generating self-signed TLS certificate..."
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout "$KEY_PATH" \
  -out "$CERT_PATH" \
  -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "Certificate and key written to:"
echo "  $CERT_PATH"
echo "  $KEY_PATH"
