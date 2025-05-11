#!/bin/bash

set -e

CERT_DIR="./config"
CERT_PATH="$CERT_DIR/cert.pem"
KEY_PATH="$CERT_DIR/key.pem"

mkdir -p "$CERT_DIR"

# Use Dilithium3 for signature (NIST Round 3 approved)
echo "Generating PQ-safe self-signed TLS certificate with Dilithium3..."

openssl req -x509 -new -newkey dilithium3 -nodes \
  -keyout "$KEY_PATH" \
  -out "$CERT_PATH" \
  -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "PQ-safe certificate and key written to:"
echo "  $CERT_PATH"
echo "  $KEY_PATH"
