#!/bin/bash
# firewall-exception.sh
# Open the cichlid TLS port (default: 29170) in the system firewall

set -e

PORT="${1:-29170}"
SERVICE="cichlid"

if ! command -v firewall-cmd &> /dev/null && ! command -v ufw &> /dev/null; then
    echo "No supported firewall tool (firewalld or ufw) found." >&2
    exit 1
fi

echo "Opening TCP port $PORT for cichlid service..."

if command -v firewall-cmd &> /dev/null; then
    sudo firewall-cmd --add-port="${PORT}/tcp" --permanent
    sudo firewall-cmd --reload
    echo "firewalld: Opened TCP port $PORT (permanent)."
fi

if command -v ufw &> /dev/null; then
    sudo ufw allow "$PORT"/tcp comment "Allow cichlid TLS server"
    echo "ufw: Opened TCP port $PORT."
fi

echo "Firewall rules updated to allow TCP port $PORT for cichlid service."

exit 0
