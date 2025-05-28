#!/usr/bin/env bash

set -euo pipefail

yq="yq"
jq="jq"
ssh_opts="-o BatchMode=yes -o ConnectTimeout=5"
remote_ca_cert="/etc/cichlid/tls/default/ca-cert.pem"
local_ca_cert="${1:-/etc/cichlid/tls/default/ca-cert.pem}"

if [[ ! -f "$local_ca_cert" ]]; then
    echo "ERROR: Local CA cert not found at $local_ca_cert"
    exit 1
fi

# Calculate local CA fingerprint
local_fpr=$(openssl x509 -noout -fingerprint -sha256 -in "$local_ca_cert" | cut -d'=' -f2 | tr -d ':')

# Discover hosts from assets/nodes.yml
hosts=( $($yq -r .[].hostname "$(dirname "$0")/../assets/nodes.yml") )

echo "Reference CA fingerprint: $local_fpr"
echo

ok=0
fail=0

for h in "${hosts[@]}"; do
    if [ "${h}" = "$(hostname -s)" ]; then
        continue
    fi
    echo -n "$h ... "
    # Try to fetch/print remote CA fingerprint
    fpr=$(ssh $ssh_opts "$h" "openssl x509 -noout -fingerprint -sha256 -in '$remote_ca_cert' 2>/dev/null | cut -d'=' -f2 | tr -d ':'" || true)
    if [[ -z "$fpr" ]]; then
        echo "ERROR: Could not read $remote_ca_cert on $h"
        fail=$((fail+1))
        continue
    fi
    if [[ "$fpr" = "$local_fpr" ]]; then
        echo "OK ($fpr)"
        ok=$((ok+1))
    else
        echo "MISMATCH ($fpr)"
        fail=$((fail+1))
    fi
done

echo
echo "Summary: $ok OK, $fail MISMATCH/ERROR"
exit $fail
