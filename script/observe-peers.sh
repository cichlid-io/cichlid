#!/usr/bin/env bash

sudo setfacl -m u:$(whoami):r /etc/cichlid/tls/default/key.pem
curl \
    --verbose \
    --cert /etc/cichlid/tls/default/cert.pem \
    --key /etc/cichlid/tls/default/key.pem \
    --cacert /etc/cichlid/tls/default/ca-cert.pem \
    --url https://10.49.1.101:29170/health