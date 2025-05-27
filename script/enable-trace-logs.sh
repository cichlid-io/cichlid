#!/bin/bash

sudo systemctl stop cichlid.service
sudo mkdir -p /etc/systemd/system/cichlid.service.d
sudo tee /etc/systemd/system/cichlid.service.d/enable-trace-logging.conf <<EOF
[Service]
Environment=RUST_LOG=trace
EOF
sudo systemctl daemon-reload
sudo systemctl start cichlid.service
