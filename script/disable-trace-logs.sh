#!/bin/bash

sudo systemctl stop cichlid.service
sudo rm /etc/systemd/system/cichlid.service.d/enable-trace-logging.conf
sudo systemctl daemon-reload
sudo systemctl start cichlid.service
