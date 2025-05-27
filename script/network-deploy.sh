#!/bin/bash

port=29170

declare -a nodes=()
nodes+=( gramathea )

for node in "${nodes[@]}"; do
    echo "deploying to ${node}"
    if rsync \
        --archive \
        --compress \
        --quiet \
        ~/git/cichlid/cichlid/target/release/cichlid \
        ${node}:/tmp/cichlid; then
        echo "cichlid binary sync'd to node: ${node}"
    else
        echo "failed to sync cichlid binary to node: ${node}"
        continue
    fi
    if ssh ${node} "sudo /tmp/cichlid install --overwrite && rm /tmp/cichlid"; then
        echo "cichlid installed on node: ${node}"
    else
        echo "failed to install cichlid on node: ${node}"
        continue
    fi
    if ssh ${node} "sudo firewall-cmd \
        --zone=FedoraServer \
        --add-port=${port}/tcp \
        --permanent \
        && sudo firewall-cmd --reload"; then
        echo "firewall exception added for cichlid (${port}/tcp) on node: ${node}"
    else
        echo "failed to add firewall exception for cichlid (${port}/tcp) on node: ${node}"
        continue
    fi
done
