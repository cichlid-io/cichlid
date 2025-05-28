#!/usr/bin/env bash

port=29170
declare -a nodes=()
nodes+=( gramathea )

# CA cert/key location (generated/refreshed once)
default_ca_cert_path=/etc/cichlid/tls/default/ca-cert.pem
default_ca_key_path=/etc/cichlid/tls/default/ca-key.pem
local_default_cert_path=/etc/cichlid/tls/default/cert.pem
local_default_key_path=/etc/cichlid/tls/default/key.pem

if [[ "$*" == *"--overwrite-ca-cert"* || ! -f "${default_ca_cert_path}" || ! -f "${default_ca_key_path}" ]]; then
    sudo mkdir -p $(dirname ${default_ca_cert_path})
    sudo mkdir -p $(dirname ${default_ca_key_path})

    if sudo ~/git/cichlid/cichlid/target/release/cichlid gen-ca \
        --ca-cert-path ${default_ca_cert_path} \
        --ca-key-path ${default_ca_key_path}; then
        echo "default ca cert/key pair generated"
        echo "- file://${default_ca_cert_path}"
        echo "- file://${default_ca_key_path}"
    else
        echo "failed to generate default ca cert/key pair"
        echo "- file://${default_ca_cert_path}"
        echo "- file://${default_ca_key_path}"
    fi
fi
if [[ "$*" == *"--overwrite-ca-cert"* || "$*" == *"--overwrite-local-cert"* || ! -f "${local_default_cert_path}" || ! -f "${local_default_key_path}" ]]; then
    # generate a CA-signed default cert/key pair for local node
    if sudo ~/git/cichlid/cichlid/target/release/cichlid gen-certs \
        --cert-path ${local_default_cert_path} \
        --key-path ${local_default_key_path} \
        --ca-cert-path ${default_ca_cert_path} \
        --ca-key-path ${default_ca_key_path} \
        && sudo setfacl -m u:cichlid:r ${local_default_key_path}; then
        echo "default ca-signed cert/key pair for node (local) generated"
        echo "- file://${local_default_cert_path}"
        echo "- file://${local_default_key_path}"
    else
        echo "failed to generate default ca-signed cert/key pair for node (local)"
        echo "- file://${local_default_cert_path}"
        echo "- file://${local_default_key_path}"
    fi
fi
sudo ~/git/cichlid/cichlid/target/release/cichlid install --overwrite

for node in "${nodes[@]}"; do
    echo "deploying to ${node}"

    node_cert_path=/etc/cichlid/tls/${node}/cert.pem
    node_key_path=/etc/cichlid/tls/${node}/key.pem

    sudo mkdir -p $(dirname ${node_cert_path})
    sudo mkdir -p $(dirname ${node_key_path})

    # generate a CA-signed cert/key pair for remote node
    if [[ "$*" == *"--overwrite-ca-cert"* || "$*" == *"--overwrite-remote-cert"* || ! -f "${node_cert_path}" || ! -f "${node_key_path}" ]]; then
        if sudo ~/git/cichlid/cichlid/target/release/cichlid gen-certs \
            --cert-path ${node_cert_path} \
            --key-path ${node_key_path} \
            --ca-cert-path ${default_ca_cert_path} \
            --ca-key-path ${default_ca_key_path}; then
            echo "default ca-signed cert/key pair for node (${node}) generated"
            echo "- file://${node_cert_path}"
            echo "- file://${node_key_path}"
            sudo setfacl -m u:$(whoami):r ${node_key_path}
        else
            echo "failed to generate default ca-signed cert/key pair for node (${node})"
            echo "- file://${node_cert_path}"
            echo "- file://${node_key_path}"
        fi
    else
        echo "default ca-signed cert/key pair for node (${node}) observed"
        echo "- file://${node_cert_path}"
        echo "- file://${node_key_path}"
        sudo setfacl -m u:$(whoami):r ${node_key_path}
    fi

    # rsync cert, key, and ca cert to node's default cert dir
    if ssh ${node} "sudo mkdir -p /etc/cichlid/tls/default"; then
        echo "default cert path created on node: ${node}"
        for pem in ${node_cert_path} ${node_key_path} ${default_ca_cert_path}; do
            if rsync --archive --compress --quiet --rsync-path 'sudo rsync' ${pem} ${node}:/etc/cichlid/tls/default/; then
                echo "$(basename ${pem}) sync'd to node: ${node}"
            else
                echo "failed to sync $(basename ${pem}) to node: ${node}"
            fi
        done
    else
        echo "failed to create default cert path on node: ${node}"
    fi
    sudo setfacl -b ${node_key_path}

    # install cichlid (will not overwrite cert/key!)
    if rsync --archive --compress --quiet ~/git/cichlid/cichlid/target/release/cichlid ${node}:/tmp/cichlid \
        && ssh ${node} "sudo /tmp/cichlid install --overwrite && sudo setfacl -m u:cichlid:r /etc/cichlid/tls/default/key.pem && rm /tmp/cichlid"; then
        echo "cichlid installed on node: ${node}"
    else
        echo "failed to install cichlid on node: ${node}"
    fi
    if ssh ${node} "sudo firewall-cmd \
        --zone=FedoraServer \
        --add-port=${port}/tcp \
        --permanent \
        && sudo firewall-cmd --reload"; then
        echo "firewall exception added for cichlid (${port}/tcp) on node: ${node}"
    else
        echo "failed to add firewall exception for cichlid (${port}/tcp) on node: ${node}"
    fi
done
