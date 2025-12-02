#!/bin/bash

set -e  # Exit on error

echo "Starting configuration restore..."

# Check if backup exists
if [ ! -d "/tmp/config" ]; then
    echo "Error: Backup directory /tmp/config not found!"
    exit 1
fi

# Restore nginx configuration
if [ -d "/tmp/config/nginx" ] && [ "$(ls -A /tmp/config/nginx)" ]; then
    echo "Restoring nginx configuration..."
    mkdir -p /usr/local/openresty/nginx/conf
    cp -rf /tmp/config/nginx/* /usr/local/openresty/nginx/conf/
else
    echo "Warning: nginx backup not found, skipping..."
fi

# Restore firewall configuration
if [ -f "/tmp/config/firewall.config" ]; then
    echo "Restoring firewall.config..."
    mkdir -p /usr/local/share/ebpf_firewall
    cp -f /tmp/config/firewall.config /usr/local/share/ebpf_firewall/firewall.config
else
    echo "Warning: firewall.config backup not found, skipping..."
fi

# Restore firewall control database
if [ -f "/tmp/config/firewall_control.db" ]; then
    echo "Restoring firewall_control.db..."
    mkdir -p /usr/local/share/ebpf_firewall
    cp -f /tmp/config/firewall_control.db /usr/local/share/ebpf_firewall/firewall_control.db
else
    echo "Warning: firewall_control.db backup not found, skipping..."
fi

# Restore redis database
if [ -f "/tmp/config/redis/dump.rdb" ]; then
    echo "Restoring redis database..."
    mkdir -p /var/lib/redis
    cp -f /tmp/config/redis/dump.rdb /var/lib/redis/dump.rdb
else
    echo "Warning: redis dump.rdb backup not found, skipping..."
fi

echo "Configuration restore completed successfully!"