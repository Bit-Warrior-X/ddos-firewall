#!/bin/bash

set -e  # Exit on error

echo "Starting configuration backup..."

# Remove old backup if exists
rm -rf /tmp/config/

# Create backup directories
mkdir -p /tmp/config/
mkdir -p /tmp/config/nginx
mkdir -p /tmp/config/redis

# Backup nginx configuration
if [ -d "/usr/local/openresty/nginx/conf" ]; then
    echo "Backing up nginx configuration..."
    cp -r /usr/local/openresty/nginx/conf/* /tmp/config/nginx/
else
    echo "Warning: nginx config directory not found"
fi

# Backup firewall configuration
if [ -f "/usr/local/share/ebpf_firewall/firewall.config" ]; then
    echo "Backing up firewall.config..."
    cp /usr/local/share/ebpf_firewall/firewall.config /tmp/config/firewall.config
else
    echo "Warning: firewall.config not found"
fi

# Backup firewall control database
if [ -f "/usr/local/share/ebpf_firewall/firewall_control.db" ]; then
    echo "Backing up firewall_control.db..."
    cp /usr/local/share/ebpf_firewall/firewall_control.db /tmp/config/firewall_control.db
else
    echo "Warning: firewall_control.db not found"
fi

# Backup redis database
if [ -f "/var/lib/redis/dump.rdb" ]; then
    echo "Backing up redis database..."
    cp /var/lib/redis/dump.rdb /tmp/config/redis/dump.rdb
else
    echo "Warning: redis dump.rdb not found"
fi

echo "Configuration backup completed successfully!"
echo "Backup location: /tmp/config/"



