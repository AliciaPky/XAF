#!/bin/bash
set -e

# Create needed directories
mkdir -p /var/log/nginx
mkdir -p /var/log/modsecurity

# Set permissions
chmod 755 /var/log/nginx
chmod 755 /var/log/modsecurity

# Start nginx in foreground
/usr/local/nginx/sbin/nginx -g 'daemon off;'

