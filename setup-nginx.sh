#!/bin/bash

# Sendinator nginx setup script
# Installs nginx config to proxy to Node.js with X-Accel-Redirect for chunk files

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPLOADS_DIR="/var/lib/sendinator/uploads"
NGINX_SITE_CONF="/etc/nginx/sites-available/sendinator"
NGINX_ENABLED_LINK="/etc/nginx/sites-enabled/sendinator"
NODE_PORT=3000

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "================================"
echo "Sendinator nginx Setup"
echo "================================"
echo ""

# Check if nginx is installed
if ! command -v nginx &> /dev/null; then
    echo -e "${RED}nginx is not installed${NC}"
    echo ""
    echo "Install it with:"
    echo "  apt update && apt install -y nginx"
    echo ""
    echo "Then run this script again."
    exit 1
fi

echo -e "${GREEN}nginx found${NC}"
echo "Uploads directory: $UPLOADS_DIR"
echo ""

# Check permissions
if [ ! -w "/etc/nginx/sites-available" ]; then
    echo -e "${RED}No write permission. Run with sudo:${NC}"
    echo "  sudo ./setup-nginx.sh"
    exit 1
fi

# Create uploads directory with proper permissions
echo "Creating uploads directory..."
mkdir -p "$UPLOADS_DIR"
chown www-data:www-data "$UPLOADS_DIR"
chmod 755 "$UPLOADS_DIR"
echo -e "${GREEN}Created: $UPLOADS_DIR (owned by www-data)${NC}"

# Create the nginx config
echo "Creating nginx config..."

cat > "$NGINX_SITE_CONF" << EOF
# Sendinator nginx configuration
# Proxies to Node.js with X-Accel-Redirect for efficient chunk serving

server {
    listen 80;
    listen [::]:80;
    server_name _;

    # Max upload size (chunk size + overhead)
    client_max_body_size 20M;

    # Proxy to Node.js
    location / {
        proxy_pass http://127.0.0.1:${NODE_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Timeouts for large uploads
        proxy_connect_timeout 60s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }

    # Internal location for X-Accel-Redirect (chunk downloads)
    # Node.js sends X-Accel-Redirect header, nginx serves file directly
    location /internal-chunks/ {
        internal;
        alias ${UPLOADS_DIR}/;

        # Optimize for large file serving
        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;

        # No gzip for binary data
        gzip off;
    }
}
EOF

echo -e "${GREEN}Created: $NGINX_SITE_CONF${NC}"

# Enable the site
if [ -L "$NGINX_ENABLED_LINK" ]; then
    rm "$NGINX_ENABLED_LINK"
fi
ln -s "$NGINX_SITE_CONF" "$NGINX_ENABLED_LINK"
echo -e "${GREEN}Enabled site${NC}"

# Disable default site if it exists and conflicts
if [ -L "/etc/nginx/sites-enabled/default" ]; then
    rm "/etc/nginx/sites-enabled/default"
    echo "Disabled default nginx site"
fi

# Test nginx config
echo ""
echo "Testing nginx configuration..."
if nginx -t 2>&1; then
    echo -e "${GREEN}Config test passed${NC}"
else
    echo -e "${RED}Config test failed!${NC}"
    exit 1
fi

# Reload nginx
echo "Reloading nginx..."
if systemctl reload nginx 2>/dev/null; then
    echo -e "${GREEN}nginx reloaded${NC}"
elif service nginx reload 2>/dev/null; then
    echo -e "${GREEN}nginx reloaded${NC}"
else
    nginx -s reload
    echo -e "${GREEN}nginx reloaded${NC}"
fi

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Setup complete!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo "nginx is now listening on port 80 and proxying to Node.js on port ${NODE_PORT}."
echo "Chunk downloads use X-Accel-Redirect for low CPU usage."
echo ""
echo "Point your reverse proxy (NPM) to this server's port 80."
echo ""
echo "Start sendinator:"
echo "  pm2 restart sendinator"
echo ""
