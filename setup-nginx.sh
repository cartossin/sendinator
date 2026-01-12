#!/bin/bash

# Sendinator nginx X-Accel-Redirect setup script
# This configures nginx to serve chunk files directly for low CPU usage

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPLOADS_DIR="$SCRIPT_DIR/uploads"
NGINX_CONF_NAME="sendinator-accel.conf"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================"
echo "Sendinator nginx X-Accel-Redirect Setup"
echo "========================================"
echo ""

# Generate the nginx config snippet
generate_config() {
    local uploads_path="$1"
    cat << EOF
# Sendinator X-Accel-Redirect configuration
# Internal location for serving chunk files directly
location /internal-chunks/ {
    internal;  # Cannot be accessed directly by clients
    alias $uploads_path/;

    # Disable gzip - chunks are binary data
    gzip off;

    # Optimize for large files
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
}
EOF
}

# Check if nginx is installed locally
if command -v nginx &> /dev/null; then
    echo -e "${GREEN}nginx found locally${NC}"
    echo ""

    # Detect nginx config directory
    if [ -d "/etc/nginx/sites-available" ]; then
        NGINX_CONF_DIR="/etc/nginx/sites-available"
        NGINX_ENABLED_DIR="/etc/nginx/sites-enabled"
        USE_SITES_AVAILABLE=true
    elif [ -d "/etc/nginx/conf.d" ]; then
        NGINX_CONF_DIR="/etc/nginx/conf.d"
        USE_SITES_AVAILABLE=false
    else
        echo -e "${RED}Could not find nginx config directory${NC}"
        echo "Please manually add the following to your nginx server block:"
        echo ""
        generate_config "$UPLOADS_DIR"
        exit 1
    fi

    echo "Uploads directory: $UPLOADS_DIR"
    echo "nginx config directory: $NGINX_CONF_DIR"
    echo ""

    # Check if we have write permissions
    if [ ! -w "$NGINX_CONF_DIR" ]; then
        echo -e "${YELLOW}No write permission to $NGINX_CONF_DIR${NC}"
        echo "Run this script with sudo, or manually add this config:"
        echo ""
        generate_config "$UPLOADS_DIR"
        exit 1
    fi

    # Check if config already exists
    if [ -f "$NGINX_CONF_DIR/$NGINX_CONF_NAME" ]; then
        echo -e "${YELLOW}Config file already exists: $NGINX_CONF_DIR/$NGINX_CONF_NAME${NC}"
        read -p "Overwrite? (y/n) " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Aborted."
            exit 0
        fi
    fi

    # Write the config
    echo "Writing nginx config..."
    generate_config "$UPLOADS_DIR" > "$NGINX_CONF_DIR/$NGINX_CONF_NAME"

    # Create symlink if using sites-available
    if [ "$USE_SITES_AVAILABLE" = true ] && [ ! -L "$NGINX_ENABLED_DIR/$NGINX_CONF_NAME" ]; then
        ln -sf "$NGINX_CONF_DIR/$NGINX_CONF_NAME" "$NGINX_ENABLED_DIR/$NGINX_CONF_NAME"
        echo "Created symlink in sites-enabled"
    fi

    # Test nginx config
    echo "Testing nginx configuration..."
    if nginx -t; then
        echo -e "${GREEN}nginx config test passed${NC}"

        # Reload nginx
        echo "Reloading nginx..."
        if systemctl reload nginx 2>/dev/null || service nginx reload 2>/dev/null || nginx -s reload; then
            echo -e "${GREEN}nginx reloaded successfully${NC}"
        else
            echo -e "${YELLOW}Could not reload nginx automatically. Please run: sudo nginx -s reload${NC}"
        fi
    else
        echo -e "${RED}nginx config test failed!${NC}"
        echo "Please check the configuration and fix any errors."
        exit 1
    fi

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Setup complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "IMPORTANT: You also need to add the internal-chunks location"
    echo "to your main server block. Add this inside your server { } block:"
    echo ""
    echo "    include $NGINX_CONF_DIR/$NGINX_CONF_NAME;"
    echo ""
    echo "Then reload nginx and start sendinator with:"
    echo ""
    echo "    USE_NGINX_ACCEL=true pm2 restart sendinator"
    echo ""

else
    # nginx not found locally - output config for remote setup
    echo -e "${YELLOW}nginx not found locally${NC}"
    echo ""
    echo "If nginx is on a remote server/container, add this configuration"
    echo "to your nginx server block:"
    echo ""
    echo "========================================"
    generate_config "$UPLOADS_DIR"
    echo "========================================"
    echo ""
    echo -e "${YELLOW}IMPORTANT:${NC}"
    echo "1. nginx must have read access to: $UPLOADS_DIR"
    echo "   (use shared storage, NFS, or bind mount)"
    echo ""
    echo "2. Add the above location block inside your server { } block"
    echo ""
    echo "3. Reload nginx: sudo nginx -s reload"
    echo ""
    echo "4. Start sendinator with X-Accel-Redirect enabled:"
    echo "   USE_NGINX_ACCEL=true pm2 restart sendinator"
    echo ""
    echo "   Or add to ecosystem.config.js:"
    echo "   env: { USE_NGINX_ACCEL: 'true' }"
    echo ""
fi
