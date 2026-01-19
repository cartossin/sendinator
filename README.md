# Sendinator

Chunked file sharing with progressive downloads.

## Features

- Chunked uploads (16MB default) with SHA-256 verification
- Progressive downloads - start downloading before upload completes
- Multi-file/folder upload as streaming ZIP archives
- Resilient to network interruptions (infinite retry with backoff)
- No file size limits
- Zero third-party runtime dependencies - pure Node.js

## Install

```bash
# Install required packages
apt update && apt install -y git nodejs npm nginx

# Clone and install
git clone https://github.com/cartossin/sendinator.git
cd sendinator
npm install

# Set up nginx (serves chunk files directly for better performance)
sudo ./setup-nginx.sh

# Install PM2 and start
npm install -g pm2
pm2 start server.js --name sendinator
pm2 save
pm2 startup
```

Done. nginx listens on port 80.

### Docker Alternative

```bash
git clone https://github.com/cartossin/sendinator.git
cd sendinator
docker compose up -d
```

Access at `http://localhost:3000`.

## Update

```bash
cd sendinator
git pull
npm install
pm2 restart sendinator
```

For Docker: `git pull && docker compose up -d --build`

## HTTPS Setup (required)

Sendinator requires HTTPS for the File System Access API used by managed downloads.

**Architecture:** Node.js (port 3000) → nginx (port 80) → reverse proxy (HTTPS)

### Option 1: Nginx Proxy Manager (recommended)

If you run [Nginx Proxy Manager](https://nginxproxymanager.com/) on your network:

1. Add a new proxy host pointing to this server's port 80 (or port 3000 for Docker)
2. Enable SSL with Let's Encrypt

### Option 2: Direct SSL on nginx

Edit `/etc/nginx/sites-available/sendinator` and add SSL configuration:

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    # ... rest of existing config ...
}
```

Use [certbot](https://certbot.eff.org/) for free Let's Encrypt certificates.

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `APP_NAME` | Sendinator | Application name in UI |
| `PORT` | 3000 | Node.js server port |
| `UPLOAD_DIR` | /var/lib/sendinator/uploads | Storage location |
| `USE_NGINX_ACCEL` | true | Use nginx X-Accel-Redirect |

To change settings:
```bash
APP_NAME="MyFileShare" USE_NGINX_ACCEL=false pm2 restart sendinator
```

For Docker, edit `docker-compose.yaml` environment section:
```yaml
environment:
  - APP_NAME=MyFileShare
  - PORT=3000
  # ...
```

Then rebuild: `docker compose up -d --build`

## Admin Panel

Access at `/admin`. On first launch, create a passkey.

Features:
- Create upload keys with bandwidth quotas
- View all uploads with progress/status
- Delete uploads
- Copy download links

To reset passkey: delete `/var/lib/sendinator/passkey.json` and restart.

## TODO

- Resume broken uploads
- Stale upload warning (no new chunks received in X time)
- Upload pipeline optimization (separate workers for receive/hash/write)
- Admin panel: upload timestamps, sortable columns, search/filter
- Brave browser: blocked by design (File System Access API disabled for privacy)

## License

MIT
