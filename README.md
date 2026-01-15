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

### 1. Install required packages

```bash
apt update && apt install -y git nodejs npm nginx
```

### 2. Clone and install

```bash
git clone https://github.com/cartossin/sendinator.git
cd sendinator
npm install
```

### 3. Set up nginx

nginx serves chunk files directly for better performance.

```bash
sudo ./setup-nginx.sh
```

### 4. Install PM2 and start

```bash
npm install -g pm2
pm2 start server.js --name sendinator
pm2 save
pm2 startup
```

The server is now running. nginx listens on port 80.

## Update

```bash
cd sendinator
git pull
npm install
pm2 restart sendinator
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `PORT` | 3000 | Node.js server port |
| `UPLOAD_DIR` | /var/lib/sendinator/uploads | Storage location |
| `USE_NGINX_ACCEL` | true | Use nginx X-Accel-Redirect |

To change settings:
```bash
USE_NGINX_ACCEL=false pm2 restart sendinator
```

## Admin Panel

Access at `/admin`. On first launch, create a passkey.

Features:
- Create upload keys with bandwidth quotas
- View all uploads with progress/status
- Delete uploads
- Copy download links

To reset passkey: delete `/var/lib/sendinator/passkey.json` and restart.

## TODO

- Stale upload warning (no new chunks received in X time)
- Upload pipeline optimization (separate workers for receive/hash/write)
