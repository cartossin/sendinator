# Not fully tested yet; use with caution

# Sendinator

Chunked file sharing with progressive downloads.

## Features

- Chunked uploads (16MB default, configurable) with SHA-256 verification
- Zero third-party dependencies - pure Node.js
- Progressive downloads - recipients can start downloading before upload completes
- Resilient to network interruptions (infinite retry with backoff)
- No file size limits

## Install

```bash
git clone https://github.com/cartossin/sendinator.git
cd sendinator
npm install
```

## Run

```bash
node server.js
```

Listens on `http://localhost:3000`

## Run with PM2 (recommended for production)

```bash
npm install -g pm2
pm2 start server.js --name sendinator
pm2 save
pm2 startup
```

## Update

```bash
cd sendinator
git pull
npm install
pm2 restart sendinator
```

## nginx Setup (required)

nginx sits in front of Node.js and serves chunk files directly for low CPU usage.

```bash
# Install nginx
apt update && apt install -y nginx

# Run setup script
sudo ./setup-nginx.sh

# Restart sendinator
pm2 restart sendinator
```

nginx now listens on port 80. Point your reverse proxy (NPM, etc.) to this server's port 80.

**To disable nginx mode** (not recommended):
```bash
USE_NGINX_ACCEL=false pm2 restart sendinator
```

## Storage

Uploaded chunks are stored in `/var/lib/sendinator/uploads/` (configurable via `UPLOAD_DIR` env var).

## Admin Panel

Access at `/admin`. On first launch, you'll be prompted to create a passkey.

Features:
- View all uploads with completion status, size, date
- Search and sort uploads
- Delete uploads
- Copy download links

To reset passkey: delete `/var/lib/sendinator/passkey.json` and restart.

## TODO

### Admin Panel Improvements
- Clearer visibility of upload completion status (done vs incomplete)
- Stale upload warning (no new chunks received in X time)
- Download percentage indicator

### Upload Keys
- Admin can issue upload keys with bandwidth limits (e.g., "50GB one-time upload")
- Uploading requires a valid key
- Once bandwidth limit reached, upload is auto-deleted
- Prevents abuse, enables controlled sharing

### Upload Speed: Pipeline Architecture
- Separate workers for receiving, hashing, writing
- Decouple network I/O from CPU (hashing) from disk I/O
- Could improve upload throughput significantly

### Folder Upload: Tar Streaming
- Client creates tar stream on-the-fly (pure JS, no library)
- Tar is uncompressed - just concatenation with 512-byte headers
- Streams through existing chunked upload
- Download side: File System Access API writes files directly to disk
- Resume support via IndexedDB
- Browser support: Chrome, Edge, Opera

### Firefox/Safari Fallback
- Download: Fall back to direct browser download (single .tar file)
- Upload: Standard file picker (no folder upload until APIs improve)
