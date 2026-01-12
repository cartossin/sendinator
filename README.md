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

## TODO: Future Optimizations

### Upload Speed: Pipeline Architecture

Apply same buffering/pipeline approach used for downloads:
- Separate workers for receiving, hashing, writing
- Decouple network I/O from CPU (hashing) from disk I/O
- Could improve upload throughput significantly

### Folder Upload: Tar Streaming

Support uploading entire folders:
- Client creates tar stream on-the-fly (pure JS, no library)
- Tar is uncompressed - just concatenation with 512-byte headers, maximum speed
- Streams through existing chunked upload
- No temp storage needed on client

Download side:
- File System Access API (`showDirectoryPicker()`) lets user select destination folder
- JS parses tar stream and writes files directly to disk as they arrive
- Can handle millions of files - processes one at a time, memory stays flat
- Resume support: track `{ tarByteOffset, currentFilePath, bytesWritten }` in IndexedDB
- Browser support: Chrome, Edge, Opera

### Firefox/Safari Fallback

These browsers lack full File System Access API support:
- Download: Fall back to direct browser download (single .tar file) instead of JS streaming
- Upload: Standard file picker (no folder upload until APIs improve)

### Admin Panel & Upload Keys

Passkey-based admin authentication:
- On first launch, prompt to create a passkey (WebAuthn) stored by browser/OS
- Passkey grants access to admin panel
- No passwords to remember or leak
- To reset: delete the passkey file and restart (prompts for new passkey)

Upload key system:
- Admin can issue upload keys with bandwidth limits (e.g., "50GB one-time upload")
- Uploading requires a valid key
- Once bandwidth limit reached, upload is auto-deleted
- Prevents abuse, enables controlled sharing
