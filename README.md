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

## Reverse Proxy (nginx)

### Basic Setup

```nginx
server {
    listen 443 ssl;
    server_name send.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    client_max_body_size 20M;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Low-CPU Mode (X-Accel-Redirect)

For high-performance deployments, enable nginx to serve chunk files directly. This reduces Node.js CPU usage by 10-20x.

**Setup:**
```bash
# Run the setup script (or see output for remote nginx)
sudo ./setup-nginx.sh

# Add the include to your nginx server block:
# include /etc/nginx/sites-available/sendinator-accel.conf;

# Reload nginx
sudo nginx -s reload

# Start sendinator with X-Accel-Redirect enabled
USE_NGINX_ACCEL=true pm2 restart sendinator
```

**How it works:**
- Node.js handles auth and tracking only (near-zero CPU)
- nginx serves chunk files directly using kernel-level `sendfile()`
- Requires nginx to have read access to the uploads folder

## Storage

Uploaded chunks are stored in `./uploads/`. Files are automatically cleaned up after 24 hours.

## TODO: Future Optimizations

### Upload Speed: Pipeline Architecture

Apply same buffering/pipeline approach used for downloads:
- Separate workers for receiving, hashing, writing
- Decouple network I/O from CPU (hashing) from disk I/O
- Could improve upload throughput significantly

### Folder Upload: Tar Streaming

Support uploading entire folders:
- Client creates tar stream on-the-fly
- Streams through existing chunked upload
- Download extracts tar or offers as archive
- No temp storage needed on client
