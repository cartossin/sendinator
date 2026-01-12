# Not fully tested yet; use with caution

# Sendinator

Chunked file sharing with progressive downloads.

## Features

- Chunked uploads (4MB chunks) with SHA-256 verification
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

```nginx
server {
    listen 443 ssl;
    server_name send.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Storage

Uploaded chunks are stored in `./uploads/`. Clean this directory periodically to free space.
