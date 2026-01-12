import http from 'http';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// === CONFIGURATION ===
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = process.env.UPLOAD_DIR || '/var/lib/sendinator/uploads';
const PUBLIC_DIR = path.join(__dirname, 'public');
const CHUNK_SIZE = 16 * 1024 * 1024;        // 16MB chunks (can change for new uploads)
const TARGET_BUFFER_MEMORY = 100 * 1024 * 1024; // 100MB target buffer memory for clients
const USE_NGINX_ACCEL = process.env.USE_NGINX_ACCEL !== 'false'; // nginx X-Accel-Redirect (default: on)

// MIME types for static files
const MIME_TYPES = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.ico': 'image/x-icon'
};

// Ensure upload directory exists
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// In-memory store for file metadata (loaded from disk on startup)
const files = new Map();

// Load existing files from disk on startup
function loadFilesFromDisk() {
    if (!fs.existsSync(UPLOAD_DIR)) return;
    const dirs = fs.readdirSync(UPLOAD_DIR);
    for (const id of dirs) {
        const metaPath = path.join(UPLOAD_DIR, id, 'meta.json');
        if (fs.existsSync(metaPath)) {
            try {
                const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));

                // Scan for actual chunk files instead of trusting meta.chunksReceived
                const fileDir = path.join(UPLOAD_DIR, id);
                const chunkFiles = fs.readdirSync(fileDir).filter(f => f.startsWith('chunk_'));
                const actualChunks = new Set();
                for (const f of chunkFiles) {
                    const idx = parseInt(f.replace('chunk_', ''), 10);
                    if (!isNaN(idx)) actualChunks.add(idx);
                }

                // Use actual chunks found on disk
                meta.chunksReceived = actualChunks;
                files.set(id, meta);

                const status = actualChunks.size === meta.totalChunks ? 'complete' : `${actualChunks.size}/${meta.totalChunks}`;
                console.log(`Loaded: ${id} - ${meta.filename} (${status})`);
            } catch (err) {
                console.error(`Failed to load ${id}:`, err.message);
            }
        }
    }
    console.log(`Loaded ${files.size} files from disk`);
}

// Save file metadata to disk
function saveMetadata(id, fileInfo) {
    const metaPath = path.join(UPLOAD_DIR, id, 'meta.json');
    const toSave = {
        ...fileInfo,
        chunksReceived: Array.from(fileInfo.chunksReceived)
    };
    fs.writeFileSync(metaPath, JSON.stringify(toSave));
}

// Helper: Send JSON response
function sendJson(res, statusCode, data) {
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
}

// Helper: Read JSON body from request
function readJsonBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                resolve(JSON.parse(body));
            } catch (err) {
                reject(err);
            }
        });
        req.on('error', reject);
    });
}

// Helper: Serve static file
async function serveStatic(res, filePath) {
    try {
        const ext = path.extname(filePath);
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';
        const stat = await fs.promises.stat(filePath);
        res.writeHead(200, {
            'Content-Type': contentType,
            'Content-Length': stat.size
        });
        fs.createReadStream(filePath).pipe(res);
    } catch (err) {
        res.writeHead(404);
        res.end('Not found');
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// === REQUEST HANDLER ===
const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const pathname = url.pathname;
    const method = req.method;

    try {
        // GET /api/config
        if (method === 'GET' && pathname === '/api/config') {
            return sendJson(res, 200, {
                chunkSize: CHUNK_SIZE,
                targetBufferMemory: TARGET_BUFFER_MEMORY
            });
        }

        // POST /api/create
        if (method === 'POST' && pathname === '/api/create') {
            const body = await readJsonBody(req);
            const { filename, size, totalChunks } = body;

            if (!filename || !size || !totalChunks) {
                return sendJson(res, 400, { error: 'Missing required fields' });
            }

            const id = crypto.randomBytes(4).toString('hex');
            const fileDir = path.join(UPLOAD_DIR, id);
            fs.mkdirSync(fileDir, { recursive: true });

            const fileInfo = {
                id,
                filename,
                size,
                totalChunks,
                chunkSize: CHUNK_SIZE,
                chunkHashes: new Array(totalChunks).fill(null),
                chunksReceived: new Set(),
                createdAt: Date.now()
            };

            files.set(id, fileInfo);
            saveMetadata(id, fileInfo);

            console.log(`Created file: ${id} - ${filename} (${formatBytes(size)}, ${totalChunks} chunks)`);
            return sendJson(res, 200, { id, url: `/download/${id}` });
        }

        // POST /api/chunk/:id/:index
        const chunkUploadMatch = pathname.match(/^\/api\/chunk\/([a-f0-9]+)\/(\d+)$/);
        if (method === 'POST' && chunkUploadMatch) {
            const id = chunkUploadMatch[1];
            const chunkIndex = parseInt(chunkUploadMatch[2], 10);
            const expectedHash = req.headers['x-chunk-hash'];

            const fileInfo = files.get(id);
            if (!fileInfo) {
                return sendJson(res, 404, { error: 'File not found' });
            }

            if (chunkIndex < 0 || chunkIndex >= fileInfo.totalChunks) {
                return sendJson(res, 400, { error: 'Invalid chunk index' });
            }

            const chunks = [];
            const hash = crypto.createHash('sha256');

            req.on('data', (chunk) => {
                chunks.push(chunk);
                hash.update(chunk);
            });

            req.on('end', () => {
                try {
                    const data = Buffer.concat(chunks);
                    const computedHash = hash.digest('hex');

                    if (expectedHash && computedHash !== expectedHash) {
                        return sendJson(res, 400, {
                            error: 'Hash mismatch',
                            expected: expectedHash,
                            got: computedHash
                        });
                    }

                    const chunkPath = path.join(UPLOAD_DIR, id, `chunk_${chunkIndex}`);
                    fs.writeFileSync(chunkPath, data);

                    // Verify chunk was written correctly
                    const stat = fs.statSync(chunkPath);
                    if (stat.size !== data.length) {
                        throw new Error(`Chunk size mismatch: wrote ${data.length}, got ${stat.size}`);
                    }

                    fileInfo.chunkHashes[chunkIndex] = computedHash;
                    fileInfo.chunksReceived.add(chunkIndex);
                    saveMetadata(id, fileInfo);

                    const progress = (fileInfo.chunksReceived.size / fileInfo.totalChunks * 100).toFixed(1);
                    console.log(`Chunk ${chunkIndex}/${fileInfo.totalChunks - 1} received for ${id} (${progress}%)`);

                    sendJson(res, 200, {
                        success: true,
                        chunksReceived: fileInfo.chunksReceived.size,
                        totalChunks: fileInfo.totalChunks
                    });
                } catch (err) {
                    console.error(`Chunk ${chunkIndex} write failed for ${id}:`, err.message);
                    sendJson(res, 500, { error: 'Chunk write failed: ' + err.message });
                }
            });

            req.on('error', (err) => {
                console.error(`Chunk upload error for ${id}:`, err);
                sendJson(res, 500, { error: 'Upload failed' });
            });

            return; // Response sent in event handlers
        }

        // GET /api/info/:id
        const infoMatch = pathname.match(/^\/api\/info\/([a-f0-9]+)$/);
        if (method === 'GET' && infoMatch) {
            const id = infoMatch[1];
            const fileInfo = files.get(id);

            if (!fileInfo) {
                return sendJson(res, 404, { error: 'File not found' });
            }

            return sendJson(res, 200, {
                id: fileInfo.id,
                filename: fileInfo.filename,
                size: fileInfo.size,
                totalChunks: fileInfo.totalChunks,
                chunkHashes: fileInfo.chunkHashes,
                chunksReceived: fileInfo.chunksReceived.size,
                complete: fileInfo.chunksReceived.size === fileInfo.totalChunks,
                chunkSize: fileInfo.chunkSize || CHUNK_SIZE,
                targetBufferMemory: TARGET_BUFFER_MEMORY
            });
        }

        // GET /api/chunk/:id/:index
        const chunkDownloadMatch = pathname.match(/^\/api\/chunk\/([a-f0-9]+)\/(\d+)$/);
        if (method === 'GET' && chunkDownloadMatch) {
            const id = chunkDownloadMatch[1];
            const chunkIndex = parseInt(chunkDownloadMatch[2], 10);

            const fileInfo = files.get(id);
            if (!fileInfo) {
                return sendJson(res, 404, { error: 'File not found' });
            }

            if (!fileInfo.chunksReceived.has(chunkIndex)) {
                return sendJson(res, 404, { error: 'Chunk not yet uploaded' });
            }

            const chunkPath = path.join(UPLOAD_DIR, id, `chunk_${chunkIndex}`);

            if (USE_NGINX_ACCEL) {
                // Let nginx serve the file directly (near-zero CPU)
                try {
                    const stat = await fs.promises.stat(chunkPath);
                    res.writeHead(200, {
                        'X-Accel-Redirect': `/internal-chunks/${id}/chunk_${chunkIndex}`,
                        'Content-Type': 'application/octet-stream',
                        'Content-Length': stat.size,
                        'X-Chunk-Hash': fileInfo.chunkHashes[chunkIndex]
                    });
                    res.end();
                } catch (err) {
                    return sendJson(res, 404, { error: 'Chunk file missing' });
                }
            } else {
                // Stream directly from Node.js (fallback)
                try {
                    const stat = await fs.promises.stat(chunkPath);
                    res.writeHead(200, {
                        'Content-Length': stat.size,
                        'Content-Type': 'application/octet-stream',
                        'X-Chunk-Hash': fileInfo.chunkHashes[chunkIndex]
                    });
                    fs.createReadStream(chunkPath).pipe(res);
                } catch (err) {
                    return sendJson(res, 404, { error: 'Chunk file missing' });
                }
            }
            return;
        }

        // GET /download/:id - serve download page
        const downloadMatch = pathname.match(/^\/download\/([a-f0-9]+)$/);
        if (method === 'GET' && downloadMatch) {
            return serveStatic(res, path.join(PUBLIC_DIR, 'download.html'));
        }

        // Static files from public/
        if (method === 'GET') {
            const safePath = pathname === '/' ? '/index.html' : pathname;
            // Prevent directory traversal
            const filePath = path.join(PUBLIC_DIR, safePath);
            if (!filePath.startsWith(PUBLIC_DIR)) {
                res.writeHead(403);
                return res.end('Forbidden');
            }
            return serveStatic(res, filePath);
        }

        // 404 for everything else
        res.writeHead(404);
        res.end('Not found');

    } catch (err) {
        console.error('Request error:', err);
        res.writeHead(500);
        res.end('Internal server error');
    }
});

// Load existing files and start server
loadFilesFromDisk();

server.listen(PORT, () => {
    console.log(`Sendinator running on http://localhost:${PORT}`);
    console.log(`Chunk size: ${formatBytes(CHUNK_SIZE)}`);
    if (USE_NGINX_ACCEL) {
        console.log(`nginx X-Accel-Redirect: ENABLED (low CPU mode)`);
    } else {
        console.log(`nginx X-Accel-Redirect: disabled (set USE_NGINX_ACCEL=true to enable)`);
    }
});
