import http from 'http';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);
const pkg = require('./package.json');

// === ADMIN CONFIGURATION ===
const ADMIN_DIR = process.env.ADMIN_DIR || '/var/lib/sendinator';
const PASSKEY_FILE = path.join(ADMIN_DIR, 'passkey.json');
const UPLOAD_KEYS_FILE = path.join(ADMIN_DIR, 'upload-keys.json');
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours
const KEY_SESSION_DURATION = 7 * 24 * 60 * 60 * 1000; // 7 days for upload key sessions

// In-memory stores for auth
const pendingChallenges = new Map(); // challengeId -> { challenge, timestamp }
const sessions = new Map(); // token -> { createdAt } (admin sessions)
const keySessions = new Map(); // token -> { key, createdAt } (upload key sessions)

// Upload keys storage
let uploadKeys = new Map(); // key -> { quotaBytes, usedBytes, createdAt, uploads[] }

// Clean up old challenges/sessions periodically
setInterval(() => {
    const now = Date.now();
    for (const [id, data] of pendingChallenges) {
        if (now - data.timestamp > 5 * 60 * 1000) pendingChallenges.delete(id);
    }
    for (const [token, data] of sessions) {
        if (now - data.createdAt > SESSION_DURATION) sessions.delete(token);
    }
    for (const [token, data] of keySessions) {
        if (now - data.createdAt > KEY_SESSION_DURATION) keySessions.delete(token);
    }
}, 60 * 1000);

// Load upload keys from disk
function loadUploadKeys() {
    try {
        if (fs.existsSync(UPLOAD_KEYS_FILE)) {
            const data = JSON.parse(fs.readFileSync(UPLOAD_KEYS_FILE, 'utf8'));
            uploadKeys = new Map(Object.entries(data));
            console.log(`Loaded ${uploadKeys.size} upload keys`);
        }
    } catch (err) {
        console.error('Failed to load upload keys:', err.message);
    }
}

// Save upload keys to disk
function saveUploadKeys() {
    const data = Object.fromEntries(uploadKeys);
    fs.writeFileSync(UPLOAD_KEYS_FILE, JSON.stringify(data, null, 2));
}

// Generate a 20-character upload key
function generateUploadKey() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    let key = '';
    const bytes = crypto.randomBytes(20);
    for (let i = 0; i < 20; i++) {
        key += chars[bytes[i] % chars.length];
    }
    return key;
}

// Verify upload key session from cookie
function verifyKeySession(req) {
    const cookies = req.headers.cookie?.split(';').reduce((acc, c) => {
        const [k, v] = c.trim().split('=');
        acc[k] = v;
        return acc;
    }, {}) || {};

    const token = cookies['upload_session'];
    if (!token) return null;

    const session = keySessions.get(token);
    if (!session) return null;

    if (Date.now() - session.createdAt > KEY_SESSION_DURATION) {
        keySessions.delete(token);
        return null;
    }

    const keyData = uploadKeys.get(session.key);
    if (!keyData) return null;

    return { key: session.key, ...keyData };
}

// === CONFIGURATION ===
const APP_NAME = process.env.APP_NAME || 'Sendinator';
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
                let actualSize = 0;
                for (const f of chunkFiles) {
                    const idx = parseInt(f.replace('chunk_', ''), 10);
                    if (!isNaN(idx)) {
                        actualChunks.add(idx);
                        // Calculate actual size from disk
                        try {
                            const stat = fs.statSync(path.join(fileDir, f));
                            actualSize += stat.size;
                        } catch (e) { /* ignore */ }
                    }
                }

                // Use actual chunks found on disk
                meta.chunksReceived = actualChunks;

                // Fix size for archives if it differs from actual
                if (actualChunks.size === meta.totalChunks && actualSize > 0 && actualSize !== meta.size) {
                    console.log(`Fixing ${id} size: ${formatBytes(meta.size)} -> ${formatBytes(actualSize)}`);
                    meta.size = actualSize;
                    // Save corrected metadata
                    const toSave = { ...meta, chunksReceived: Array.from(meta.chunksReceived) };
                    fs.writeFileSync(metaPath, JSON.stringify(toSave));
                }

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

// Helper: Read JSON body from request (with size limit to prevent memory exhaustion)
const MAX_JSON_BODY_SIZE = 1024 * 1024; // 1MB limit for JSON bodies
function readJsonBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        let size = 0;
        req.on('data', chunk => {
            size += chunk.length;
            if (size > MAX_JSON_BODY_SIZE) {
                req.destroy();
                reject(new Error('Request body too large'));
                return;
            }
            body += chunk;
        });
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
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// === ADMIN HELPERS ===

function getPasskey() {
    try {
        if (fs.existsSync(PASSKEY_FILE)) {
            return JSON.parse(fs.readFileSync(PASSKEY_FILE, 'utf8'));
        }
    } catch (err) {
        console.error('Failed to load passkey:', err.message);
    }
    return null;
}

function savePasskey(passkey) {
    fs.writeFileSync(PASSKEY_FILE, JSON.stringify(passkey, null, 2));
}

function generateChallenge() {
    return crypto.randomBytes(32).toString('base64url');
}

function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

function verifySession(req) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) return false;
    const token = authHeader.slice(7);
    const session = sessions.get(token);
    if (!session) return false;
    if (Date.now() - session.createdAt > SESSION_DURATION) {
        sessions.delete(token);
        return false;
    }
    return true;
}

// Base64URL helpers
function base64urlToBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
    return Buffer.from(padded, 'base64');
}

function bufferToBase64url(buffer) {
    return Buffer.from(buffer).toString('base64url');
}

// Parse authenticator data from WebAuthn response
function parseAuthenticatorData(authData) {
    const rpIdHash = authData.slice(0, 32);
    const flags = authData[32];
    const signCount = authData.readUInt32BE(33);

    const result = { rpIdHash, flags, signCount };

    // Check if attested credential data is present (bit 6)
    if (flags & 0x40) {
        const aaguid = authData.slice(37, 53);
        const credIdLen = authData.readUInt16BE(53);
        const credentialId = authData.slice(55, 55 + credIdLen);
        const publicKeyBytes = authData.slice(55 + credIdLen);

        result.aaguid = aaguid;
        result.credentialId = credentialId;
        result.publicKeyBytes = publicKeyBytes;
    }

    return result;
}

// Simple CBOR decoder for the specific structures we need
function decodeCBOR(buffer) {
    let offset = 0;

    function read() {
        const first = buffer[offset++];
        const major = first >> 5;
        const additional = first & 0x1f;

        let value;
        if (additional < 24) {
            value = additional;
        } else if (additional === 24) {
            value = buffer[offset++];
        } else if (additional === 25) {
            value = buffer.readUInt16BE(offset);
            offset += 2;
        } else if (additional === 26) {
            value = buffer.readUInt32BE(offset);
            offset += 4;
        } else if (additional === 27) {
            // 8-byte integer (read as BigInt, convert to Number for our use)
            value = Number(buffer.readBigUInt64BE(offset));
            offset += 8;
        } else {
            throw new Error(`Unsupported CBOR additional info: ${additional}`);
        }

        switch (major) {
            case 0: // unsigned int
                return value;
            case 1: // negative int
                return -1 - value;
            case 2: // byte string
                const bytes = buffer.slice(offset, offset + value);
                offset += value;
                return bytes;
            case 3: // text string
                const text = buffer.slice(offset, offset + value).toString('utf8');
                offset += value;
                return text;
            case 4: // array
                const arr = [];
                for (let i = 0; i < value; i++) arr.push(read());
                return arr;
            case 5: // map
                const map = {};
                for (let i = 0; i < value; i++) {
                    const k = read();
                    const v = read();
                    map[k] = v;
                }
                return map;
            default:
                throw new Error(`Unsupported CBOR major type: ${major}`);
        }
    }

    return read();
}

// Parse COSE public key to crypto-usable format
function coseToPublicKey(coseKey) {
    // COSE key structure for ES256 (P-256):
    // 1 (kty): 2 (EC)
    // 3 (alg): -7 (ES256)
    // -1 (crv): 1 (P-256)
    // -2 (x): x coordinate
    // -3 (y): y coordinate

    const kty = coseKey[1];
    const alg = coseKey[3];

    if (kty === 2 && alg === -7) {
        // EC key with ES256
        const x = coseKey[-2];
        const y = coseKey[-3];

        // Create uncompressed point format (0x04 || x || y)
        const uncompressed = Buffer.concat([Buffer.from([0x04]), x, y]);

        return {
            algorithm: 'ES256',
            publicKey: uncompressed
        };
    }

    throw new Error(`Unsupported key type: kty=${kty}, alg=${alg}`);
}

// Verify ES256 signature
function verifyES256Signature(publicKeyUncompressed, signature, data) {
    // Convert uncompressed point to PEM format
    // P-256 public key ASN.1 structure
    const header = Buffer.from([
        0x30, 0x59, // SEQUENCE, 89 bytes
        0x30, 0x13, // SEQUENCE, 19 bytes
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID 1.2.840.10045.2.1 (ecPublicKey)
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID 1.2.840.10045.3.1.7 (P-256)
        0x03, 0x42, 0x00 // BIT STRING, 66 bytes, 0 unused bits
    ]);

    const derKey = Buffer.concat([header, publicKeyUncompressed]);
    const pem = '-----BEGIN PUBLIC KEY-----\n' +
                derKey.toString('base64').match(/.{1,64}/g).join('\n') +
                '\n-----END PUBLIC KEY-----';

    // Try IEEE P1363 format first (raw r||s), then DER format
    // Different authenticators may use different formats
    for (const dsaEncoding of ['ieee-p1363', 'der']) {
        try {
            const verify = crypto.createVerify('SHA256');
            verify.update(data);
            if (verify.verify({ key: pem, dsaEncoding }, signature)) {
                return true;
            }
        } catch (err) {
            // Try next format
        }
    }

    console.error('Signature verification failed for all formats');
    return false;
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
            // Require upload key session
            const keySession = verifyKeySession(req);
            if (!keySession) {
                return sendJson(res, 401, { error: 'Upload key required' });
            }

            const body = await readJsonBody(req);
            const { filename, size, totalChunks, type, fileCount, rootName } = body;

            // Validate required fields exist and have correct types
            if (!filename || typeof filename !== 'string') {
                return sendJson(res, 400, { error: 'Invalid filename' });
            }
            if (filename.length > 255) {
                return sendJson(res, 400, { error: 'Filename too long' });
            }
            if (typeof size !== 'number' || !Number.isInteger(size) || size <= 0) {
                return sendJson(res, 400, { error: 'Invalid size' });
            }
            if (typeof totalChunks !== 'number' || !Number.isInteger(totalChunks) || totalChunks <= 0) {
                return sendJson(res, 400, { error: 'Invalid totalChunks' });
            }
            if (type !== undefined && type !== 'archive') {
                return sendJson(res, 400, { error: 'Invalid type' });
            }
            if (fileCount !== undefined && (typeof fileCount !== 'number' || !Number.isInteger(fileCount) || fileCount < 0)) {
                return sendJson(res, 400, { error: 'Invalid fileCount' });
            }
            if (rootName !== undefined && typeof rootName !== 'string') {
                return sendJson(res, 400, { error: 'Invalid rootName' });
            }

            // Check quota (upload + download counts, so multiply by 2 for conservative estimate)
            const remainingQuota = keySession.quotaBytes - keySession.usedBytes;
            if (size > remainingQuota) {
                return sendJson(res, 403, { error: `File size (${formatBytes(size)}) exceeds remaining quota (${formatBytes(remainingQuota)})` });
            }

            const id = crypto.randomBytes(16).toString('hex');
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
                createdAt: Date.now(),
                uploadKey: keySession.key  // Track which key uploaded this
            };

            // Optional archive metadata
            if (type === 'archive') {
                fileInfo.type = 'archive';
                fileInfo.fileCount = fileCount || 0;
                fileInfo.rootName = rootName || '';
            }

            files.set(id, fileInfo);
            saveMetadata(id, fileInfo);

            // Add upload to key's list
            const keyData = uploadKeys.get(keySession.key);
            if (keyData) {
                keyData.uploads.push(id);
                saveUploadKeys();
            }

            const typeLabel = type === 'archive' ? ` [archive: ${fileCount} files]` : '';
            console.log(`Created file: ${id} - ${filename} (${formatBytes(size)}, ${totalChunks} chunks)${typeLabel} [key: ${keySession.key.slice(0, 8)}...]`);
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

            // Verify upload key session matches file owner
            const keySession = verifyKeySession(req);
            if (!keySession || keySession.key !== fileInfo.uploadKey) {
                return sendJson(res, 403, { error: 'Not authorized to upload to this file' });
            }

            if (chunkIndex < 0) {
                return sendJson(res, 400, { error: 'Invalid chunk index' });
            }

            // For archives, allow chunks beyond initial estimate (ZIP size is approximate)
            // Dynamically expand arrays if needed
            if (chunkIndex >= fileInfo.totalChunks) {
                if (fileInfo.type === 'archive') {
                    // Expand to accommodate this chunk
                    const newSize = chunkIndex + 1;
                    while (fileInfo.chunkHashes.length < newSize) {
                        fileInfo.chunkHashes.push(null);
                    }
                    fileInfo.totalChunks = newSize;
                } else {
                    return sendJson(res, 400, { error: 'Invalid chunk index' });
                }
            }

            const chunks = [];
            const hash = crypto.createHash('sha256');
            let totalSize = 0;
            let aborted = false;

            req.on('data', (chunk) => {
                if (aborted) return;
                totalSize += chunk.length;
                // Early abort if chunk is oversized (don't buffer the whole thing)
                if (totalSize > CHUNK_SIZE) {
                    aborted = true;
                    console.warn(`Rejected oversized chunk ${chunkIndex} for ${id}: ${totalSize}+ > ${CHUNK_SIZE}`);
                    req.destroy();
                    return sendJson(res, 400, { error: 'Chunk too large' });
                }
                chunks.push(chunk);
                hash.update(chunk);
            });

            req.on('end', () => {
                if (aborted) return;
                try {
                    const data = Buffer.concat(chunks);
                    const computedHash = hash.digest('hex');

                    // For non-archives, validate exact chunk sizes
                    if (fileInfo.type !== 'archive') {
                        const isLastChunk = chunkIndex === fileInfo.totalChunks - 1;
                        const expectedSize = isLastChunk
                            ? (fileInfo.size % CHUNK_SIZE) || CHUNK_SIZE
                            : CHUNK_SIZE;

                        if (data.length !== expectedSize) {
                            console.warn(`Rejected wrong-sized chunk ${chunkIndex} for ${id}: got ${data.length}, expected ${expectedSize}`);
                            return sendJson(res, 400, { error: 'Invalid chunk size' });
                        }
                    }

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

                    // Track upload bytes against quota
                    if (fileInfo.uploadKey) {
                        const keyData = uploadKeys.get(fileInfo.uploadKey);
                        if (keyData) {
                            keyData.usedBytes += data.length;
                            saveUploadKeys();
                        }
                    }

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

        // POST /api/finalize/:id - finalize archive upload with actual chunk count
        const finalizeMatch = pathname.match(/^\/api\/finalize\/([a-f0-9]+)$/);
        if (method === 'POST' && finalizeMatch) {
            const id = finalizeMatch[1];
            const fileInfo = files.get(id);
            if (!fileInfo) {
                return sendJson(res, 404, { error: 'File not found' });
            }

            // Verify upload key session matches file owner
            const keySession = verifyKeySession(req);
            if (!keySession || keySession.key !== fileInfo.uploadKey) {
                return sendJson(res, 403, { error: 'Not authorized to finalize this file' });
            }

            try {
                const body = await readJsonBody(req);
                const { actualChunks } = body;

                // Validate actualChunks if provided
                if (actualChunks !== undefined) {
                    if (typeof actualChunks !== 'number' || !Number.isInteger(actualChunks) || actualChunks <= 0) {
                        return sendJson(res, 400, { error: 'Invalid actualChunks' });
                    }

                    // Update total chunks to actual count
                    const oldTotal = fileInfo.totalChunks;
                    fileInfo.totalChunks = actualChunks;

                    // Adjust chunkHashes array
                    if (actualChunks < oldTotal) {
                        fileInfo.chunkHashes = fileInfo.chunkHashes.slice(0, actualChunks);
                    }
                    // If actualChunks > oldTotal, array was already expanded during upload

                    // ALWAYS calculate actual size from chunks on disk
                    // (ZIP size estimation is approximate, byte count may differ even if chunk count matches)
                    const fileDir = path.join(UPLOAD_DIR, id);
                    let actualSize = 0;
                    let allChunksFound = true;
                    for (let i = 0; i < actualChunks; i++) {
                        const chunkPath = path.join(fileDir, `chunk_${i}`);
                        try {
                            const stat = fs.statSync(chunkPath);
                            actualSize += stat.size;
                        } catch (e) {
                            // Chunk missing - leave size as estimated
                            allChunksFound = false;
                            actualSize = fileInfo.size;
                            break;
                        }
                    }

                    const oldSize = fileInfo.size;
                    fileInfo.size = actualSize;

                    saveMetadata(id, fileInfo);
                    console.log(`Finalized ${id}: ${oldTotal} -> ${actualChunks} chunks, size: ${formatBytes(oldSize)} -> ${formatBytes(actualSize)}${allChunksFound ? '' : ' (estimated)'}`);
                }

                return sendJson(res, 200, { success: true });
            } catch (err) {
                return sendJson(res, 500, { error: err.message });
            }
        }

        // GET /api/version
        if (method === 'GET' && pathname === '/api/version') {
            return sendJson(res, 200, { version: pkg.version });
        }

        // GET /api/config/app
        if (method === 'GET' && pathname === '/api/config/app') {
            return sendJson(res, 200, { name: APP_NAME });
        }

        // GET /api/info/:id
        const infoMatch = pathname.match(/^\/api\/info\/([a-f0-9]+)$/);
        if (method === 'GET' && infoMatch) {
            const id = infoMatch[1];
            const fileInfo = files.get(id);

            if (!fileInfo) {
                return sendJson(res, 404, { error: 'File not found' });
            }

            // Check if file is downloadable
            let downloadable = true;
            let downloadError = null;
            if (!fileInfo.uploadKey) {
                downloadable = false;
                downloadError = 'This file is no longer available';
            } else {
                const keyData = uploadKeys.get(fileInfo.uploadKey);
                if (!keyData) {
                    downloadable = false;
                    downloadError = 'This file is no longer available';
                } else if (keyData.usedBytes >= keyData.quotaBytes) {
                    downloadable = false;
                    downloadError = 'Download unavailable - quota exhausted';
                }
            }

            const response = {
                id: fileInfo.id,
                filename: fileInfo.filename,
                size: fileInfo.size,
                totalChunks: fileInfo.totalChunks,
                chunkHashes: fileInfo.chunkHashes,
                chunksReceived: fileInfo.chunksReceived.size,
                complete: fileInfo.chunksReceived.size === fileInfo.totalChunks,
                chunkSize: fileInfo.chunkSize || CHUNK_SIZE,
                targetBufferMemory: TARGET_BUFFER_MEMORY,
                downloadable,
                downloadError
            };

            // Include archive metadata if present
            if (fileInfo.type === 'archive') {
                response.type = 'archive';
                response.fileCount = fileInfo.fileCount;
                response.rootName = fileInfo.rootName;
            }

            return sendJson(res, 200, response);
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

            // Block downloads for orphaned files
            if (!fileInfo.uploadKey) {
                return sendJson(res, 403, { error: 'File is no longer available' });
            }

            // Block downloads if quota exhausted
            const keyData = uploadKeys.get(fileInfo.uploadKey);
            if (!keyData) {
                return sendJson(res, 403, { error: 'File is no longer available' });
            }
            if (keyData.usedBytes >= keyData.quotaBytes) {
                return sendJson(res, 403, { error: 'Download unavailable - quota exhausted' });
            }

            const chunkPath = path.join(UPLOAD_DIR, id, `chunk_${chunkIndex}`);

            if (USE_NGINX_ACCEL) {
                // Let nginx serve the file directly (near-zero CPU)
                try {
                    const stat = await fs.promises.stat(chunkPath);

                    // Track download bytes against quota
                    keyData.usedBytes += stat.size;
                    saveUploadKeys();

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

                    // Track download bytes against quota
                    keyData.usedBytes += stat.size;
                    saveUploadKeys();

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

        // GET/HEAD /api/download/:id - direct download with Range support
        const directDownloadMatch = pathname.match(/^\/api\/download\/([a-f0-9]+)$/);
        if ((method === 'GET' || method === 'HEAD') && directDownloadMatch) {
            const id = directDownloadMatch[1];

            const fileInfo = files.get(id);
            if (!fileInfo) {
                return sendJson(res, 404, { error: 'File not found' });
            }

            // Only allow direct download for complete files
            if (fileInfo.chunksReceived.size !== fileInfo.totalChunks) {
                return sendJson(res, 400, { error: 'File upload not complete' });
            }

            // Block downloads for orphaned files
            if (!fileInfo.uploadKey) {
                return sendJson(res, 403, { error: 'File is no longer available' });
            }

            // Block downloads if quota exhausted
            const keyData = uploadKeys.get(fileInfo.uploadKey);
            if (!keyData) {
                return sendJson(res, 403, { error: 'File is no longer available' });
            }
            if (keyData.usedBytes >= keyData.quotaBytes) {
                return sendJson(res, 403, { error: 'Download unavailable - quota exhausted' });
            }

            // Parse Range header for resume/seeking support
            const rangeHeader = req.headers.range;
            let start = 0;
            let end = fileInfo.size - 1;

            if (rangeHeader) {
                const match = rangeHeader.match(/bytes=(\d*)-(\d*)/);
                if (match) {
                    if (match[1] === '' && match[2]) {
                        // Suffix range: bytes=-500 means last 500 bytes
                        const suffix = parseInt(match[2]);
                        start = Math.max(0, fileInfo.size - suffix);
                        end = fileInfo.size - 1;
                    } else {
                        start = match[1] ? parseInt(match[1]) : 0;
                        end = match[2] ? parseInt(match[2]) : fileInfo.size - 1;
                    }

                    // Validate range
                    if (start > end || start >= fileInfo.size) {
                        res.writeHead(416, { 'Content-Range': `bytes */${fileInfo.size}` });
                        return res.end();
                    }
                    end = Math.min(end, fileInfo.size - 1);
                }
            }

            const contentLength = end - start + 1;
            const chunkSize = fileInfo.chunkSize;

            // Calculate which chunks we need
            const startChunk = Math.floor(start / chunkSize);
            const endChunk = Math.floor(end / chunkSize);
            const startOffsetInChunk = start % chunkSize;
            const endOffsetInChunk = end % chunkSize;

            // Detect content type from filename for proper embedding
            const ext = path.extname(fileInfo.filename).toLowerCase();
            const mimeTypes = {
                '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
                '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
                '.mp4': 'video/mp4', '.webm': 'video/webm', '.mov': 'video/quicktime',
                '.mp3': 'audio/mpeg', '.wav': 'audio/wav', '.ogg': 'audio/ogg',
                '.pdf': 'application/pdf', '.txt': 'text/plain', '.html': 'text/html',
                '.css': 'text/css', '.js': 'application/javascript', '.json': 'application/json',
                '.tar': 'application/x-tar', '.zip': 'application/zip', '.gz': 'application/gzip'
            };
            const contentType = mimeTypes[ext] || 'application/octet-stream';

            // Set headers - 206 for partial, 200 for full
            const headers = {
                'Content-Type': contentType,
                'Content-Length': contentLength,
                'Accept-Ranges': 'bytes',
                'Content-Disposition': `inline; filename="${encodeURIComponent(fileInfo.filename)}"`
            };

            if (rangeHeader) {
                headers['Content-Range'] = `bytes ${start}-${end}/${fileInfo.size}`;
                res.writeHead(206, headers);
            } else {
                res.writeHead(200, headers);
            }

            // HEAD request - return headers only, no body
            if (method === 'HEAD') {
                return res.end();
            }

            // Stream the requested range
            let currentChunk = startChunk;
            let aborted = false;
            let bytesServed = 0;

            const streamNextChunk = () => {
                if (aborted) return;

                if (currentChunk > endChunk) {
                    // Done - track quota for bytes actually served
                    keyData.usedBytes += bytesServed;
                    saveUploadKeys();
                    console.log(`Direct download ${rangeHeader ? '(range) ' : ''}completed: ${id} - ${formatBytes(bytesServed)}`);
                    res.end();
                    return;
                }

                const chunkPath = path.join(UPLOAD_DIR, id, `chunk_${currentChunk}`);

                // Calculate read boundaries within this chunk
                let readStart = 0;
                let readEnd = chunkSize - 1;

                if (currentChunk === startChunk) {
                    readStart = startOffsetInChunk;
                }
                if (currentChunk === endChunk) {
                    readEnd = endOffsetInChunk;
                }

                const stream = fs.createReadStream(chunkPath, { start: readStart, end: readEnd });
                currentChunk++;

                stream.on('data', (chunk) => {
                    bytesServed += chunk.length;
                });

                stream.on('error', (err) => {
                    console.error(`Stream error:`, err.message);
                    if (!aborted) res.end();
                });

                stream.on('end', streamNextChunk);

                stream.pipe(res, { end: false });
            };

            // Handle client disconnect
            res.on('close', () => {
                aborted = true;
                if (currentChunk <= endChunk) {
                    // Track partial download quota
                    if (bytesServed > 0) {
                        keyData.usedBytes += bytesServed;
                        saveUploadKeys();
                    }
                    console.log(`Direct download aborted: ${id} after ${formatBytes(bytesServed)}`);
                }
            });

            streamNextChunk();
            return;
        }

        // === ADMIN API ===

        // GET /api/admin/status - check if passkey exists
        if (method === 'GET' && pathname === '/api/admin/status') {
            const passkey = getPasskey();
            return sendJson(res, 200, { passkeyExists: !!passkey });
        }

        // POST /api/admin/register/start - begin passkey registration
        if (method === 'POST' && pathname === '/api/admin/register/start') {
            const existingPasskey = getPasskey();
            if (existingPasskey) {
                return sendJson(res, 400, { error: 'Passkey already registered' });
            }

            const challenge = generateChallenge();
            const challengeId = crypto.randomBytes(16).toString('hex');
            pendingChallenges.set(challengeId, { challenge, timestamp: Date.now() });

            // Set challenge ID in cookie for the finish step
            res.setHeader('Set-Cookie', `webauthn_challenge=${challengeId}; HttpOnly; SameSite=Strict; Path=/; Max-Age=300`);

            return sendJson(res, 200, {
                challenge,
                rp: { name: APP_NAME, id: new URL(`http://${req.headers.host}`).hostname },
                user: {
                    id: bufferToBase64url(crypto.randomBytes(16)),
                    name: 'admin',
                    displayName: `${APP_NAME} Admin`
                },
                pubKeyCredParams: [{ alg: -7, type: 'public-key' }], // ES256
                timeout: 300000,
                attestation: 'none'
            });
        }

        // POST /api/admin/register/finish - complete passkey registration
        if (method === 'POST' && pathname === '/api/admin/register/finish') {
            try {
                const body = await readJsonBody(req);

                // Get challenge from cookie
                const cookies = req.headers.cookie?.split(';').reduce((acc, c) => {
                    const [k, v] = c.trim().split('=');
                    acc[k] = v;
                    return acc;
                }, {}) || {};

                const challengeId = cookies['webauthn_challenge'];
                const pending = pendingChallenges.get(challengeId);
                if (!pending) {
                    return sendJson(res, 400, { error: 'Challenge expired or not found' });
                }
                pendingChallenges.delete(challengeId);

                // Parse attestation object
                const attestationBuffer = base64urlToBuffer(body.response.attestationObject);
                const attestation = decodeCBOR(attestationBuffer);

                // Parse authenticator data
                const authData = parseAuthenticatorData(attestation.authData);

                // Verify RP ID hash
                const expectedRpIdHash = crypto.createHash('sha256')
                    .update(new URL(`http://${req.headers.host}`).hostname)
                    .digest();
                if (!authData.rpIdHash.equals(expectedRpIdHash)) {
                    return sendJson(res, 400, { error: 'RP ID mismatch' });
                }

                // Verify user present flag
                if (!(authData.flags & 0x01)) {
                    return sendJson(res, 400, { error: 'User not present' });
                }

                // Parse and store the public key
                const coseKey = decodeCBOR(authData.publicKeyBytes);
                const { algorithm, publicKey } = coseToPublicKey(coseKey);

                const passkey = {
                    credentialId: bufferToBase64url(authData.credentialId),
                    publicKey: bufferToBase64url(publicKey),
                    algorithm,
                    signCount: authData.signCount,
                    createdAt: Date.now()
                };

                savePasskey(passkey);

                // Create session
                const token = generateSessionToken();
                sessions.set(token, { createdAt: Date.now() });

                console.log('Admin passkey registered successfully');
                return sendJson(res, 200, { success: true, token });

            } catch (err) {
                console.error('Registration error:', err);
                return sendJson(res, 500, { error: err.message });
            }
        }

        // POST /api/admin/login/start - begin passkey authentication
        if (method === 'POST' && pathname === '/api/admin/login/start') {
            const passkey = getPasskey();
            if (!passkey) {
                return sendJson(res, 400, { error: 'No passkey registered' });
            }

            const challenge = generateChallenge();
            const challengeId = crypto.randomBytes(16).toString('hex');
            pendingChallenges.set(challengeId, { challenge, timestamp: Date.now() });

            res.setHeader('Set-Cookie', `webauthn_challenge=${challengeId}; HttpOnly; SameSite=Strict; Path=/; Max-Age=300`);

            return sendJson(res, 200, {
                challenge,
                timeout: 300000,
                rpId: new URL(`http://${req.headers.host}`).hostname,
                allowCredentials: [{
                    type: 'public-key',
                    id: passkey.credentialId
                }]
            });
        }

        // POST /api/admin/login/finish - complete passkey authentication
        if (method === 'POST' && pathname === '/api/admin/login/finish') {
            try {
                const body = await readJsonBody(req);
                const passkey = getPasskey();

                if (!passkey) {
                    return sendJson(res, 400, { error: 'No passkey registered' });
                }

                // Get challenge from cookie
                const cookies = req.headers.cookie?.split(';').reduce((acc, c) => {
                    const [k, v] = c.trim().split('=');
                    acc[k] = v;
                    return acc;
                }, {}) || {};

                const challengeId = cookies['webauthn_challenge'];
                const pending = pendingChallenges.get(challengeId);
                if (!pending) {
                    return sendJson(res, 400, { error: 'Challenge expired or not found' });
                }
                pendingChallenges.delete(challengeId);

                // Verify credential ID matches
                if (body.id !== passkey.credentialId) {
                    return sendJson(res, 400, { error: 'Unknown credential' });
                }

                // Parse client data
                const clientDataJSON = base64urlToBuffer(body.response.clientDataJSON);
                const clientData = JSON.parse(clientDataJSON.toString('utf8'));

                // Verify challenge
                if (clientData.challenge !== pending.challenge) {
                    return sendJson(res, 400, { error: 'Challenge mismatch' });
                }

                // Verify origin
                const expectedOrigin = `${req.headers['x-forwarded-proto'] || 'http'}://${req.headers.host}`;
                if (clientData.origin !== expectedOrigin && clientData.origin !== `http://${req.headers.host}` && clientData.origin !== `https://${req.headers.host}`) {
                    console.log(`Origin mismatch: expected ${expectedOrigin}, got ${clientData.origin}`);
                    // Be lenient with origin for local development
                }

                // Verify type
                if (clientData.type !== 'webauthn.get') {
                    return sendJson(res, 400, { error: 'Invalid type' });
                }

                // Parse authenticator data
                const authData = base64urlToBuffer(body.response.authenticatorData);
                const parsedAuthData = parseAuthenticatorData(authData);

                // Verify RP ID hash
                const expectedRpIdHash = crypto.createHash('sha256')
                    .update(new URL(`http://${req.headers.host}`).hostname)
                    .digest();
                if (!parsedAuthData.rpIdHash.equals(expectedRpIdHash)) {
                    return sendJson(res, 400, { error: 'RP ID mismatch' });
                }

                // Verify user present flag
                if (!(parsedAuthData.flags & 0x01)) {
                    return sendJson(res, 400, { error: 'User not present' });
                }

                // Verify signature
                const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();
                const signedData = Buffer.concat([authData, clientDataHash]);
                const signature = base64urlToBuffer(body.response.signature);
                const publicKey = base64urlToBuffer(passkey.publicKey);

                console.log('Verifying signature:', {
                    publicKeyLen: publicKey.length,
                    signatureLen: signature.length,
                    signedDataLen: signedData.length
                });
                const valid = verifyES256Signature(publicKey, signature, signedData);
                if (!valid) {
                    return sendJson(res, 400, { error: 'Invalid signature' });
                }

                // Update sign count
                if (parsedAuthData.signCount > passkey.signCount) {
                    passkey.signCount = parsedAuthData.signCount;
                    savePasskey(passkey);
                }

                // Create session
                const token = generateSessionToken();
                sessions.set(token, { createdAt: Date.now() });

                console.log('Admin login successful');
                return sendJson(res, 200, { success: true, token });

            } catch (err) {
                console.error('Login error:', err);
                return sendJson(res, 500, { error: err.message });
            }
        }

        // === UPLOAD KEY ADMIN APIs ===

        // POST /api/admin/keys - create new upload key
        if (method === 'POST' && pathname === '/api/admin/keys') {
            if (!verifySession(req)) {
                return sendJson(res, 401, { error: 'Unauthorized' });
            }

            try {
                const body = await readJsonBody(req);
                const { quotaValue, quotaUnit, label } = body;

                // Validate inputs
                if (typeof quotaValue !== 'number' || !isFinite(quotaValue) || quotaValue <= 0) {
                    return sendJson(res, 400, { error: 'Invalid quota value' });
                }
                const validUnits = ['MiB', 'GiB', 'TiB'];
                if (quotaUnit !== undefined && !validUnits.includes(quotaUnit)) {
                    return sendJson(res, 400, { error: 'Invalid quota unit' });
                }
                if (label !== undefined && typeof label !== 'string') {
                    return sendJson(res, 400, { error: 'Invalid label' });
                }
                if (label && label.length > 100) {
                    return sendJson(res, 400, { error: 'Label too long' });
                }

                // Convert to bytes based on unit (binary units)
                const unitMultipliers = {
                    'MiB': 1024 * 1024,
                    'GiB': 1024 * 1024 * 1024,
                    'TiB': 1024 * 1024 * 1024 * 1024
                };
                const multiplier = unitMultipliers[quotaUnit] || unitMultipliers['GiB'];
                const quotaBytes = Math.round(quotaValue * multiplier);

                const key = generateUploadKey();
                const keyData = {
                    label: label || '',
                    quotaBytes,
                    usedBytes: 0,
                    createdAt: Date.now(),
                    uploads: []
                };

                uploadKeys.set(key, keyData);
                saveUploadKeys();

                console.log(`Created upload key: ${key} (${quotaValue} ${quotaUnit || 'GiB'}, label: "${label || ''}")`);
                return sendJson(res, 200, { key, ...keyData });

            } catch (err) {
                return sendJson(res, 500, { error: err.message });
            }
        }

        // GET /api/admin/keys - list all upload keys with their uploads
        if (method === 'GET' && pathname === '/api/admin/keys') {
            if (!verifySession(req)) {
                return sendJson(res, 401, { error: 'Unauthorized' });
            }

            const keys = [];
            for (const [key, data] of uploadKeys) {
                // Get upload details for this key
                const uploads = data.uploads.map(uploadId => {
                    const info = files.get(uploadId);
                    if (!info) return null;
                    const chunksReceived = info.chunksReceived instanceof Set
                        ? info.chunksReceived.size
                        : (Array.isArray(info.chunksReceived) ? info.chunksReceived.length : 0);
                    return {
                        id: uploadId,
                        filename: info.filename,
                        size: info.size,
                        totalChunks: info.totalChunks,
                        chunksReceived,
                        createdAt: info.createdAt || 0
                    };
                }).filter(u => u !== null);

                keys.push({
                    key,
                    label: data.label || '',
                    quotaBytes: data.quotaBytes,
                    usedBytes: data.usedBytes,
                    createdAt: data.createdAt,
                    uploads
                });
            }

            // Find orphaned uploads (no uploadKey or key doesn't exist)
            const orphanedUploads = [];
            for (const [uploadId, info] of files) {
                if (!info.uploadKey || !uploadKeys.has(info.uploadKey)) {
                    const chunksReceived = info.chunksReceived instanceof Set
                        ? info.chunksReceived.size
                        : (Array.isArray(info.chunksReceived) ? info.chunksReceived.length : 0);
                    orphanedUploads.push({
                        id: uploadId,
                        filename: info.filename,
                        size: info.size,
                        totalChunks: info.totalChunks,
                        chunksReceived,
                        createdAt: info.createdAt || 0
                    });
                }
            }

            return sendJson(res, 200, { keys, orphanedUploads });
        }

        // PATCH /api/admin/keys/:key - update an upload key's quota
        const patchKeyMatch = pathname.match(/^\/api\/admin\/keys\/(.+)$/);
        if (method === 'PATCH' && patchKeyMatch) {
            if (!verifySession(req)) {
                return sendJson(res, 401, { error: 'Unauthorized' });
            }

            const key = patchKeyMatch[1];
            const keyData = uploadKeys.get(key);
            if (!keyData) {
                return sendJson(res, 404, { error: 'Key not found' });
            }

            try {
                const body = await readJsonBody(req);
                const { quotaValue, quotaUnit } = body;

                // Validate inputs
                if (typeof quotaValue !== 'number' || !isFinite(quotaValue) || quotaValue <= 0) {
                    return sendJson(res, 400, { error: 'Invalid quota value' });
                }
                const validUnits = ['MiB', 'GiB', 'TiB'];
                if (quotaUnit !== undefined && !validUnits.includes(quotaUnit)) {
                    return sendJson(res, 400, { error: 'Invalid quota unit' });
                }

                // Convert to bytes based on unit (binary units)
                const unitMultipliers = {
                    'MiB': 1024 * 1024,
                    'GiB': 1024 * 1024 * 1024,
                    'TiB': 1024 * 1024 * 1024 * 1024
                };
                const multiplier = unitMultipliers[quotaUnit] || unitMultipliers['GiB'];
                const quotaBytes = Math.round(quotaValue * multiplier);

                keyData.quotaBytes = quotaBytes;
                saveUploadKeys();

                console.log(`Updated upload key quota: ${key.slice(0, 8)}... -> ${quotaValue} ${quotaUnit}`);
                return sendJson(res, 200, { success: true, quotaBytes });

            } catch (err) {
                return sendJson(res, 500, { error: err.message });
            }
        }

        // DELETE /api/admin/keys/:key - delete an upload key
        const deleteKeyMatch = pathname.match(/^\/api\/admin\/keys\/(.+)$/);
        if (method === 'DELETE' && deleteKeyMatch) {
            if (!verifySession(req)) {
                return sendJson(res, 401, { error: 'Unauthorized' });
            }

            const key = deleteKeyMatch[1];
            const keyData = uploadKeys.get(key);
            if (!keyData) {
                return sendJson(res, 404, { error: 'Key not found' });
            }

            // Orphan all uploads associated with this key (remove uploadKey reference)
            for (const uploadId of keyData.uploads) {
                const fileInfo = files.get(uploadId);
                if (fileInfo) {
                    fileInfo.uploadKey = null;
                    saveMetadata(uploadId, fileInfo);
                    console.log(`Orphaned upload: ${uploadId} - ${fileInfo.filename}`);
                }
            }

            uploadKeys.delete(key);
            saveUploadKeys();

            // Also invalidate any sessions using this key
            for (const [token, session] of keySessions) {
                if (session.key === key) {
                    keySessions.delete(token);
                }
            }

            console.log(`Deleted upload key: ${key}`);
            return sendJson(res, 200, { success: true });
        }

        // === UPLOAD KEY USER APIs ===

        // POST /api/key/login - login with upload key
        if (method === 'POST' && pathname === '/api/key/login') {
            try {
                const body = await readJsonBody(req);
                const { key } = body;

                // Validate key is a non-empty string
                if (!key || typeof key !== 'string') {
                    return sendJson(res, 400, { error: 'Invalid key format' });
                }

                const keyData = uploadKeys.get(key);
                if (!keyData) {
                    return sendJson(res, 401, { error: 'Invalid upload key' });
                }

                // Check if quota is exhausted
                if (keyData.usedBytes >= keyData.quotaBytes) {
                    return sendJson(res, 403, { error: 'Quota exhausted' });
                }

                // Create session
                const token = crypto.randomBytes(32).toString('hex');
                keySessions.set(token, { key, createdAt: Date.now() });

                // Set cookie
                res.setHeader('Set-Cookie', `upload_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${KEY_SESSION_DURATION / 1000}`);

                return sendJson(res, 200, {
                    success: true,
                    label: keyData.label,
                    quotaBytes: keyData.quotaBytes,
                    usedBytes: keyData.usedBytes,
                    remainingBytes: keyData.quotaBytes - keyData.usedBytes
                });

            } catch (err) {
                return sendJson(res, 500, { error: err.message });
            }
        }

        // POST /api/key/logout - logout from upload key session
        if (method === 'POST' && pathname === '/api/key/logout') {
            const cookies = req.headers.cookie?.split(';').reduce((acc, c) => {
                const [k, v] = c.trim().split('=');
                acc[k] = v;
                return acc;
            }, {}) || {};

            const token = cookies['upload_session'];
            if (token) {
                keySessions.delete(token);
            }

            // Clear cookie
            res.setHeader('Set-Cookie', 'upload_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
            return sendJson(res, 200, { success: true });
        }

        // GET /api/key/status - check upload key session status
        if (method === 'GET' && pathname === '/api/key/status') {
            const keySession = verifyKeySession(req);
            if (!keySession) {
                return sendJson(res, 200, { loggedIn: false });
            }

            return sendJson(res, 200, {
                loggedIn: true,
                label: keySession.label || '',
                quotaBytes: keySession.quotaBytes,
                usedBytes: keySession.usedBytes,
                remainingBytes: keySession.quotaBytes - keySession.usedBytes
            });
        }

        // GET /api/admin/uploads - list all uploads
        if (method === 'GET' && pathname === '/api/admin/uploads') {
            if (!verifySession(req)) {
                return sendJson(res, 401, { error: 'Unauthorized' });
            }

            const uploads = [];
            let totalSize = 0;
            let completeCount = 0;

            for (const [id, info] of files) {
                const chunksReceived = info.chunksReceived instanceof Set
                    ? info.chunksReceived.size
                    : (Array.isArray(info.chunksReceived) ? info.chunksReceived.length : 0);

                const isComplete = chunksReceived === info.totalChunks;
                if (isComplete) completeCount++;
                totalSize += info.size;

                uploads.push({
                    id,
                    filename: info.filename,
                    size: info.size,
                    totalChunks: info.totalChunks,
                    chunksReceived,
                    createdAt: info.createdAt || 0
                });
            }

            return sendJson(res, 200, { uploads, totalSize, completeCount });
        }

        // DELETE /api/admin/uploads/:id - delete an upload
        const deleteMatch = pathname.match(/^\/api\/admin\/uploads\/([a-f0-9]+)$/);
        if (method === 'DELETE' && deleteMatch) {
            if (!verifySession(req)) {
                return sendJson(res, 401, { error: 'Unauthorized' });
            }

            const id = deleteMatch[1];
            const fileInfo = files.get(id);

            if (!fileInfo) {
                return sendJson(res, 404, { error: 'Upload not found' });
            }

            try {
                // Delete directory and all contents
                const fileDir = path.join(UPLOAD_DIR, id);
                fs.rmSync(fileDir, { recursive: true, force: true });
                files.delete(id);

                // Update the upload key that owns this upload
                for (const [key, keyData] of uploadKeys) {
                    const idx = keyData.uploads.indexOf(id);
                    if (idx !== -1) {
                        keyData.uploads.splice(idx, 1);
                        // Subtract the file size from usedBytes
                        keyData.usedBytes = Math.max(0, keyData.usedBytes - fileInfo.size);
                        saveUploadKeys();
                        break;
                    }
                }

                console.log(`Deleted upload: ${id} - ${fileInfo.filename}`);
                return sendJson(res, 200, { success: true });
            } catch (err) {
                console.error(`Failed to delete ${id}:`, err);
                return sendJson(res, 500, { error: 'Delete failed' });
            }
        }

        // GET /admin - serve admin page
        if (method === 'GET' && pathname === '/admin') {
            return serveStatic(res, path.join(PUBLIC_DIR, 'admin.html'));
        }

        // GET /download/:id - serve download page
        const downloadMatch = pathname.match(/^\/download\/([a-f0-9]+)$/);
        if (method === 'GET' && downloadMatch) {
            return serveStatic(res, path.join(PUBLIC_DIR, 'download.html'));
        }

        // Static files from public/
        if (method === 'GET') {
            // Redirect to admin setup if no passkey exists
            if (pathname === '/' && !getPasskey()) {
                res.writeHead(302, { 'Location': '/admin' });
                return res.end();
            }

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

// Load existing files and upload keys, then start server
loadFilesFromDisk();
loadUploadKeys();

server.listen(PORT, () => {
    console.log(`${APP_NAME} running on http://localhost:${PORT}`);
    console.log(`Chunk size: ${formatBytes(CHUNK_SIZE)}`);
    if (USE_NGINX_ACCEL) {
        console.log(`nginx X-Accel-Redirect: ENABLED (low CPU mode)`);
    } else {
        console.log(`nginx X-Accel-Redirect: disabled (set USE_NGINX_ACCEL=true to enable)`);
    }
});
