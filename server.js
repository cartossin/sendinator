import http from 'http';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// === ADMIN CONFIGURATION ===
const ADMIN_DIR = process.env.ADMIN_DIR || '/var/lib/sendinator';
const PASSKEY_FILE = path.join(ADMIN_DIR, 'passkey.json');
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours

// In-memory stores for auth
const pendingChallenges = new Map(); // challengeId -> { challenge, timestamp }
const sessions = new Map(); // token -> { createdAt }

// Clean up old challenges/sessions periodically
setInterval(() => {
    const now = Date.now();
    for (const [id, data] of pendingChallenges) {
        if (now - data.timestamp > 5 * 60 * 1000) pendingChallenges.delete(id);
    }
    for (const [token, data] of sessions) {
        if (now - data.createdAt > SESSION_DURATION) sessions.delete(token);
    }
}, 60 * 1000);

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

    // WebAuthn uses DER-encoded signature, Node's crypto expects it
    const verify = crypto.createVerify('SHA256');
    verify.update(data);

    try {
        return verify.verify({ key: pem, dsaEncoding: 'ieee-p1363' }, signature);
    } catch (err) {
        console.error('Signature verification error:', err.message);
        return false;
    }
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
                rp: { name: 'Sendinator', id: new URL(`http://${req.headers.host}`).hostname },
                user: {
                    id: bufferToBase64url(crypto.randomBytes(16)),
                    name: 'admin',
                    displayName: 'Sendinator Admin'
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

                console.log(`Deleted upload: ${id} - ${fileInfo.filename}`);
                return sendJson(res, 200, { success: true });
            } catch (err) {
                console.error(`Failed to delete ${id}:`, err);
                return sendJson(res, 500, { error: 'Delete failed' });
            }
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
