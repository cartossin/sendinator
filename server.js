import express from 'express';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// === CONFIGURATION ===
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const CHUNK_SIZE = 16 * 1024 * 1024;        // 16MB chunks (can change for new uploads)
const TARGET_BUFFER_MEMORY = 100 * 1024 * 1024; // 100MB target buffer memory for clients

// Ensure upload directory exists
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// In-memory store for file metadata (loaded from disk on startup)
const files = new Map();

// Load existing files from disk on startup
function loadFilesFromDisk() {
    const dirs = fs.readdirSync(UPLOAD_DIR);
    for (const id of dirs) {
        const metaPath = path.join(UPLOAD_DIR, id, 'meta.json');
        if (fs.existsSync(metaPath)) {
            try {
                const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
                meta.chunksReceived = new Set(meta.chunksReceived);
                files.set(id, meta);
                console.log(`Loaded: ${id} - ${meta.filename}`);
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

app.use(express.static('public'));
app.use(express.json());

// Get server configuration (for clients to fetch chunk size, buffer targets)
app.get('/api/config', (req, res) => {
    res.json({
        chunkSize: CHUNK_SIZE,
        targetBufferMemory: TARGET_BUFFER_MEMORY
    });
});

// Create a new file - just reserve ID, hashes come with chunks
app.post('/api/create', (req, res) => {
    const { filename, size, totalChunks } = req.body;

    if (!filename || !size || !totalChunks) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const id = crypto.randomBytes(4).toString('hex'); // 8 char ID
    const fileDir = path.join(UPLOAD_DIR, id);
    fs.mkdirSync(fileDir, { recursive: true });

    const fileInfo = {
        id,
        filename,
        size,
        totalChunks,
        chunkSize: CHUNK_SIZE,  // Store chunk size with file for backwards compatibility
        chunkHashes: new Array(totalChunks).fill(null),
        chunksReceived: new Set(),
        createdAt: Date.now()
    };

    files.set(id, fileInfo);
    saveMetadata(id, fileInfo);

    console.log(`Created file: ${id} - ${filename} (${formatBytes(size)}, ${totalChunks} chunks)`);
    res.json({ id, url: `/download/${id}` });
});

// Upload a chunk
app.post('/api/chunk/:id/:index', (req, res) => {
    const { id, index } = req.params;
    const chunkIndex = parseInt(index, 10);
    const expectedHash = req.headers['x-chunk-hash'];

    const fileInfo = files.get(id);
    if (!fileInfo) {
        return res.status(404).json({ error: 'File not found' });
    }

    if (chunkIndex < 0 || chunkIndex >= fileInfo.totalChunks) {
        return res.status(400).json({ error: 'Invalid chunk index' });
    }

    const chunks = [];
    const hash = crypto.createHash('sha256');

    req.on('data', (chunk) => {
        chunks.push(chunk);
        hash.update(chunk);
    });

    req.on('end', () => {
        const data = Buffer.concat(chunks);
        const computedHash = hash.digest('hex');

        // Verify hash matches what client sent
        if (expectedHash && computedHash !== expectedHash) {
            return res.status(400).json({
                error: 'Hash mismatch',
                expected: expectedHash,
                got: computedHash
            });
        }

        // Save chunk and store its hash
        const chunkPath = path.join(UPLOAD_DIR, id, `chunk_${chunkIndex}`);
        fs.writeFileSync(chunkPath, data);
        fileInfo.chunkHashes[chunkIndex] = computedHash;
        fileInfo.chunksReceived.add(chunkIndex);

        // Persist metadata to disk
        saveMetadata(id, fileInfo);

        const progress = (fileInfo.chunksReceived.size / fileInfo.totalChunks * 100).toFixed(1);
        console.log(`Chunk ${chunkIndex}/${fileInfo.totalChunks - 1} received for ${id} (${progress}%)`);

        res.json({
            success: true,
            chunksReceived: fileInfo.chunksReceived.size,
            totalChunks: fileInfo.totalChunks
        });
    });

    req.on('error', (err) => {
        console.error(`Chunk upload error for ${id}:`, err);
        res.status(500).json({ error: 'Upload failed' });
    });
});

// Get file info
app.get('/api/info/:id', (req, res) => {
    const { id } = req.params;
    const fileInfo = files.get(id);

    if (!fileInfo) {
        return res.status(404).json({ error: 'File not found' });
    }

    res.json({
        id: fileInfo.id,
        filename: fileInfo.filename,
        size: fileInfo.size,
        totalChunks: fileInfo.totalChunks,
        chunkHashes: fileInfo.chunkHashes,
        chunksReceived: fileInfo.chunksReceived.size,
        complete: fileInfo.chunksReceived.size === fileInfo.totalChunks,
        chunkSize: fileInfo.chunkSize || CHUNK_SIZE,  // Use file's chunk size, fallback for old files
        targetBufferMemory: TARGET_BUFFER_MEMORY
    });
});

// Download a chunk
app.get('/api/chunk/:id/:index', (req, res) => {
    const { id, index } = req.params;
    const chunkIndex = parseInt(index, 10);

    const fileInfo = files.get(id);
    if (!fileInfo) {
        return res.status(404).json({ error: 'File not found' });
    }

    if (!fileInfo.chunksReceived.has(chunkIndex)) {
        return res.status(404).json({ error: 'Chunk not yet uploaded' });
    }

    const chunkPath = path.join(UPLOAD_DIR, id, `chunk_${chunkIndex}`);
    if (!fs.existsSync(chunkPath)) {
        return res.status(404).json({ error: 'Chunk file missing' });
    }

    const stat = fs.statSync(chunkPath);
    res.setHeader('Content-Length', stat.size);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('X-Chunk-Hash', fileInfo.chunkHashes[chunkIndex]);

    fs.createReadStream(chunkPath).pipe(res);
});

// Download page
app.get('/download/:id', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'download.html'));
});

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Cleanup old files (older than 24 hours)
setInterval(() => {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000;

    for (const [id, fileInfo] of files.entries()) {
        if (now - fileInfo.createdAt > maxAge) {
            console.log(`Cleaning up: ${id}`);
            const fileDir = path.join(UPLOAD_DIR, id);
            if (fs.existsSync(fileDir)) {
                fs.rmSync(fileDir, { recursive: true });
            }
            files.delete(id);
        }
    }
}, 60 * 60 * 1000);

// Load existing files and start server
loadFilesFromDisk();

app.listen(PORT, () => {
    console.log(`Sendinator running on http://localhost:${PORT}`);
    console.log(`Chunk size: ${formatBytes(CHUNK_SIZE)}`);
});
