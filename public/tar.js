// Minimal streaming TAR implementation for browser
// Supports USTAR format, handles files and directories

const TAR_BLOCK_SIZE = 512;

// Create a TAR header for a file or directory
function createTarHeader(name, size, isDirectory, mtime = Date.now()) {
    const header = new Uint8Array(TAR_BLOCK_SIZE);
    const encoder = new TextEncoder();

    // Handle long names with prefix (USTAR allows 155 + 100 = 255 bytes)
    // Must check byte length, not character length, for UTF-8 support
    let prefix = '';
    let fileName = name;

    const getByteLength = (str) => encoder.encode(str).length;

    // Check if name fits in 100 bytes
    if (getByteLength(name) > 100) {
        // Try to split at a slash to use prefix field
        const lastSlash = name.lastIndexOf('/');
        if (lastSlash > 0) {
            const possiblePrefix = name.substring(0, lastSlash);
            const possibleName = name.substring(lastSlash + 1);
            if (getByteLength(possiblePrefix) <= 155 && getByteLength(possibleName) <= 100) {
                prefix = possiblePrefix;
                fileName = possibleName;
            }
        }

        // If still too long, truncate bytes (not chars) from the end
        if (getByteLength(fileName) > 100) {
            // Truncate character by character until it fits
            while (getByteLength(fileName) > 100 && fileName.length > 0) {
                fileName = fileName.slice(0, -1);
            }
            console.warn(`Path truncated to fit TAR header: ${name}`);
        }
    }

    // Name (0-100)
    const encodedName = encoder.encode(fileName);
    header.set(encodedName.slice(0, 100), 0);

    // Mode (100-108) - 0755 for dirs, 0644 for files
    const mode = isDirectory ? '0000755' : '0000644';
    header.set(encoder.encode(mode + '\0'), 100);

    // UID (108-116)
    header.set(encoder.encode('0000000\0'), 108);

    // GID (116-124)
    header.set(encoder.encode('0000000\0'), 116);

    // Size (124-136) - 12 bytes
    // Standard USTAR: octal ASCII, max ~8GB
    // GNU extension: base-256 binary for files > 8GB (first byte 0x80)
    const MAX_OCTAL_SIZE = 0o77777777777; // 8,589,934,591 bytes (~8GB)
    if (size > MAX_OCTAL_SIZE) {
        // GNU base-256 encoding: 0x80 flag + 11 bytes big-endian binary
        const sizeBytes = new Uint8Array(12);
        sizeBytes[0] = 0x80; // Flag for base-256
        // Write size as big-endian into bytes 1-11 (88 bits, but we only use lower 64)
        // JavaScript numbers are safe up to 2^53, which is ~9 petabytes - plenty
        let remaining = size;
        for (let i = 11; i >= 1; i--) {
            sizeBytes[i] = remaining & 0xff;
            remaining = Math.floor(remaining / 256);
        }
        header.set(sizeBytes, 124);
    } else {
        // Standard octal encoding
        const sizeStr = size.toString(8).padStart(11, '0') + '\0';
        header.set(encoder.encode(sizeStr), 124);
    }

    // Mtime (136-148) - seconds since epoch, octal
    const mtimeSec = Math.floor(mtime / 1000);
    const mtimeStr = mtimeSec.toString(8).padStart(11, '0') + '\0';
    header.set(encoder.encode(mtimeStr), 136);

    // Checksum placeholder (148-156) - filled in later
    header.set(encoder.encode('        '), 148);

    // Type flag (156) - '0' for file, '5' for directory
    header[156] = isDirectory ? 53 : 48; // ASCII '5' or '0'

    // Link name (157-257) - empty for regular files

    // Magic (257-263) - "ustar\0"
    header.set(encoder.encode('ustar\0'), 257);

    // Version (263-265) - "00"
    header.set(encoder.encode('00'), 263);

    // User name (265-297)
    header.set(encoder.encode('user'), 265);

    // Group name (297-329)
    header.set(encoder.encode('user'), 297);

    // Dev major (329-337) - unused
    // Dev minor (337-345) - unused

    // Prefix (345-500) - for long names (155 bytes max)
    if (prefix) {
        const encodedPrefix = encoder.encode(prefix);
        header.set(encodedPrefix.slice(0, 155), 345);
    }

    // Calculate checksum
    let checksum = 0;
    for (let i = 0; i < TAR_BLOCK_SIZE; i++) {
        checksum += header[i];
    }
    const checksumStr = checksum.toString(8).padStart(6, '0') + '\0 ';
    header.set(encoder.encode(checksumStr), 148);

    return header;
}

// Pad data to 512-byte boundary
function padToBlock(data) {
    const remainder = data.length % TAR_BLOCK_SIZE;
    if (remainder === 0) return data;

    const padded = new Uint8Array(data.length + (TAR_BLOCK_SIZE - remainder));
    padded.set(data);
    return padded;
}

// Create TAR end marker (two zero blocks)
function createTarEnd() {
    return new Uint8Array(TAR_BLOCK_SIZE * 2);
}

// Create a ReadableStream that produces TAR data from an async iterable of files
// files: async iterable of { path: string, file: File | null (for dirs), isDirectory: boolean }
function createTarStream(files) {
    let fileIterator;
    let currentFile = null;
    let headerSent = false;
    let ended = false;

    return new ReadableStream({
        async start() {
            fileIterator = files[Symbol.asyncIterator]();
        },

        async pull(controller) {
            try {
                // If we've ended, close the stream
                if (ended) {
                    controller.close();
                    return;
                }

                // If we need a new file
                if (!currentFile) {
                    const { value, done } = await fileIterator.next();
                    if (done) {
                        // End of files - send TAR end marker
                        controller.enqueue(createTarEnd());
                        ended = true;
                        return;
                    }
                    currentFile = value;
                    headerSent = false;
                    console.log('TAR processing:', currentFile.path, currentFile.isDirectory ? '(dir)' : currentFile.file?.size + ' bytes');
                }

                // Send header if not sent yet
                if (!headerSent) {
                    const size = currentFile.isDirectory ? 0 : currentFile.file.size;
                    const mtime = currentFile.file?.lastModified || Date.now();
                    const header = createTarHeader(currentFile.path, size, currentFile.isDirectory, mtime);
                    controller.enqueue(header);
                    headerSent = true;

                    // If directory or empty file, move to next file
                    if (currentFile.isDirectory || size === 0) {
                        currentFile = null;
                        return;
                    }

                    // Read entire file content using arrayBuffer (more reliable than stream)
                    try {
                        const buffer = await currentFile.file.arrayBuffer();
                        controller.enqueue(new Uint8Array(buffer));

                        // Pad to block boundary
                        const remainder = size % TAR_BLOCK_SIZE;
                        if (remainder > 0) {
                            controller.enqueue(new Uint8Array(TAR_BLOCK_SIZE - remainder));
                        }
                    } catch (readErr) {
                        console.error('Failed to read file:', currentFile.path, readErr);
                        // Enqueue zeros for declared size to maintain TAR structure
                        const paddedSize = Math.ceil(size / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE;
                        controller.enqueue(new Uint8Array(paddedSize));
                    }
                    currentFile = null;
                    return;
                }
            } catch (err) {
                console.error('TAR stream pull error:', err, 'currentFile:', currentFile?.path);
                controller.error(err);
            }
        }
    });
}

// Parse TAR header
function parseTarHeader(header) {
    const decoder = new TextDecoder();

    // Check for end marker (all zeros)
    let allZero = true;
    for (let i = 0; i < TAR_BLOCK_SIZE; i++) {
        if (header[i] !== 0) {
            allZero = false;
            break;
        }
    }
    if (allZero) return null;

    // Extract name
    let name = decoder.decode(header.slice(0, 100)).replace(/\0.*$/, '');

    // Extract prefix and combine
    const prefix = decoder.decode(header.slice(345, 500)).replace(/\0.*$/, '');
    if (prefix) {
        name = prefix + '/' + name;
    }

    // Extract size - check for GNU base-256 encoding
    const sizeBytes = header.slice(124, 136);
    let size;
    if (sizeBytes[0] & 0x80) {
        // GNU base-256: first byte has high bit set, rest is big-endian binary
        size = 0;
        for (let i = 1; i < 12; i++) {
            size = size * 256 + sizeBytes[i];
        }
    } else {
        // Standard octal ASCII
        const sizeStr = decoder.decode(sizeBytes).replace(/\0.*$/, '').trim();
        size = parseInt(sizeStr, 8) || 0;
    }

    // Extract type
    const typeFlag = header[156];
    const isDirectory = typeFlag === 53 || typeFlag === 0x35 || name.endsWith('/'); // '5' or ends with /

    // Extract mtime
    const mtimeStr = decoder.decode(header.slice(136, 148)).replace(/\0.*$/, '').trim();
    const mtime = (parseInt(mtimeStr, 8) || 0) * 1000;

    return { name, size, isDirectory, mtime };
}

// Extract TAR stream to FileSystemDirectoryHandle
// Returns async generator yielding progress updates
async function* extractTarToDirectory(tarStream, destDir, onProgress) {
    const reader = tarStream.getReader();
    let buffer = new Uint8Array(0);
    let totalBytesRead = 0;
    let filesExtracted = 0;

    // Helper to read exactly n bytes
    async function readBytes(n) {
        while (buffer.length < n) {
            const { value, done } = await reader.read();
            if (done) {
                if (buffer.length < n) throw new Error('Unexpected end of TAR stream');
                break;
            }
            const newBuffer = new Uint8Array(buffer.length + value.length);
            newBuffer.set(buffer);
            newBuffer.set(value, buffer.length);
            buffer = newBuffer;
            totalBytesRead += value.length;
        }
        const result = buffer.slice(0, n);
        buffer = buffer.slice(n);
        return result;
    }

    // Create directory recursively
    async function ensureDir(dirHandle, pathParts) {
        let current = dirHandle;
        for (const part of pathParts) {
            if (part && part !== '.') {
                current = await current.getDirectoryHandle(part, { create: true });
            }
        }
        return current;
    }

    // Process TAR entries
    while (true) {
        // Read header
        const headerData = await readBytes(TAR_BLOCK_SIZE);
        const header = parseTarHeader(headerData);

        // End of TAR
        if (!header) break;

        // Clean path (remove leading ./ or /)
        let cleanPath = header.name.replace(/^\.\//, '').replace(/^\//, '');
        if (!cleanPath) continue;

        // Remove trailing slash from directories
        if (cleanPath.endsWith('/')) {
            cleanPath = cleanPath.slice(0, -1);
        }

        const pathParts = cleanPath.split('/');
        const fileName = pathParts.pop();

        if (header.isDirectory) {
            // Create directory
            await ensureDir(destDir, [...pathParts, fileName]);
            filesExtracted++;
            yield { type: 'directory', path: cleanPath, filesExtracted, bytesRead: totalBytesRead };
        } else {
            // Create parent directories
            const parentDir = await ensureDir(destDir, pathParts);

            // Create and write file
            const fileHandle = await parentDir.getFileHandle(fileName, { create: true });
            const writable = await fileHandle.createWritable();

            try {
                // Read file data in chunks
                let remaining = header.size;
                while (remaining > 0) {
                    const chunkSize = Math.min(remaining, 65536);
                    const chunk = await readBytes(chunkSize);
                    await writable.write(chunk);
                    remaining -= chunkSize;
                    yield { type: 'progress', path: cleanPath, bytesRead: totalBytesRead, remaining };
                }

                await writable.close();
            } catch (err) {
                // Clean up on error
                try { await writable.abort(); } catch (e) { /* ignore */ }
                throw err;
            }

            // Skip padding
            const padding = (TAR_BLOCK_SIZE - (header.size % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
            if (padding > 0) {
                await readBytes(padding);
            }

            filesExtracted++;
            yield { type: 'file', path: cleanPath, size: header.size, filesExtracted, bytesRead: totalBytesRead };
        }
    }

    yield { type: 'complete', filesExtracted, bytesRead: totalBytesRead };
}

// Export for use in other scripts
window.TarStream = {
    createTarStream,
    extractTarToDirectory,
    parseTarHeader,
    TAR_BLOCK_SIZE
};
