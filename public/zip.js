// Streaming ZIP implementation for browser
// Supports: STORE (no compression), ZIP64 for large files, UTF-8 filenames

const ZIP_VERSION = 20;           // 2.0 - minimum for deflate/folders
const ZIP_VERSION_ZIP64 = 45;     // 4.5 - minimum for ZIP64
const ZIP_STORE = 0;              // No compression

// CRC32 lookup table
const crc32Table = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
        c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    crc32Table[i] = c;
}

function crc32(data, prev = 0) {
    let crc = prev ^ 0xFFFFFFFF;
    for (let i = 0; i < data.length; i++) {
        crc = crc32Table[(crc ^ data[i]) & 0xFF] ^ (crc >>> 8);
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
}

// Helper to write little-endian values
function writeUint16(arr, offset, value) {
    arr[offset] = value & 0xFF;
    arr[offset + 1] = (value >> 8) & 0xFF;
}

function writeUint32(arr, offset, value) {
    arr[offset] = value & 0xFF;
    arr[offset + 1] = (value >> 8) & 0xFF;
    arr[offset + 2] = (value >> 16) & 0xFF;
    arr[offset + 3] = (value >> 24) & 0xFF;
}

function writeUint64(arr, offset, value) {
    // JavaScript numbers are safe up to 2^53
    const low = value & 0xFFFFFFFF;
    const high = Math.floor(value / 0x100000000) & 0xFFFFFFFF;
    writeUint32(arr, offset, low);
    writeUint32(arr, offset + 4, high);
}

// DOS date/time format
function dosDateTime(date) {
    const d = date || new Date();
    const time = ((d.getHours() & 0x1F) << 11) |
                 ((d.getMinutes() & 0x3F) << 5) |
                 ((d.getSeconds() >> 1) & 0x1F);
    const dateVal = (((d.getFullYear() - 1980) & 0x7F) << 9) |
                    (((d.getMonth() + 1) & 0x0F) << 5) |
                    (d.getDate() & 0x1F);
    return { time, date: dateVal };
}

// Create local file header
function createLocalHeader(fileName, fileSize, isDirectory, mtime) {
    const encoder = new TextEncoder();
    const nameBytes = encoder.encode(fileName);
    const needsZip64 = fileSize > 0xFFFFFFFF;

    const { time, date } = dosDateTime(mtime);

    // ZIP64 extra field if needed (for local header with data descriptor)
    // When using data descriptors (bit 3), sizes here should be 0 - actual sizes are in descriptor
    let extraField = new Uint8Array(0);
    if (needsZip64) {
        extraField = new Uint8Array(20);
        writeUint16(extraField, 0, 0x0001);  // ZIP64 tag
        writeUint16(extraField, 2, 16);       // Size of extra data
        writeUint64(extraField, 4, 0);        // Uncompressed size (0 = in data descriptor)
        writeUint64(extraField, 12, 0);       // Compressed size (0 = in data descriptor)
    }

    const header = new Uint8Array(30 + nameBytes.length + extraField.length);

    // Local file header signature
    writeUint32(header, 0, 0x04034B50);

    // Version needed (4.5 for ZIP64, 2.0 otherwise)
    writeUint16(header, 4, needsZip64 ? ZIP_VERSION_ZIP64 : ZIP_VERSION);

    // General purpose bit flag
    // Bit 3: sizes in data descriptor (required for streaming - CRC unknown until after data)
    // Bit 11: UTF-8 filename
    writeUint16(header, 6, 0x0808);  // Data descriptor + UTF-8 flags

    // Compression method (0 = STORE)
    writeUint16(header, 8, ZIP_STORE);

    // Last mod time/date
    writeUint16(header, 10, time);
    writeUint16(header, 12, date);

    // CRC32 - set to 0 when using data descriptor (bit 3)
    writeUint32(header, 14, 0);

    // Compressed size - 0 for data descriptor, 0xFFFFFFFF signals ZIP64 extra field
    writeUint32(header, 18, needsZip64 ? 0xFFFFFFFF : 0);

    // Uncompressed size - 0 for data descriptor, 0xFFFFFFFF signals ZIP64 extra field
    writeUint32(header, 22, needsZip64 ? 0xFFFFFFFF : 0);

    // Filename length
    writeUint16(header, 26, nameBytes.length);

    // Extra field length
    writeUint16(header, 28, extraField.length);

    // Filename
    header.set(nameBytes, 30);

    // Extra field
    if (extraField.length > 0) {
        header.set(extraField, 30 + nameBytes.length);
    }

    return { header, nameBytes, needsZip64 };
}

// Create data descriptor (written after file data with CRC)
function createDataDescriptor(crc, size, needsZip64) {
    if (needsZip64) {
        const desc = new Uint8Array(24);
        writeUint32(desc, 0, 0x08074B50);  // Signature
        writeUint32(desc, 4, crc);
        writeUint64(desc, 8, size);         // Compressed
        writeUint64(desc, 16, size);        // Uncompressed
        return desc;
    } else {
        const desc = new Uint8Array(16);
        writeUint32(desc, 0, 0x08074B50);  // Signature
        writeUint32(desc, 4, crc);
        writeUint32(desc, 8, size);         // Compressed
        writeUint32(desc, 12, size);        // Uncompressed
        return desc;
    }
}

// Create central directory entry
function createCentralDirectoryEntry(fileName, fileSize, crc, localHeaderOffset, isDirectory, mtime) {
    const encoder = new TextEncoder();
    const nameBytes = encoder.encode(fileName);
    const needsZip64 = fileSize > 0xFFFFFFFF || localHeaderOffset > 0xFFFFFFFF;

    const { time, date } = dosDateTime(mtime);

    // ZIP64 extra field if needed
    let extraField = new Uint8Array(0);
    if (needsZip64) {
        extraField = new Uint8Array(28);
        writeUint16(extraField, 0, 0x0001);  // ZIP64 tag
        writeUint16(extraField, 2, 24);       // Size
        writeUint64(extraField, 4, fileSize); // Uncompressed
        writeUint64(extraField, 12, fileSize); // Compressed
        writeUint64(extraField, 20, localHeaderOffset);
    }

    const entry = new Uint8Array(46 + nameBytes.length + extraField.length);

    // Central directory signature
    writeUint32(entry, 0, 0x02014B50);

    // Version made by (MS-DOS = 0 for max compatibility)
    const version = needsZip64 ? ZIP_VERSION_ZIP64 : ZIP_VERSION;
    writeUint16(entry, 4, version);

    // Version needed
    writeUint16(entry, 6, version);

    // Flags (UTF-8 + data descriptor)
    writeUint16(entry, 8, 0x0808);

    // Compression
    writeUint16(entry, 10, ZIP_STORE);

    // Time/date
    writeUint16(entry, 12, time);
    writeUint16(entry, 14, date);

    // CRC
    writeUint32(entry, 16, crc);

    // Sizes
    writeUint32(entry, 20, needsZip64 ? 0xFFFFFFFF : fileSize);
    writeUint32(entry, 24, needsZip64 ? 0xFFFFFFFF : fileSize);

    // Filename length
    writeUint16(entry, 28, nameBytes.length);

    // Extra field length
    writeUint16(entry, 30, extraField.length);

    // Comment length
    writeUint16(entry, 32, 0);

    // Disk number
    writeUint16(entry, 34, 0);

    // Internal attributes
    writeUint16(entry, 36, 0);

    // External attributes (directory flag for dirs)
    const externalAttr = isDirectory ? 0x10 : 0;
    writeUint32(entry, 38, externalAttr);

    // Local header offset
    writeUint32(entry, 42, needsZip64 ? 0xFFFFFFFF : localHeaderOffset);

    // Filename
    entry.set(nameBytes, 46);

    // Extra field
    if (extraField.length > 0) {
        entry.set(extraField, 46 + nameBytes.length);
    }

    return entry;
}

// Create end of central directory
function createEndOfCentralDirectory(entryCount, centralDirSize, centralDirOffset) {
    const needsZip64 = entryCount > 0xFFFF || centralDirSize > 0xFFFFFFFF || centralDirOffset > 0xFFFFFFFF;

    if (needsZip64) {
        // ZIP64 end of central directory + locator + regular end
        const zip64End = new Uint8Array(56);
        writeUint32(zip64End, 0, 0x06064B50);  // ZIP64 EOCD signature
        writeUint64(zip64End, 4, 44);           // Size of this record
        writeUint16(zip64End, 12, ZIP_VERSION_ZIP64);
        writeUint16(zip64End, 14, ZIP_VERSION_ZIP64);
        writeUint32(zip64End, 16, 0);           // Disk number
        writeUint32(zip64End, 20, 0);           // Disk with central dir
        writeUint64(zip64End, 24, entryCount);  // Entries on this disk
        writeUint64(zip64End, 32, entryCount);  // Total entries
        writeUint64(zip64End, 40, centralDirSize);
        writeUint64(zip64End, 48, centralDirOffset);

        const zip64Locator = new Uint8Array(20);
        writeUint32(zip64Locator, 0, 0x07064B50);  // Locator signature
        writeUint32(zip64Locator, 4, 0);           // Disk with ZIP64 EOCD
        writeUint64(zip64Locator, 8, centralDirOffset + centralDirSize);
        writeUint32(zip64Locator, 16, 1);          // Total disks

        const end = new Uint8Array(22);
        writeUint32(end, 0, 0x06054B50);
        writeUint16(end, 4, 0);
        writeUint16(end, 6, 0);
        writeUint16(end, 8, 0xFFFF);
        writeUint16(end, 10, 0xFFFF);
        writeUint32(end, 12, 0xFFFFFFFF);
        writeUint32(end, 16, 0xFFFFFFFF);
        writeUint16(end, 20, 0);

        // Combine all three
        const result = new Uint8Array(zip64End.length + zip64Locator.length + end.length);
        result.set(zip64End, 0);
        result.set(zip64Locator, zip64End.length);
        result.set(end, zip64End.length + zip64Locator.length);
        return result;
    } else {
        const end = new Uint8Array(22);
        writeUint32(end, 0, 0x06054B50);
        writeUint16(end, 4, 0);
        writeUint16(end, 6, 0);
        writeUint16(end, 8, entryCount);
        writeUint16(end, 10, entryCount);
        writeUint32(end, 12, centralDirSize);
        writeUint32(end, 16, centralDirOffset);
        writeUint16(end, 20, 0);
        return end;
    }
}

// Streaming ZIP generator
// files: async iterable of { path, file, isDirectory }
// onFile: callback(path, size, isDirectory, index)
async function* createZipGenerator(files, onFile) {
    const centralDirectory = [];
    let offset = 0;
    let fileIndex = 0;

    for await (const item of files) {
        if (onFile) onFile(item.path, item.file?.size || 0, item.isDirectory, fileIndex++);

        const size = item.isDirectory ? 0 : item.file.size;
        const mtime = item.file?.lastModified ? new Date(item.file.lastModified) : new Date();

        // Normalize path: use forward slashes, add trailing slash for directories
        let zipPath = item.path.replace(/\\/g, '/');
        if (item.isDirectory && !zipPath.endsWith('/')) {
            zipPath += '/';
        }

        const localHeaderOffset = offset;
        const { header, nameBytes, needsZip64 } = createLocalHeader(zipPath, size, item.isDirectory, mtime);

        yield header;
        offset += header.length;

        // Stream file content and calculate CRC
        let crc = 0;
        if (!item.isDirectory && size > 0) {
            const reader = item.file.stream().getReader();
            while (true) {
                const { value, done } = await reader.read();
                if (done) break;
                crc = crc32(value, crc);
                yield value;
                offset += value.length;
            }
        }

        // Data descriptor with CRC
        const descriptor = createDataDescriptor(crc, size, needsZip64);
        yield descriptor;
        offset += descriptor.length;

        // Store info for central directory
        centralDirectory.push({
            path: zipPath,
            size,
            crc,
            offset: localHeaderOffset,
            isDirectory: item.isDirectory,
            mtime
        });
    }

    // Write central directory
    const centralDirOffset = offset;
    let centralDirSize = 0;

    for (const entry of centralDirectory) {
        const cdEntry = createCentralDirectoryEntry(
            entry.path,
            entry.size,
            entry.crc,
            entry.offset,
            entry.isDirectory,
            entry.mtime
        );
        yield cdEntry;
        centralDirSize += cdEntry.length;
    }

    // End of central directory
    const eocd = createEndOfCentralDirectory(centralDirectory.length, centralDirSize, centralDirOffset);
    yield eocd;
}

// Wrapper to create ReadableStream from generator
function createZipStream(files, onFile) {
    const generator = createZipGenerator(files, onFile);

    return new ReadableStream({
        async pull(controller) {
            const { value, done } = await generator.next();
            if (done) {
                controller.close();
            } else {
                controller.enqueue(value);
            }
        }
    });
}

// Calculate total ZIP size (for progress estimation)
// This is approximate due to variable-length headers
function estimateZipSize(items) {
    let size = 0;
    for (const item of items) {
        const pathBytes = new TextEncoder().encode(item.path).length;
        const fileSize = item.isDirectory ? 0 : item.file.size;
        const needsZip64 = fileSize > 0xFFFFFFFF;

        // Local header + data + data descriptor
        size += 30 + pathBytes + (needsZip64 ? 20 : 0);  // Local header
        size += fileSize;                                  // File data
        size += needsZip64 ? 24 : 16;                     // Data descriptor

        // Central directory entry
        size += 46 + pathBytes + (needsZip64 ? 28 : 0);
    }

    // End of central directory (assume ZIP64 for safety)
    size += 56 + 20 + 22;

    return size;
}

// Export for use in other scripts
window.ZipStream = {
    createZipStream,
    createZipGenerator,
    estimateZipSize,
    crc32
};
