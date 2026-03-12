import { timelockEncrypt, timelockDecrypt } from "https://esm.sh/tlock-js@0.9.0?bundle";
import * as drandClient from "https://esm.sh/drand-client@1.2.0?bundle";

// Expose for usage
window.drandClient = drandClient;

const chainHash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
const drandUrl = "https://api.drand.sh";
const chainUrl = `${drandUrl}/${chainHash}`;

const CHUNK_SIZE = 1024 * 1024 * 5; // 5MB chunks for better throughput
const MAGIC_BYTES = new TextEncoder().encode("CHRONOS1"); // 8 bytes
const TAG_LENGTH = 16;
const IV_LENGTH = 12;

const statusEl = (id) => document.getElementById(id);
const downloadEl = (id) => document.getElementById(id + '-download-area');

// --- Crypto Helpers ---

function calculateRound(targetTimeMs, chainInfo) {
    const genesis = chainInfo.genesis_time;
    const period = chainInfo.period;
    const targetSeconds = Math.floor(targetTimeMs / 1000);

    if (targetSeconds < genesis) return 1;
    return Math.floor((targetSeconds - genesis) / period) + 1;
}

async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

async function encryptChunk(key, chunk) {
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const ciphertext = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        chunk
    );
    // Return IV + Ciphertext (includes tag)
    const result = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(ciphertext), IV_LENGTH);
    return result;
}

async function decryptChunk(key, chunkWithIv) {
    const iv = chunkWithIv.slice(0, IV_LENGTH);
    const ciphertext = chunkWithIv.slice(IV_LENGTH);
    return window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        ciphertext
    );
}

async function generateMasterKey() {
    return window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

async function exportKey(key) {
    return new Uint8Array(await window.crypto.subtle.exportKey("raw", key));
}

async function importKey(bytes) {
    return window.crypto.subtle.importKey(
        "raw", bytes, "AES-GCM", true, ["encrypt", "decrypt"]
    );
}

async function encryptWithKey(key, data) {
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        data
    );
    return { iv: Array.from(iv), ciphertext: Array.from(new Uint8Array(encrypted)) };
}

async function decryptWithKeySimple(key, iv, ciphertext) {
    return window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: new Uint8Array(iv) },
        key,
        new Uint8Array(ciphertext)
    );
}

// --- Drand Network ---

async function fetchChainInfo() {
    const url = `${chainUrl}/info`;
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Network Error: ${response.status}`);
    return await response.json();
}

async function getDrandClient() {
    const options = { chainHash };
    const chain = new window.drandClient.HttpCachingChain(chainUrl, options);
    return new window.drandClient.HttpChainClient(chain, options);
}

// --- Stream Logic ---

async function handleEncrypt() {
    const fileInput = document.getElementById('enc-file');
    const passInput = document.getElementById('enc-password');
    const dateInput = document.getElementById('enc-date');
    const status = statusEl('enc-status');
    const download = downloadEl('enc');

    if (!fileInput.files[0] || !passInput.value || !dateInput.value) {
        status.innerText = "Error: Please fill all fields.";
        status.className = "status-box error";
        return;
    }

    if (!window.showSaveFilePicker) {
        status.innerText = "Error: Your browser does not support Stream Saving. Use Chrome/Edge or Desktop.";
        status.className = "status-box error";
        return;
    }

    status.innerText = "Initializing Stream Encryption...";
    status.className = "status-box";
    download.innerHTML = "";

    try {
        const file = fileInput.files[0];
        const password = passInput.value;
        const targetDate = new Date(dateInput.value).getTime();

        if (targetDate <= Date.now()) throw new Error("Target time must be in the future.");

        // 1. Prompt Save Location
        const saveHandle = await window.showSaveFilePicker({
            suggestedName: file.name + ".chronos",
            types: [{
                description: 'Chronos Encrypted File',
                accept: { 'application/octet-stream': ['.chronos'] },
            }],
        });
        const writable = await saveHandle.createWritable();

        // 2. Prepare Keys
        status.innerText = "Generating Military-Grade Keys...";
        const masterKey = await generateMasterKey();
        const masterKeyBytes = await exportKey(masterKey);
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const pwKey = await deriveKey(password, salt);
        const { iv: kIv, ciphertext: kCipher } = await encryptWithKey(pwKey, masterKeyBytes);

        // 3. Time Lock
        status.innerText = "Contacting Drand Network...";
        const chainInfo = await fetchChainInfo();
        const round = calculateRound(targetDate, chainInfo);
        const client = await getDrandClient();

        console.log(`Locking to round: ${round}`);
        const timeLockedCipher = await timelockEncrypt(
            round,
            new Uint8Array(kCipher),
            client
        );

        // 4. Create Header
        const header = {
            version: "2.0",
            meta: {
                filename: file.name,
                unlockTime: targetDate,
                round: round,
                chainHash: chainHash,
                fileSize: file.size,
                chunkSize: CHUNK_SIZE
            },
            security: {
                salt: Array.from(salt),
                keyIv: Array.from(kIv)
            },
            data: {
                timeLockedKey: typeof timeLockedCipher === 'string' ? timeLockedCipher : Array.from(new Uint8Array(timeLockedCipher))
            }
        };

        const headerJson = JSON.stringify(header);
        const headerBytes = new TextEncoder().encode(headerJson);
        const headerLen = new Uint8Array(4);
        new DataView(headerLen.buffer).setUint32(0, headerBytes.length, true);

        // 5. Write Header
        await writable.write(MAGIC_BYTES);
        await writable.write(headerLen);
        await writable.write(headerBytes);

        // 6. Encrypt & Stream Chunks
        status.innerText = "Encrypting Large File (Stream Mode)...";

        // Manual slicing to ensure fixed chunk sizes (easier decryption)
        let offset = 0;
        const totalSize = file.size; // 2GB+ supported

        while (offset < totalSize) {
            const size = Math.min(CHUNK_SIZE, totalSize - offset);
            const chunkBlob = file.slice(offset, offset + size);
            const chunkBuffer = await chunkBlob.arrayBuffer();

            const encryptedChunk = await encryptChunk(masterKey, chunkBuffer);
            await writable.write(encryptedChunk);

            offset += size;

            // UI Updates (throttle?)
            if (offset % (CHUNK_SIZE * 5) === 0 || offset === totalSize) {
                const progress = ((offset / totalSize) * 100).toFixed(1);
                status.innerText = `Encrypting: ${progress}%`;
            }
        }

        await writable.close();
        status.innerText = "Encryption Complete. File Saved.";
        status.className = "status-box success";

    } catch (e) {
        console.error(e);
        status.innerText = "Encryption Failed: " + e.message;
        status.className = "status-box error";
    }
}

async function handleDecrypt() {
    const fileInput = document.getElementById('dec-file');
    const passInput = document.getElementById('dec-password');
    const status = statusEl('dec-status');

    if (!fileInput.files[0] || !passInput.value) {
        status.innerText = "Error: Please provide file and password.";
        status.className = "status-box error";
        return;
    }

    if (!window.showSaveFilePicker) {
        status.innerText = "Error: Your browser does not support Stream Saving.";
        status.className = "status-box error";
        return;
    }

    status.innerText = "Analyzing Artifact...";
    status.className = "status-box";

    try {
        const file = fileInput.files[0];
        const password = passInput.value;
        const totalSize = file.size;

        // 1. Read Header
        const preambleInfo = await file.slice(0, 12).arrayBuffer();
        const preambleView = new DataView(preambleInfo);

        const magic = new Uint8Array(preambleInfo, 0, 8);
        const magicStr = new TextDecoder().decode(magic);
        if (magicStr !== "CHRONOS1") {
            // Backward compatibility for v1.0 (JSON) can be added here if needed
            throw new Error("Invalid Format. Expected .chronos 2.0");
        }

        const headerLength = preambleView.getUint32(8, true);
        const headerEnd = 12 + headerLength;

        const headerInfo = await file.slice(12, headerEnd).arrayBuffer();
        const headerJson = new TextDecoder().decode(headerInfo);
        const payload = JSON.parse(headerJson);

        // 2. Time Check
        const unlockTime = payload.meta.unlockTime;
        if (unlockTime - Date.now() > 0) {
            const seconds = Math.ceil((unlockTime - Date.now()) / 1000);
            throw new Error(`Time Lock Active. Decryption available in ${seconds} seconds.`);
        }

        // 3. Save Prompt
        const saveHandle = await window.showSaveFilePicker({
            suggestedName: payload.meta.filename || "decrypted_file",
        });
        const writable = await saveHandle.createWritable();

        // 4. Verification
        status.innerText = "Verifying Signatures...";
        const client = await getDrandClient();

        let tlockCipher = payload.data.timeLockedKey;
        if (Array.isArray(tlockCipher)) tlockCipher = new Uint8Array(tlockCipher);

        let pwEncryptedKeyBytes;
        try {
            pwEncryptedKeyBytes = await timelockDecrypt(tlockCipher, client);
        } catch (err) {
            if (err.message && err.message.includes("future")) {
                throw new Error("Too early to decrypt.");
            }
            throw err;
        }

        status.innerText = "Decrypting Keys...";
        const salt = new Uint8Array(payload.security.salt);
        const kIv = new Uint8Array(payload.security.keyIv);
        const pwKey = await deriveKey(password, salt);

        let masterKeyBytes;
        try {
            const buf = await decryptWithKeySimple(pwKey, kIv, pwEncryptedKeyBytes);
            masterKeyBytes = new Uint8Array(buf);
        } catch (e) { throw new Error("Incorrect Password."); }

        const masterKey = await importKey(masterKeyBytes);

        // 5. Stream Decrypt
        status.innerText = "Decrypting Stream...";
        let offset = headerEnd;
        const fileDataSize = totalSize - offset;

        // Chunk Size from header or default
        const ORIG_CHUNK_SIZE = payload.meta.chunkSize || (1024 * 1024);

        // Calculate Encrypted Chunk Size = IV + Orig + Tag
        // Tag is 16 bytes for AES-GCM, IV is 12
        // AES-GCM output size = Input size + 16 (Tag)
        // Total Chunk = 12 + (Size + 16) = Size + 28

        const ENC_OVERHEAD = IV_LENGTH + TAG_LENGTH;
        const ENC_CHUNK_SIZE = ORIG_CHUNK_SIZE + ENC_OVERHEAD;

        // Note: The LAST chunk might be smaller.

        let decryptedBytes = 0;

        while (offset < totalSize) {
            // How much to read?
            // We know chunks are ENC_CHUNK_SIZE unless it's the last one.
            let bytesToRead = ENC_CHUNK_SIZE;

            // Check if this is the last chunk
            if (offset + bytesToRead > totalSize) {
                bytesToRead = totalSize - offset;
            }

            const chunkBlob = file.slice(offset, offset + bytesToRead);
            const chunkBuffer = await chunkBlob.arrayBuffer();

            const decryptedChunk = await decryptChunk(masterKey, chunkBuffer);
            await writable.write(decryptedChunk);

            decryptedBytes += decryptedChunk.byteLength;
            offset += bytesToRead;

            if (offset % (ENC_CHUNK_SIZE * 5) === 0 || offset === totalSize) {
                const progress = ((offset / totalSize) * 100).toFixed(1);
                status.innerText = `Decrypting: ${progress}%`;
            }
        }

        await writable.close();
        status.innerText = "Decryption Complete. Access Granted.";
        status.className = "status-box success";

    } catch (e) {
        console.error(e);
        status.innerText = "Decryption Failed: " + e.message;
        status.className = "status-box error";
    }
}

document.getElementById('btn-encrypt').addEventListener('click', handleEncrypt);
document.getElementById('btn-decrypt').addEventListener('click', handleDecrypt);
