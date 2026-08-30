// Real encryption/decryption for the shielded-balance audit view.
//
// Uses AES-256-GCM (authenticated encryption) via the Web Crypto API with a
// key derived from the viewing key through PBKDF2-HMAC-SHA256 (310,000
// iterations, OWASP-recommended). A random 12-byte GCM nonce and a random
// 16-byte salt are generated per message, so ciphertexts are semantically
// secure: the same amount + key produce different ciphertext on every call,
// and tampering with the ciphertext is detected by GCM's authentication tag
// instead of silently returning garbage.
//
// Ciphertext encoding (base64):
//   version(1) ‖ salt(16) ‖ nonce(12) ‖ AES-256-GCM(plaintext ‖ authTag(16))
//
// The plaintext is the UTF-8 encoding of the amount. This replaces the
// previous FNV-1a-style hash, which had no key material and no cryptographic
// security.

const ITERATIONS = 310_000;
const VERSION = 1;
const SALT_LEN = 16;
const NONCE_LEN = 12;
const TAG_LEN = 16;

function getCrypto() {
  if (typeof globalThis.crypto?.subtle !== 'object') {
    throw new Error('Web Crypto (crypto.subtle) is not available in this runtime.');
  }
  return globalThis.crypto;
}

function validateViewingKey(viewingKey) {
  if (typeof viewingKey !== 'string' || viewingKey.trim().length === 0) {
    throw new Error('Viewing key must be a non-empty string.');
  }
}

function bytesToBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(base64) {
  const normalized = base64.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function deriveKey(cryptoApi, viewingKey, salt) {
  const keyMaterial = await cryptoApi.subtle.importKey(
    'raw',
    new TextEncoder().encode(viewingKey.trim()),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return cryptoApi.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function encryptAmount(amount, viewingKey) {
  const numeric = Number(amount);
  if (typeof amount !== 'number' || !Number.isFinite(numeric)) {
    throw new Error('Expected a finite number for the amount to encrypt.');
  }
  validateViewingKey(viewingKey);
  const cryptoApi = getCrypto();

  const salt = cryptoApi.getRandomValues(new Uint8Array(SALT_LEN));
  const nonce = cryptoApi.getRandomValues(new Uint8Array(NONCE_LEN));
  const key = await deriveKey(cryptoApi, viewingKey, salt);
  const plaintext = new TextEncoder().encode(String(numeric));
  const sealed = new Uint8Array(
    await cryptoApi.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plaintext),
  );

  const blob = new Uint8Array(1 + SALT_LEN + NONCE_LEN + sealed.length);
  blob[0] = VERSION;
  blob.set(salt, 1);
  blob.set(nonce, 1 + SALT_LEN);
  blob.set(sealed, 1 + SALT_LEN + NONCE_LEN);
  return bytesToBase64(blob);
}

export async function decryptAmount(ciphertext, viewingKey) {
  if (typeof ciphertext !== 'string' || ciphertext.trim().length === 0) {
    throw new Error('Expected base64-encoded AES ciphertext.');
  }
  validateViewingKey(viewingKey);
  const cryptoApi = getCrypto();

  const blob = base64ToBytes(ciphertext.trim());
  if (blob[0] !== VERSION) {
    throw new Error('Unsupported ciphertext version.');
  }
  const headerLen = 1 + SALT_LEN + NONCE_LEN;
  if (blob.length < headerLen + TAG_LEN + 1) {
    throw new Error('Ciphertext is too short to be a valid AES-GCM payload.');
  }

  const salt = blob.subarray(1, 1 + SALT_LEN);
  const nonce = blob.subarray(1 + SALT_LEN, headerLen);
  const sealed = blob.subarray(headerLen);
  const key = await deriveKey(cryptoApi, viewingKey, salt);

  let plaintext;
  try {
    plaintext = await cryptoApi.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, sealed);
  } catch {
    throw new Error('Decryption failed: wrong viewing key or corrupted ciphertext.');
  }

  const decoded = new TextDecoder().decode(plaintext);
  if (decoded.length === 0 || !Number.isFinite(Number(decoded))) {
    throw new Error('Decrypted payload is not a valid amount.');
  }
  return Number(Number(decoded).toFixed(2));
}