import test from 'node:test';
import assert from 'node:assert/strict';
import { decryptAmount, encryptAmount } from './decryption.mjs';

test('decryptAmount returns the original amount after encryptAmount round-trip', async () => {
  const ciphertext = await encryptAmount(12.5, 'auditor-key');
  const result = await decryptAmount(ciphertext, 'auditor-key');

  assert.equal(typeof result, 'number');
  assert.equal(result, 12.5);
});

test('encryptAmount produces a distinct ciphertext on every call (randomized nonce)', async () => {
  const first = await encryptAmount(12.5, 'auditor-key');
  const second = await encryptAmount(12.5, 'auditor-key');

  assert.notEqual(first, second);
});

test('decryptAmount rejects a wrong viewing key', async () => {
  const ciphertext = await encryptAmount(12.5, 'auditor-key');

  await assert.rejects(() => decryptAmount(ciphertext, 'wrong-key'), /wrong viewing key/);
});

test('decryptAmount rejects tampered ciphertext', async () => {
  const ciphertext = await encryptAmount(12.5, 'auditor-key');
  const bytes = Uint8Array.from(atob(ciphertext), (c) => c.charCodeAt(0));
  bytes[bytes.length - 1] ^= 0x01; // flip one ciphertext/tag bit
  const tampered = btoa(String.fromCharCode(...bytes));

  await assert.rejects(() => decryptAmount(tampered, 'auditor-key'), /corrupted ciphertext/);
});

test('decryptAmount rejects invalid ciphertext input', async () => {
  await assert.rejects(() => decryptAmount('', 'auditor-key'), /base64-encoded AES ciphertext/);
  await assert.rejects(() => decryptAmount('bm90LWVuY3J5cHRlZA==', 'auditor-key'), /too short|version/);
});

test('decryptAmount rejects a missing or malformed viewing key', async () => {
  const ciphertext = await encryptAmount(12.5, 'auditor-key');

  await assert.rejects(() => decryptAmount(ciphertext, ''), /non-empty string/);
  await assert.rejects(() => decryptAmount(ciphertext, 12345), /non-empty string/);
});

test('encryptAmount rejects invalid numeric input', async () => {
  await assert.rejects(() => encryptAmount(Number.NaN, 'auditor-key'), /finite number/);
  await assert.rejects(() => encryptAmount('not-a-number', 'auditor-key'), /finite number/);
});