import assert from 'node:assert/strict';
import test from 'node:test';
import { Blowfish } from 'egoroof-blowfish';
import {
  CHUNK_BYTES,
  STRIPE_EVERY,
  blowfishKey,
  decryptBuffer,
  decryptChunks,
  isEncryptedChunk,
  looksLikeAudioStart,
} from '../dist/decoder.js';

const TRACK = '456789';
const IV = Uint8Array.from([0, 1, 2, 3, 4, 5, 6, 7]);

function plaintext(chunks = 12) {
  const out = new Uint8Array(chunks * CHUNK_BYTES);
  out.set([0x66, 0x4c, 0x61, 0x43, 0x00, 0x00, 0x00, 0x22], 0);
  for (let i = 8; i < out.length; i++) out[i] = (i * 37) & 0xff;
  return out;
}

function encrypt(plain) {
  const bf = new Blowfish(blowfishKey(TRACK), Blowfish.MODE.CBC, Blowfish.PADDING.NULL);
  const out = Uint8Array.from(plain);
  for (let i = 0; i < out.length / CHUNK_BYTES; i++) {
    if (!isEncryptedChunk(i)) continue;
    const off = i * CHUNK_BYTES;
    bf.setIv(IV);
    out.set(bf.encode(out.subarray(off, off + CHUNK_BYTES)), off);
  }
  return out;
}

test('decrypts the stripe layout back to the original bytes', () => {
  const plain = plaintext();
  const cipher = encrypt(plain);
  assert.notDeepEqual(cipher.subarray(0, 4), plain.subarray(0, 4));
  assert.deepEqual(decryptBuffer(cipher, TRACK), plain);
  assert.equal(looksLikeAudioStart(plain), true);
});

test('only every third chunk from index 0 is enciphered', () => {
  assert.equal(STRIPE_EVERY, 3);
  assert.deepEqual([0, 1, 2, 3, 4, 5].map(isEncryptedChunk), [
    true,
    false,
    false,
    true,
    false,
    false,
  ]);
});

test('refuses unaligned buffers', () => {
  assert.throws(() => decryptChunks(new Uint8Array(100), 0, blowfishKey(TRACK)), /chunk-aligned/);
});

test('keeps trailing NUL bytes in a decrypted chunk', () => {
  const plain = plaintext(6);
  plain.fill(0, CHUNK_BYTES - 8, CHUNK_BYTES);
  assert.deepEqual(decryptBuffer(encrypt(plain), TRACK), plain);
});

test('an aligned slice decrypts from its own chunk index', () => {
  const plain = plaintext();
  const work = encrypt(plain);
  const tail = work.subarray(3 * CHUNK_BYTES);
  decryptChunks(tail, 3, blowfishKey(TRACK));
  assert.deepEqual(tail, plain.subarray(3 * CHUNK_BYTES));
});
