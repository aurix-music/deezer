// Deezer BF_CBC_STRIPE decoder.
//
// Deezer never serves plain audio: get_url answers with a signed CDN URL whose
// bytes are Blowfish-CBC encrypted, and asking for cipher NONE/PLAIN returns
// 403 code 1002.
//
// Scheme: the file is cut into 2048-byte chunks and every third one, starting
// at index 0, is an independent Blowfish-CBC message with IV 00..07.
//   key[i] = md5(id)[i] ^ md5(id)[i+16] ^ 'g4el58wc0zvf9na1'[i]
// Each encrypted chunk decrypts in place to the same 2048 bytes, so plaintext
// and ciphertext offsets are identical.

import { createHash } from 'node:crypto';
import { Blowfish } from 'egoroof-blowfish';

export const CHUNK_BYTES = 2048;
export const STRIPE_EVERY = 3;

const BF_SECRET = 'g4el58wc0zvf9na1';
const BF_IV = Uint8Array.from([0, 1, 2, 3, 4, 5, 6, 7]);

export function isEncryptedChunk(index: number): boolean {
  return index % STRIPE_EVERY === 0;
}

export function blowfishKey(trackId: string | number): Uint8Array {
  const id = String(trackId).replace(/^deezer:/, '');
  const md5 = createHash('md5').update(id).digest('hex');
  const key = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    key[i] = md5.charCodeAt(i) ^ md5.charCodeAt(i + 16) ^ BF_SECRET.charCodeAt(i);
  }
  return key;
}

/** Decrypt in place. `buf` must be 2048-aligned; `firstChunk` is buf[0]'s index. */
export function decryptChunks(buf: Uint8Array, firstChunk: number, key: Uint8Array): void {
  if (buf.length === 0) return;
  if (buf.length % CHUNK_BYTES !== 0) throw new Error('buffer is not chunk-aligned');

  const bf = new Blowfish(key, Blowfish.MODE.CBC, Blowfish.PADDING.NULL);
  for (let i = 0; i < buf.length / CHUNK_BYTES; i++) {
    if (!isEncryptedChunk(firstChunk + i)) continue;
    const off = i * CHUNK_BYTES;
    // Fresh CBC state per chunk: a stale chain corrupts everything after it.
    bf.setIv(BF_IV);
    // TYPE.UINT8_ARRAY is mandatory; the default returns a string.
    const out = bf.decode(buf.subarray(off, off + CHUNK_BYTES), Blowfish.TYPE.UINT8_ARRAY);
    // PADDING.NULL trims trailing NULs, but a real chunk may end in NULs
    // (silence). The full plaintext still sits in the view's buffer.
    buf.set(new Uint8Array(out.buffer, out.byteOffset, CHUNK_BYTES), off);
  }
}

/** Whole-file convenience. Returns a copy; the input is untouched. */
export function decryptBuffer(buf: Uint8Array, trackId: string | number): Uint8Array {
  const out = buf.slice();
  decryptChunks(out, 0, blowfishKey(trackId));
  return out;
}

/** Sanity gate: a decrypted file must start with FLAC, ID3 or an MPEG sync. */
export function looksLikeAudioStart(bytes: Uint8Array): boolean {
  if (bytes.length < 4) return false;
  const flac = bytes[0] === 0x66 && bytes[1] === 0x4c && bytes[2] === 0x61 && bytes[3] === 0x43;
  const id3 = bytes[0] === 0x49 && bytes[1] === 0x44 && bytes[2] === 0x33;
  const mpeg = bytes[0] === 0xff && (bytes[1] & 0xe0) === 0xe0;
  return flac || id3 || mpeg;
}
