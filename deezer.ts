#!/usr/bin/env node
// Minimal Deezer client, standalone.
//
// ARL cookie -> deezer.ping (session) -> deezer.getUserData (api_token +
// license_token) -> song.getData (track token) -> media.deezer.com/v1/get_url
// (signed CDN URL) -> decrypt with decoder.ts.
//
// Deps: node >= 18 (global fetch), egoroof-blowfish.
//
// CLI:
//   npx tsx deezer.ts <ARL> search "get lucky"
//   npx tsx deezer.ts <ARL> get 3135556 [out.flac]
//
// The ARL is a full-account cookie. Keep it out of git and shell history.

import { createWriteStream, realpathSync } from 'node:fs';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import {
  CHUNK_BYTES,
  blowfishKey,
  decryptChunks,
  looksLikeAudioStart,
} from './decoder.js';

const GW = 'https://www.deezer.com/ajax/gw-light.php';
const MEDIA = 'https://media.deezer.com/v1/get_url';
const PUBLIC = 'https://api.deezer.com';

export type Quality = 'lossless' | 'high' | 'low';

const CHAINS: Record<Quality, string[]> = {
  lossless: ['FLAC', 'MP3_320', 'MP3_128'],
  high: ['MP3_320', 'MP3_128'],
  low: ['MP3_128'],
};

const BITRATE: Record<string, number> = { FLAC: 1411, MP3_320: 320, MP3_128: 128 };

export interface Session {
  arl: string;
  sid: string;
  apiToken: string;
  licenseToken: string;
}

export interface Track {
  id: number;
  title: string;
  artist: string;
  album: string;
  duration: number;
}

export interface Stream {
  url: string;
  format: string;
  bitrate: number;
}

class CsrfError extends Error {}

const cookieOf = (s: Session) => `arl=${s.arl}; sid=${s.sid}`;

async function gw(
  method: string,
  apiToken: string,
  cookie: string,
  body: unknown = {},
): Promise<any> {
  const url = `${GW}?method=${method}&input=3&api_version=1.0&api_token=${encodeURIComponent(apiToken)}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: cookie },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`gw ${method}: HTTP ${res.status} ${text.slice(0, 200)}`);
  const json = JSON.parse(text);
  const results = json?.results ?? null;
  if (results && typeof results === 'object' && 'VALID_TOKEN_REQUIRED' in results) {
    throw new CsrfError(`${method}: stale api_token`);
  }
  return results;
}

export async function login(arl: string): Promise<Session> {
  const ping = await gw('deezer.ping', '', `arl=${arl}`);
  const sid = ping?.SESSION;
  if (!sid) throw new Error('login: bad or expired ARL (no session)');

  const session: Session = { arl, sid, apiToken: '', licenseToken: '' };
  const user = await gw('deezer.getUserData', '', cookieOf(session));
  session.apiToken = user?.checkForm ?? '';
  session.licenseToken = user?.USER?.OPTIONS?.license_token ?? '';
  if (!session.apiToken || !session.licenseToken) {
    throw new Error('login: bad ARL (no checkForm / license_token)');
  }
  return session;
}

/** The fresh checkForm after a CSRF rejection. */
async function refreshToken(s: Session): Promise<string> {
  const user = await gw('deezer.getUserData', '', cookieOf(s));
  const token = user?.checkForm ?? '';
  if (!token) throw new Error('refresh: no checkForm');
  return token;
}

async function callAuthed(s: Session, method: string, body: unknown): Promise<any> {
  try {
    return await gw(method, s.apiToken, cookieOf(s), body);
  } catch (e) {
    if (!(e instanceof CsrfError)) throw e;
    s.apiToken = await refreshToken(s);
    return gw(method, s.apiToken, cookieOf(s), body);
  }
}

export async function search(query: string, limit = 10): Promise<Track[]> {
  const url = `${PUBLIC}/search/track?q=${encodeURIComponent(query)}&limit=${limit}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`search: HTTP ${res.status}`);
  const json: any = await res.json();
  return (json?.data ?? []).map((t: any) => ({
    id: t.id,
    title: t.title_version && !t.title.includes(t.title_version)
      ? `${t.title} ${t.title_version}`
      : t.title,
    artist: t.artist?.name ?? '',
    album: t.album?.title ?? '',
    duration: Math.floor(t.duration ?? 0),
  }));
}

async function trackTokens(s: Session, id: number): Promise<string[]> {
  const body = () => ({ SNG_ID: id, sng_id: String(id), api_token: s.apiToken });
  let song = await callAuthed(s, 'song.getData', body());

  let tokens = [song?.TRACK_TOKEN, song?.FALLBACK?.TRACK_TOKEN].filter(Boolean) as string[];
  if (tokens.length) return [...new Set(tokens)];

  // getData can answer 200 with no token; getListData is the other path.
  s.apiToken = await refreshToken(s).catch(() => s.apiToken);
  const list = await callAuthed(s, 'song.getListData', {
    sng_ids: [id],
    api_token: s.apiToken,
  });
  const first = list?.data?.[0];
  tokens = [first?.TRACK_TOKEN, first?.FALLBACK?.TRACK_TOKEN].filter(Boolean) as string[];
  if (!tokens.length) throw new Error(`track ${id}: no track token (restricted or not entitled)`);
  return [...new Set(tokens)];
}

export async function getStream(s: Session, id: number, quality: Quality = 'lossless'): Promise<Stream> {
  const tokens = await trackTokens(s, id);

  for (const token of tokens) {
    for (const format of CHAINS[quality]) {
      const res = await fetch(MEDIA, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          license_token: s.licenseToken,
          media: [{ type: 'FULL', formats: [{ cipher: 'BF_CBC_STRIPE', format }] }],
          track_tokens: [token],
        }),
      });
      if (!res.ok) continue;

      const json: any = await res.json();
      const sources = json?.data?.[0]?.media?.[0]?.sources ?? [];
      const http = sources.filter((x: any) => String(x.url ?? '').startsWith('http'));
      const pick = http.find((x: any) => x.provider === 'ak') ?? http[0];
      if (!pick) continue;

      return {
        url: pick.url,
        format: format === 'FLAC' ? 'flac' : 'mp3',
        bitrate: BITRATE[format] ?? 0,
      };
    }
  }
  throw new Error(`track ${id}: no playable source in ${quality}`);
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length === 0) return b;
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** Fetch a CDN url, decrypt every enciphered chunk, write the plain audio. */
export async function downloadDecrypted(
  cdnUrl: string,
  trackId: number | string,
  outPath: string,
): Promise<{ bytes: number; head: Uint8Array }> {
  const res = await fetch(cdnUrl);
  if (!res.ok || !res.body) throw new Error(`cdn: HTTP ${res.status}`);

  const key = blowfishKey(trackId);
  const file = createWriteStream(outPath);
  const reader = res.body.getReader();

  let pending: Uint8Array = new Uint8Array(0);
  let chunk = 0;
  let bytes = 0;
  let head: Uint8Array | null = null;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      pending = concat(pending, value);

      const usable = Math.floor(pending.length / CHUNK_BYTES) * CHUNK_BYTES;
      if (usable === 0) continue;

      const block = pending.subarray(0, usable);
      decryptChunks(block, chunk, key);
      chunk += usable / CHUNK_BYTES;
      pending = pending.subarray(usable);

      if (!head) head = block.slice(0, 4);
      bytes += block.length;
      if (!file.write(block)) await once(file, 'drain');
    }

    // A trailing partial chunk is never enciphered.
    if (pending.length > 0) {
      bytes += pending.length;
      file.write(pending);
    }
    file.end();
    await once(file, 'finish');
  } catch (e) {
    file.destroy();
    throw e;
  } finally {
    reader.releaseLock();
  }

  const start = head ?? new Uint8Array(0);
  if (!looksLikeAudioStart(start)) {
    throw new Error('decrypted bytes are not audio — cipher may have changed');
  }
  return { bytes, head: start };
}

export function parseTrackId(input: string): number {
  const fromUrl = /deezer\.com\/(?:[a-z-]+\/)?track\/(\d+)/i.exec(input)?.[1];
  const m = fromUrl ?? /(\d+)/.exec(input)?.[1];
  if (!m) throw new Error(`no numeric track id in: ${input}`);
  return Number(m);
}

async function main(): Promise<void> {
  const [, , arl, command, ...rest] = process.argv;

  if (!arl || !command) {
    console.error('usage:');
    console.error('  aurix-deezer <ARL> search "<query>"');
    console.error('  aurix-deezer <ARL> get <trackId|url> [out.flac]');
    process.exit(1);
  }

  if (command === 'search') {
    const tracks = await search(rest.join(' ') || '', 10);
    for (const t of tracks) {
      console.log(`${t.id}\t${t.artist} — ${t.title} (${t.album}, ${t.duration}s)`);
    }
    return;
  }

  if (command === 'get') {
    const id = parseTrackId(rest[0] ?? '');
    const session = await login(arl);
    const stream = await getStream(session, id);
    const outPath = rest[1] ?? `deezer-${id}.${stream.format}`;
    console.log(`${stream.format} ${stream.bitrate}kbps -> ${outPath}`);
    const { bytes } = await downloadDecrypted(stream.url, id, outPath);
    console.log(`wrote ${bytes} bytes`);
    return;
  }

  console.error(`unknown command: ${command}`);
  process.exit(1);
}

function isMain(): boolean {
  const arg = process.argv[1];
  if (!arg) return false;
  try {
    return realpathSync(arg) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isMain()) {
  main().catch((e) => {
    console.error(e instanceof Error ? e.message : e);
    process.exit(1);
  });
}
