# @aurix-music/deezer

Resolve a Deezer track and decrypt it into a playable file.

| File | What it does |
|---|---|
| `decoder.ts` | Blowfish key derivation, 2048-byte stripe decryption, audio magic check |
| `deezer.ts` | ARL login, search, track token, signed CDN URL, streaming download + decrypt |

## Install

```bash
npm i @aurix-music/deezer
```

## Use as a library

```ts
import { login, getStream, downloadDecrypted } from '@aurix-music/deezer';
import { blowfishKey, decryptChunks } from '@aurix-music/deezer/decoder';

const session = await login(process.env.DEEZER_ARL!);
const { url, format } = await getStream(session, 3135556);
await downloadDecrypted(url, 3135556, `out.${format}`);
```

Exports from the root: `login`, `search`, `getStream`, `downloadDecrypted`, `parseTrackId`,
plus the types `Session`, `Track`, `Stream`, `Quality`.
From `@aurix-music/deezer/decoder`: `blowfishKey`, `decryptChunks`, `decryptBuffer`,
`isEncryptedChunk`, `looksLikeAudioStart`, `CHUNK_BYTES`, `STRIPE_EVERY`.

## Use as a CLI

```bash
npx aurix-deezer "<ARL>" search "get lucky"
npx aurix-deezer "<ARL>" get 3135556 out.flac
```

`get` takes a bare id, `deezer:3135556`, or a full `deezer.com/track/...` URL.
Quality falls back FLAC → MP3_320 → MP3_128 depending on what the account is entitled to.

## How it works

```
ARL ─ ping ─▶ session
    ─ getUserData ─▶ api_token + license_token
    ─ song.getData ─▶ track token
    ─ get_url ─▶ signed CDN url
    ─ GET ─▶ decrypt stripes ─▶ file
```

Deezer never serves plain audio: the CDN bytes are Blowfish-CBC encrypted. Every third
2048-byte chunk, starting at index 0, is an independent message with IV `00..07`:

```
key[i] = md5(trackId)[i] ^ md5(trackId)[i+16] ^ "g4el58wc0zvf9na1"[i]
```

Decrypted chunks are the same 2048 bytes, so offsets are unchanged.

## Develop

```bash
npm i
npm run build        # emits dist/ + .d.ts
npm run typecheck
npm start -- "<ARL>" search "get lucky"
```

## Publish

Version, push, then run the **Release** workflow from the Actions tab (`dist_tag`,
plus a dry-run toggle). It typechecks, builds, tests and publishes with provenance.

```bash
npm version patch --no-git-tag-version
git commit -am "chore(release): bump version"
git push
```

Requires `NPM_TOKEN` in repository secrets and the matching npm scope.
`publishConfig.access` is `public` — scoped packages default to private.

## Notes

- The **ARL is a full-account cookie**, not an API key. Keep it out of git and shell history.
- Search uses the public `api.deezer.com` and needs no ARL; only resolution does.
- Reference implementation. Nothing here is affiliated with Deezer.

MIT © vanquzie
