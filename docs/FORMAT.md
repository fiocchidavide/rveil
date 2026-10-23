# rveil/v1 format

Everything rveil writes can be read back with stock tools (`age`, `zstd`,
`tar`, and OpenSSL 3 for the key derivation). This document is enough to
recover archives without rveil.

## Keys

- A **master key** is 32 random bytes, stored as unpadded base64url.
- A **key id** is 6 characters of lowercase base32 (`a-z2-7`).
- In 1Password, each key is one item in the vault (default `rveil`): the
  title is the key id, and the concealed field `key` holds the master key.
  The **current key** is the newest item, by 1Password's creation time.
- The key file store (`RVEIL_KEYSTORE=file:<path>`) is JSON:
  `{"keys": [{"id": …, "created": …, "key": …}]}`.

## Archive ids and passphrases

- An **archive id** is `<keyid>.<26 lowercase base32 characters>`: the key it
  was made under, then 130 random bits. The archive is stored as `<id>.age`.
- Its **passphrase** is

  ```
  base64url(HKDF-SHA256(ikm = master key, salt = "rveil/v1", info = id, 32 bytes))
  ```

  without padding. Every archive has its own passphrase, bound to its id:
  handing one out exposes nothing else, and a renamed or swapped file
  doesn't decrypt.
- The index's id is `index`, so its passphrase is the same derivation with
  `info = "index"`, under whichever key sealed it.

## Archives

```
tar  →  zstd  →  Padmé padding  →  age (scrypt passphrase)
```

- **tar**: libarchive's bsdtar, default options, of one file or folder
  (`bsdtar -c -f - -C <parent> -- <name>`). The top-level entry is the
  file's or folder's name. On macOS, bsdtar also writes AppleDouble
  `._<name>` entries carrying metadata (xattrs, ACLs). macOS restores them
  on extraction; other systems' tars extract them as `._` files.
- **zstd**: one or more standard frames, with a window of at most 8 MiB, well
  under the reference decoder's default limit, so `zstd -d` needs no
  `--long`.
- **Padmé padding** (Nikitin et al., PETS 2019): the compressed stream is
  followed by zstd *skippable frames* (magic `0x184D2A50`, a little-endian
  32-bit body length, zero bytes), which `zstd -d` skips on its own. The
  total, payload plus frames, is the Padmé bucket of `payload + 8`: for
  `L ≥ 2`, with `E = ⌊log2 L⌋` and `S = ⌊log2 E⌋ + 1`, round `L` up to a
  multiple of `2^(E−S)`. That reveals O(log log n) bits of the size, for at
  most 12% overhead. Frames hold at most 2^32−1 bytes each; the last two
  are split so no remainder is smaller than a frame header.
- **age**: one scrypt stanza with work factor `logN = 10`. The passphrase is
  already a 256-bit random value, so stretching it adds nothing; rveil
  refuses any other work factor. age is ChaCha20-Poly1305 in 64 KiB chunks,
  so any change or truncation fails to decrypt.

## Index

`index.age`, next to the archives, sealed under the current key with the
same pipeline minus tar: JSON lines → zstd → padding → age, with id `index`.
One line per archive:

```json
{"id":"k7f3a2.…","key":"k7f3a2","name":"tax docs 2019","kind":"dir",
 "created":"2026-10-23T10:59:01Z","size":3014656,"sha256":"…","age_sha256":"…"}
```

- `name` is the top-level entry of the tar, `kind` is `file` or `dir`.
- `size` and `sha256` are of the tar stream, `age_sha256` of the `.age` file.
- There are no original paths.

rveil reads the index by trying each key, newest first.

## On the remote

- `<id>.age`: archives; `index.age`: the index.
- `<name>.partial`: an upload in progress. Every upload goes to a partial,
  is checked against the SHA-256 the remote reports, then moved into place,
  so a file without `.partial` is always complete. If only
  `index.age.partial` exists, a save was interrupted after its upload was
  verified, and it is the index.

## Recovery without rveil

You need the master key and the archive's id (its file name without
`.age`). With OpenSSL 3 (on macOS: Homebrew's, not the system LibreSSL):

```sh
id=k7f3a2.abcdefghijklmnopqrstuvwxyz
master='<base64url master key>'
m=$(printf '%s' "$master" | tr '_-' '/+')
while [ $(( ${#m} % 4 )) -ne 0 ]; do m="$m="; done   # restore base64 padding
key=$(printf '%s' "$m" | base64 -d | xxd -p | tr -d '\n')
info=$(printf '%s' "$id" | xxd -p | tr -d '\n')
openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt hexkey:$key \
  -kdfopt salt:rveil/v1 -kdfopt hexinfo:$info -binary HKDF |
  base64 | tr '+/' '-_' | tr -d '='                  # → the passphrase

age -d $id.age | zstd -d | tar x                     # age asks for it
```

With rveil at hand, `rveil key <id>` prints the passphrase, and
`rveil key --index` prints the index's candidates, one per key. The index
decrypts with `age -d index.age | zstd -d` (no tar).
