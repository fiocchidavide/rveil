# rveil

Encrypted, padded archives of your files and folders on an rclone remote,
with the keys in 1Password.

- **Each archive has its own key**, derived from a master key and the
  archive's id. You can hand out one archive's passphrase and nothing else
  is exposed.
- **The remote learns almost nothing**: not the content, not the names, and
  not the exact sizes (Padmé padding leaves only a size bucket).
- **Every upload is verified**: while sealing, the archive is decrypted again
  in-process, and the remote's SHA-256 must match the bytes sent. That proves
  the copy on the remote opens to your content, without downloading it back.
- **Stock tools can recover everything**: `age -d | zstd -d | tar x`. The
  format is in [docs/FORMAT.md](docs/FORMAT.md).
- **One fixed construction, no options:** HKDF-SHA256, then age
  (ChaCha20-Poly1305), then zstd. It's symmetric throughout, so a future
  quantum computer doesn't help anyone who stored the ciphertext.

## Install

Build with Go 1.24 or newer:

```sh
go install github.com/fiocchidavide/rveil/cmd/rveil@latest
```

rveil needs **rclone**, **bsdtar** (from libarchive: built into macOS; on
Debian/Ubuntu `apt install libarchive-tools`) and, for the default key store,
the **1Password CLI** (`op`).

## Setup

1. **An rclone remote.** rveil needs a remote that reports SHA-256, such as
   Google Drive or a local folder. For Drive, create a remote named `rveil`
   with `rclone config`. The `drive.file` scope is the safest choice:
   rveil's token then reaches only the files rveil created. Archives go in
   the folder `rveil` on it, which rclone creates on the first upload.
2. **A master key:** `rveil keys new`. This creates the 1Password vault
   `rveil` if it's missing.

Settings, all optional, come from the environment:

| Variable | Default | |
| --- | --- | --- |
| `RVEIL_KEYSTORE` | `op:rveil` | `op:<1Password vault>` or `file:<path>` (a 0600 JSON file) |
| `RVEIL_REMOTE` | `rveil:rveil` | rclone path of the archive folder; any rclone path, including a local folder |
| `RVEIL_STAGING` | `~/.local/share/rveil/staging` | where `put` seals archives before `push` |

## Use

```sh
rveil put ~/Documents/"tax docs 2019"   # seal into staging
rveil push                              # upload, verify, clear staging
rveil put --direct /Volumes/Ext/Photos  # or stream straight to the remote
rveil ls                                # date, key, size, name
rveil get tax                           # download and extract here
```

- **Archives are found** by their id, or by any piece of their name (case
  doesn't matter). If several match, rveil lists them and you pick one by id.
- **Nothing is overwritten**: `get` extracts into the current folder (`-C`
  for another), and if the name is taken, into `<name>.unsealed`.
- **Your originals are never touched.** Delete them yourself once `push`
  reports the upload verified.
- **Only names are recorded**, not where things came from, so an archive
  means the same thing on any machine. Name folders for what they are.

| Command | |
| --- | --- |
| `put [--direct] <path>…` | seal into staging, or with `--direct` straight to the remote |
| `push [match…]` | upload staged archives; each staged copy goes once its upload is verified |
| `ls [-l] [match]` | list archives (`-l`: with ids) |
| `get [-C dir] <match>` | download, verify, extract |
| `key <match\|id>` / `key --index` | print a passphrase, for stock tools |
| `keys` / `keys new` | list keys, newest (current) first / create one |
| `rekey [-y] --from <key> \| <match>…` | re-encrypt under the current key, remote to remote |
| `rm [-y] <match>…` | delete from the index, then from the remote |
| `check [--deep] [-y]` | compare the index with the remote, offer fixes; `--deep` decrypts everything |
| `share <match>` | public link + message for a friend |
| `seal [-o out] <path>` / `open [-C dir] [-k -] <file>` | local archives, not indexed |

`rm`, `rekey` and `check`'s fixes ask first; `-y` skips the question, and
without a terminal they refuse.

### Rotating keys

`rveil keys new` makes a new key current: new archives and the index use it
from then on. Older archives stay readable. Move them with
`rveil rekey --from <old key>`. A rekey swaps only the encryption: the
content isn't recompressed and never touches your disk. Each new archive is
verified before the index switches to it and the old one is deleted.

### When something is off

`rveil check` compares the index with the remote:

- **Unfinished uploads** (`*.partial`) are deleted.
- **Orphans**, archives on the remote that the index doesn't list (after an
  interrupted rekey, or if an older index was put back), are read and
  re-added. Their name is inside the archive, so nothing is lost.
- **Entries whose archive is gone** are dropped.

`check --deep` also downloads and decrypts every archive.

### Sharing

`rveil share <match>` makes an anyone-with-the-link URL for an archive and
prints a message to send: the link, that archive's passphrase, and a line to
paste into Terminal:

```sh
curl -fsSL https://github.com/fiocchidavide/rveil/releases/download/<version>/open.sh | bash -s -- <passphrase> <id>.age
```

The script downloads that release's rveil, checks it against the checksum
written into the script, and opens the file next to where it was downloaded.
The friend needs only bash, curl and any tar, on macOS or Linux. The
passphrase opens that one archive. `rveil rm` deletes it and the link;
`rveil rekey` cuts the passphrase off.

## Threat model

- **The remote (Google, or anyone with your Drive) sees** archive ids, the
  key id each was made under, the number of archives, padded sizes and
  upload times. Everything else is encrypted and authenticated: it can't
  read or alter anything without the decryption failing.
- **The remote could** delete archives, or put back an older index.
  `rveil check` notices both, and repairs the index from the archives
  themselves.
- **Master keys live in 1Password**, and only in memory for the life of one
  command. They reach `op` as JSON on stdin, never in argv or the
  environment.
- **A shared passphrase** opens only its archive. It ends up in the
  recipient's shell history.
- **Archives made on macOS** carry AppleDouble `._` entries with their
  metadata. On other systems these extract as `._` files.

## Development

```sh
go vet ./... && go test -race ./...        # integration tests need rclone and bsdtar
uvx --from shellcheck-py shellcheck share/open.sh scripts/render-open.sh
```

The integration tests drive the built binary against a key file and a local
folder as the remote. With `age`, `age-plugin-batchpass`, `zstd` and
OpenSSL 3 installed, they also check recovery with stock tools. With GNU
tar, they check extraction on a machine without bsdtar.

Releases are cut by pushing a `v*` tag. CI builds the four binaries, fills
their checksums into `open.sh`, and publishes them as a GitHub release.
Enable immutable releases in the repository settings, so a published
`open.sh` and its binaries can't change.

## License

MIT
