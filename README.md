<p align="center">
  <img src="https://raw.githubusercontent.com/Xyvran/tgfs/master/tgfs.png" alt="logo" width="100"/>
</p>

[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)](https://hub.docker.com/r/xyvran/tgfs)
[![Telegram Group](https://img.shields.io/badge/telegram-group-blue?style=for-the-badge&logo=telegram)](https://t.me/+vhZW50O-LVliNzE6)
[![Telegram Mini App](https://img.shields.io/badge/telegram-miniapp-blue?style=for-the-badge&logo=telegram)](https://xyvran.github.io/tgfs/telegram-mini-app)
[![Tests](https://img.shields.io/github/actions/workflow/status/Xyvran/tgfs/test.yml?branch=master&style=for-the-badge&label=tests)](https://github.com/Xyvran/tgfs/actions/workflows/test.yml)
[![Docker build](https://img.shields.io/github/actions/workflow/status/Xyvran/tgfs/docker-publish.yml?branch=master&style=for-the-badge&label=docker%20build)](https://github.com/Xyvran/tgfs/actions/workflows/docker-publish.yml)
[![Image size](https://img.shields.io/docker/image-size/xyvran/tgfs/latest?style=for-the-badge&label=image)](https://hub.docker.com/r/xyvran/tgfs/tags)

# tgfs

Telegram becomes a WebDAV and SFTP server.

Many thanks to [WheatCarrier](https://github.com/TheodoreKrypton/tgfs) for creating the original tgfs project this repository is built upon.

Refer to [getting started](https://xyvran.github.io/tgfs/) for installation and usage. (Docker or other container engine is required)

Refer to the [wiki page](https://github.com/Xyvran/tgfs/wiki/TGFS-Wiki) for technical detail.

## Tested Clients
* [rclone](https://rclone.org/)
* [Cyberduck](https://cyberduck.io/)
* [WinSCP](https://winscp.net/)
* [Documents](https://readdle.com/documents) by Readdle
* [VidHub](https://okaapps.com/product/1659622164)

WinSCP, Cyberduck and rclone speak both protocols; the OpenSSH `sftp`
command line and `sshfs` work against the SFTP interface as well.

## Features
* Upload and download files to/from a private Telegram channel via WebDAV
* **Optional SFTP interface** serving the same tree next to WebDAV (see below)
* Group files on Telegram channels into folders
* Infinite versioning of files and folders (Folder versioning is only available when Metadata is maintained on Github repository)
* Importing files that are already on Telegram (Only via the Telegram Mini App)
* File size is unlimited (larger files are chunked into parts but appear as a single file to the user)
* Live streaming of videos
* **Optional at-rest encryption** (AES-256-GCM, see below)
* **Optional channel redundancy** (RAID-1-style mirroring to extra channels, see below)


## SFTP interface

Next to the HTTP surface (WebDAV under `/webdav`, manager API under `/api`)
TGFS can serve the very same file tree over SFTP. It is off by default;
switch it on with an `sftp` block in `config.yaml`:

```yaml
tgfs:
  sftp:
    enabled: true
    host: 0.0.0.0
    port: 2222
    host_key_file: sftp_host_key
    # authorized_keys_dir: sftp_authorized_keys
    # upload_buffer_size_mb: 64
    # upload_buffer_dir: ''
```

Both interfaces run in the same process and go through the same core, so
what you see over SFTP is what you see over WebDAV — including at-rest
encryption, channel redundancy and the manager UI's task list. SSH cannot
share a socket with HTTP, hence the separate port.

**Layout and accounts.** The root lists one directory per configured
channel, exactly like `/webdav` does, and everything below it is that
channel's tree. Accounts are the `tgfs.users` from the same config: a user
with `readonly: true` can list and download but gets "permission denied" on
uploads, deletes, renames and directory creation. With no users configured
at all, SFTP allows anonymous read-only access — the same deal the HTTP
side offers.

```bash
sftp -P 2222 <user>@<host>          # interactive
sshfs -p 2222 <user>@<host>:/ /mnt  # mount it
rclone config create tgfs sftp host=<host> port=2222 user=<user> pass=<pass>
```

**Host key.** On the first start an ed25519 key is generated at
`host_key_file` (relative paths resolve against the TGFS data directory)
with mode 0600, and its fingerprint is logged. Back it up together with the
rest of that directory: without it every restart presents a new host key
and clients refuse to connect until their `known_hosts` entry is cleared.

**Public keys** are optional. Point `authorized_keys_dir` at a directory
holding one file per user — named after the username, in the usual
`authorized_keys` format — and those users may log in with a key. They
still have to be listed under `tgfs.users` so the readonly flag keeps
applying; everyone else falls back to password authentication.

**Uploads are buffered.** Telegram needs a file's total size before the
first byte goes out and SFTP never announces it, so an incoming upload is
held in memory up to `upload_buffer_size_mb` (default 64) and spills to
`upload_buffer_dir` (the system temp directory when unset) beyond that.
Plan for that much scratch space when pushing large files. A transfer that
is cut off mid-flight is discarded rather than committed, so an interrupted
upload never truncates an existing file.

**Known limits**, all of them shared with the WebDAV interface: files
cannot be appended to or partially updated (every write stores a new
version), moving between two channels is refused, and there are no symlinks
or real POSIX permissions — `chmod`, `chown` and `touch -t` are accepted
and ignored so clients like `rsync` do not abort.

## Channel redundancy

Telegram channels can be banned or deleted, taking every stored file with
them. With redundancy enabled, TGFS keeps a full copy of everything in one
or more *mirror channels*:

* **Mirroring is server-side.** New uploads are copied to the mirrors via
  Telegram's message forwarding — no re-upload, one API call per file part.
* **Reads fail over automatically.** If a part (or the whole primary
  channel) becomes unavailable, downloads are served from a mirror.
* **File descriptors are mirrored too**, and in `pinned_message` metadata
  mode a pinned copy of the metadata blob is maintained in every mirror,
  so a mirror channel is self-sufficient: if the primary is banned, swap
  the mirror in as `private_file_channel` in the config and keep going.
* **Pre-existing files are covered by the backfill task**
  (`POST /redundancy/backfill/<channel-name>` on the manager API, progress
  via the regular `/tasks` endpoints; add `?verify=true` to also re-mirror
  copies that were manually deleted). Backfill forwards server-side as
  well, so mirroring a multi-terabyte library costs API calls, not
  bandwidth.
* **Works with encryption**: mirrors receive the ciphertext messages
  including the inline header, so files remain decryptable from a mirror
  alone.

Set up:

```yaml
telegram:
  private_file_channel:
    - '1234567890'
  redundancy:
    mirrors:
      '1234567890':      # primary channel id
        - '9876543210'   # mirror channel id(s)
    mode: forward        # forward (default) | reupload
    strict: false        # true: uploads fail when mirroring fails
```

Requirements: the bot(s) must be admin in every mirror channel, and the
primary channel must not have "Restrict saving content" enabled —
otherwise set `mode: reupload` (bandwidth-bound). With `strict: false`
(default) a failing mirror never fails the upload; gaps are logged and can
be closed by re-running the backfill task.

When redundancy matters to you, prefer the `github_repo` metadata type:
the directory tree then survives even the loss of *all* channels.

## At-rest encryption

When ``encryption.enabled: true`` is set in ``config.yaml``, every byte
TGFS uploads to Telegram is encrypted client-side. The Telegram channel and
the metadata repository never see plaintext.

* **Cipher:** AES-256-GCM in 64 KiB chunks, each with its own nonce + auth tag.
  Random-access decryption (HTTP Range requests, video streaming) keeps working.
* **Keys:** the master key is derived from a passphrase via Argon2id at startup.
  Per-file keys are derived via HKDF-SHA256 from the master key and a 32-byte
  random salt stored in the file header.
* **Header:** each encrypted file starts with a self-describing 60-byte header
  embedded *inline* in the first Telegram message, so a file can be decrypted
  from the channel even if the TGFS metadata store is lost.
* **Tamper detection:** every chunk has its own GCM tag plus an HMAC on the
  header, so flipped bits or chunk reordering are caught before plaintext is
  returned.
* **Optional name obfuscation:** with ``encrypt_names: true`` the Telegram
  document name of every new upload (and the pinned metadata blob) is
  replaced with an AES-GCM ciphertext token. The plaintext names stay
  inside the (already encrypted) metadata, so WebDAV and the manager UI
  are unaffected. Only new uploads are obfuscated; pre-existing files keep
  their original document name in Telegram.

Set up:

```yaml
tgfs:
  encryption:
    enabled: true
    encrypt_names: true  # optional, hide file/dir names from channel observers
    passphrase_env: TGFS_MASTER_PASSPHRASE
    master_salt_file: master.salt
    chunk_size: 65536
```

### Master salt

The Argon2 master salt is the value referenced by ``master_salt_file``. It is
**not** secret, but it is required to re-derive the master key from your
passphrase, so it must survive container/host rebuilds.

* **Auto-generated on first start.** If ``master_salt_file`` does not exist
  when TGFS boots, 16 random bytes are written there via
  ``secrets.token_bytes`` and the file is ``chmod 0600``'d. No manual step is
  required.
* **Path resolution.** The value is resolved relative to ``TGFS_DATA_DIR``
  (defaults to ``~/.tgfs``), so ``master_salt_file: master.salt`` lands at
  ``~/.tgfs/master.salt`` unless you override the data dir.
* **Manual creation (optional).** If you prefer to seed the salt yourself --
  e.g. to push it into a secret manager before the first start -- generate at
  least 8 bytes (16 recommended) and drop them at the configured path:

  ```bash
  mkdir -p ~/.tgfs
  head -c 16 /dev/urandom > ~/.tgfs/master.salt
  chmod 600 ~/.tgfs/master.salt
  ```

* **Back it up, never rotate it in place.** Losing the salt (or replacing it
  with fresh random bytes) makes every previously uploaded file unreadable,
  even with the correct passphrase. Back ``master.salt`` up alongside your
  passphrase and your metadata.

See ``demo-config.yaml`` for the full set of options.

### Master passphrase

The master passphrase is the only secret an attacker needs to decrypt
every file in your channel, so treat it like a long-lived database
credential: never commit it, never log it, and back it up to the same
place you keep your other production secrets.

TGFS reads the passphrase from exactly one of three sources, checked in
this order:

1. ``passphrase_env`` -- the name of an environment variable to read
   (recommended for container deployments)
2. ``passphrase_file`` -- a path to a file containing just the
   passphrase (recommended for systemd via ``LoadCredential=``)
3. ``passphrase`` -- the literal passphrase inlined in ``config.yaml``
   (development only; the value ends up on disk in cleartext)

The recipes below all assume the default ``passphrase_env:
TGFS_MASTER_PASSPHRASE`` from ``demo-config.yaml``. Replace the variable
name if you picked a different one.

**Generate a strong passphrase** (only needed once -- store the output
in your password manager):

```bash
# 32 random base64 characters; ~190 bits of entropy.
python -c "import secrets; print(secrets.token_urlsafe(24))"
```

**Docker / docker-compose.** Pass the variable through to the
container -- never hard-code it into the image:

```bash
docker run -e TGFS_MASTER_PASSPHRASE \
  -v ~/.tgfs:/root/.tgfs \
  xyvran/tgfs
```

```yaml
# docker-compose.yml
services:
  tgfs:
    image: xyvran/tgfs
    environment:
      TGFS_MASTER_PASSPHRASE: ${TGFS_MASTER_PASSPHRASE}
    volumes:
      - ~/.tgfs:/root/.tgfs
```

Keep the actual value in a ``.env`` file next to ``docker-compose.yml``
(and add ``.env`` to ``.gitignore``):

```
TGFS_MASTER_PASSPHRASE=your-long-random-passphrase-here
```

**systemd.** Prefer a credential file managed by systemd so the secret
is mode-0400 and only visible to the unit:

```ini
# /etc/systemd/system/tgfs.service
[Service]
LoadCredential=master_passphrase:/etc/tgfs/master.passphrase
Environment=TGFS_MASTER_PASSPHRASE_FILE=%d/master_passphrase
ExecStart=/usr/local/bin/tgfs
```

Then set ``passphrase_file: ${TGFS_MASTER_PASSPHRASE_FILE}`` in
``config.yaml`` (or read the variable in a wrapper script). Make sure
``/etc/tgfs/master.passphrase`` is ``chmod 0400`` and owned by
``root:root``.

**Plain shell / development.** Export it in your current shell only;
do **not** persist it in ``~/.bashrc`` or ``~/.zshrc``:

```bash
read -rs TGFS_MASTER_PASSPHRASE && export TGFS_MASTER_PASSPHRASE
poetry run python main.py
```

**Kubernetes.** Store the passphrase in a Secret and project it as an
env var:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: tgfs-master-passphrase
type: Opaque
stringData:
  passphrase: your-long-random-passphrase-here
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: tgfs
          image: xyvran/tgfs
          env:
            - name: TGFS_MASTER_PASSPHRASE
              valueFrom:
                secretKeyRef:
                  name: tgfs-master-passphrase
                  key: passphrase
```

**Operational notes.**

* **Never change the passphrase in place.** TGFS has no built-in key
  rotation: changing the passphrase makes every previously uploaded
  file unreadable. Decrypt everything to a staging location and
  re-upload under a fresh passphrase if you really need to rotate.
* **Pair with the master salt.** Backups MUST include both the
  passphrase and ``master.salt`` -- either one missing is equivalent
  to a total key loss.
* **Forgetting the passphrase is fatal.** There is no recovery
  mechanism (that's the entire point of the design). Keep a copy in
  your password manager.


## Development

Install the dependencies:
```bash
poetry install
```

Run the app:
```bash
poetry run python main.py
```

Typecheck && lint:
```bash
make mypy
make ruff
```

Before committing and pushing, run the following command to install git hooks:
```bash
pre-commit install
```

### Preview builds

Pushing any branch other than `master` runs the full test suite and, in
parallel, builds a Docker image from that exact commit so a change can be tried
out on a real machine before it is merged. The release tags are never touched.

```bash
docker pull xyvran/tgfs:preview-<commit>     # pinned to one commit
docker pull xyvran/tgfs:preview              # whichever branch built last
```

The commit-pinned tag is printed as a ready-to-copy command in the workflow run
summary; prefer it whenever more than one branch is in flight. The frontend is
built the same way as `xyvran/tgfs-fe:preview-<commit>`.

Preview images are amd64 only (release images are also arm64) and are built
before the test workflow finishes, so a green preview image is not a statement
about the tests. Both images are smoke-checked first, though: the backend has to
serve a working SFTP session and the frontend has to answer on `/tgfs/`, so a
broken build never reaches the registry.

These tags accumulate — delete them from Docker Hub once a branch is merged.

The backend smoke check runs against any image, locally too:

```bash
docker run --rm -v "$PWD/scripts:/app/scripts:ro" xyvran/tgfs:preview \
  python scripts/docker_smoke_check.py
```
