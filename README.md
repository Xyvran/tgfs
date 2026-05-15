<p align="center">
  <img src="https://raw.githubusercontent.com/TheodoreKrypton/tgfs/master/tgfs.png" alt="logo" width="100"/>
</p>

[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)](https://hub.docker.com/r/wheatcarrier/tgfs)
[![Telegram Group](https://img.shields.io/badge/telegram-group-blue?style=for-the-badge&logo=telegram)](https://theodorekrypton.github.io/tgfs/join-group)
[![Telegram Mini App](https://img.shields.io/badge/telegram-miniapp-blue?style=for-the-badge&logo=telegram)](https://theodorekrypton.github.io/tgfs/telegram-mini-app)
[![Codecov](https://img.shields.io/codecov/c/github/TheodoreKrypton/tgfs?style=for-the-badge)](https://codecov.io/gh/TheodoreKrypton/tgfs)

# tgfs

Telegram becomes a WebDAV server.

Refer to [getting started](https://theodorekrypton.github.io/tgfs/) for installation and usage. (Docker or other container engine is required)

Refer to the [wiki page](https://github.com/TheodoreKrypton/tgfs/wiki/TGFS-Wiki) for technical detail.

## Tested Clients
* [rclone](https://rclone.org/)
* [Cyberduck](https://cyberduck.io/)
* [WinSCP](https://winscp.net/)
* [Documents](https://readdle.com/documents) by Readdle
* [VidHub](https://okaapps.com/product/1659622164)

## Features
* Upload and download files to/from a private Telegram channel via WebDAV
* Group files on Telegram channels into folders
* Infinite versioning of files and folders (Folder versioning is only available when Metadata is maintained on Github repository)
* Importing files that are already on Telegram (Only via the Telegram Mini App)
* File size is unlimited (larger files are chunked into parts but appear as a single file to the user)
* Live streaming of videos
* **Optional at-rest encryption** (AES-256-GCM, see below)


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

Set up:

```yaml
tgfs:
  encryption:
    enabled: true
    passphrase_env: TGFS_MASTER_PASSPHRASE
    master_salt_file: master.salt
    chunk_size: 65536
```

Back up ``master.salt`` together with your passphrase -- losing either makes
decryption impossible. See ``demo-config.yaml`` for the full set of options.


## Demo Server
* WebDAV URL: `https://tgfs-demo.wheatcarrier.site/webdav`
* `username` and `password` can be any
* File channel on Telegram: [@tgfsdemo](https://t.me/tgfsdemo)
* Github repository for metadata: [https://github.com/tgfs-demo/tgfs-demo](https://github.com/tgfs-demo/tgfs-demo)
* Config file: [config.yaml](https://github.com/TheodoreKrypton/tgfs/blob/master/demo-config.yaml)

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
