# SFTP interface

## Why

TGFS published its store over exactly one surface: a single uvicorn process
with WebDAV mounted at `/webdav` and the manager REST API at `/api`. That
covers WebDAV-capable clients and nothing else, while SFTP is what a great
many file managers, backup tools and mount helpers reach for first.

The goal was a second access interface of equal standing — same tree, same
accounts, same guarantees — not a reduced side door.

## Where it sits

```
        SFTP client                       WebDAV client
             |                                  |
      asyncssh listener                 uvicorn / FastAPI
   (tgfs/app/sftp/server.py)          (tgfs/app/__init__.py)
             |                                  |
             +--------------+   +---------------+
                            |   |
                       tgfs/core/ops.py  (Ops)
                            |
              FileApi / DirectoryApi / MetaDataApi
                            |
            repositories (+ encryption, + mirroring)
                            |
                        Telegram
```

Both front-ends are thin: they translate a protocol into `Ops` calls. That
is the whole reason the two behave identically — at-rest encryption, mirror
failover, upload task tracking and metadata batching all live below the
fork, so neither interface can drift from the other.

The SFTP layer deliberately does **not** build on the `asgidav` classes.
Those model WebDAV specifically — `copy_to`/`move_to` take destinations
still carrying the `/webdav/<client>` prefix — so reusing them would have
meant either bending SFTP paths into WebDAV shapes or reworking the WebDAV
layer. Going straight to `Ops` costs a little duplication in exchange for
leaving the running interface untouched.

## Layout and accounts

The namespace matches WebDAV exactly: the root is synthetic and lists one
entry per configured client, and `/<client>/<path>` addresses that client's
tree. `split_global_path()` in `tgfs/app/utils.py` is shared between the two.

Authentication reuses `tgfs.auth.basic.authenticate`, so the same
`tgfs.users` block drives both interfaces, including the anonymous
read-only fallback when no users are configured. Write enforcement mirrors
`READONLY_METHODS`: everything that mutates goes through `_require_write()`
and raises `SFTPPermissionDenied` for a readonly user.

Public key authentication is the one thing SFTP adds. It is off unless
`authorized_keys_dir` is configured, and even then the account must exist
in `tgfs.users` — the config stays the single source of truth for who may
write.

## The two hard parts

Everything in SFTP maps onto `Ops` cleanly except file I/O, where the
protocol and Telegram want opposite things.

### Reads: random access over a one-shot stream

SFTP reads are `read(handle, offset, size)` at arbitrary offsets, and
clients pipeline several at once. `Ops.download(path, begin, end, name)`
gives an async iterator that only moves forward.

`ReadHandle` keeps one open stream plus the offset it has reached:

* a read continuing where the last one stopped — the overwhelming majority —
  is served straight from the buffer and the stream;
* a backward seek, or a forward jump larger than `SEEK_FORWARD_THRESHOLD`
  (1 MiB), re-opens the stream at the new offset, which is exactly what a
  WebDAV range request does;
* a smaller forward gap is bridged by reading through, because re-opening
  costs a Telegram round trip while the skipped bytes are already in flight.

An `asyncio.Lock` serialises the handle so pipelined reads cannot interleave
into the shared buffer.

One asyncssh-specific wrinkle: before copying, a client may probe the source
handle with `SEEK_DATA`/`SEEK_HOLE` to skip sparse regions. Nothing stored
here is sparse, so `Handle.seek` answers with a single solid data region and
raises `ENXIO` past the end. Without it, transfers from an asyncssh-based
client fail outright — which is exactly what the integration test caught.

### Writes: a size that is not known in advance

Telegram uploads need the total size up front (it decides the part layout);
SFTP never sends it. So `WriteHandle` spools the payload — in memory up to
`upload_buffer_size_mb`, on disk beyond that, via `SpooledTemporaryFile` —
and only on `close()` streams it into `Ops.upload_from_stream` with the
size now known.

Buffering is not just a workaround for the missing size: it also makes
out-of-order and sparse writes work, since the spool is seekable, and it
keeps a dropped connection from committing a truncated file — `exit()`
aborts anything still open rather than closing it.

`Ops.touch()` is called at open time so the name shows up in a listing
while the upload is still running, matching the WebDAV `PUT` path.

## Lifecycle

`start_sftp_server()` returns `None` when disabled and otherwise an
`SSHAcceptor` that keeps serving in the background of the same event loop
as uvicorn. `main()` shuts it down in a `finally` around `run_server`. A
failure to start it (port taken, unwritable host key) is logged and leaves
the HTTP interface running — the second interface must never be able to
take down the first.

The host key is generated on first start (ed25519, mode 0600) and lives in
the TGFS data directory, because a key that changes on every restart makes
clients refuse to connect.

## Known limits

All of these are shared with WebDAV and documented in the README:

* uploads need scratch space the size of the file;
* no append and no partial update — every write stores a new version;
* moving between two clients is refused;
* no symlinks and no real permissions; `setstat` accepts and ignores, since
  refusing would abort otherwise fine `rsync` and `sftp put` transfers.

## Tests

`tests/tgfs/app/sftp/` covers the pieces in isolation (path translation,
attribute mapping, both handles, the server methods against a mocked
`Client`, and authentication) plus `test_integration.py`, which drives a
real asyncssh client against a listener on an ephemeral port. The
integration layer is worth its weight: it exercises asyncssh's own protocol
handlers and the OPEN/READ/WRITE/CLOSE handle bookkeeping that the unit
tests bypass.
