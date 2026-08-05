# Design: Channel Redundancy (RAID-1-style Mirroring)

Status: implemented. This document describes the design; see the code
for the authoritative behavior (`tgfs/core/mirror.py`,
`tgfs/core/backfill.py`, and the `redundancy` config block).

## Goal

Protect files stored by TGFS against the loss of a Telegram channel
(ban, accidental deletion, takeover). Every file uploaded to a primary
channel should additionally exist in one or more *mirror channels*, and
TGFS should be able to keep serving files when the primary channel
becomes unavailable.

## Why RAID-1 (mirror), not RAID-5 (parity)

The failure unit on Telegram is the *whole channel*, not individual
messages or bits. Parity/erasure-coding across channels (RAID-5/6 style)
only pays off when failures are partial and storage is expensive —
neither is true here: Telegram storage is free and a ban removes an
entire "disk" at once. A plain mirror (RAID-1) gives the same protection
with a fraction of the complexity, and — crucially — Telegram gives us
mirroring almost for free via **server-side message forwarding**.

## Key insight: forwarding is the cheap replication primitive

`messages.forwardMessages` copies a document to another chat **without
re-uploading a single byte** — the copy happens on Telegram's servers.
So the write path stays: upload once to the primary channel, then
forward each part message to the mirror channel(s). Cost per mirror is
one RPC per part message, not a second multi-GB upload.

Two constraints follow directly:

1. **Mirroring must happen at upload time.** Once a channel is banned,
   its messages are unreachable — you cannot forward *out of* a banned
   channel. Reactive copying after a ban is too late.
2. **Forwarding must be allowed.** Channels with "restrict saving
   content" (`noforwards`) enabled cannot be forwarded from. The bot
   must be admin in every mirror channel. As a fallback (e.g. if
   forwarding fails), the mirror can be filled by re-uploading — slower
   but always possible.

## What must be mirrored

A file in TGFS consists of three layers, all of which currently live in
the primary channel:

| Layer | Where it lives today | Mirror strategy |
|---|---|---|
| File content (document part messages) | channel messages | forward to mirror channel |
| File descriptor (JSON text message, `TGMsgFDRepository`) | channel text message | send the same JSON as a *fresh* text message to the mirror (a forwarded text message cannot be edited later; FDs get edited on every new version) |
| Directory metadata | pinned message in channel **or** GitHub repo | pinned-message mode: maintain a pinned copy in the mirror channel too; GitHub mode: already off-Telegram, nothing to do |

Recommendation: for users who care about ban-resilience, document that
`github_repo` metadata is the safer choice — the directory tree then
survives even a total loss of all channels, and only content + FDs need
channel-level mirroring.

## Data model changes

`TGFSFileVersion` today:

```json
{"type": "FV", "id": "...", "updatedAt": 0, "messageIds": [1, 2], "size": 123}
```

Add an optional, backward-compatible map of mirror locations:

```json
{"type": "FV", "...": "...",
 "messageIds": [1, 2],
 "mirrors": {"-1001234567890": [17, 18]}}
```

- Key: resolved channel id of the mirror; value: message ids of the
  forwarded parts, **in the same order** as `messageIds`.
- `TGFSFileVersion.from_dict` treats a missing `mirrors` key as "no
  mirrors" → old metadata keeps loading unchanged.
- `TGFSFileRef` (in the directory metadata) analogously gets an optional
  `mirrors: {channel_id: fd_message_id}` for the descriptor message.

Because message ids are only unique *per channel*, every mirror entry
must be keyed by channel id — never store bare ids.

## Configuration

```yaml
telegram:
  private_file_channel:
    - "1234567890"          # primary, unchanged
  redundancy:
    mirrors:
      "1234567890":          # primary channel
        - "9876543210"       # mirror channel(s)
    mode: forward            # forward (default) | reupload
    strict: false            # false: mirror failures are logged + queued for
                             # repair; true: upload fails if mirroring fails
```

- `strict: false` is the right default: a mirror hiccup should not fail
  the user's WebDAV PUT. Failed mirror writes go into a repair queue
  (see below).
- Promotion after a ban is a pure config change: swap primary and mirror
  in the list. Reads work immediately because every version knows its
  per-channel message ids.

## Code changes, layer by layer

### 1. Telegram layer — new primitive

Add to `ITDLibClient` (tgfs/telegram/interface.py) and both impls:

```python
async def forward_messages(self, req: ForwardMessagesReq) -> List[SendMessageResp]:
    """from_chat, to_chat, message_ids → new message ids in to_chat (same order)."""
```

Telethon: `client.forward_messages(...)`; Pyrogram:
`client.forward_messages(...)`. Both return the new messages. Respect
the existing 20 msg/s rate limiter.

### 2. `MessageApi` becomes multi-channel-aware

Today `MessageApi` is bound to a single `private_file_channel`. The
cleanest change: keep `MessageApi` single-channel, and give the client
**one `MessageApi` per channel** (primary + each mirror). A thin
`ChannelGroup` object holds them:

```python
class ChannelGroup:
    primary: MessageApi
    mirrors: dict[int, MessageApi]
```

### 3. Write path — `MirroredFileContentRepository` decorator

Mirror at the same layer as encryption, as a decorator around
`IFileContentRepository` — **outside** the encryption wrapper is wrong,
**inside** is wrong too; it must wrap the *Telegram* repository directly
so it sees final (already encrypted) part messages:

```
FileDescApi → EncryptingFileContentRepository → MirroredFileContentRepository → TGMsgFileContentRepository
```

(Equivalently: implement mirroring inside `TGMsgFileContentRepository.save`;
the decorator keeps it testable and optional.)

`save()` flow:
1. delegate upload to the primary (unchanged),
2. for each mirror channel: `forward_messages(primary → mirror, part_ids)`,
3. return `SentFileMessage`s enriched with the mirror map so
   `TGFSFileVersion.from_sent_file_message` can record `mirrors`.

`update()` (edit_message_media) cannot be forwarded — after an edit,
delete the old mirror message and forward the edited one again.

### 4. FD write path — `TGMsgFDRepository`

- `save()` new FD: `send_text` to primary (unchanged) **and** to each
  mirror; record both ids.
- `save()` existing FD: `edit_message_text` in primary and in each
  mirror (this is why FDs are sent fresh, not forwarded — forwarded
  messages can't be edited by the forwarder in the target channel).
- Mirror FD writes are best-effort under `strict: false`.

### 5. Read path — failover

`TGMsgFileContentRepository.get` / `TGMsgFDRepository.get` currently ask
one `MessageApi`. With the `ChannelGroup`:

1. try primary;
2. on `MessageNotFound` / channel-level errors (`CHANNEL_PRIVATE`,
   `CHANNEL_INVALID` — the errors a ban produces), retry against each
   mirror using the version's `mirrors` map;
3. `_validate_fv` marks a version invalid only if *no* channel has it.

A small circuit breaker (remember "primary is dead" for N minutes)
avoids paying a failed RPC on every read once a channel is gone.

### 6. Delete path

`FileApi.rm` / `delete_messages` must fan out: collect ids per channel
(primary ids + everything in `mirrors`) and delete in each channel.
Honors the existing `delete_messages_on_remove` flag.

### 7. Repair & backfill job (tgfs/tasks/)

A background task, also exposed in the manager UI:

- **Backfill**: mirror all pre-existing data — detailed below.
- **Repair**: drain the queue of failed mirror writes; verify with
  `get_messages` that mirror copies still exist (they can be deleted
  manually too).
- **Promote** (manual/CLI): given "primary X is banned", rewrite config
  guidance — data-side nothing to do, since mirrors are already
  first-class in the metadata.

## Backfill: mirroring pre-existing data

When redundancy is enabled on an existing installation, nothing that is
already in the channel has a mirror. The backfill job closes that gap.
It reuses the exact same primitives as the live write path, so there is
no second implementation to maintain.

### Enumeration: the metadata tree is the work list

There is no need to scan the channel history. Everything TGFS serves is
reachable from the directory metadata:

```
TGFSDirectory (root)
  └─ TGFSFileRef.message_id      → FD text message in primary channel
       └─ TGFSFileDesc.versions   → TGFSFileVersion.message_ids (content parts)
```

A depth-first walk over `TGFSDirectory` yields every file ref; loading
each FD (`TGMsgFDRepository.get`) yields every version and its part
message ids. Messages *not* referenced by metadata are invisible to
TGFS anyway and are deliberately out of scope (an optional "orphan
sweep" over channel history could be a later addition).

### Unit of work: one file version, idempotent

For each version of each file:

1. **Skip check** — if `version.mirrors[mirror_channel]` exists and has
   the right number of ids, the version is done. This makes the whole
   job resumable for free: the FD itself is the checkpoint, no separate
   state file needed (and the in-memory `TaskStore` never has to
   survive a restart).
2. **Validate** — drop invalid versions (`_validate_fv` already marks
   versions whose primary messages were manually deleted; nothing to
   mirror there).
3. **Forward** — one `forward_messages(primary → mirror, part_ids)`
   call. Telegram accepts up to 100 ids per call and returns the new
   ids in order, so even a 100-part (≈200 GB) file is a single RPC.
4. **Commit** — write the `mirrors` map into the FD JSON via the
   existing `edit_message_text` on the FD message. This edit is the
   commit point of the unit of work.
5. **Mirror the FD itself** — `send_text` the updated FD JSON to the
   mirror channel, record its id in `fr.mirrors`, push metadata
   (batched: one metadata push per N files, not per file).

Crash-safety: a crash between step 3 and 4 leaves already-forwarded
copies in the mirror that the re-run does not know about. The re-run
simply forwards again — the stale copies are harmless orphans (bytes
are free) and can be swept by the repair job later. No step can lose
data; the commit point makes duplicates the *worst* outcome.

### Throughput and rate limits

- `forward_messages` is server-side: **zero download/upload bandwidth**,
  cost is one RPC per version (plus one FD edit + one FD send). A
  library of 10 000 files ≈ 30 000 RPCs ≈ under an hour at the existing
  20 req/s limiter, independent of data volume.
- Telegram may still answer `FLOOD_WAIT_X` on sustained forwarding —
  the job must honor it (sleep X, resume), which the idempotent design
  makes trivial.
- `mode: reupload` fallback (for `noforwards` channels): the job streams
  each part down and up again — bandwidth-bound, so it should run with
  low concurrency and clearly report ETA in the manager UI.

### Ordering and operation

- Process **newest files first** (sort by `updated_at`) — recent data is
  usually the most valuable, and the job may run for a while.
- Expose as a manager-UI task (progress = versions done / total, reusing
  `TaskStore`) and optionally auto-start on boot when redundancy is
  enabled and unmirrored versions exist ("eventual redundancy").
- Live uploads during backfill are unaffected: they mirror themselves
  synchronously via the write path, and the skip check keeps the two
  from colliding.
- A final **verification pass** (`get_messages` on all recorded mirror
  ids, batched 100 per call) confirms the mirror is actually complete —
  this is the same code the repair job runs periodically.

## Interaction with existing features

- **Encryption**: unaffected. Mirroring copies ciphertext messages; the
  inline 60-byte header travels with the forwarded document, so a file
  remains decryptable from the mirror alone.
- **`encrypt_names`**: forwarded documents keep their obfuscated names —
  fine.
- **Premium 4 GB parts**: forwarding is size-agnostic — works.
- **Multiple bots**: forwarding uses `next_bot`; every bot must be admin
  in primary *and* mirror channels (document this).
- **Import via Mini App**: imported messages live in the primary; the
  backfill job mirrors them like any other file.

## Config generator (tgfs-gh-pages)

The interactive config generator
(`tgfs-gh-pages/app/config-generator/`) builds the YAML clientside and
must learn the new `redundancy` block:

- **Data model** (`page.tsx`): extend `ChannelConfig` with
  `mirrors: string[]`, and add a top-level
  `redundancy: { mode: "forward" | "reupload"; strict: boolean }` to
  `ConfigData` (+ the matching `ConfigUpdatePaths` entries).
- **UI**: per-channel mirror inputs belong inside `ChannelField.tsx` —
  a "Mirror Channel IDs" list under each channel (add/remove rows, same
  pattern as bot tokens), so it is visually obvious *which* primary a
  mirror protects. Global `mode`/`strict` go into a new optional
  "Redundancy" `FormSection` next to "Encryption (Optional)", hidden
  behind an enable checkbox like encryption is.
- **YAML generation** (`generateYaml`): emit
  `telegram.redundancy.mirrors` as a map keyed by primary channel id,
  only for channels that have non-empty mirror entries; omit the block
  entirely when no mirrors are configured (keeps generated configs for
  non-users unchanged).
- **Validation** (same style as `getChannelNameErrors`):
  - mirror id must be non-empty and numeric-ish like channel ids;
  - a mirror must not equal its own primary;
  - no duplicate mirrors within one channel;
  - warn if a mirror id is also used as a primary channel (two
    filesystems writing into one channel invites id confusion).
- **Inline help text** (the generator is the de-facto documentation):
  - bots must be admin in every mirror channel;
  - the primary channel must not have "Restrict saving content"
    enabled, otherwise only `mode: reupload` works;
  - recommend `github_repo` metadata when redundancy is enabled — the
    directory tree then survives even a total channel loss;
  - note that enabling redundancy later is fine: the backfill task
    mirrors existing files.

## Documentation updates

- **README.md**: new feature bullet ("Optional channel redundancy —
  files are mirrored to additional channels via server-side
  forwarding") and a "Channel redundancy" section mirroring the
  encryption section's structure: motivation (channel ban), config
  example, requirements (bot admin rights, `noforwards` off), and the
  promotion runbook (what to change in the config when the primary is
  banned).
- **Getting-started page** (`tgfs-gh-pages/app/getting-started/`):
  short subsection pointing at the config generator's redundancy
  section.
- **Wiki (technical detail)**: document the `mirrors` field in the FD
  serialization (`TGFSFileVersion` / `TGFSFileRef`) so third-party
  tooling that parses FD JSON knows the format is
  backward-compatible.
- **Example configs**: `demo-config.yaml` and `config-test.yaml` gain a
  commented-out `redundancy` block showing the shape.
- **Manager UI**: the backfill task's surface (start button, progress,
  verification result) documented alongside the existing task UI docs.

## Failure modes considered

- Mirror channel down during upload → logged + repair queue (non-strict)
  or upload error (strict).
- Forward silently dropped / mirror message manually deleted →
  detected by repair verification, re-forwarded from primary.
- Primary banned → reads fail over automatically; writes require config
  promotion (a banned primary cannot accept uploads anyway).
- Both channels banned, GitHub metadata → tree intact, content lost →
  this is why ≥2 mirrors are configurable.
- FD edit raced between primary and mirror → mirror FD is only a cache;
  on failover, `_validate_fv` re-validates against actual mirror
  messages, so a stale mirror FD self-heals.

## Suggested implementation order

1. `forward_messages` in `ITDLibClient` + Telethon/Pyrogram impls + tests.
2. Config schema (`redundancy` block) + `ChannelGroup` wiring in
   `Client.create` / `main.create_clients`.
3. `TGFSFileVersion` / `TGFSFileRef` serialization with `mirrors`
   (backward compatible, round-trip tests).
4. Write path: `MirroredFileContentRepository` + FD mirroring.
5. Read path failover + circuit breaker.
6. Delete fan-out.
7. Backfill/repair task + manager UI hook.
8. Config generator: `redundancy` block, per-channel mirror fields,
   validation, inline help (tgfs-gh-pages).
9. Docs: README section, getting-started, wiki (FD `mirrors` format),
   example configs, promotion runbook.

Steps 1–4 already deliver the core value (every new upload is mirrored);
5–7 make it operationally complete; 8–9 ship it to users.
