# Design: Transfer Performance

Status: implemented. This document explains why the transfer path looks the
way it does; the code is the authoritative description of what it does
(`tgfs/core/api/message/__init__.py`, `tgfs/utils/prefetching_chain.py`,
`tgfs/utils/chunk_cache.py`, and the `transfer` config block).

## The starting point

Throughput was not limited by Telegram. It was limited by four things in
this code base:

1. **The parallel download path never ran.** The helper that decides
   whether a range is worth splitting computed its size as
   `begin - end + 1`. For every ordinary range that is negative, the
   "is this big?" test was never true, and the split never happened.
2. **Splitting would not have helped anyway.** The parts were concatenated
   with a plain chained iterator, which pulls the next source only once the
   previous one is exhausted. The requests were issued in parallel; the
   bytes were still fetched one part after another.
3. **Every range request re-resolved its message**, bypassing the message
   cache -- one extra round trip per request, paid over and over by a video
   player.
4. **A failing upload part retried forever without sleeping**, turning one
   broken part into a busy loop against Telegram.

## Ordered output is the whole problem

A download must deliver bytes in order. That single constraint decides the
shape of everything else.

The obvious split -- one contiguous slice per bot -- does not work under
that constraint. Slice 2 cannot be handed out until slice 1 is finished, so
either slice 2 buffers its entire output (gigabytes) or its reader blocks
almost immediately and the download is sequential again in all but name.
Measured against a simulated link, slice-per-bot with a small buffer came
out at 1.14x sequential: all of the complexity, none of the speed.

Fixed-size **pieces** fix this. With pieces of a few megabytes, a piece that
finishes early holds only its own piece worth of memory, and the buffer is
bounded by `piece size x pieces in flight` regardless of file size. The same
simulated workload runs 3.99x faster with four pieces in flight and 7.96x
with eight (`scripts/measure_transfer.py`).

Two consequences follow:

* **The queue in front of each piece must fit a whole piece.** If it is
  shallower, a ready piece blocks instead of releasing its connection for
  the next one, and the parallelism disappears.
* **Pieces are generators, started when they are reached.** A large file is
  hundreds of pieces; building them eagerly would replace one slow download
  with a burst of hundreds of requests.

## Where the parallelism actually comes from

Pieces are handed to bot clients round-robin, so the number of configured
bot tokens is the natural width of a download. A single MTProto connection
sends its requests one after another, so a deployment with one token could
not overlap transfers no matter how many pieces were in flight.

`connection_pool_size` opens more connections for the same session --
Telegram accepts several per authorization. Only the file-part calls are
spread over them; metadata calls stay on the primary connection, where the
message cache and session state live. A connection that fails to open is
logged, not fatal: fewer connections is a slower transfer, not a broken one.

Uploads work the same way from the other side, with one hard constraint:
the parts of one file are tied to the uploading session by their `file_id`,
so they can be spread across the connections of one bot but never across
different bots.

## The cache sits below encryption

`EncryptingFileContentRepository` translates a plaintext range into a
ciphertext range and calls the inner repository with it. A cache above that
layer would have to redo the translation to know what it is holding, so the
cache lives below it and stores on-wire bytes. Encrypted and plaintext files
are then cached the same way, and neither path needs to know the cache
exists.

Keys are `(channel, message id, block index)`. The channel is part of the key
because mirror copies live in their own channels under their own message
ids; failover therefore reads what it asked for and never a primary block
wearing a mirror's name.

Two rules keep it honest:

* **The budget is bytes, not entries.** An entry count says nothing about
  how much memory a cache of megabyte blocks is holding.
* **Only complete blocks are stored.** A block is complete when it has the
  length its position calls for. The last block of a document is
  legitimately short; a truncated stream is not, and serving one as the
  other would hand out corrupt data.

Fetches are rounded out to whole block boundaries, which is what makes the
cache useful for small reads: an SFTP client reading 32 KiB at a time pulls
one block and then hits it for the rest of that megabyte.

## What is deliberately not tuned

`is_big_file` used to decide two unrelated things: which upload RPC to use,
and whether a download is worth splitting. Only the second is a preference.
The first is Telegram's rule -- files over 10 MB must use
`saveBigFilePart` -- and making it configurable would let a config change
produce uploads Telegram rejects. The download threshold moved into the
config; the protocol rule stayed a constant.

Read-ahead is best-effort by construction: capped, de-duplicated per range,
and silent about failures. Nothing waits on it, so it must never crowd out
the requests that someone does wait on.

## Rate limits

More parallelism means more requests per second, and Telegram answers a
flood with a wait. That wait is honoured rather than retried against:
retrying on our own schedule is what turns a short throttle into a long one.
Upload parts get a bounded number of attempts with exponential backoff, and
when a part gives up its sibling workers are cancelled -- the `file_id` is
unusable at that point anyway.

If a deployment starts logging flood waits, lower `upload_workers_big` and
`connection_pool_size` before raising anything else.
