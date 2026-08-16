"""Smoke-check a built TGFS image by serving SFTP from it and talking back.

Building an image proves nothing about it running. Two things can break here
that no unit test would catch: a dependency missing from the runtime layer, and
the non-root ``tgfs`` user being unable to write the generated host key.

``main.py`` logs into Telegram before it serves anything, so the container
cannot simply be started in CI. ``start_sftp_server`` takes the client map as an
argument, though, so passing an empty one gives a real, running server with an
empty root and no Telegram involved.

Run it against an image with::

    docker run --rm -v "$PWD/scripts:/app/scripts:ro" <image> \\
        python scripts/docker_smoke_check.py

or straight from a checkout with ``python scripts/docker_smoke_check.py``.

Everything with a side effect lives under the ``__main__`` guard: this script
points TGFS at a throwaway config through the environment, which would corrupt
any process that merely imported it. The filename avoids pytest's collection
patterns (``test_*.py`` and ``*_test.py``) for the same reason.
"""

import asyncio
import logging
import os
import sys
import tempfile

PORT = 22222
USERNAME = "smoke"
PASSWORD = "smoke-password"  # noqa: S105 - throwaway credential for this check

CONFIG_TEMPLATE = """
telegram:
  api_id: 1
  api_hash: smoke
  bot:
    session_file: smoke_bot.session
    tokens:
      - smoke_bot_token
  private_file_channel:
    - '1'
tgfs:
  users:
    {username}:
      password: {password}
      readonly: false
  download:
    chunk_size_kb: 1024
  jwt:
    secret: smoke
    algorithm: HS256
    life: 3600
  metadata:
    '1':
      name: smoke
      type: pinned_message
  server:
    host: 127.0.0.1
    port: 1900
  sftp:
    enabled: true
    host: 127.0.0.1
    port: {port}
    host_key_file: sftp_host_key
"""

logger = logging.getLogger("smoke")


def prepare_environment() -> str:
    """Write a throwaway config and point TGFS at it.

    This has to happen before anything from ``tgfs`` is imported:
    ``tgfs/auth/basic.py`` calls ``get_config()`` at import time, so the
    environment must already be in place.
    """
    data_dir = tempfile.mkdtemp(prefix="tgfs-smoke-")
    config_path = os.path.join(data_dir, "config.yaml")

    with open(config_path, "w", encoding="utf-8") as fh:
        fh.write(
            CONFIG_TEMPLATE.format(username=USERNAME, password=PASSWORD, port=PORT)
        )

    os.environ["TGFS_DATA_DIR"] = data_dir
    os.environ["TGFS_CONFIG_FILE"] = "config.yaml"
    return data_dir


async def connect(password: str):
    return await asyncssh.connect(
        host="127.0.0.1",
        port=PORT,
        username=USERNAME,
        password=password,
        known_hosts=None,
    )


async def check_listing() -> None:
    async with await connect(PASSWORD) as conn:
        async with conn.start_sftp_client() as sftp:
            entries = sorted(await sftp.listdir("/"))

    # No clients are configured, so the virtual root is empty.
    if entries != [".", ".."]:
        raise AssertionError(f"unexpected root listing: {entries}")
    logger.info("Authenticated and listed the virtual root")


async def check_wrong_password_is_rejected() -> None:
    try:
        conn = await connect("definitely-not-the-password")
    except asyncssh.PermissionDenied:
        logger.info("A wrong password is rejected")
        return
    conn.close()
    raise AssertionError("a wrong password was accepted")


async def check_image() -> None:
    logger.info("asyncssh %s", asyncssh.__version__)

    acceptor = await start_sftp_server({}, get_config())
    if acceptor is None:
        raise AssertionError("the SFTP server did not start")

    try:
        host_key = os.path.join(DATA_DIR, "sftp_host_key")
        if not os.path.exists(host_key):
            raise AssertionError(f"no host key was generated at {host_key}")
        logger.info("Generated a host key and bound port %d", PORT)

        await check_listing()
        await check_wrong_password_is_rejected()
    finally:
        acceptor.close()
        await acceptor.wait_closed()

    logger.info("SFTP smoke check passed")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
    # asyncssh narrates every packet exchange at INFO, which would bury the few
    # lines that actually say whether the check passed.
    logging.getLogger("asyncssh").setLevel(logging.WARNING)

    DATA_DIR = prepare_environment()

    import asyncssh

    from tgfs.app.sftp import start_sftp_server
    from tgfs.config import get_config

    try:
        asyncio.run(check_image())
    except Exception as ex:
        logger.error("SFTP smoke check failed: %s", ex)
        sys.exit(1)
