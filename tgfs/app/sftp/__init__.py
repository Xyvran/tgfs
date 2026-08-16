import logging
from typing import Optional

import asyncssh

from tgfs.config import Config
from tgfs.core import Clients

from .host_key import load_or_create_host_key
from .server import (
    TGFSSFTPServer,
    TGFSSSHServer,
    make_server_factory,
    make_sftp_factory,
)

logger = logging.getLogger(__name__)


async def start_sftp_server(
    clients: Clients, config: Config
) -> Optional[asyncssh.SSHAcceptor]:
    """Start the SFTP listener, or return ``None`` when it is switched off.

    The listener keeps serving in the background of the running event loop,
    next to the HTTP server, and is handed back so the caller can shut it
    down again.
    """
    sftp_cfg = config.tgfs.sftp
    if not sftp_cfg.enabled:
        logger.info("SFTP server is disabled")
        return None

    host_key = load_or_create_host_key(sftp_cfg.host_key_file)

    acceptor = await asyncssh.listen(
        host=sftp_cfg.host,
        port=sftp_cfg.port,
        server_factory=make_server_factory(config),
        server_host_keys=[host_key],
        sftp_factory=make_sftp_factory(clients, config),
        allow_scp=True,
    )

    logger.info("Starting SFTP server on %s:%s", sftp_cfg.host, sftp_cfg.port)
    return acceptor


__all__ = [
    "TGFSSFTPServer",
    "TGFSSSHServer",
    "start_sftp_server",
]
