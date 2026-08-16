import logging
import os

import asyncssh

logger = logging.getLogger(__name__)

HOST_KEY_ALGORITHM = "ssh-ed25519"


def load_or_create_host_key(path: str) -> asyncssh.SSHKey:
    """Return the server's host key, generating it on first start.

    The key identifies this server to clients, so it must survive restarts:
    a fresh key on every boot makes every client refuse to connect until
    its known_hosts entry is cleared. It is written with mode 0600 and
    belongs in the same backed-up directory as the rest of the TGFS data.
    """
    if os.path.exists(path):
        key = asyncssh.read_private_key(path)
        logger.info("Using SFTP host key %s (%s)", path, key.get_fingerprint())
        return key

    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    key = asyncssh.generate_private_key(HOST_KEY_ALGORITHM)
    key.write_private_key(path)
    os.chmod(path, 0o600)
    logger.info("Generated SFTP host key %s (%s)", path, key.get_fingerprint())
    return key
