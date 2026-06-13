"""One-off migration: encrypt existing plaintext names in the metadata repo.

Renames every directory folder and file-reference in the TGFS GitHub
metadata repo to its deterministic AES-SIV encrypted form, so a repo that
was populated *before* name encryption was enabled matches what the running
server now writes. Idempotent: already-encrypted components are left as-is,
so it is safe to re-run and to run against a partially-migrated repo.

ORDER MATTERS: deploy the path-name-encryption feature first (so the server
decrypts on read), *then* run this. The whole rewrite is one commit and a
backup tag is created first, so it is fully reversible.

Usage (inside the tgfs container or any env with the config + deps):

    python -m scripts.encrypt_metadata_names            # dry run (default)
    python -m scripts.encrypt_metadata_names --apply    # perform the rename
"""
# This is an operator CLI tool; user-facing output is intentionally via print.
# ruff: noqa: T201
from __future__ import annotations

import argparse
import sys

from github import Github, InputGitTreeElement

from tgfs.config import get_config
from tgfs.crypto.bootstrap import load_master_key
from tgfs.crypto.path_names import (
    derive_path_name_key,
    encrypt_path_name,
    is_encrypted_path_name,
)


def _encrypt_component(key: bytes, name: str) -> str:
    """Encrypt one path segment, leaving already-encrypted ones untouched."""
    return name if is_encrypted_path_name(name) else encrypt_path_name(key, name)


def migrate_path(key: bytes, path: str) -> str:
    """Map a stored repo path to its fully-encrypted equivalent."""
    *dirs, leaf = path.split("/")
    new_dirs = [_encrypt_component(key, d) for d in dirs]
    if leaf == ".gitkeep":
        new_leaf = leaf
    else:
        # File reference "<name>.<message_id>"; the name may contain dots.
        name, _, message_id = leaf.rpartition(".")
        if name and message_id.isdigit():
            new_leaf = f"{_encrypt_component(key, name)}.{message_id}"
        else:
            new_leaf = leaf  # unexpected shape -> leave untouched
    return "/".join(new_dirs + [new_leaf])


def main() -> int:
    ap = argparse.ArgumentParser(description="Encrypt metadata-repo path names.")
    ap.add_argument(
        "--apply",
        action="store_true",
        help="perform the rename (default: dry run, no writes)",
    )
    args = ap.parse_args()

    cfg = get_config()
    enc_cfg = cfg.tgfs.encryption
    if not enc_cfg.enabled:
        print("encryption is not enabled in config; nothing to do.")
        return 1
    key = derive_path_name_key(load_master_key(enc_cfg).key)

    gh_repo_cfg = next(
        (m.github_repo for m in cfg.tgfs.metadata.values() if m.github_repo), None
    )
    if gh_repo_cfg is None:
        print("no github_repo metadata backend configured.")
        return 1

    repo = Github(gh_repo_cfg.access_token).get_repo(gh_repo_cfg.repo)
    branch = gh_repo_cfg.commit

    ref = repo.get_git_ref(f"heads/{branch}")
    base_commit = repo.get_git_commit(ref.object.sha)
    tree = repo.get_git_tree(base_commit.tree.sha, recursive=True)

    elements = []
    changes = 0
    for entry in tree.tree:
        if entry.type != "blob":
            continue
        new_path = migrate_path(key, entry.path)
        if new_path != entry.path:
            changes += 1
            print(f"  {entry.path}\n    -> {new_path}")
        elements.append(
            InputGitTreeElement(
                path=new_path, mode=entry.mode, type="blob", sha=entry.sha
            )
        )

    print(f"\n{changes} path(s) to encrypt out of {len(elements)} blob(s).")
    if changes == 0:
        print("repo already fully encrypted; nothing to do.")
        return 0
    if not args.apply:
        print("dry run -- re-run with --apply to perform the rename.")
        return 0

    backup = f"refs/tags/pre-name-encryption-{base_commit.sha[:12]}"
    try:
        repo.create_git_ref(backup, base_commit.sha)
        print(f"backup tag created: {backup}")
    except Exception as ex:
        print(f"backup tag not created ({ex}); aborting to stay safe.")
        return 1

    new_tree = repo.create_git_tree(elements)
    new_commit = repo.create_git_commit(
        "Encrypt metadata path names", new_tree, [base_commit]
    )
    ref.edit(new_commit.sha)
    print(f"done: {branch} now at {new_commit.sha[:12]} ({changes} renamed).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
