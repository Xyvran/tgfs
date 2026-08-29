"""The smoke check has to survive the import path the image actually has.

The Docker image installs its dependencies with ``poetry install --no-root``,
so the application is not on ``sys.path`` at all -- it is importable only
because the process starts in the directory it was copied to. A script under
``scripts/`` starts out with its own directory on ``sys.path[0]`` instead, so
without help it cannot import ``tgfs``.

A development checkout hides this: ``poetry install`` drops a ``tgfs.pth`` into
the virtualenv, and the application resolves from site-packages no matter where
the process starts. That is exactly how a broken check reached CI once. These
tests run the script with the entries the container does not have stripped from
``sys.path``, which reproduces the container faithfully enough to catch it.
"""

import socket
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "docker_smoke_check.py"
SCRIPTS_DIR = SCRIPT.parent

BOOTSTRAP = """
import runpy, sys
# What `python scripts/docker_smoke_check.py` gets inside the image: the
# script's own directory, and no application anywhere on the path.
sys.path = [p for p in sys.path if p not in ("", {repo!r})]
sys.path.insert(0, {scripts!r})
runpy.run_path({script!r}, run_name="__main__")
"""


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run_like_the_image(env_extra: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            "-c",
            BOOTSTRAP.format(
                repo=str(REPO_ROOT), scripts=str(SCRIPTS_DIR), script=str(SCRIPT)
            ),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        env={**_clean_env(), **env_extra},
    )


def _clean_env() -> dict:
    import os

    # TGFS_DATA_DIR / TGFS_CONFIG_FILE are set for the test suite; the script
    # points at its own throwaway config and must not inherit them.
    return {
        k: v
        for k, v in os.environ.items()
        if k not in ("TGFS_DATA_DIR", "TGFS_CONFIG_FILE", "PYTHONPATH")
    }


class TestRunsWithTheImagesImportPath:
    @pytest.fixture(scope="class")
    def result(self) -> subprocess.CompletedProcess:
        return run_like_the_image({"TGFS_SMOKE_PORT": str(free_port())})

    def test_exits_successfully(self, result):
        assert result.returncode == 0, (
            f"the smoke check failed with the image's import path\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    def test_does_not_fail_to_import_the_application(self, result):
        # The specific failure this test exists for.
        assert "No module named 'tgfs'" not in result.stderr

    def test_reports_that_it_passed(self, result):
        assert "SFTP smoke check passed" in result.stdout + result.stderr


class TestPortIsConfigurable:
    def test_binds_the_port_it_was_given(self):
        port = free_port()

        result = run_like_the_image({"TGFS_SMOKE_PORT": str(port)})

        assert result.returncode == 0, result.stderr
        assert f"127.0.0.1:{port}" in result.stdout + result.stderr


class TestImportingItIsInert:
    def test_import_does_not_touch_the_environment(self):
        # Its side effects live under a __main__ guard, so an accidental import
        # -- by a test collector, say -- must not swap the config out from
        # under the importing process.
        probe = (
            "import importlib.util, os, sys;"
            f"spec = importlib.util.spec_from_file_location('probe', {str(SCRIPT)!r});"
            "m = importlib.util.module_from_spec(spec);"
            "spec.loader.exec_module(m);"
            "print(os.environ.get('TGFS_DATA_DIR'));"
            "print(any(k.startswith('tgfs') for k in sys.modules))"
        )
        result = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            timeout=60,
            env=_clean_env(),
        )

        assert result.returncode == 0, result.stderr
        assert result.stdout.split() == ["None", "False"]
