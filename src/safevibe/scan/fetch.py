"""Fetch a GitHub (or git) URL for static scanning. Hooks are never run."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


class FetchError(RuntimeError):
    pass


def is_remote_url(target: str) -> bool:
    return target.startswith(("https://", "http://", "git@", "git://", "ssh://"))


def safe_clone(url: str, dest: Path | None = None) -> Path:
    """Clone with hooks disabled and no checkout scripts executed by us."""
    if shutil.which("git") is None:
        raise FetchError("git is not installed; cannot clone a remote URL")
    dest = dest or Path(tempfile.mkdtemp(prefix="safevibe-scan-"))
    dest.mkdir(parents=True, exist_ok=True)
    # core.hooksPath=/dev/null is the important bit. We also disable
    # interactive credentials so a typo cannot hang waiting for a password.
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    cmd = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "advice.detachedHead=false",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        url,
        str(dest),
    ]
    try:
        subprocess.run(
            cmd,
            check=True,
            env=env,
            timeout=60,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise FetchError(f"git clone failed: {exc.stderr.strip() or exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise FetchError("git clone timed out") from exc
    # Belt and braces after checkout.
    hooks = dest / ".git" / "hooks"
    if hooks.is_dir():
        for hook in hooks.iterdir():
            if hook.is_file():
                hook.chmod(0o644)
    return dest
