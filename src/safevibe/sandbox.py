"""Optional no-network runner for model-generated snippets."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

DOCKER_FLAGS = [
    "--rm",
    "--network", "none",
    "--read-only",
    "--tmpfs", "/tmp",
    "--memory", "256m",
    "--pids-limit", "64",
    "--user", "nobody",
]


@dataclass
class RunResult:
    available: bool
    runtime: str | None
    command: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    message: str

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "runtime": self.runtime,
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "message": self.message,
        }


def detect_runtime() -> str | None:
    if shutil.which("docker"):
        return "docker"
    if shutil.which("podman"):
        return "podman"
    return None


def run_sandboxed(path: Path, *, image: str = "python:3.12-slim") -> RunResult:
    runtime = detect_runtime()
    source = path.expanduser().resolve()
    if not source.is_file():
        return RunResult(False, runtime, [], None, "", "", f"file not found: {source}")
    if runtime is None:
        return RunResult(
            False,
            None,
            [],
            None,
            "",
            "",
            "Sandbox unavailable: neither Docker nor Podman is installed. "
            "SafeVibe will not run untrusted code on the host. "
            f"Install Docker or Podman, pre-pull {image}, and retry with --sandbox. "
            "RO: Mediul izolat nu este disponibil (lipsește Docker/Podman). "
            "SafeVibe nu rulează pe gazdă cod neverificat.",
        )
    inner = f"/work/{source.name}"
    command = [
        runtime, "run", *DOCKER_FLAGS,
        "-v", f"{source}:{inner}:ro",
        image, "python", inner,
    ]
    try:
        proc = subprocess.run(command, check=False, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        return RunResult(False, runtime, command, None, "", "", f"{runtime} disappeared before the run started.")
    except subprocess.TimeoutExpired:
        return RunResult(True, runtime, command, None, "", "", "sandbox run timed out after 60s")
    return RunResult(
        True, runtime, command, proc.returncode, proc.stdout, proc.stderr,
        "completed in sandbox (no network, read-only root)",
    )
