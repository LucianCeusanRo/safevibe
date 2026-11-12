"""Append-only JSONL audit log. Raw secrets, CNPs and full prompts are not stored."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from safevibe.config import XDG_DATA


def _now() -> str:
    return datetime.now(UTC).astimezone().isoformat(timespec="seconds")


class AuditLog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (XDG_DATA / "audit.jsonl")
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: str, **fields: Any) -> dict[str, Any]:
        record = {"ts": _now(), "event": event, **fields}
        # Defence in depth: never persist obvious raw-value keys.
        for banned in ("prompt", "original", "secret", "cnp", "cui", "vault", "api_key", "passphrase"):
            record.pop(banned, None)
        line = json.dumps(record, ensure_ascii=False)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        return record

    def tail(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        rows: list[dict[str, Any]] = []
        for line in lines[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows
