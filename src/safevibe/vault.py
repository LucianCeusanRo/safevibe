"""Process-local placeholder vault.

The mapping of real values to placeholders never leaves the process unless the
operator explicitly enables an encrypted on-disk backup. Audit logs never
receive the raw values.
"""

from __future__ import annotations

import base64
import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from safevibe.patterns import PLACEHOLDER_RE

PLACEHOLDER_FMT = "{{{{{category}_{index:02d}}}}}"


@dataclass
class Vault:
    """Bidirectional map between original strings and placeholders."""

    _forward: dict[tuple[str, str], str] = field(default_factory=dict)
    _reverse: dict[str, str] = field(default_factory=dict)
    _counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    warnings: list[str] = field(default_factory=list)

    def placeholder_for(self, category: str, value: str) -> str:
        key = (category, value)
        existing = self._forward.get(key)
        if existing is not None:
            return existing
        self._counts[category] += 1
        token = PLACEHOLDER_FMT.format(category=category, index=self._counts[category])
        self._forward[key] = token
        self._reverse[token] = value
        return token

    def restore(self, text: str, *, unknown: str = "[UNMAPPED_PLACEHOLDER]") -> str:
        def _sub(match: re.Match[str]) -> str:
            token = match.group(0)
            if token in self._reverse:
                return self._reverse[token]
            self.warnings.append(f"unknown placeholder {token}")
            return unknown

        return PLACEHOLDER_RE.sub(_sub, text)

    def counts(self) -> dict[str, int]:
        return dict(self._counts)

    def known_placeholders(self) -> set[str]:
        return set(self._reverse)

    def is_empty(self) -> bool:
        return not self._forward

    def export_encrypted(self, path: Path, passphrase: str) -> None:
        """Write an encrypted mapping. The passphrase never goes to the audit log."""
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=400_000)
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
        payload = {
            "forward": [[cat, val, tok] for (cat, val), tok in self._forward.items()],
        }
        token = Fernet(key).encrypt(json.dumps(payload).encode("utf-8"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"svb1" + salt + token)

    @classmethod
    def import_encrypted(cls, path: Path, passphrase: str) -> Vault:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        raw = path.read_bytes()
        if not raw.startswith(b"svb1") or len(raw) < 20:
            raise ValueError("not a SafeVibe vault file")
        salt, token = raw[4:20], raw[20:]
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=400_000)
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
        payload = json.loads(Fernet(key).decrypt(token).decode("utf-8"))
        vault = cls()
        for cat, val, tok in payload["forward"]:
            vault._forward[(cat, val)] = tok
            vault._reverse[tok] = val
            try:
                idx = int(tok.strip("{}").split("_")[-1])
            except ValueError:
                idx = 0
            if idx > vault._counts[cat]:
                vault._counts[cat] = idx
        return vault
