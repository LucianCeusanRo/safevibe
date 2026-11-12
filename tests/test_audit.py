from pathlib import Path

from safevibe.audit import AuditLog
from safevibe.redact import redact
from safevibe.vault import Vault


def test_audit_strips_banned_fields_and_keeps_counts(tmp_path: Path):
    log = AuditLog(tmp_path / "audit.jsonl")
    secret = "sk-proj-SAFE_VIBE_DEMO_NOT_A_REAL_SECRET_000000"
    result = redact(f"key {secret}", Vault())
    log.write(
        "redact_preview",
        destination="test",
        decision="preview",
        counts=result.counts,
        prompt="should not persist",
        secret=secret,
        cnp="1900115100015",
    )
    raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert secret not in raw
    assert "should not persist" not in raw
    assert "1900115100015" not in raw
    rows = log.tail(5)
    assert rows[0]["counts"]["SECRET"] == 1
    assert "prompt" not in rows[0]
