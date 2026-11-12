from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

from safevibe.audit import AuditLog
from safevibe.config import Settings
from safevibe.web.app import create_app


def _client(tmp_path, **kw) -> TestClient:
    settings = Settings(backend="ollama", bind="127.0.0.1", audit_log=tmp_path / "audit.jsonl", **kw)
    return TestClient(create_app(settings, AuditLog(settings.audit_log)))


def test_healthz_and_ui(tmp_path):
    client = _client(tmp_path)
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["ok"] is True
    assert health.json()["backend"] == "ollama"
    page = client.get("/")
    assert page.status_code == 200
    assert "SafeVibe" in page.text
    assert "Pseudonymization is not encryption" in page.text


def test_redact_api_does_not_return_raw_secret(tmp_path):
    client = _client(tmp_path)
    secret = "sk-proj-SAFE_VIBE_DEMO_NOT_A_REAL_SECRET_000000"
    res = client.post("/api/redact", json={"text": f"token {secret}"})
    assert res.status_code == 200
    data = res.json()
    assert secret not in data["redacted"]
    assert secret not in res.text
    assert "SECRET" in data["counts"]
    # mapping of raw values must not be sent to the browser
    assert secret not in str(data)


def test_scan_api_on_clean_fixture(tmp_path):
    client = _client(tmp_path)
    from pathlib import Path

    target = Path(__file__).resolve().parents[1] / "examples" / "fixtures" / "clean-skill"
    res = client.post("/api/scan", json={"target": str(target)})
    assert res.status_code == 200
    assert res.json()["verdict"] == "safe"
    assert res.json()["executed"] is False


def test_proxy_redacts_and_restores(tmp_path):
    secret = "sk-proj-SAFE_VIBE_DEMO_NOT_A_REAL_SECRET_000000"
    captured = {}

    class _Resp:
        status_code = 200

        def json(self):
            sent = captured["payload"]["messages"][0]["content"]
            assert secret not in sent
            assert "{{SECRET_" in sent
            placeholder = [part for part in sent.split() if part.startswith("{{")][0]
            return {
                "id": "demo",
                "choices": [
                    {"message": {"role": "assistant", "content": f"I will use {placeholder} as asked."}}
                ],
            }

    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(side_effect=lambda *a, **k: captured.update(payload=k["json"]) or _Resp())

    client = _client(tmp_path)
    with patch("safevibe.web.app.httpx.AsyncClient", return_value=mock_client):
        res = client.post(
            "/v1/chat/completions",
            json={"model": "demo", "messages": [{"role": "user", "content": f"use {secret} please"}]},
        )
    assert res.status_code == 200
    body = res.json()
    assert secret in body["choices"][0]["message"]["content"]
    log = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert secret not in log
    assert '"decision": "sent"' in log


def test_proxy_rejects_streaming(tmp_path):
    client = _client(tmp_path)
    res = client.post("/v1/chat/completions", json={"stream": True, "messages": []})
    assert res.status_code == 400


def test_bind_must_be_loopback():
    import pytest

    with pytest.raises(ValueError, match="loopback"):
        Settings(bind="0.0.0.0").validate_backend()
