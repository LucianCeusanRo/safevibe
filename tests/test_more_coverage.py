from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from safevibe.audit import AuditLog
from safevibe.cli import main
from safevibe.config import Settings
from safevibe.dictionary import OrgDictionary
from safevibe.sandbox import run_sandboxed
from safevibe.scan.fetch import FetchError, safe_clone
from safevibe.scan.report import ScanReport, scan_target
from safevibe.scan.rules import Finding
from safevibe.web.app import create_app


def test_settings_extra_suffixes_and_openai_destination():
    settings = Settings(backend="openai", extra_suffixes=".lab.test, .foo")
    assert settings.extra_suffix_tuple() == (".lab.test", ".foo")
    assert settings.destination_name() == "openai-compatible"
    assert "openai.com" in settings.upstream_base()
    settings.validate_backend()


def test_settings_reject_unknown_backend():
    with pytest.raises(ValueError):
        Settings(backend="somewhere-else").validate_backend()


def test_dictionary_round_trip(tmp_path: Path):
    path = tmp_path / "dict.yml"
    path.write_text("hostnames:\n  - box-01\nsuffixes:\n  - .lab.test\n", encoding="utf-8")
    loaded = OrgDictionary.load(path)
    assert loaded.hostnames == ("box-01",)
    assert "box-01" in loaded.to_mapping()["hostnames"]
    with pytest.raises(ValueError):
        OrgDictionary.from_yaml_text("- just a list")


def test_scan_report_text_en_and_ro():
    report = ScanReport(
        target="demo",
        resolved_path="demo",
        verdict="blocked",
        executed=False,
        findings=[
            Finding("blocked", "prompt-injection", "SKILL.md", 3, "ignore previous", "why en", "why ro")
        ],
    )
    en = report.format_text("en")
    ro = report.format_text("ro")
    assert "nothing was executed" in en
    assert "prompt-injection" in en
    assert "doar analiză statică" in ro
    assert "why ro" in ro
    err = ScanReport("x", "", "safe", False, error="boom")
    assert "Error: boom" in err.format_text("en")
    assert "Eroare: boom" in err.format_text("ro")
    clean = ScanReport("x", "x", "safe", False)
    assert "does not mean" in clean.format_text("en")
    assert "nu înseamnă" in clean.format_text("ro")


def test_safe_clone_local_repo(tmp_path: Path):
    origin = tmp_path / "origin"
    origin.mkdir()
    subprocess.run(["git", "init"], cwd=origin, check=True, capture_output=True)
    (origin / "SKILL.md").write_text("# hello\n", encoding="utf-8")
    subprocess.run(["git", "add", "SKILL.md"], cwd=origin, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.email=dev@example.com", "-c", "user.name=Dev", "commit", "-m", "init"],
        cwd=origin,
        check=True,
        capture_output=True,
    )
    cloned = safe_clone(str(origin), tmp_path / "clone")
    assert (cloned / "SKILL.md").is_file()
    report = scan_target(str(origin))
    assert report.executed is False
    assert report.verdict == "safe"


def test_safe_clone_failure(tmp_path: Path):
    with pytest.raises(FetchError):
        safe_clone("https://example.invalid/no-such-repo.git", tmp_path / "nope")


def test_run_sandboxed_success_mocked(tmp_path: Path):
    snippet = tmp_path / "demo.py"
    snippet.write_text("print(1)\n", encoding="utf-8")

    class Proc:
        returncode = 0
        stdout = "1\n"
        stderr = ""

    with (
        patch("safevibe.sandbox.detect_runtime", return_value="docker"),
        patch("safevibe.sandbox.subprocess.run", return_value=Proc()),
    ):
        result = run_sandboxed(snippet)
    assert result.available is True
    assert result.exit_code == 0
    assert "1" in result.stdout
    assert "--network" in result.command


def test_cli_audit_and_sandbox_unavailable(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.setenv("SAFE_VIBE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    snippet = tmp_path / "x.py"
    snippet.write_text("print(1)\n", encoding="utf-8")
    with patch("safevibe.sandbox.shutil.which", return_value=None):
        code = main(["run", "--sandbox", str(snippet)])
    assert code == 3
    assert "Sandbox unavailable" in capsys.readouterr().out
    AuditLog(tmp_path / "audit.jsonl").write("scan", destination="cli", decision="safe", counts={})
    code = main(["audit", "--limit", "5"])
    assert code == 0
    assert "scan" in capsys.readouterr().out
    code = main(["audit", "--json"])
    assert code == 0
    assert "scan" in capsys.readouterr().out


def test_cli_redact_from_text(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.setenv("SAFE_VIBE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    code = main(["redact", "--text", "mail ana.demo@northpeak.example"])
    assert code == 0
    out = capsys.readouterr().out
    assert "ana.demo@northpeak.example" not in out
    assert "EMAIL" in out


def test_app_dictionary_audit_and_models(tmp_path: Path):
    settings = Settings(backend="ollama", bind="127.0.0.1", audit_log=tmp_path / "audit.jsonl")
    client = TestClient(create_app(settings, AuditLog(settings.audit_log)))
    res = client.post("/api/dictionary", json={"yaml_text": "hostnames: [lab-box]\n"})
    assert res.status_code == 200
    bad = client.post("/api/dictionary", json={"yaml_text": "- no"})
    assert bad.status_code == 400
    client.post("/api/redact", json={"text": "see lab-box please"})
    audit = client.get("/api/audit")
    assert audit.status_code == 200
    assert audit.json()["entries"]
    models = client.get("/v1/models")
    assert models.status_code == 200
    assert "data" in models.json()
    cfg = client.get("/api/config")
    assert cfg.json()["backend"] == "ollama"


def test_completions_proxy_and_stream_reject(tmp_path: Path):
    captured: dict = {}

    class _Resp:
        status_code = 200

        def json(self):
            return {"choices": [{"text": f"echo {captured['payload']['prompt']}"}]}

    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(side_effect=lambda *a, **k: captured.update(payload=k["json"]) or _Resp())
    mock_client.get = AsyncMock(return_value=MagicMock(status_code=200, json=lambda: {"data": []}))

    settings = Settings(backend="ollama", bind="127.0.0.1", audit_log=tmp_path / "audit.jsonl")
    client = TestClient(create_app(settings, AuditLog(settings.audit_log)))
    with patch("safevibe.web.app.httpx.AsyncClient", return_value=mock_client):
        res = client.post("/v1/completions", json={"prompt": "mail ana.demo@northpeak.example"})
        assert res.status_code == 200
        assert "ana.demo@northpeak.example" in res.json()["choices"][0]["text"]
        assert "ana.demo@northpeak.example" not in captured["payload"]["prompt"]
        blocked = client.post("/v1/completions", json={"stream": True, "prompt": "x"})
        assert blocked.status_code == 400
