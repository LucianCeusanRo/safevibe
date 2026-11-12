from pathlib import Path

from safevibe.cli import main


def test_redact_cli_json(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.setenv("SAFE_VIBE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    prompt = Path(__file__).resolve().parents[1] / "examples" / "sample" / "prompt.txt"
    code = main(["redact", "--file", str(prompt), "--json"])
    assert code == 0
    out = capsys.readouterr().out
    assert "1900115100015" not in out
    assert "redacted" in out


def test_scan_cli_clean(fixtures_dir: Path, capsys, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SAFE_VIBE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    code = main(["scan", str(fixtures_dir / "clean-skill")])
    captured = capsys.readouterr().out
    assert "SAFE" in captured or "safe" in captured.lower()
    assert code == 0


def test_scan_cli_blocked_exit_code(fixtures_dir: Path, capsys, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SAFE_VIBE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    code = main(["scan", str(fixtures_dir / "risky-skill"), "--json"])
    assert code == 2


def test_run_refuses_without_flag(tmp_path: Path, capsys):
    snippet = tmp_path / "x.py"
    snippet.write_text("print(1)\n", encoding="utf-8")
    code = main(["run", str(snippet)])
    assert code == 3
    assert "Refusing" in capsys.readouterr().out


def test_version():
    import pytest

    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
