from __future__ import annotations

import json
from pathlib import Path

from safevibe.scan import scan_target
from safevibe.scan.fetch import is_remote_url
from safevibe.scan.rules import scan_path


def test_clean_skill_is_safe(fixtures_dir: Path):
    report = scan_target(str(fixtures_dir / "clean-skill"))
    assert report.executed is False
    assert report.verdict == "safe"
    assert report.exit_code() == 0
    assert report.findings == []


def test_risky_skill_is_blocked_for_prompt_injection(fixtures_dir: Path):
    report = scan_target(str(fixtures_dir / "risky-skill"))
    assert report.executed is False
    rules = {f.rule for f in report.findings}
    assert "prompt-injection" in rules
    assert "credential-access" in rules
    assert "exfil-host" in rules
    assert report.verdict == "blocked"
    assert report.exit_code() == 2


def test_blocked_npm_postinstall_and_binary(fixtures_dir: Path):
    report = scan_target(str(fixtures_dir / "blocked-npm"))
    assert report.executed is False
    rules = {f.rule for f in report.findings}
    assert "install-hook" in rules
    assert "curl-pipe-shell" in rules or "install-hook" in rules
    assert "obfuscation" in rules
    assert "committed-binary" in rules
    assert report.verdict == "blocked"


def test_vscode_extension_is_flagged(fixtures_dir: Path):
    report = scan_target(str(fixtures_dir / "vscode-ext"))
    assert any(f.rule == "vscode-extension" for f in report.findings)
    assert report.verdict in {"risky", "blocked"}
    assert report.executed is False


def test_python_setup_hook_is_flagged(fixtures_dir: Path):
    report = scan_target(str(fixtures_dir / "py-package"))
    assert any(f.rule == "python-install-hook" for f in report.findings)
    assert report.executed is False


def test_scan_does_not_execute_hooks(fixtures_dir: Path, tmp_path: Path, monkeypatch):
    """A postinstall that would write a marker must not run during scan."""
    marker = tmp_path / "pwned"
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "package.json").write_text(
        json.dumps({"name": "demo", "scripts": {"postinstall": f"touch {marker}"}}),
        encoding="utf-8",
    )
    report = scan_target(str(pkg))
    assert report.executed is False
    assert not marker.exists()
    assert any(f.rule == "install-hook" for f in report.findings)


def test_scan_missing_path_errors(tmp_path: Path):
    report = scan_target(str(tmp_path / "nope"))
    assert report.error
    assert report.exit_code() == 3
    assert report.executed is False


def test_single_file_scan(fixtures_dir: Path):
    report = scan_target(str(fixtures_dir / "risky-skill" / "SKILL.md"))
    assert report.verdict == "blocked"
    assert report.executed is False


def test_is_remote_url():
    assert is_remote_url("https://github.com/example/demo")
    assert not is_remote_url("./local")


def test_scan_path_on_directory(fixtures_dir: Path):
    findings = scan_path(fixtures_dir / "clean-skill")
    assert findings == []
