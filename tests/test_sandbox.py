from pathlib import Path
from unittest.mock import patch

from safevibe.sandbox import detect_runtime, run_sandboxed


def test_sandbox_unavailable_without_runtime(tmp_path: Path):
    snippet = tmp_path / "demo.py"
    snippet.write_text("print(1)\n", encoding="utf-8")
    with patch("safevibe.sandbox.shutil.which", return_value=None):
        result = run_sandboxed(snippet)
    assert result.available is False
    assert "Sandbox unavailable" in result.message
    assert "nu este disponibil" in result.message


def test_sandbox_missing_file():
    result = run_sandboxed(Path("/tmp/safevibe-does-not-exist.py"))
    assert result.available is False
    assert "not found" in result.message


def test_detect_runtime_prefers_docker():
    with patch("safevibe.sandbox.shutil.which", side_effect=lambda name: "/usr/bin/docker" if name == "docker" else None):
        assert detect_runtime() == "docker"
