from __future__ import annotations

from pathlib import Path

import pytest

from safevibe.audit import AuditLog
from safevibe.config import Settings
from safevibe.dictionary import OrgDictionary


@pytest.fixture
def tmp_audit(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture
def settings(tmp_audit: Path, tmp_path: Path) -> Settings:
    return Settings(
        backend="ollama",
        bind="127.0.0.1",
        port=8787,
        audit_log=tmp_audit,
        log_redacted_prompts=False,
        dictionary=None,
    )


@pytest.fixture
def audit(tmp_audit: Path) -> AuditLog:
    return AuditLog(tmp_audit)


@pytest.fixture
def demo_dictionary() -> OrgDictionary:
    return OrgDictionary(
        hostnames=("core-sw-01", "noc-jump"),
        suffixes=(".lab.internal",),
        project_names=("Project Meridian",),
        ticket_prefixes=("INC-", "CHG-"),
    )


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "examples" / "fixtures"
