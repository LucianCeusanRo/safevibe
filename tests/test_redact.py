from pathlib import Path

from safevibe.dictionary import OrgDictionary
from safevibe.redact import redact, restore
from safevibe.vault import Vault

DEMO = Path(__file__).resolve().parents[1] / "examples" / "sample" / "prompt.txt"
DICTIONARY = OrgDictionary(
    hostnames=("core-sw-01", "noc-jump"),
    suffixes=(".lab.internal",),
    project_names=("Project Meridian",),
    ticket_prefixes=("INC-",),
)


def test_round_trip_demo_prompt():
    text = DEMO.read_text(encoding="utf-8")
    vault = Vault()
    result = redact(text, vault, DICTIONARY)
    assert "10.20.30.40" not in result.redacted
    assert "1900115100015" not in result.redacted
    assert "RO123456789" not in result.redacted
    assert "sk-proj-SAFE_VIBE_DEMO_NOT_A_REAL_SECRET_000000" not in result.redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted
    assert "ana.demo@northpeak.example" not in result.redacted
    assert "intranet.lab.internal" not in result.redacted
    assert "{{" in result.redacted
    assert restore(result.redacted, vault) == text
    assert result.counts["SECRET"] >= 2
    assert result.counts["CNP"] == 1
    assert result.counts["CUI"] == 1
    assert result.counts["EMAIL"] == 1
    assert result.counts["PHONE"] == 1
    assert result.counts["IPV4"] == 2  # 10.20.30.40 and 192.168.50.10
    assert result.counts["IPV6"] == 1
    assert result.counts["MAC"] == 1
    assert result.counts["IBAN"] == 1


def test_same_value_gets_stable_placeholder():
    vault = Vault()
    text = "Reach 10.20.30.40 first, then 10.20.30.40 again."
    result = redact(text, vault)
    assert result.redacted.count("{{IPV4_01}}") == 2
    assert "IPV4_02" not in result.redacted


def test_cui_without_context_is_not_redacted():
    result = redact("The rack number is 123456789 and that is all.")
    assert "123456789" in result.redacted
    assert "CUI" not in result.counts


def test_cui_with_context_is_redacted():
    result = redact("Vendor CUI 123456789 is synthetic.")
    assert "123456789" not in result.redacted
    assert result.counts.get("CUI") == 1


def test_unknown_placeholder_fails_closed():
    vault = Vault()
    redact("key AKIAIOSFODNN7EXAMPLE", vault)
    restored = vault.restore("see {{SECRET_99}} and {{SECRET_01}}")
    assert "[UNMAPPED_PLACEHOLDER]" in restored
    assert "AKIAIOSFODNN7EXAMPLE" in restored
    assert vault.warnings


def test_org_dictionary_terms():
    result = redact("Open INC-1042 for Project Meridian on core-sw-01", Vault(), DICTIONARY)
    assert "INC-1042" not in result.redacted
    assert "Project Meridian" not in result.redacted
    assert "core-sw-01" not in result.redacted
    assert restore(result.redacted, result.vault) == "Open INC-1042 for Project Meridian on core-sw-01"


def test_public_hostname_is_not_redacted():
    result = redact("Clone from https://github.com/example/demo and read https://openai.com")
    assert "github.com" in result.redacted
    assert "openai.com" in result.redacted
