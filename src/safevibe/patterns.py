"""Detection patterns for secrets, network identifiers, and contact data.

Secret rules are written in the spirit of Gitleaks (MIT-licensed, public rule
shapes) but are a small, original subset — not a copy of the Gitleaks rule
file. They are best-effort and will miss novel token formats.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

# Documentation / example tokens that must never be treated as findings in
# our own fixtures if we later tighten things; detectors still redact them
# when they appear in a prompt, which is the correct behaviour.


@dataclass(frozen=True)
class Pattern:
    category: str
    name: str
    regex: re.Pattern[str]
    priority: int


def _re(category: str, name: str, source: str, priority: int, flags: int = 0) -> Pattern:
    return Pattern(category, name, re.compile(source, flags), priority)


# Higher priority wins on overlap. Secrets and emails beat hostnames.
PATTERNS: tuple[Pattern, ...] = (
    _re(
        "SECRET",
        "pem-private-key",
        r"-----BEGIN (?:[A-Z0-9 ]+)?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9 ]+)?PRIVATE KEY-----",
        100,
    ),
    _re("SECRET", "aws-access-key", r"\bAKIA[0-9A-Z]{16}\b", 90),
    _re("SECRET", "github-pat", r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", 90),
    _re("SECRET", "github-token", r"\bghp_[A-Za-z0-9]{20,}\b", 90),
    _re("SECRET", "slack-token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", 90),
    _re("SECRET", "anthropic-key", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", 90),
    _re("SECRET", "openai-key", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b", 90),
    _re("SECRET", "google-api-key", r"\bAIza[0-9A-Za-z_-]{35}\b", 90),
    _re("SECRET", "stripe-key", r"\bsk_(?:live|test)_[A-Za-z0-9]{8,}\b", 90),
    _re(
        "SECRET",
        "jwt",
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        85,
    ),
    _re(
        "SECRET",
        "assigned-secret",
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password)\s*[:=]\s*['\"]?[^\s'\"\\]{8,}",
        80,
    ),
    _re(
        "EMAIL",
        "email",
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        70,
        re.IGNORECASE,
    ),
    _re(
        "IBAN",
        "iban",
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b",
        68,
    ),
    _re(
        "PHONE",
        "ro-phone",
        r"(?:\+40|0040|0)\s*7\d{2}(?:[\s.-]?\d{3}){2}\b",
        60,
    ),
    _re(
        "CIDR",
        "cidr",
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)/(?:3[0-2]|[12]?\d)\b",
        52,
    ),
    _re(
        "IPV4",
        "ipv4",
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        50,
    ),
    _re(
        "MAC",
        "mac",
        r"\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b",
        48,
        re.IGNORECASE,
    ),
)

INTERNAL_HOST_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".intranet",
    ".corp",
    ".private",
    ".gov.ro",
)

# Hostname labels, with a suffix from the internal list (or extra user suffixes).
_HOST_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
HOST_NAME_RE = re.compile(rf"\b(?:{_HOST_LABEL}\.)+{_HOST_LABEL}\b", re.IGNORECASE)

URL_RE = re.compile(
    r"https?://[^\s)\]}>'\"<>]+",
    re.IGNORECASE,
)

PLACEHOLDER_RE = re.compile(r"\{\{([A-Z][A-Z0-9]*)_(\d{2,})\}\}")

PRIVATE_IPV4_RE = re.compile(
    r"^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.|169\.254\.)"
)


def is_private_ipv4(ip: str) -> bool:
    return PRIVATE_IPV4_RE.match(ip) is not None


def looks_internal_host(host: str, extra_suffixes: tuple[str, ...] = ()) -> bool:
    lower = host.lower().rstrip(".")
    suffixes = tuple(s.lower() for s in INTERNAL_HOST_SUFFIXES + extra_suffixes)
    return any(lower.endswith(suf) for suf in suffixes)


def iban_is_valid(iban: str) -> bool:
    raw = re.sub(r"\s+", "", iban).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", raw):
        return False
    rearranged = raw[4:] + raw[:4]
    digits = "".join(str(ord(ch) - 55) if ch.isalpha() else ch for ch in rearranged)
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False


_IPV6_CANDIDATE = re.compile(r"\b[0-9a-f:]{2,39}\b", re.IGNORECASE)


def find_ipv6(text: str) -> list[re.Match[str]]:
    matches: list[re.Match[str]] = []
    for match in _IPV6_CANDIDATE.finditer(text):
        value = match.group(0)
        if value.count(":") < 2:
            continue
        try:
            ipaddress.IPv6Address(value)
        except ValueError:
            continue
        matches.append(match)
    return matches
