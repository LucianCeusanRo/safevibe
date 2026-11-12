"""Redact sensitive spans and restore placeholders from a vault."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from safevibe.dictionary import OrgDictionary
from safevibe.patterns import (
    HOST_NAME_RE,
    PATTERNS,
    URL_RE,
    find_ipv6,
    iban_is_valid,
    is_private_ipv4,
    looks_internal_host,
)
from safevibe.romanian import find_cnp, find_cui
from safevibe.vault import Vault


@dataclass(frozen=True, order=True)
class Span:
    start: int
    end: int
    priority: int
    category: str
    value: str


@dataclass
class RedactResult:
    original: str
    redacted: str
    vault: Vault
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def categories(self) -> list[str]:
        return sorted(self.counts)


def _collect(text: str, dictionary: OrgDictionary) -> list[Span]:
    spans: list[Span] = []

    def add(start: int, end: int, category: str, value: str, priority: int) -> None:
        if start >= end:
            return
        spans.append(Span(start=start, end=end, priority=-priority, category=category, value=value))

    for pattern in PATTERNS:
        for match in pattern.regex.finditer(text):
            value = match.group(0)
            if pattern.category == "IBAN" and not iban_is_valid(value):
                continue
            if pattern.category == "IPV6" and value.count(":") < 2:
                continue
            add(match.start(), match.end(), pattern.category, value, pattern.priority)

    for match in find_cnp(text):
        add(match.start(), match.end(), "CNP", match.group(0), 65)

    for match in find_cui(text, require_context=True):
        add(match.start(), match.end(), "CUI", match.group(0), 64)

    for match in find_ipv6(text):
        add(match.start(), match.end(), "IPV6", match.group(0), 55)

    extra = dictionary.suffixes
    for match in URL_RE.finditer(text):
        value = match.group(0).rstrip(".,;:!?)")
        parsed = urlparse(value)
        host = parsed.hostname or ""
        if host and (
            looks_internal_host(host, extra)
            or (re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host) and is_private_ipv4(host))
            or host.lower() in {h.lower() for h in dictionary.hostnames}
        ):
            add(match.start(), match.start() + len(value), "URL", value, 72)

    for match in HOST_NAME_RE.finditer(text):
        value = match.group(0)
        if looks_internal_host(value, extra) or value.lower() in {h.lower() for h in dictionary.hostnames}:
            add(match.start(), match.end(), "HOST", value, 45)

    for name in dictionary.hostnames:
        for match in re.finditer(rf"(?<![\w.-]){re.escape(name)}(?![\w.-])", text, re.IGNORECASE):
            add(match.start(), match.end(), "HOST", match.group(0), 46)

    for name in dictionary.project_names:
        for match in re.finditer(re.escape(name), text, re.IGNORECASE):
            add(match.start(), match.end(), "PROJECT", match.group(0), 40)

    for prefix in dictionary.ticket_prefixes:
        pattern = re.compile(rf"\b{re.escape(prefix)}\d+\b", re.IGNORECASE)
        for match in pattern.finditer(text):
            add(match.start(), match.end(), "TICKET", match.group(0), 42)

    return spans


def _pick(spans: list[Span]) -> list[Span]:
    chosen: list[Span] = []
    # Sort: higher original priority first (we stored -priority), then longer, then earlier.
    ordered = sorted(spans, key=lambda s: (s.priority, -(s.end - s.start), s.start))
    occupied: list[tuple[int, int]] = []
    for span in ordered:
        if any(not (span.end <= a or span.start >= b) for a, b in occupied):
            continue
        chosen.append(span)
        occupied.append((span.start, span.end))
    return sorted(chosen, key=lambda s: s.start)


def redact(text: str, vault: Vault | None = None, dictionary: OrgDictionary | None = None) -> RedactResult:
    vault = vault or Vault()
    dictionary = dictionary or OrgDictionary.empty()
    chosen = _pick(_collect(text, dictionary))
    pieces: list[str] = []
    cursor = 0
    for span in chosen:
        pieces.append(text[cursor : span.start])
        pieces.append(vault.placeholder_for(span.category, span.value))
        cursor = span.end
    pieces.append(text[cursor:])
    redacted = "".join(pieces)
    return RedactResult(original=text, redacted=redacted, vault=vault, counts=vault.counts())


def restore(text: str, vault: Vault) -> str:
    return vault.restore(text)


def redact_messages(messages: list[dict], vault: Vault, dictionary: OrgDictionary | None = None) -> list[dict]:
    """Redact OpenAI-style chat messages, including tool-call arguments when present."""
    out: list[dict] = []
    for message in messages:
        item = dict(message)
        content = item.get("content")
        if isinstance(content, str):
            item["content"] = redact(content, vault, dictionary).redacted
        elif isinstance(content, list):
            new_parts = []
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    part = dict(part)
                    part["text"] = redact(part["text"], vault, dictionary).redacted
                new_parts.append(part)
            item["content"] = new_parts
        tool_calls = item.get("tool_calls")
        if isinstance(tool_calls, list):
            new_calls = []
            for call in tool_calls:
                call = dict(call)
                fn = call.get("function")
                if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                    fn = dict(fn)
                    fn["arguments"] = redact(fn["arguments"], vault, dictionary).redacted
                    call["function"] = fn
                new_calls.append(call)
            item["tool_calls"] = new_calls
        if isinstance(item.get("tool_call_id"), str):
            pass
        out.append(item)
    return out
