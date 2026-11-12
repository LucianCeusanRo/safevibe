"""Romanian CNP and CUI/CIF checksum validation.

All examples in this project are synthetic. A valid checksum does not mean
the identifier belongs to a real person or company.
"""

from __future__ import annotations

import re

_CNP_WEIGHTS = (2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9)
_CUI_WEIGHTS = (7, 5, 3, 2, 1, 7, 5, 3, 2)
_CNP_RE = re.compile(r"\b[1-8]\d{12}\b")
_CUI_RE = re.compile(r"\b(?:RO)?[1-9]\d{1,9}\b", re.IGNORECASE)
_CUI_CONTEXT_RE = re.compile(r"(?i)(?:\bCUI\b|\bCIF\b|\bRO\s*)")


def cnp_control_digit(first12: str) -> str:
    if len(first12) != 12 or not first12.isdigit():
        raise ValueError("CNP body must be 12 digits")
    total = sum(int(ch) * w for ch, w in zip(first12, _CNP_WEIGHTS, strict=True))
    rest = total % 11
    return "1" if rest == 10 else str(rest)


def _valid_cnp_date(cnp: str) -> bool:
    century_map = {
        "1": 1900,
        "2": 1900,
        "3": 1800,
        "4": 1800,
        "5": 2000,
        "6": 2000,
        "7": 2000,
        "8": 2000,
    }
    sex = cnp[0]
    if sex not in century_map:
        return False
    year = century_map[sex] + int(cnp[1:3])
    month = int(cnp[3:5])
    day = int(cnp[5:7])
    if month < 1 or month > 12 or day < 1 or day > 31:
        return False
    # Light calendar check; Feb 29 is accepted on leap years only.
    if month in {4, 6, 9, 11} and day > 30:
        return False
    if month == 2:
        leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        if day > (29 if leap else 28):
            return False
    county = int(cnp[7:9])
    return 1 <= county <= 52


def is_valid_cnp(value: str) -> bool:
    text = value.strip()
    if not _CNP_RE.fullmatch(text):
        return False
    if not _valid_cnp_date(text):
        return False
    return cnp_control_digit(text[:12]) == text[12]


def cui_control_digit(body: str) -> str:
    if not body.isdigit() or not (1 <= len(body) <= 9):
        raise ValueError("CUI body must be 1–9 digits")
    padded = body.zfill(9)
    total = sum(int(padded[i]) * _CUI_WEIGHTS[i] for i in range(9))
    calc = (total * 10) % 11
    if calc == 10:
        calc = 0
    return str(calc)


def normalize_cui(value: str) -> str:
    return re.sub(r"(?i)^RO", "", value.strip())


def is_valid_cui(value: str) -> bool:
    body = normalize_cui(value)
    if not body.isdigit() or not (2 <= len(body) <= 10):
        return False
    return cui_control_digit(body[:-1]) == body[-1]


def find_cnp(text: str) -> list[re.Match[str]]:
    return [m for m in _CNP_RE.finditer(text) if is_valid_cnp(m.group(0))]


def find_cui(text: str, *, require_context: bool = True) -> list[re.Match[str]]:
    matches: list[re.Match[str]] = []
    for m in _CUI_RE.finditer(text):
        raw = m.group(0)
        if not is_valid_cui(raw):
            continue
        if raw.upper().startswith("RO"):
            matches.append(m)
            continue
        if not require_context:
            matches.append(m)
            continue
        window = text[max(0, m.start() - 12) : m.start()]
        if _CUI_CONTEXT_RE.search(window):
            matches.append(m)
    return matches
