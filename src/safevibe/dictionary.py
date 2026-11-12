"""Organisation dictionary: extra hostnames, suffixes, project names, ticket prefixes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_DICTIONARY_YAML = """\
# Local organisation dictionary for SafeVibe.
# These values never leave your machine except as placeholders.
# Use fictional or your own names — never commit a filled copy with real ones.

hostnames:
  - core-sw-01
  - noc-jump

suffixes:
  - .lab.internal

project_names:
  - Project Meridian

ticket_prefixes:
  - INC-
  - CHG-
"""


@dataclass(frozen=True)
class OrgDictionary:
    hostnames: tuple[str, ...] = ()
    suffixes: tuple[str, ...] = ()
    project_names: tuple[str, ...] = ()
    ticket_prefixes: tuple[str, ...] = ()

    @classmethod
    def empty(cls) -> OrgDictionary:
        return cls()

    @classmethod
    def from_mapping(cls, data: dict) -> OrgDictionary:
        def _list(key: str) -> tuple[str, ...]:
            raw = data.get(key, []) or []
            return tuple(str(item).strip() for item in raw if str(item).strip())

        return cls(
            hostnames=_list("hostnames"),
            suffixes=_list("suffixes"),
            project_names=_list("project_names"),
            ticket_prefixes=_list("ticket_prefixes"),
        )

    @classmethod
    def from_yaml_text(cls, text: str) -> OrgDictionary:
        data = yaml.safe_load(text) or {}
        if not isinstance(data, dict):
            raise ValueError("organisation dictionary must be a YAML mapping")
        return cls.from_mapping(data)

    @classmethod
    def load(cls, path: Path) -> OrgDictionary:
        return cls.from_yaml_text(path.read_text(encoding="utf-8"))

    def to_mapping(self) -> dict:
        return {
            "hostnames": list(self.hostnames),
            "suffixes": list(self.suffixes),
            "project_names": list(self.project_names),
            "ticket_prefixes": list(self.ticket_prefixes),
        }
