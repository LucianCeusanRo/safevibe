"""Scan a local path or a git URL and produce a bilingual verdict."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from safevibe.scan.fetch import FetchError, is_remote_url, safe_clone
from safevibe.scan.rules import SEVERITY_ORDER, Finding, scan_path

VERDICT_LABELS = {
    "safe": {"en": "safe", "ro": "sigur"},
    "risky": {"en": "risky", "ro": "riscant"},
    "blocked": {"en": "blocked", "ro": "blocat"},
}

EXIT_CODES = {"safe": 0, "risky": 1, "blocked": 2}


@dataclass
class ScanReport:
    target: str
    resolved_path: str
    verdict: str
    executed: bool
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    def exit_code(self) -> int:
        if self.error:
            return 3
        return EXIT_CODES[self.verdict]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "resolved_path": self.resolved_path,
            "verdict": self.verdict,
            "verdict_ro": VERDICT_LABELS[self.verdict]["ro"] if self.verdict in VERDICT_LABELS else self.verdict,
            "executed": self.executed,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }

    def format_text(self, lang: str = "en") -> str:
        labels = VERDICT_LABELS.get(self.verdict, {"en": self.verdict, "ro": self.verdict})
        if lang == "ro":
            lines = [
                "SafeVibe scan  ·  doar analiză statică, nu s-a executat nimic",
                f"Țintă: {self.target}",
                f"Verdict: {labels['en'].upper()}  ({labels['ro']})",
                "",
            ]
            if self.error:
                lines.append(f"Eroare: {self.error}")
                return "\n".join(lines)
            if not self.findings:
                lines.append("Nu s-a declanșat niciun tipar cunoscut.")
                lines.append("Asta nu înseamnă că ținta este inofensivă.")
                return "\n".join(lines)
            lines.append("Găsiri:")
            for item in self.findings:
                loc = f"{item.path}" + (f":{item.line}" if item.line else "")
                lines.append(f"  [{item.severity}] {item.rule}  {loc}")
                lines.append(f"    {item.why_ro}")
                if item.excerpt:
                    lines.append(f"    » {item.excerpt}")
            return "\n".join(lines)

        lines = [
            "SafeVibe scan  ·  static only, nothing was executed",
            f"Target: {self.target}",
            f"Verdict: {labels['en'].upper()}  ({labels['ro']})",
            "",
        ]
        if self.error:
            lines.append(f"Error: {self.error}")
            return "\n".join(lines)
        if not self.findings:
            lines.append("No known static pattern fired.")
            lines.append("That does not mean the target is harmless.")
            return "\n".join(lines)
        lines.append("Findings:")
        for item in self.findings:
            loc = f"{item.path}" + (f":{item.line}" if item.line else "")
            lines.append(f"  [{item.severity}] {item.rule}  {loc}")
            lines.append(f"    {item.why_en}")
            if item.excerpt:
                lines.append(f"    » {item.excerpt}")
        return "\n".join(lines)


def _verdict_for(findings: list[Finding]) -> str:
    level = 0
    for item in findings:
        level = max(level, SEVERITY_ORDER.get(item.severity, 0))
    for name, value in SEVERITY_ORDER.items():
        if value == level:
            return name
    return "safe"


def scan_target(target: str) -> ScanReport:
    cleanup: Path | None = None
    try:
        if is_remote_url(target):
            cleanup = Path(tempfile.mkdtemp(prefix="safevibe-scan-"))
            path = safe_clone(target, cleanup)
        else:
            path = Path(target).expanduser().resolve()
            if not path.exists():
                return ScanReport(
                    target=target,
                    resolved_path=str(path),
                    verdict="safe",
                    executed=False,
                    error=f"path does not exist: {path}",
                )
        findings = scan_path(path)
        return ScanReport(
            target=target,
            resolved_path=str(path),
            verdict=_verdict_for(findings),
            executed=False,
            findings=findings,
        )
    except FetchError as exc:
        return ScanReport(
            target=target,
            resolved_path="",
            verdict="safe",
            executed=False,
            error=str(exc),
        )
    finally:
        if cleanup is not None:
            # Leave the clone for the duration of scan_tree only; we already scanned.
            import shutil

            shutil.rmtree(cleanup, ignore_errors=True)
