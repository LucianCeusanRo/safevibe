"""SafeVibe command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table
from rich.theme import Theme

from safevibe import __version__
from safevibe.audit import AuditLog
from safevibe.config import Settings
from safevibe.dictionary import DEFAULT_DICTIONARY_YAML, OrgDictionary
from safevibe.redact import redact
from safevibe.sandbox import run_sandboxed
from safevibe.scan import scan_target
from safevibe.vault import Vault

THEME = Theme(
    {
        "safe": "green",
        "risky": "yellow",
        "blocked": "bold red",
        "muted": "dim",
    }
)
console = Console(theme=THEME)


def _settings(**overrides) -> Settings:
    settings = Settings()
    for key, value in overrides.items():
        if value is not None:
            setattr(settings, key, value)
    settings.validate_backend()
    return settings


def _dictionary(settings: Settings, dictionary: str | None) -> OrgDictionary:
    if dictionary:
        return OrgDictionary.load(Path(dictionary))
    if settings.dictionary and Path(settings.dictionary).is_file():
        return OrgDictionary.load(Path(settings.dictionary))
    return OrgDictionary.from_yaml_text(DEFAULT_DICTIONARY_YAML)


def cmd_redact(args: argparse.Namespace) -> int:
    settings = _settings()
    dictionary = _dictionary(settings, args.dictionary)
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
    elif args.text is not None:
        text = args.text
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        console.print("[blocked]Pass --text, --file, or pipe a prompt on stdin.[/]")
        return 3
    result = redact(text, Vault(), dictionary)
    AuditLog(settings.audit_log).write(
        "redact_preview",
        destination="cli",
        decision="preview",
        counts=result.counts,
    )
    if args.json:
        print(json.dumps({"redacted": result.redacted, "counts": result.counts}, ensure_ascii=False, indent=2))
    else:
        console.print("[muted]redacted prompt (placeholders only; originals stay in the local vault)[/]")
        console.print(Syntax(result.redacted, "text", theme="ansi_dark", word_wrap=True))
        if result.counts:
            table = Table(title="Replaced", show_header=True)
            table.add_column("Category")
            table.add_column("Count", justify="right")
            for category, count in sorted(result.counts.items()):
                table.add_row(category, str(count))
            console.print(table)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    settings = _settings()
    report = scan_target(args.target)
    AuditLog(settings.audit_log).write(
        "scan",
        destination="cli",
        decision=report.verdict if not report.error else "error",
        target=str(args.target)[:200],
        finding_count=len(report.findings),
        executed=False,
    )
    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        console.print(report.format_text(args.lang), markup=False)
        style = {"safe": "safe", "risky": "risky", "blocked": "blocked"}.get(report.verdict, "")
        if not report.error:
            console.print(f"[{style}]verdict: {report.verdict}[/]  [muted]exit {report.exit_code()}[/]")
    return report.exit_code()


def cmd_run(args: argparse.Namespace) -> int:
    settings = _settings()
    if not args.sandbox and not args.no_sandbox:
        console.print(
            "[blocked]Refusing to run untrusted code on the host.[/]\n"
            "Use [bold]--sandbox[/] (Docker/Podman, --network none) or, only for a snippet you trust, [bold]--no-sandbox[/]."
        )
        return 3
    if args.no_sandbox and not args.sandbox:
        console.print("[risky]--no-sandbox is a last resort for trusted files only. Prefer --sandbox.[/]")
        if not Path(args.file).is_file():
            console.print("[blocked]file not found[/]")
            return 3
        console.print("[blocked]v1 will not execute a snippet on the host. Install Docker or Podman and use --sandbox.[/]")
        AuditLog(settings.audit_log).write("run", destination="host", decision="blocked", reason="no-host-exec")
        return 3
    result = run_sandboxed(Path(args.file))
    AuditLog(settings.audit_log).write(
        "run",
        destination="sandbox" if result.available else "unavailable",
        decision="ran" if result.available and result.exit_code == 0 else "blocked",
        runtime=result.runtime,
    )
    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        console.print(result.message)
        if result.command:
            console.print("[muted]$ " + " ".join(result.command) + "[/]")
        if result.stdout:
            console.print(result.stdout)
        if result.stderr:
            console.print(result.stderr, style="blocked")
    if not result.available:
        return 3
    return result.exit_code if result.exit_code is not None else 3


def cmd_audit(args: argparse.Namespace) -> int:
    settings = _settings()
    rows = AuditLog(settings.audit_log).tail(args.limit)
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    if not rows:
        console.print("[muted]No audit entries yet.[/]")
        return 0
    table = Table(title=str(settings.audit_log))
    table.add_column("Time")
    table.add_column("Event")
    table.add_column("Destination")
    table.add_column("Decision")
    table.add_column("Counts")
    for row in rows:
        table.add_row(
            str(row.get("ts", "")),
            str(row.get("event", "")),
            str(row.get("destination", "")),
            str(row.get("decision", "")),
            json.dumps(row.get("counts", {}), ensure_ascii=False),
        )
    console.print(table)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    settings = _settings(backend=args.backend, port=args.port, bind=args.bind)
    if args.upstream:
        if settings.backend == "openai":
            settings.openai_base = args.upstream
        else:
            settings.ollama_base = args.upstream
    settings.validate_backend()
    import uvicorn

    from safevibe.web.app import create_app

    app = create_app(settings)
    console.print(
        f"SafeVibe v{__version__}  ·  http://{settings.bind}:{settings.port}\n"
        f"backend: {settings.backend} → {settings.upstream_base()}\n"
        "[muted]Loopback only. The vault never leaves this process.[/]"
    )
    uvicorn.run(app, host=settings.bind, port=settings.port, log_level="info")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safevibe",
        description="Local redaction proxy and static scanner for safer AI-assisted coding.",
    )
    parser.add_argument("--version", action="version", version=f"safevibe {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    redact_p = sub.add_parser("redact", help="Redact a prompt locally and print placeholders")
    redact_p.add_argument("--text", help="Prompt text")
    redact_p.add_argument("--file", help="Read the prompt from a file")
    redact_p.add_argument("--dictionary", help="Path to an organisation dictionary YAML")
    redact_p.add_argument("--json", action="store_true")
    redact_p.set_defaults(func=cmd_redact)

    scan_p = sub.add_parser("scan", help="Statically scan a path or git URL (never executes the target)")
    scan_p.add_argument("target", help="Local path or GitHub/git URL")
    scan_p.add_argument("--json", action="store_true")
    scan_p.add_argument("--lang", choices=("en", "ro"), default="en")
    scan_p.set_defaults(func=cmd_scan)

    run_p = sub.add_parser("run", help="Run a Python snippet in a no-network sandbox")
    run_p.add_argument("file", help="Path to a .py snippet")
    run_p.add_argument("--sandbox", action="store_true", help="Require Docker/Podman --network none")
    run_p.add_argument("--no-sandbox", action="store_true", help="Refused in v1; kept as an explicit flag")
    run_p.add_argument("--json", action="store_true")
    run_p.set_defaults(func=cmd_run)

    audit_p = sub.add_parser("audit", help="Show the local audit log")
    audit_p.add_argument("--limit", type=int, default=20)
    audit_p.add_argument("--json", action="store_true")
    audit_p.set_defaults(func=cmd_audit)

    serve_p = sub.add_parser("serve", help="Start the local UI and OpenAI-compatible proxy")
    serve_p.add_argument("--port", type=int, default=None)
    serve_p.add_argument("--bind", default=None, help="Loopback only (127.0.0.1 or ::1)")
    serve_p.add_argument("--backend", choices=("ollama", "openai"), default=None)
    serve_p.add_argument("--upstream", help="Override the upstream OpenAI-compatible base URL")
    serve_p.set_defaults(func=cmd_serve)

    ui_p = sub.add_parser("ui", help="Alias for serve")
    ui_p.add_argument("--port", type=int, default=None)
    ui_p.add_argument("--bind", default=None)
    ui_p.add_argument("--backend", choices=("ollama", "openai"), default=None)
    ui_p.add_argument("--upstream", default=None)
    ui_p.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
