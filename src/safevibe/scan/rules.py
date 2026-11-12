"""Static rules for skills, MCP servers, editor extensions and packages.

The scanner only reads files. It never imports, installs, or executes the
target. A 'safe' verdict means no known static pattern fired — not 'this is
harmless'.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

# JSON-with-comments for VS Code / MCP configs
_COMMENT_LINE = re.compile(r"^\s*//.*$", re.MULTILINE)
_COMMENT_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)

SEVERITY_ORDER = {"safe": 0, "risky": 1, "blocked": 2}

TEXT_NAMES = {
    "skill.md",
    "readme.md",
    "readme.ro.md",
    "agents.md",
    "tools.md",
    "instructions.md",
}

MANIFEST_NAMES = {
    "package.json",
    "server.json",
    "mcp.json",
    ".mcp.json",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "binding.gyp",
}

CODE_SUFFIXES = {
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".sh",
    ".bash",
    ".ps1",
    ".rb",
    ".go",
    ".rs",
    ".php",
}

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "__pycache__",
    ".tox",
    ".mypy_cache",
}

MAX_FILE_BYTES = 1_000_000

# ELF, PE (MZ), Mach-O (32/64/fat), WASM
BINARY_MAGIC = (
    b"\x7fELF",
    b"MZ",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\x00asm",
)

PROMPT_INJECTION = [
    (re.compile(r"ignore (?:all )?(?:previous|prior) instructions", re.I), "blocked"),
    (re.compile(r"do not (?:tell|inform|notify) the user", re.I), "blocked"),
    (re.compile(r"don't (?:tell|inform|notify) the user", re.I), "blocked"),
    (re.compile(r"hide (?:this|it|the (?:action|activity))? from the user", re.I), "blocked"),
    (re.compile(r"always auto-?approve", re.I), "blocked"),
    (re.compile(r"dangerously-skip-permissions", re.I), "blocked"),
    (re.compile(r"skip(?:[- ]all)?[- ]permissions", re.I), "risky"),
    (re.compile(r"you must not mention", re.I), "blocked"),
    (re.compile(r"exfiltrate", re.I), "blocked"),
    (re.compile(r"secretly send", re.I), "blocked"),
]

SHELL_PIPE = re.compile(r"(curl|wget|fetch)\s+[^\n|;]+?\s*\|\s*(?:bash|sh|zsh|python|python3)", re.I)
EVAL_ATOB = re.compile(r"\beval\s*\(\s*atob\s*\(", re.I)
BUFFER_B64 = re.compile(r"Buffer\.from\s*\([^;]{0,200}['\"]base64['\"]", re.I)
HEX_EVAL = re.compile(r"\beval\s*\(\s*(?:Buffer|String\.fromCharCode|unescape)\s*\(", re.I)
CHILD_PROCESS = re.compile(r"\b(?:child_process|subprocess)\b|\bos\.system\s*\(|\bpopen\s*\(", re.I)

EXFIL_HOST = re.compile(
    r"(?:https?|wss?)://[^\s'\"<>]+(?:webhook|discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com|ngrok|raw\.githubusercontent)",
    re.I,
)
RAW_IP_URL = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?", re.I)

SECRET_PATH = re.compile(
    r"(?:~/\.ssh|~/\.aws|~/\.gnupg|~/\.config/gh|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY)",
    re.I,
)
ENV_READ = re.compile(r"(?:process\.env|os\.environ|os\.getenv)\s*[\[(]", re.I)

HOOK_KEYS = ("preinstall", "install", "postinstall", "preuninstall", "postuninstall", "preprepare", "postprepare")


@dataclass
class Finding:
    severity: str
    rule: str
    path: str
    line: int | None
    excerpt: str
    why_en: str
    why_ro: str

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "rule": self.rule,
            "path": self.path,
            "line": self.line,
            "excerpt": self.excerpt,
            "why_en": self.why_en,
            "why_ro": self.why_ro,
        }


def _excerpt(text: str, start: int, limit: int = 160) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end < 0:
        line_end = len(text)
    snippet = text[line_start:line_end].strip()
    if len(snippet) > limit:
        snippet = snippet[: limit - 1] + "…"
    return snippet


def _line_no(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _loads_jsonish(text: str) -> dict | list | None:
    stripped = _COMMENT_BLOCK.sub("", _COMMENT_LINE.sub("", text))
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, (dict, list)) else None


def _is_binary(path: Path) -> bool:
    try:
        head = path.read_bytes()[:8]
    except OSError:
        return False
    return any(head.startswith(magic) for magic in BINARY_MAGIC)


def iter_scan_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os_walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git")]
        for name in filenames:
            files.append(Path(dirpath) / name)
    return files


def os_walk(root: Path):
    import os

    return os.walk(root)


def scan_tree(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_scan_files(root):
        rel = _rel(root, path)
        if _is_binary(path):
            findings.append(
                Finding(
                    severity="blocked",
                    rule="committed-binary",
                    path=rel,
                    line=None,
                    excerpt="binary file (ELF, PE, Mach-O or WASM magic)",
                    why_en="A compiled executable is committed in the tree. This is a common malware drop pattern.",
                    why_ro="Un executabil compilat este inclus în arbore. Este un tipar frecvent de livrare a malware-ului.",
                )
            )
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > MAX_FILE_BYTES:
            findings.append(
                Finding(
                    severity="risky",
                    rule="oversized-file",
                    path=rel,
                    line=None,
                    excerpt=f"file is {size} bytes; skipped content scan",
                    why_en="The file is larger than 1 MB, so its contents were not inspected.",
                    why_ro="Fișierul are peste 1 MB, deci conținutul nu a fost inspectat.",
                )
            )
            continue
        if path.suffix.lower() not in CODE_SUFFIXES | {
            ".md",
            ".json",
            ".toml",
            ".yml",
            ".yaml",
            ".cfg",
            ".txt",
        } and path.name.lower() not in MANIFEST_NAMES | TEXT_NAMES:
            # Still peek at install-ish names
            if path.name.lower() not in {"skill.md", "dockerfile"}:
                continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(_scan_text(root, path, text))
        if path.name.lower() in {"package.json", "server.json", "mcp.json", ".mcp.json"}:
            findings.extend(_scan_manifest(root, path, text))
        if path.name.lower() in {"pyproject.toml", "setup.py", "setup.cfg"}:
            findings.extend(_scan_python_packaging(root, path, text))
    return _dedupe(findings)


def _rel(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _scan_text(root: Path, path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    rel = _rel(root, path)
    lower_name = path.name.lower()
    in_skill_docs = lower_name in TEXT_NAMES or "skill" in lower_name

    def emit(severity: str, rule: str, index: int, why_en: str, why_ro: str) -> None:
        findings.append(
            Finding(
                severity=severity,
                rule=rule,
                path=rel,
                line=_line_no(text, index),
                excerpt=_excerpt(text, index),
                why_en=why_en,
                why_ro=why_ro,
            )
        )

    if in_skill_docs or lower_name.endswith((".md", ".json")):
        for regex, severity in PROMPT_INJECTION:
            for match in regex.finditer(text):
                emit(
                    severity,
                    "prompt-injection",
                    match.start(),
                    "Instruction text tries to override the agent's rules, hide activity from the user, or auto-approve tools.",
                    "Textul de instrucțiuni încearcă să treacă peste regulile agentului, să ascundă activitatea față de utilizator sau să auto-aprobe uneltele.",
                )

    for match in SHELL_PIPE.finditer(text):
        emit(
            "blocked",
            "curl-pipe-shell",
            match.start(),
            "The file pipes a downloaded script straight into a shell. This is a classic install-time malware pattern.",
            "Fișierul trimite un script descărcat direct într-un shell. Este un tipar clasic de malware la instalare.",
        )
    for match in EVAL_ATOB.finditer(text):
        emit(
            "blocked",
            "obfuscation",
            match.start(),
            "eval(atob(...)) decodes hidden JavaScript at runtime.",
            "eval(atob(...)) decodează JavaScript ascuns în timpul rulării.",
        )
    for match in BUFFER_B64.finditer(text):
        emit(
            "risky",
            "obfuscation",
            match.start(),
            "Base64-decoded buffers in source can hide a payload.",
            "Buffere decode-ate din Base64 în sursă pot ascunde un payload.",
        )
    for match in HEX_EVAL.finditer(text):
        emit(
            "blocked",
            "obfuscation",
            match.start(),
            "Dynamic eval of constructed data is a common obfuscation trick.",
            "eval dinamic pe date construite este un truc frecvent de ofuscare.",
        )
    for match in EXFIL_HOST.finditer(text):
        emit(
            "blocked",
            "exfil-host",
            match.start(),
            "A webhook, Telegram bot, pastebin or similar exfil endpoint is hardcoded.",
            "Un webhook, bot de Telegram, pastebin sau un endpoint similar de exfiltrare este scris în clar.",
        )
    for match in RAW_IP_URL.finditer(text):
        emit(
            "risky",
            "raw-ip-url",
            match.start(),
            "An HTTP URL points at a raw IP address, which is unusual for a legitimate package.",
            "Un URL HTTP indică o adresă IP brută, lucru neobișnuit pentru un pachet legitim.",
        )
    for match in SECRET_PATH.finditer(text):
        emit(
            "risky",
            "credential-access",
            match.start(),
            "The file refers to SSH keys, cloud credentials or well-known API-key environment variables.",
            "Fișierul face referire la chei SSH, credențiale cloud sau variabile de mediu cunoscute pentru chei API.",
        )
    return findings


def _scan_manifest(root: Path, path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    rel = _rel(root, path)
    data = _loads_jsonish(text)
    if not isinstance(data, dict):
        return findings

    scripts = data.get("scripts") or {}
    if isinstance(scripts, dict):
        for hook in HOOK_KEYS:
            if hook in scripts:
                command = str(scripts[hook])
                severity = "blocked" if SHELL_PIPE.search(command) or EVAL_ATOB.search(command) else "risky"
                if hook in {"prepare", "preprepare", "postprepare"} and severity == "risky":
                    severity = "risky"
                findings.append(
                    Finding(
                        severity=severity,
                        rule="install-hook",
                        path=rel,
                        line=_line_no(text, text.find(hook)),
                        excerpt=f"{hook}: {command[:140]}",
                        why_en=f"package.json defines a {hook} script that runs on install, before you can review the code.",
                        why_ro=f"package.json definește un script {hook} care rulează la instalare, înainte să poți revizui codul.",
                    )
                )

    # VS Code / Cursor extension?
    engines = data.get("engines") or {}
    if isinstance(engines, dict) and "vscode" in engines:
        main = str(data.get("main") or "")
        findings.append(
            Finding(
                severity="risky",
                rule="vscode-extension",
                path=rel,
                line=None,
                excerpt=f"VS Code extension entry: {main or '(missing main)'}",
                why_en="This looks like a VS Code / Cursor extension. Review the publisher and the entry script before installing from a marketplace or a VSIX.",
                why_ro="Pare o extensie VS Code / Cursor. Verifică editorul (publisher) și scriptul de intrare înainte de instalare din marketplace sau dintr-un VSIX.",
            )
        )

    # MCP server manifest hints
    if path.name.lower() in {"server.json", "mcp.json", ".mcp.json"} or "mcpServers" in data or data.get("name") and data.get("tools"):
        pass
    return findings


def _scan_python_packaging(root: Path, path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    rel = _rel(root, path)
    lowered = text.lower()
    hook_markers = (
        "cmdclass",
        "post-install",
        "post_install",
        "custominstall",
        "os.system",
        "subprocess",
    )
    if path.name.lower() == "setup.py" and any(m in lowered for m in hook_markers):
        findings.append(
            Finding(
                severity="risky",
                rule="python-install-hook",
                path=rel,
                line=None,
                excerpt=_excerpt(text, 0),
                why_en="setup.py appears to run custom code at install time.",
                why_ro="setup.py pare să ruleze cod personalizat la instalare.",
            )
        )
    if "[project]" in lowered and re.search(r"post(?:-|_)?install|cmdclass", lowered):
        findings.append(
            Finding(
                severity="risky",
                rule="python-install-hook",
                path=rel,
                line=None,
                excerpt="packaging metadata mentions an install hook",
                why_en="Python packaging metadata refers to an install-time hook.",
                why_ro="Metadatele de împachetare Python menționează un hook la instalare.",
            )
        )
    return findings


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for item in findings:
        key = (item.severity, item.rule, item.path, item.line, item.excerpt)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def scan_path(path: Path) -> list[Finding]:
    """Scan a file or a directory tree. Never executes anything."""
    path = path.resolve()
    if path.is_file():
        import shutil
        import tempfile

        wrap = Path(tempfile.mkdtemp(prefix="safevibe-file-"))
        try:
            shutil.copy2(path, wrap / path.name)
            findings = scan_tree(wrap)
            for item in findings:
                item.path = path.name
            return _dedupe(findings)
        finally:
            shutil.rmtree(wrap, ignore_errors=True)
    return scan_tree(path)
