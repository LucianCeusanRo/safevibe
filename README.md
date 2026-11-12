<div align="center">

<div style="font-size:64px">🛡️</div>

# SafeVibe

**Keep secrets, infrastructure and personal data on the machine — even when you use an AI coding assistant.**

  <a href="https://github.com/LucianCeusanRo/safevibe/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/LucianCeusanRo/safevibe/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://safevibe-demo.vercel.app"><img alt="Live demo" src="https://img.shields.io/badge/live%20demo-safevibe--demo.vercel.app-4caf7a"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green.svg"></a>
  <img alt="Python 3.11+" src="https://img.shields.io/badge/language-Python%203.11%2B-blue">
  <a href="https://github.com/LucianCeusanRo/safevibe/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/LucianCeusanRo/safevibe?style=flat"></a>
  <a href="https://github.com/LucianCeusanRo/safevibe/commits/main"><img alt="Last commit" src="https://img.shields.io/github/last-commit/LucianCeusanRo/safevibe"></a>

[English](#-about) · [Română](#-română)

</div>

<p align="center"><img src="docs/screenshots/ui-redact-desktop.png" alt="SafeVibe redaction preview on the desktop UI" width="900"></p>

## 📑 Table of contents

- [📖 About](#-about)
- [⚠️ Limits (read this first)](#-limits-read-this-first)
- [✨ Features](#-features)
- [🧠 How it works](#-how-it-works)
- [⚡ Quick start](#-quick-start)
- [📚 Step-by-step tutorial](#-step-by-step-tutorial)
- [🖼️ Screenshots](#-screenshots)
- [🔧 Configuration](#-configuration)
- [🗂️ Project structure](#-project-structure)
- [❓ FAQ](#-faq)
- [🗺️ Roadmap](#-roadmap)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [🇷🇴 Română](#-română)
- [👤 Author](#-author)

## 📖 About

SafeVibe is a **local** toolkit for people who want to use AI-assisted coding (“vibe coding”) without quietly sending API keys, internal hostnames, private addresses or personal identifiers to a cloud model — and without installing an untrusted GitHub skill, MCP server, editor extension or package on a work machine.

It does **not** replace a proper security review, a classified-information process, or a human reading the model’s output. It sits on `127.0.0.1`: a reversible redaction proxy, a static pre-install scanner, an optional no-network sandbox, a switch to a local Ollama model, and a local audit log.

All sample identifiers in this repository are **synthetic** (including a made-up CNP with a valid checksum, a demo CUI, and AWS’s official example access key). They do not belong to a real person, company or institution.

**Live demo** (browser-only, synthetic sample data; not the self-hosted proxy): [safevibe-demo.vercel.app](https://safevibe-demo.vercel.app)

- **Used for:** checking a prompt before it leaves the workstation; pointing Cursor / Continue / a script at a local OpenAI-compatible proxy; scanning a skill or package *before* `npm install`.
- **Helps:** public-sector and other cautious IT teams who want a bilingual (English / Romanian) tool they can run themselves, with honest limits written on the box.

## ⚠️ Limits (read this first)

The short version, which also appears at the top of the local UI:

**Pseudonymization is not encryption.** If you point the proxy at a cloud model, a transformed prompt still leaves the machine. SafeVibe is **not for classified data** or “secrete de serviciu”, is **not a certification**, and a green scan is **not** a guarantee of safety.

The full list — unknown placeholders fail closed, the vault is sensitive, scanners miss delayed payloads, no AI Act / GDPR / DNSC claim — is in [`docs/limits.md`](docs/limits.md) (EN + RO). Please read it.

## ✨ Features

- 🛡️ Local OpenAI-compatible proxy on loopback only (`127.0.0.1`). Cloud is never the silent default; Ollama is.
- 🔎 Reversible placeholders: secrets (Gitleaks-style rules), IPv4 / IPv6 / CIDR / MAC, internal hostnames and URLs, emails, Romanian phones, **CNP** and **CUI/CIF** with checksum validation, IBAN, plus a local organisation dictionary.
- 🧠 Restoration of placeholders in the model response. Unknown placeholders become `[UNMAPPED_PLACEHOLDER]` — v1 does not guess.
- 🧪 `safevibe scan <path|git-url>` — static only, hooks disabled on clone, never executes the target. Verdicts: **safe** / **risky** / **blocked** (`sigur` / `riscant` / `blocat`), with explanations in English and Romanian.
- 📦 Rules for agent `SKILL.md` files, MCP manifests, VS Code / Cursor extensions, npm `postinstall` hooks, and Python packaging hooks. Flags obfuscation, `curl | bash`, credential paths, hardcoded exfil URLs, prompt-injection phrasing, and committed binaries.
- 🐳 `safevibe run --sandbox` uses Docker or Podman with `--network none`, a read-only root, memory and PID limits. If neither runtime is installed, SafeVibe says so and refuses to run the snippet on the host.
- 📝 Local JSONL audit log of destinations, decisions and category counts — not raw secrets, CNPs or original prompts.
- 🌐 A small dark local web UI: redaction preview, scanner, audit log, dictionary editor, language toggle (EN / RO). No account, no telemetry.
- ⚙️ pytest suite and GitHub Actions CI.

## 🧠 How it works

```mermaid
flowchart LR
  subgraph workstation [Workstation]
    IDE[Editor / agent / CLI]
    UI[Local web UI]
    CLI[safevibe scan / run]
    PROXY[Loopback OpenAI-compatible proxy]
    DET[Detectors + org dictionary]
    VAULT[Local placeholder vault]
    AUDIT[Local audit log]
    SANDBOX[Optional Docker/Podman<br/>network none]
    OLLAMA[Ollama local model]
  end

  CLOUD[Cloud LLM — only if you opt in]
  GH[Untrusted skill / MCP / package]

  IDE -->|http://127.0.0.1:8787| PROXY
  UI --> PROXY
  PROXY --> DET --> VAULT
  PROXY --> AUDIT
  VAULT -->|restore| PROXY
  PROXY -->|redacted prompt only| CLOUD
  PROXY -->|nothing leaves| OLLAMA
  CLOUD -->|redacted completion| PROXY
  OLLAMA --> PROXY
  PROXY -->|restored completion| IDE
  CLI --> GH
  CLI -->|static read only| CLI
  CLI --> SANDBOX
```

Trust boundary: everything left of “Cloud LLM” stays on the machine. The vault never crosses that line. The upstream, if used, sees only placeholders plus whatever the detectors missed.

**Tech stack:** Python 3.11+, FastAPI, httpx, Pydantic settings, Rich, pytest, a vanilla HTML/CSS/JS UI with no build step and no CDN.

## ⚡ Quick start

```bash
git clone https://github.com/LucianCeusanRo/safevibe.git && cd safevibe
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Preview a demo prompt (synthetic data only)
safevibe redact --file examples/sample/prompt.txt

# Scan the bundled fixtures (nothing is executed)
safevibe scan examples/fixtures/clean-skill
safevibe scan examples/fixtures/risky-skill

# Local UI + proxy on 127.0.0.1:8787  (default backend: Ollama)
safevibe serve
```

Open [http://127.0.0.1:8787](http://127.0.0.1:8787). Point an editor’s OpenAI-compatible base URL at the same address when you are ready. Start Ollama first, or pass `--backend openai` and `SAFE_VIBE_API_KEY` *explicitly* if you accept that a redacted prompt will leave the machine.

## 📚 Step-by-step tutorial

### 1. Redact a prompt on the command line

```bash
pip install -e ".[dev]"
safevibe redact --file examples/sample/prompt.txt
```

The demo prompt contains a synthetic CNP, a demo CUI, lab IPs, an internal URL and obviously fake API keys. The command prints the redacted text and a table of categories. Originals are not written to the audit log.

<p><img src="docs/screenshots/cli-redact.png" alt="CLI redaction of the demo prompt" width="900"></p>

### 2. Scan before you install

```bash
safevibe scan examples/fixtures/risky-skill
safevibe scan examples/fixtures/blocked-npm --json
# a GitHub URL is cloned with hooks disabled, then read only:
# safevibe scan https://github.com/example/some-skill
```

`clean-skill` should come back **safe**. `risky-skill` and `blocked-npm` should come back **blocked**. Exit codes: `0` safe, `1` risky, `2` blocked, `3` error — useful in CI.

<p><img src="docs/screenshots/cli-scan.png" alt="CLI scan of the risky skill fixture" width="900"></p>

### 3. Use the local web UI

```bash
safevibe serve
```

1. Open [http://127.0.0.1:8787](http://127.0.0.1:8787).
2. Read the limits banner.
3. Click **Load demo prompt** (or **Încarcă promptul demo**), then **Redact locally**.
4. Switch to **Scan** and scan `examples/fixtures/risky-skill`.
5. Open **Audit** — you should see counts and destinations, not the raw CNP or API key.
6. Toggle **RO** / **EN** in the left rail.

<p>
<img src="docs/screenshots/ui-redact-desktop.png" alt="Desktop redaction UI" width="900">
<img src="docs/screenshots/ui-redact-mobile.png" alt="Mobile redaction UI" width="390">
</p>

### 4. Optional sandbox and local model

```bash
# Requires Docker or Podman, with python:3.12-slim already pulled.
safevibe run --sandbox examples/sample/snippet.py

# Local model (default): start Ollama, then
SAFE_VIBE_BACKEND=ollama safevibe serve
```

If Docker is not installed, the command says the sandbox is unavailable rather than running the snippet on the host.

## 🖼️ Screenshots

| View | Desktop | Mobile |
|------|---------|--------|
| Redaction preview | [ui-redact-desktop.png](docs/screenshots/ui-redact-desktop.png) | [ui-redact-mobile.png](docs/screenshots/ui-redact-mobile.png) |
| Scanner | [ui-scan-desktop.png](docs/screenshots/ui-scan-desktop.png) | [ui-scan-mobile.png](docs/screenshots/ui-scan-mobile.png) |
| Audit log | [ui-audit-desktop.png](docs/screenshots/ui-audit-desktop.png) | [ui-audit-mobile.png](docs/screenshots/ui-audit-mobile.png) |
| CLI | [cli-redact.png](docs/screenshots/cli-redact.png) · [cli-scan.png](docs/screenshots/cli-scan.png) | — |

These are real captures of the v1 UI and CLI, not mockups.

## 🔧 Configuration

Environment variables use the prefix `SAFE_VIBE_`. See [`.env.example`](.env.example).

| Variable | Default | Meaning |
|----------|---------|---------|
| `SAFE_VIBE_BACKEND` | `ollama` | `ollama` or `openai` (explicit) |
| `SAFE_VIBE_OLLAMA_BASE` | `http://127.0.0.1:11434/v1` | Local OpenAI-compatible base |
| `SAFE_VIBE_OPENAI_BASE` | `https://api.openai.com/v1` | Only used if backend is `openai` |
| `SAFE_VIBE_API_KEY` | empty | Forwarded to the upstream, never logged |
| `SAFE_VIBE_BIND` | `127.0.0.1` | Loopback only in v1 |
| `SAFE_VIBE_PORT` | `8787` | UI and proxy port |
| `SAFE_VIBE_DICTIONARY` | bundled demo YAML | Organisation dictionary path |
| `SAFE_VIBE_AUDIT_LOG` | `~/.local/share/safevibe/audit.jsonl` | Audit file |
| `SAFE_VIBE_LOG_REDACTED_PROMPTS` | `false` | Opt-in; still never stores raw secrets |

The dictionary file is YAML: `hostnames`, `suffixes`, `project_names`, `ticket_prefixes`. A filled dictionary with real names should stay on the workstation, not in a public repository.

In an editor, set the OpenAI base URL to `http://127.0.0.1:8787/v1` (Cursor, Continue, and similar). Streaming is not in v1; turn stream off.

## 🗂️ Project structure

```
src/safevibe/          # library, CLI, proxy, scanner, UI
examples/sample/       # synthetic demo prompt and snippet
examples/fixtures/     # clean / risky / blocked scan targets
docs/limits.md         # full non-claims (EN + RO)
docs/screenshots/      # real CLI and UI captures
tests/                 # pytest
.github/workflows/ci.yml
```

## ❓ FAQ

**Is this encryption?** No. It is reversible placeholder substitution on this machine. See [limits](#-limits-read-this-first).

**Can I paste classified data if I redact it first?** No.

**Does a `safe` scan mean the repo is clean?** No. It means no known static pattern fired.

**Will this certify me under the EU AI Act or GDPR?** No.

**Does the scanner run `postinstall` to “see what happens”?** No. That would be the risk it is meant to avoid.

**Why Romanian CNP and CUI?** Because those identifiers matter in a Romanian workplace and most generic PII tools do not ship a first-class pack for them.

**Is the bundled lab a real institution?** No. Names like Northpeak, Project Meridian and `lab.internal` are fictional training data.

## 🗺️ Roadmap

- Streaming restore for `/v1/chat/completions`
- Optional spaCy `ro` pass for free-text names (best-effort, clearly labelled)
- A small Rust CLI for the scanner, if the Python v1 earns its keep
- Broader install-hook coverage (more packaging ecosystems)
- Not planned: certification marks, telemetry, or a mode that “makes classified data safe for a cloud model”

## 🤝 Contributing

Issues and patches are welcome once the repository is public. Please do not open issues that include real secrets, real CNPs, or real internal hostnames — redact them first, or use the synthetic fixtures.

## 📄 License

[MIT](LICENSE) © 2026 Lucian Ceusan

## 🇷🇴 Română

<details>
<summary><b>Click pentru versiunea în limba română</b></summary>

**SafeVibe** este un set de unelte **locale** pentru cine vrea să folosească programarea asistată de AI („vibe coding”) fără să trimită pe tăcute chei API, hostname-uri interne, adrese private sau identificatori personali către un model în cloud — și fără să instaleze pe o mașină de lucru un skill, un server MCP, o extensie de editor sau un pachet neverificat.

Nu înlocuiește un control de securitate, un procedeu pentru informații clasificate sau citirea de către un om a rezultatului. Rulează pe `127.0.0.1`.

Toți identificatorii din exemple sunt **sintetici**. Nu aparțin unei persoane, unei firme sau unei instituții reale.

**Demo live** (doar în browser, date sintetice de exemplu; nu este proxy-ul self-hosted): [safevibe-demo.vercel.app](https://safevibe-demo.vercel.app)

#### Limite — citește mai întâi

**Pseudonimizarea nu este criptare.** Dacă îndrepți proxy-ul spre un model în cloud, un prompt transformat tot părăsește mașina. SafeVibe **nu este pentru date clasificate** sau secrete de serviciu, **nu este o certificare**, iar un scan verde **nu** este o garanție de siguranță.

Lista completă este în [`docs/limits.md`](docs/limits.md).

#### La ce folosește și pe cine ajută

- **Folosește la:** verificarea unui prompt înainte să plece de pe stație; îndreptarea editorului spre un proxy local compatibil OpenAI; scanarea unui skill sau a unui pachet *înainte* de `npm install`.
- **Ajută:** echipe IT din sectorul public și pe oricine vrea un instrument bilingv (română / engleză), rulat local, cu limitele scrise clar.

#### Funcționalități

- Proxy local compatibil OpenAI, doar pe loopback. Cloud-ul nu este ales pe tăcute; implicit este Ollama.
- Substituenți reversibili: secrete, IP-uri, hostname-uri interne, e-mailuri, telefoane, **CNP** și **CUI/CIF** cu cifră de control, IBAN, dicționar de organizație.
- Restaurare în răspuns; substituenții necunoscuți devin `[UNMAPPED_PLACEHOLDER]`.
- `safevibe scan` — doar analiză statică, fără a executa ținta. Verdict: **sigur** / **riscant** / **blocat**.
- `safevibe run --sandbox` cu Docker sau Podman (`--network none`). Dacă lipsește runtime-ul, spune asta și refuză să ruleze pe gazdă.
- Jurnal de audit local, fără secrete sau CNP-uri în clar.
- Interfață web locală, temă întunecată, comutator RO / EN, fără cont și fără telemetrie.

#### Tutorial

```bash
pip install -e ".[dev]"
safevibe redact --file examples/sample/prompt.txt
safevibe scan examples/fixtures/risky-skill
safevibe serve    # http://127.0.0.1:8787
```

În interfață: citește banda de limite, încarcă promptul demo, redactează, scanează `examples/fixtures/risky-skill`, deschide Auditul. Comută RO / EN din coloana stângă.

#### Tehnologii

Python 3.11+, FastAPI, httpx, Pydantic, Rich, pytest, HTML/CSS/JS fără pas de build și fără CDN.

</details>

## 👤 Author

Lucian Ceusan · [github.com/LucianCeusanRo](https://github.com/LucianCeusanRo)
