"""Local FastAPI app: UI, preview APIs, and an OpenAI-compatible proxy."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from safevibe import __version__
from safevibe.audit import AuditLog
from safevibe.config import Settings
from safevibe.dictionary import DEFAULT_DICTIONARY_YAML, OrgDictionary
from safevibe.redact import redact, redact_messages, restore
from safevibe.sandbox import detect_runtime
from safevibe.scan import scan_target
from safevibe.vault import Vault

STATIC_DIR = Path(__file__).resolve().parent / "static"


class RedactRequest(BaseModel):
    text: str
    dictionary_yaml: str | None = None


class ScanRequest(BaseModel):
    target: str


class DictionaryRequest(BaseModel):
    yaml_text: str


def _dictionary_from(settings: Settings, yaml_text: str | None = None) -> OrgDictionary:
    if yaml_text:
        return OrgDictionary.from_yaml_text(yaml_text)
    if settings.dictionary and settings.dictionary.is_file():
        return OrgDictionary.load(settings.dictionary)
    return OrgDictionary.from_yaml_text(DEFAULT_DICTIONARY_YAML)


def create_app(settings: Settings | None = None, audit: AuditLog | None = None) -> FastAPI:
    settings = settings or Settings()
    settings.validate_backend()
    audit = audit or AuditLog(settings.audit_log)
    session_vault = Vault()
    dictionary_holder: dict[str, OrgDictionary] = {
        "current": _dictionary_from(settings),
    }
    dictionary_yaml = {"current": DEFAULT_DICTIONARY_YAML}

    app = FastAPI(title="SafeVibe", version=__version__, docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.audit = audit
    app.state.vault = session_vault

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {
            "ok": True,
            "version": __version__,
            "backend": settings.backend,
            "bind": settings.bind,
            "sandbox": detect_runtime() is not None,
        }

    @app.get("/api/config")
    def get_config() -> dict[str, Any]:
        return {
            "backend": settings.backend,
            "destination": settings.destination_name(),
            "upstream": settings.upstream_base(),
            "model": settings.model,
            "bind": settings.bind,
            "port": settings.port,
            "log_redacted_prompts": settings.log_redacted_prompts,
            "sandbox": detect_runtime(),
            "dictionary_yaml": dictionary_yaml["current"],
            "version": __version__,
        }

    @app.post("/api/redact")
    def api_redact(body: RedactRequest) -> dict[str, Any]:
        dictionary = _dictionary_from(settings, body.dictionary_yaml)
        result = redact(body.text, Vault(), dictionary)
        audit.write(
            "redact_preview",
            destination="local-preview",
            decision="preview",
            counts=result.counts,
        )
        # Never return the raw mapping of secrets to the browser.
        return {
            "redacted": result.redacted,
            "counts": result.counts,
            "placeholders": sorted(result.vault.known_placeholders()),
        }

    @app.post("/api/scan")
    def api_scan(body: ScanRequest) -> dict[str, Any]:
        # Remote git URLs are allowed; the fetch path never executes hooks.
        # Local paths must stay inside the workspace-ish area? For a local
        # workstation tool, the operator is expected to pass a path they chose.
        report = scan_target(body.target)
        audit.write(
            "scan",
            destination="local-scan",
            decision=report.verdict,
            target=str(body.target)[:200],
            finding_count=len(report.findings),
            executed=False,
        )
        return report.to_dict()

    @app.get("/api/audit")
    def api_audit(limit: int = 50) -> dict[str, Any]:
        return {"entries": audit.tail(max(1, min(limit, 200)))}

    @app.post("/api/dictionary")
    def api_dictionary(body: DictionaryRequest) -> dict[str, Any]:
        try:
            parsed = OrgDictionary.from_yaml_text(body.yaml_text)
        except Exception as exc:  # noqa: BLE001 — surface YAML errors to the UI
            raise HTTPException(status_code=400, detail=f"invalid dictionary: {exc}") from exc
        dictionary_holder["current"] = parsed
        dictionary_yaml["current"] = body.yaml_text
        audit.write("dictionary_updated", destination="local", decision="ok", counts={"entries": sum(len(v) for v in parsed.to_mapping().values())})
        return {"ok": True, "dictionary": parsed.to_mapping()}

    def _forward_headers() -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if settings.api_key:
            headers["Authorization"] = f"Bearer {settings.api_key}"
        return headers

    def _redact_payload(payload: dict[str, Any], vault: Vault) -> dict[str, Any]:
        dictionary = dictionary_holder["current"]
        body = dict(payload)
        if isinstance(body.get("messages"), list):
            body["messages"] = redact_messages(body["messages"], vault, dictionary)
        if isinstance(body.get("prompt"), str):
            body["prompt"] = redact(body["prompt"], vault, dictionary).redacted
        if isinstance(body.get("input"), str):
            body["input"] = redact(body["input"], vault, dictionary).redacted
        return body

    def _restore_response(data: dict[str, Any], vault: Vault) -> dict[str, Any]:
        choices = data.get("choices")
        if not isinstance(choices, list):
            return data
        new_choices = []
        for choice in choices:
            choice = dict(choice)
            if isinstance(choice.get("text"), str):
                choice["text"] = restore(choice["text"], vault)
            msg = choice.get("message")
            if isinstance(msg, dict):
                msg = dict(msg)
                if isinstance(msg.get("content"), str):
                    msg["content"] = restore(msg["content"], vault)
                if isinstance(msg.get("content"), list):
                    parts = []
                    for part in msg["content"]:
                        if isinstance(part, dict) and isinstance(part.get("text"), str):
                            part = dict(part)
                            part["text"] = restore(part["text"], vault)
                        parts.append(part)
                    msg["content"] = parts
                tool_calls = msg.get("tool_calls")
                if isinstance(tool_calls, list):
                    fixed = []
                    for call in tool_calls:
                        call = dict(call)
                        fn = call.get("function")
                        if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                            fn = dict(fn)
                            fn["arguments"] = restore(fn["arguments"], vault)
                            call["function"] = fn
                        fixed.append(call)
                    msg["tool_calls"] = fixed
                choice["message"] = msg
            new_choices.append(choice)
        data = dict(data)
        data["choices"] = new_choices
        return data

    @app.post("/v1/chat/completions")
    async def chat_completions(payload: dict[str, Any]) -> JSONResponse:
        if payload.get("stream"):
            raise HTTPException(
                status_code=400,
                detail="Streaming restore is not in v1. Call without stream=true.",
            )
        vault = Vault()
        redacted = _redact_payload(payload, vault)
        audit_fields: dict[str, Any] = {
            "destination": settings.destination_name(),
            "decision": "sent",
            "counts": vault.counts(),
        }
        if settings.log_redacted_prompts:
            audit_fields["redacted_prompt"] = json.dumps(redacted.get("messages", redacted.get("prompt", "")))[:4000]
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                upstream = await client.post(
                    f"{settings.upstream_base()}/chat/completions",
                    headers=_forward_headers(),
                    json=redacted,
                )
        except httpx.RequestError as exc:
            audit.write("proxy_error", **audit_fields, decision="blocked", error=type(exc).__name__)
            raise HTTPException(
                status_code=502,
                detail=(
                    f"upstream {settings.destination_name()} is unreachable at "
                    f"{settings.upstream_base()}. Start Ollama or set an explicit "
                    "SAFE_VIBE_BACKEND=openai with SAFE_VIBE_API_KEY."
                ),
            ) from exc
        if upstream.status_code >= 400:
            audit.write("proxy_error", **audit_fields, decision="blocked", error=f"upstream {upstream.status_code}")
            raise HTTPException(status_code=upstream.status_code, detail=upstream.text[:500])
        data = upstream.json()
        restored = _restore_response(data, vault)
        if vault.warnings:
            audit_fields["restore_warnings"] = len(vault.warnings)
        audit.write("proxy", **audit_fields)
        return JSONResponse(restored)

    @app.post("/v1/completions")
    async def completions(payload: dict[str, Any]) -> JSONResponse:
        payload = dict(payload)
        if "messages" not in payload and "prompt" in payload:
            # reuse the chat path's redaction; still call the completions endpoint
            pass
        if payload.get("stream"):
            raise HTTPException(status_code=400, detail="Streaming restore is not in v1.")
        vault = Vault()
        redacted = _redact_payload(payload, vault)
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                upstream = await client.post(
                    f"{settings.upstream_base()}/completions",
                    headers=_forward_headers(),
                    json=redacted,
                )
        except httpx.RequestError as exc:
            audit.write("proxy_error", destination=settings.destination_name(), decision="blocked", counts=vault.counts())
            raise HTTPException(status_code=502, detail=f"upstream unreachable: {exc}") from exc
        if upstream.status_code >= 400:
            raise HTTPException(status_code=upstream.status_code, detail=upstream.text[:500])
        restored = _restore_response(upstream.json(), vault)
        audit.write("proxy", destination=settings.destination_name(), decision="sent", counts=vault.counts())
        return JSONResponse(restored)

    @app.get("/v1/models")
    async def list_models() -> JSONResponse:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                upstream = await client.get(f"{settings.upstream_base()}/models", headers=_forward_headers())
            return JSONResponse(upstream.json(), status_code=upstream.status_code)
        except httpx.RequestError:
            return JSONResponse(
                {
                    "object": "list",
                    "data": [{"id": settings.model, "object": "model", "owned_by": settings.destination_name()}],
                }
            )

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    return app
