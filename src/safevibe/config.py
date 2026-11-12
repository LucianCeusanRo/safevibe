"""SafeVibe settings. Cloud is never a silent default."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

XDG_DATA = Path.home() / ".local" / "share" / "safevibe"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SAFE_VIBE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ollama is the default so a typo cannot silently ship prompts to a vendor.
    backend: str = Field(default="ollama", description="ollama or openai")
    bind: str = "127.0.0.1"
    port: int = 8787
    ollama_base: str = "http://127.0.0.1:11434/v1"
    openai_base: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "llama3.2"
    dictionary: Path | None = None
    audit_log: Path = Field(default_factory=lambda: XDG_DATA / "audit.jsonl")
    log_redacted_prompts: bool = False
    extra_suffixes: str = ""

    def extra_suffix_tuple(self) -> tuple[str, ...]:
        if not self.extra_suffixes.strip():
            return ()
        return tuple(s.strip() for s in self.extra_suffixes.split(",") if s.strip())

    def upstream_base(self) -> str:
        if self.backend == "openai":
            return self.openai_base.rstrip("/")
        return self.ollama_base.rstrip("/")

    def destination_name(self) -> str:
        return "ollama" if self.backend == "ollama" else "openai-compatible"

    def validate_backend(self) -> None:
        if self.backend not in {"ollama", "openai"}:
            raise ValueError("SAFE_VIBE_BACKEND must be 'ollama' or 'openai'")
        if self.bind not in {"127.0.0.1", "localhost", "::1"}:
            # Binding off-loopback would expose the vault on a network interface.
            raise ValueError("SafeVibe binds to loopback only in v1 (127.0.0.1 / ::1)")
