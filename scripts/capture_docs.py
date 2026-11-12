#!/usr/bin/env python3
"""Capture real CLI and UI screenshots into docs/screenshots/."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots"
OUT.mkdir(parents=True, exist_ok=True)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _run_cli(args: list[str], env: dict[str, str]) -> str:
    proc = subprocess.run(
        args,
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    return (proc.stdout or "") + (proc.stderr or "")


def _terminal_html(title: str, body: str) -> str:
    escaped = (
        body.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
  html,body {{ margin:0; background:#0b0f14; }}
  .term {{
    margin: 24px auto; width: 960px; background:#0e131a;
    border: 1px solid #243041; box-shadow: 0 12px 40px rgba(0,0,0,.45);
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    color: #e6edf3;
  }}
  .bar {{ background:#121821; color:#8b9aab; padding:8px 14px; font-size:12px;
          border-bottom:1px solid #243041; letter-spacing:.04em; }}
  .dot {{ display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:6px; }}
  pre {{ margin:0; padding:18px 20px 24px; white-space:pre-wrap; font-size:13px; line-height:1.5; }}
</style></head>
<body>
  <div class="term">
    <div class="bar">
      <span class="dot" style="background:#c45050"></span>
      <span class="dot" style="background:#d4a054"></span>
      <span class="dot" style="background:#5ea88a"></span>
      {title}
    </div>
    <pre>{escaped}</pre>
  </div>
</body></html>"""


def _shot_html(page, html: str, dest: Path, width: int = 1020, height: int = 640) -> None:
    page.set_viewport_size({"width": width, "height": height})
    page.set_content(html, wait_until="load")
    page.locator(".term").screenshot(path=str(dest))
    print(f"wrote {dest}")


def main() -> None:
    env = os.environ.copy()
    env["SAFE_VIBE_AUDIT_LOG"] = str(ROOT / "docs" / "screenshots" / ".capture-audit.jsonl")
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    python = sys.executable
    redact_out = _run_cli(
        [python, "-m", "safevibe.cli", "redact", "--file", "examples/sample/prompt.txt"],
        env,
    )
    scan_out = _run_cli(
        [python, "-m", "safevibe.cli", "scan", "examples/fixtures/risky-skill"],
        env,
    )
    redact_text = "$ safevibe redact --file examples/sample/prompt.txt\n\n" + redact_out
    scan_text = "$ safevibe scan examples/fixtures/risky-skill\n\n" + scan_out

    port = _free_port()
    server = subprocess.Popen(
        [python, "-m", "safevibe.cli", "serve", "--port", str(port)],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(40):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                    break
            except OSError:
                time.sleep(0.15)
        else:
            raise RuntimeError("SafeVibe server did not start")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            _shot_html(page, _terminal_html("safevibe  ·  redact", redact_text), OUT / "cli-redact.png")
            _shot_html(page, _terminal_html("safevibe  ·  scan", scan_text), OUT / "cli-scan.png", height=820)

            # Desktop + mobile UI
            for width, height, suffix in ((1280, 900, "desktop"), (390, 844, "mobile")):
                page.set_viewport_size({"width": width, "height": height})
                page.goto(url, wait_until="networkidle", timeout=30_000)
                page.wait_for_selector("text=SafeVibe")
                page.evaluate("localStorage.setItem('safevibe-lang','en')")
                page.reload(wait_until="networkidle")
                page.click("#btn-sample")
                page.click("#btn-redact")
                page.wait_for_selector(".chip")
                page.screenshot(path=str(OUT / f"ui-redact-{suffix}.png"), full_page=True)
                print(f"wrote {OUT / f'ui-redact-{suffix}.png'}")

                page.click("button[data-tab='scan']")
                page.fill("#scan-target", "examples/fixtures/risky-skill")
                page.click("#btn-scan")
                page.wait_for_selector("#scan-verdict:not([hidden])")
                page.wait_for_function("() => document.querySelector('#scan-verdict').textContent.includes('BLOCKED')")
                page.screenshot(path=str(OUT / f"ui-scan-{suffix}.png"), full_page=True)
                print(f"wrote {OUT / f'ui-scan-{suffix}.png'}")

                page.click("button[data-tab='audit']")
                page.wait_for_selector("#audit-table tbody tr")
                page.screenshot(path=str(OUT / f"ui-audit-{suffix}.png"), full_page=True)
                print(f"wrote {OUT / f'ui-audit-{suffix}.png'}")

            browser.close()
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
        capture_log = ROOT / "docs" / "screenshots" / ".capture-audit.jsonl"
        if capture_log.exists():
            capture_log.unlink()


if __name__ == "__main__":
    main()
