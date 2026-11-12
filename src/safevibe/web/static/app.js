const I18N = {
  en: {
    railNote: "Nothing in this UI is sent to a cloud model. Redaction and scanning run on this machine.",
    limitsTitle: "Limits — read this first",
    limitsBody: "Pseudonymization is not encryption. If you point the proxy at a cloud model, a transformed prompt still leaves the machine. SafeVibe is not for classified data or “secrete de serviciu”, is not a certification, and a green scan is not a guarantee of safety.",
    redactTitle: "Redaction preview",
    redactLead: "Paste a prompt. SafeVibe replaces secrets, addresses, Romanian CNP/CUI and dictionary terms with placeholders. The originals stay in a local vault and are not shown here.",
    inputLabel: "Input prompt",
    outputLabel: "Redacted output",
    loadSample: "Load demo prompt",
    runRedact: "Redact locally",
    scanTitle: "Static scanner",
    scanLead: "Point at a local folder, a skill, an MCP server, a VS Code extension or a package. SafeVibe only reads files. It never installs or runs the target.",
    scanTarget: "Path or git URL",
    runScan: "Scan",
    auditTitle: "Audit log",
    auditLead: "Local JSONL only. Counts and destinations, never raw secrets, CNPs or full original prompts.",
    refreshAudit: "Refresh",
    colTime: "Time", colEvent: "Event", colDest: "Destination", colDecision: "Decision", colCounts: "Counts",
    settingsTitle: "Settings",
    settingsLead: "The default backend is Ollama on this machine. A cloud upstream is never chosen silently.",
    dictLabel: "Organisation dictionary (YAML, kept in this session on the server)",
    saveDict: "Save dictionary",
    demoPrompt: `Please look at ticket INC-1042 on https://intranet.lab.internal/tickets/INC-1042.
The core switch core-sw-01.lab.internal (10.20.30.40) lost its uplink.
Jump host is noc-jump.local at 192.168.50.10, IPv6 fd00:feed::10, MAC 00:1A:2B:3C:4D:5E.
Contact: ana.demo@northpeak.example, phone +40 722 000 001.
Synthetic demo CNP (not a real person): 1900115100015.
Demo CUI: RO123456789. Demo IBAN: RO33EXMP0000000000000000.
Lab API key (not real): sk-proj-SAFE_VIBE_DEMO_NOT_A_REAL_SECRET_000000
AWS example key: AKIAIOSFODNN7EXAMPLE
This is for Project Meridian only.`,
  },
  ro: {
    railNote: "Nimic din această interfață nu este trimis către un model în cloud. Redactarea și scanarea rulează pe această mașină.",
    limitsTitle: "Limite — citește mai întâi",
    limitsBody: "Pseudonimizarea nu este criptare. Dacă îndrepți proxy-ul spre un model în cloud, un prompt transformat tot părăsește mașina. SafeVibe nu este pentru date clasificate sau secrete de serviciu, nu este o certificare, iar un scan verde nu este o garanție de siguranță.",
    redactTitle: "Previzualizare redactare",
    redactLead: "Lipește un prompt. SafeVibe înlocuiește secrete, adrese, CNP/CUI și termenii din dicționar cu substituenți. Originalele rămân într-un seif local și nu sunt afișate aici.",
    inputLabel: "Prompt de intrare",
    outputLabel: "Ieșire redactată",
    loadSample: "Încarcă promptul demo",
    runRedact: "Redactează local",
    scanTitle: "Scaner static",
    scanLead: "Indică un folder local, un skill, un server MCP, o extensie VS Code sau un pachet. SafeVibe doar citește fișiere. Nu instalează și nu rulează ținta.",
    scanTarget: "Cale sau URL git",
    runScan: "Scanează",
    auditTitle: "Jurnal de audit",
    auditLead: "Doar JSONL local. Numărători și destinații, niciodată secrete, CNP-uri sau prompturi originale complete.",
    refreshAudit: "Reîncarcă",
    colTime: "Ora", colEvent: "Eveniment", colDest: "Destinație", colDecision: "Decizie", colCounts: "Numărători",
    settingsTitle: "Setări",
    settingsLead: "Backend-ul implicit este Ollama pe această mașină. Un upstream în cloud nu este ales pe tăcute.",
    dictLabel: "Dicționar de organizație (YAML, păstrat în această sesiune pe server)",
    saveDict: "Salvează dicționarul",
    demoPrompt: `Te rog uită-te la tichetul INC-1042 de la https://intranet.lab.internal/tickets/INC-1042.
Switch-ul de bază core-sw-01.lab.internal (10.20.30.40) și-a pierdut uplink-ul.
Jump host: noc-jump.local la 192.168.50.10, IPv6 fd00:feed::10, MAC 00:1A:2B:3C:4D:5E.
Contact: ana.demo@northpeak.example, telefon +40 722 000 001.
CNP demo sintetic (nu este o persoană reală): 1900115100015.
CUI demo: RO123456789. IBAN demo: RO33EXMP0000000000000000.
Cheie API de laborator (nu este reală): sk-proj-SAFE_VIBE_DEMO_NOT_A_REAL_SECRET_000000
Cheie exemplu AWS: AKIAIOSFODNN7EXAMPLE
Doar pentru Project Meridian.`,
  },
};

let lang = localStorage.getItem("safevibe-lang") || "en";

function applyLang() {
  const pack = I18N[lang] || I18N.en;
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    if (pack[key]) el.textContent = pack[key];
  });
  document.querySelectorAll(".lang-btn").forEach((btn) => {
    btn.classList.toggle("is-on", btn.dataset.lang === lang);
  });
}

function switchTab(name) {
  document.querySelectorAll(".tab").forEach((btn) => {
    const on = btn.dataset.tab === name;
    btn.classList.toggle("is-on", on);
    btn.setAttribute("aria-selected", on ? "true" : "false");
  });
  document.querySelectorAll(".panel").forEach((panel) => {
    const on = panel.id === `panel-${name}`;
    panel.classList.toggle("is-on", on);
    panel.hidden = !on;
  });
  if (name === "audit") refreshAudit();
  if (name === "settings") loadConfig();
}

async function redact() {
  const text = document.getElementById("prompt-in").value;
  const res = await fetch("/api/redact", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
  const data = await res.json();
  document.getElementById("prompt-out").value = data.redacted || data.detail || "";
  const box = document.getElementById("redact-counts");
  box.innerHTML = "";
  Object.entries(data.counts || {}).forEach(([k, v]) => {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.textContent = `${k} × ${v}`;
    box.appendChild(chip);
  });
}

async function scan() {
  const target = document.getElementById("scan-target").value.trim();
  const verdictEl = document.getElementById("scan-verdict");
  const out = document.getElementById("scan-out");
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target }),
  });
  const data = await res.json();
  verdictEl.hidden = false;
  out.hidden = false;
  const v = data.verdict || "error";
  verdictEl.className = `verdict ${v}`;
  const ro = data.verdict_ro ? `  (${data.verdict_ro})` : "";
  verdictEl.textContent = lang === "ro"
    ? `Verdict: ${(v || "").toUpperCase()}${ro} · nimic nu a fost executat`
    : `Verdict: ${(v || "").toUpperCase()}${ro} · nothing was executed`;
  if (data.error) {
    out.textContent = data.error;
    return;
  }
  if (!data.findings || !data.findings.length) {
    out.textContent = lang === "ro"
      ? "Nu s-a declanșat niciun tipar cunoscut.\nAsta nu înseamnă că ținta este inofensivă."
      : "No known static pattern fired.\nThat does not mean the target is harmless.";
    return;
  }
  out.textContent = data.findings.map((f) => {
    const why = lang === "ro" ? f.why_ro : f.why_en;
    const loc = f.line ? `${f.path}:${f.line}` : f.path;
    return `[${f.severity}] ${f.rule}  ${loc}\n  ${why}\n  » ${f.excerpt}`;
  }).join("\n\n");
}

async function refreshAudit() {
  const res = await fetch("/api/audit?limit=50");
  const data = await res.json();
  const tbody = document.querySelector("#audit-table tbody");
  tbody.innerHTML = "";
  (data.entries || []).slice().reverse().forEach((row) => {
    const tr = document.createElement("tr");
    const counts = row.counts ? JSON.stringify(row.counts) : "";
    [row.ts, row.event, row.destination, row.decision, counts].forEach((val) => {
      const td = document.createElement("td");
      td.textContent = val || "";
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

async function loadConfig() {
  const res = await fetch("/api/config");
  const data = await res.json();
  const dl = document.getElementById("config-dl");
  dl.innerHTML = "";
  const rows = [
    ["backend", data.backend],
    ["destination", data.destination],
    ["upstream", data.upstream],
    ["model", data.model],
    ["bind", `${data.bind}:${data.port}`],
    ["sandbox", data.sandbox || "unavailable"],
    ["version", data.version],
  ];
  rows.forEach(([k, v]) => {
    const dt = document.createElement("dt");
    dt.textContent = k;
    const dd = document.createElement("dd");
    dd.textContent = v;
    dl.append(dt, dd);
  });
  if (data.dictionary_yaml) {
    document.getElementById("dict-yaml").value = data.dictionary_yaml;
  }
}

async function saveDict() {
  const yaml_text = document.getElementById("dict-yaml").value;
  const res = await fetch("/api/dictionary", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ yaml_text }),
  });
  const status = document.getElementById("dict-status");
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    status.style.color = "var(--blocked)";
    status.textContent = err.detail || "error";
    return;
  }
  status.style.color = "var(--safe)";
  status.textContent = lang === "ro" ? "Dicționar salvat pe serverul local." : "Dictionary saved on the local server.";
}

document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});
document.querySelectorAll(".lang-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    lang = btn.dataset.lang;
    localStorage.setItem("safevibe-lang", lang);
    applyLang();
  });
});
document.getElementById("btn-sample").addEventListener("click", () => {
  document.getElementById("prompt-in").value = (I18N[lang] || I18N.en).demoPrompt;
});
document.getElementById("btn-redact").addEventListener("click", () => redact().catch((err) => {
  document.getElementById("prompt-out").value = String(err);
}));
document.getElementById("btn-scan").addEventListener("click", () => scan().catch((err) => {
  document.getElementById("scan-out").hidden = false;
  document.getElementById("scan-out").textContent = String(err);
}));
document.getElementById("btn-audit").addEventListener("click", () => refreshAudit());
document.getElementById("btn-dict").addEventListener("click", () => saveDict());

applyLang();
document.getElementById("scan-target").value = "examples/fixtures/risky-skill";
