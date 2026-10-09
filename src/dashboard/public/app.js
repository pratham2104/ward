/* ===========================================================================
   Ward Mission Control — client renderer.
   Pure consumer of the SSE /events stream. One handler per WardEvent.type.
   WardEvent union is defined in src/types.ts; this file renders it verbatim.
   =========================================================================== */
"use strict";

const $ = (id) => document.getElementById(id);

/* ---- phase rail -------------------------------------------------------- */
const PHASE_ORDER = ["discover", "remediate", "intelligence", "continuous"];
// Map whatever the orchestrator calls a phase onto one of the four rail slots.
function phaseKey(name) {
  const n = String(name || "").toLowerCase();
  if (n.startsWith("disc")) return "discover";
  if (n.startsWith("remed") || n.startsWith("fix") || n.startsWith("patch")) return "remediate";
  if (n.startsWith("intel") || n.startsWith("detect")) return "intelligence";
  if (n.startsWith("contin") || n.startsWith("watch")) return "continuous";
  return n;
}
function setPhase(name, status) {
  const key = phaseKey(name);
  const idx = PHASE_ORDER.indexOf(key);
  document.querySelectorAll(".phase").forEach((el) => {
    const k = el.dataset.phase;
    const i = PHASE_ORDER.indexOf(k);
    el.classList.remove("active");
    if (status === "done" && k === key) {
      el.classList.add("done");
    } else if (status === "start" && k === key) {
      el.classList.add("active");
      el.classList.remove("done");
    }
    // Everything before the active phase is implicitly done.
    if (idx >= 0 && i >= 0 && i < idx) el.classList.add("done");
  });
}

/* ---- meters ------------------------------------------------------------ */
function fmtTime(s) {
  s = Math.max(0, Math.round(s || 0));
  const m = Math.floor(s / 60);
  const r = s % 60;
  return `${m}m ${String(r).padStart(2, "0")}s`;
}
function setMeters(m) {
  if (!m) return;
  if (typeof m.steps === "number") $("mSteps").textContent = m.steps;
  if (typeof m.wallClockS === "number") $("mTime").textContent = fmtTime(m.wallClockS);
  if (typeof m.costUsd === "number") $("mCost").textContent = "$" + m.costUsd.toFixed(3);
}

/* ---- log --------------------------------------------------------------- */
const logEl = $("log");
function addLog(line) {
  const div = document.createElement("div");
  div.className = "log-line";
  const text = String(line ?? "");
  // Light semantic coloring from keywords — purely cosmetic.
  const low = text.toLowerCase();
  if (/(verified|passed|green|0 reproduce|clean|confirmed)/.test(low)) div.classList.add("good");
  else if (/(leak|exfil|canary|fail|breach|vuln|reproduc)/.test(low)) div.classList.add("bad");
  else if (/(phase|probe|scan|replay|detect|patch|fix)/.test(low)) div.classList.add("evt");
  const ts = new Date().toLocaleTimeString("en-US", { hour12: false });
  div.innerHTML = `<span class="ts">${ts}</span>${escapeHtml(text)}`;
  logEl.appendChild(div);
  // Auto-scroll to newest (bottom) if the user is already near the bottom.
  logEl.scrollTop = logEl.scrollHeight;
}

/* ---- findings + attack chain ------------------------------------------ */
const findings = new Map(); // id -> { finding, cardEl, chipEl }
// Reproduction state per finding id, kept OUTSIDE the finding object so a
// re-emitted (patched) finding can't wipe it. Drives the replay scoreboard.
const reproState = new Map(); // id -> { reproduced: bool, lastPass: bool|null }

// A finding represents a data leak/exfil (flash the chain red) when its evidence
// shows data escaping — a canary that left, an exfil/steal action — or it is
// critical severity. A mere framework tag (e.g. a logging-gap tactic) is not a leak.
function isLeak(f) {
  const hay = `${f.technique} ${JSON.stringify(f.evidence || {})}`.toLowerCase();
  return f.severity === "critical" || /(exfil|leak|canary|steal|data.?loss|exfiltrat)/.test(hay);
}

function sevDot(sev) {
  const c = { low: "#8b9bb0", medium: "#ffb020", high: "#ff4d5e", critical: "#ff2d55" }[sev] || "#8b9bb0";
  return `<span class="sev" style="background:${c}"></span>`;
}

function renderChainChip(f) {
  const laneId = f.layer === "agent" ? "agentSteps" : "codeSteps";
  const lane = $(laneId);
  lane.querySelector(".layer-empty")?.remove();
  let chip = findings.get(f.id)?.chipEl;
  if (!chip) {
    chip = document.createElement("div");
    chip.className = "step-chip";
    lane.appendChild(chip);
  }
  const leak = isLeak(f);
  chip.className = "step-chip" + (leak ? " leak" : "");
  chip.innerHTML = `${sevDot(f.severity)}<span class="tech">${escapeHtml(f.technique)}</span>`;
  if (leak) {
    // Light the cross-layer connector: a leak means the chain reached exfiltration.
    $("chainLink").classList.add("hot");
    addLog(`⚠ data leak confirmed via "${f.technique}" (${f.layer} layer) — canary escaped`);
  }
  return chip;
}

function tagRow(fr, blindSpot) {
  const groups = [
    ["owasp_llm", fr.owasp_llm],
    ["cwe", fr.cwe],
    ["atlas", fr.atlas],
    ["attack", fr.attack],
  ];
  let html = "";
  for (const [kind, arr] of groups) {
    for (const v of arr || []) html += `<span class="tag tag-${kind}">${escapeHtml(v)}</span>`;
  }
  if (blindSpot) html += `<span class="tag tag-blindspot">BLIND SPOT</span>`;
  return html;
}

function renderDiff(diff) {
  // Color unified-diff lines. Everything is escaped first.
  return escapeHtml(diff)
    .split("\n")
    .map((ln) => {
      if (/^\+(?!\+\+)/.test(ln)) return `<span class="add">${ln}</span>`;
      if (/^-(?!--)/.test(ln)) return `<span class="del">${ln}</span>`;
      if (/^(@@|diff |index |\+\+\+|---)/.test(ln)) return `<span class="hdr">${ln}</span>`;
      return ln;
    })
    .join("\n");
}

function renderFinding(f) {
  $("findingsEmpty")?.remove();
  let rec = findings.get(f.id);
  let card = rec?.cardEl;
  if (!card) {
    card = document.createElement("div");
    card.className = "finding";
    $("findings").appendChild(card);
  }
  const fr = f.frameworks || { owasp_llm: [], cwe: [], atlas: [], attack: [] };
  card.innerHTML = `
    <div class="finding-top">
      <span class="finding-id">${escapeHtml(f.id)}</span>
      <span class="finding-tech">${escapeHtml(f.technique)}</span>
      <span class="sev-badge sev-${f.severity}">${f.severity}</span>
      <span class="status-badge status-${f.status}" data-status>${f.status}</span>
    </div>
    <div class="finding-body">
      <div class="finding-loc">◦ <b>${escapeHtml(f.location || "—")}</b> · ${f.layer} layer</div>
      <div class="tags">${tagRow(fr, f.blindSpot)}</div>
      ${
        f.fix && f.fix.diff
          ? `<div class="diff-cap">fix diff${f.fix.attempts ? ` · attempt ${f.fix.attempts}` : ""}</div><pre class="diff">${renderDiff(f.fix.diff)}</pre>`
          : ""
      }
    </div>`;

  const chip = renderChainChip(f);
  findings.set(f.id, { finding: f, cardEl: card, chipEl: chip });
  $("findingCount").textContent = findings.size;
  recomputeScore();
}

function setVerdict(findingId, verdict, pass) {
  const rec = findings.get(findingId);
  addLog(`verdict · ${findingId}: ${verdict} → ${pass ? "PASS" : "FAIL"}`);
  // Track reproduction by id: a failing verdict = the exploit reproduced at that
  // moment; the latest verdict decides whether it still reproduces after the fix.
  const rs = reproState.get(findingId) || { reproduced: false, lastPass: null };
  if (!pass) rs.reproduced = true;
  rs.lastPass = pass;
  reproState.set(findingId, rs);
  if (rec) {
    // Verdicts advance status. A passing remediation verdict = verified; failing = failed.
    const f = rec.finding;
    if (pass) f.status = f.status === "found" ? "proven" : "verified";
    else f.status = f.status === "found" ? "proven" : "failed";
    const badge = rec.cardEl.querySelector("[data-status]");
    if (badge) {
      badge.textContent = f.status;
      badge.className = `status-badge status-${f.status}`;
    }
    // A verified fix means the leak no longer reproduces: cool the chip.
    if (pass && rec.chipEl) rec.chipEl.classList.remove("leak");
  }
  recomputeScore();
}

/* ---- replay scoreboard (derived from verdicts/statuses) ---------------- */
function recomputeScore() {
  const states = [...reproState.values()];
  // "before" = exploits that actually reproduced (had a failing verdict).
  const reproduced = states.filter((s) => s.reproduced);
  const before = reproduced.length;
  if (!before) return;
  // "after" = of those, the ones whose latest verdict still fails.
  const after = reproduced.filter((s) => s.lastPass === false).length;
  const verifiedCount = reproduced.filter((s) => s.lastPass === true).length;
  $("scoreBefore").textContent = before;
  // Only show "after" once at least one remediation verdict has landed.
  const remediated = [...findings.values()].some((r) =>
    ["patched", "verified", "failed"].includes(r.finding.status)
  );
  if (remediated) {
    $("scoreAfter").textContent = after;
    const v = $("scoreVerdict");
    if (after === 0 && verifiedCount > 0) {
      v.textContent = `✓ ${verifiedCount} fixed & verified — 0 reproduce · tests green`;
      v.classList.add("win");
    } else {
      v.textContent = `${after} still reproduce`;
      v.classList.remove("win");
    }
  }
}

/* ---- detective timeline ------------------------------------------------ */
function renderTimeline(ground, reconstructed, coverage) {
  const g = ground || [];
  const r = reconstructed || [];
  const reconSteps = new Set(r.map((s) => (s.step || "").trim().toLowerCase()));

  const gl = $("tlGround");
  gl.innerHTML = "";
  for (const s of g) {
    const matched = reconSteps.has((s.step || "").trim().toLowerCase());
    const li = document.createElement("li");
    li.className = matched ? "match" : "miss";
    li.innerHTML = `<span class="tl-t">${fmtClock(s.t)}</span>${escapeHtml(s.step)}`;
    gl.appendChild(li);
  }
  if (!g.length) gl.innerHTML = `<li class="tl-empty">—</li>`;

  const rl = $("tlRecon");
  rl.innerHTML = "";
  for (const s of r) {
    const li = document.createElement("li");
    li.className = "match";
    li.innerHTML = `<span class="tl-t">${fmtClock(s.t)}</span>${escapeHtml(s.step)}`;
    rl.appendChild(li);
  }
  if (!r.length) rl.innerHTML = `<li class="tl-empty">—</li>`;

  const pct = Math.round((typeof coverage === "number" ? coverage : 0) * (coverage <= 1 ? 100 : 1));
  $("coverageVal").textContent = pct + "%";
  $("coveragePill").hidden = false;
  addLog(`detective: reconstructed ${r.length}/${g.length} steps — coverage ${pct}%`);
}
function fmtClock(iso) {
  try {
    return new Date(iso).toLocaleTimeString("en-US", { hour12: false });
  } catch {
    return String(iso || "");
  }
}

/* ---- continuous + done ------------------------------------------------- */
function showContinuous(trigger) {
  const b = $("continuousBanner");
  b.hidden = false;
  $("continuousText").textContent = `trigger fired → ${trigger}. Waking agent, no human in the loop…`;
  addLog(`CONTINUOUS: ${trigger} — autonomous loop re-armed`);
}
function showDone(meters, prUrl) {
  setMeters(meters);
  const m = meters || {};
  $("doneHeadline").textContent = `Done in ${fmtTime(m.wallClockS)} · $${(m.costUsd || 0).toFixed(3)}`;
  const report = $("btnReport");
  report.href = "/healthz"; // stand-in; the real report URL is wired by the orchestrator
  report.setAttribute("onclick", "");
  const pr = $("btnPr");
  if (prUrl) {
    pr.href = prUrl;
    pr.classList.remove("disabled");
  } else {
    pr.classList.add("disabled");
    pr.textContent = "PR pending";
  }
  $("doneOverlay").hidden = false;
  addLog(`✓ run complete — ${fmtTime(m.wallClockS)} · $${(m.costUsd || 0).toFixed(3)}`);
}

/* ---- event dispatch ---------------------------------------------------- */
function handle(ev) {
  switch (ev.type) {
    case "phase":
      setPhase(ev.phase, ev.status);
      addLog(`phase · ${ev.phase} ${ev.status === "start" ? "▶ started" : "■ done"}`);
      break;
    case "log":
      addLog(ev.line);
      break;
    case "meter":
      setMeters(ev.meters);
      break;
    case "finding":
      renderFinding(ev.finding);
      break;
    case "verdict":
      setVerdict(ev.findingId, ev.verdict, ev.pass);
      break;
    case "timeline":
      renderTimeline(ev.ground, ev.reconstructed, ev.coverage);
      break;
    case "continuous":
      showContinuous(ev.trigger);
      break;
    case "done":
      showDone(ev.meters, ev.prUrl);
      break;
    default:
      // Unknown event types are ignored (forward-compatible).
      break;
  }
}

/* ---- SSE wiring -------------------------------------------------------- */
function connect() {
  const conn = $("conn");
  const es = new EventSource("/events");
  es.addEventListener("hello", () => {
    conn.className = "conn live";
    $("connText").textContent = "live";
  });
  es.onopen = () => {
    conn.className = "conn live";
    $("connText").textContent = "live";
  };
  es.onmessage = (m) => {
    try {
      handle(JSON.parse(m.data));
    } catch (err) {
      console.error("bad event", err, m.data);
    }
  };
  es.onerror = () => {
    conn.className = "conn dead";
    $("connText").textContent = "reconnecting";
    // EventSource auto-reconnects; nothing else to do.
  };
}

/* ---- util -------------------------------------------------------------- */
function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

connect();
