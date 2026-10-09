/**
 * Ward mission-control dashboard — SSE server.
 *
 * startDashboard(bus, port?) stands up an Express server that:
 *   - GET /         -> the single hand-coded page (public/index.html + app.js + styles.css)
 *   - GET /events   -> a Server-Sent Events stream: replays bus.history() on connect,
 *                      then pushes every new WardEvent as it is emitted.
 *
 * The dashboard is a pure renderer. It never drives the agent; it only subscribes
 * to the EventBus the orchestrator publishes to (see src/types.ts -> WardEvent).
 */
import express from "express";
import { createServer, type Server } from "node:http";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { readFileSync, readdirSync } from "node:fs";
import { createHmac, timingSafeEqual } from "node:crypto";
import { config } from "../config";
import type { EventBus, WardEvent } from "../types";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, "public");

const esc = (s: unknown): string =>
  String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));

/** Pick the real run's case file (prefer case.target.json; skip test fixtures). */
function latestCaseFile(): string {
  const dir = resolve(process.cwd(), "reports");
  const preferred = join(dir, "case.target.json");
  try { readFileSync(preferred); return preferred; } catch { /* fall through */ }
  const files = readdirSync(dir).filter((f) => f.startsWith("case.") && f.endsWith(".json") && !f.includes("ward-test"));
  if (!files.length) throw new Error("no case report yet — run Ward first");
  return join(dir, files.sort().at(-1)!);
}

/** Render a human-readable run report from the case file the stores wrote. */
function renderReport(): string {
  const c = JSON.parse(readFileSync(latestCaseFile(), "utf8"));
  const findings = c.findings ?? [];
  const failed = findings.filter((f: any) => f.status === "failed");
  const verdict = failed.length ? "NEEDS HUMAN REVIEW" : "APPROVED FOR MERGE";
  const vclass = failed.length ? "warn" : "ok";
  const cov = Math.round((c.coverageScore ?? 0) * 100);
  const m = c.meters ?? {};
  const fw = (f: any) => [...(f.frameworks?.owasp_llm ?? []), ...(f.frameworks?.cwe ?? []), ...(f.frameworks?.atlas ?? []), ...(f.frameworks?.attack ?? [])].join(" · ") || "—";
  const sev = (s: string) => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
  const st = (s: string) => `<span class="st ${esc(s)}">${esc(s)}</span>`;
  const rows = findings.map((f: any) => `
    <tr>
      <td>${esc(f.id)}</td><td>${esc(f.layer)}</td><td>${esc(f.technique)}</td>
      <td class="mono">${esc(f.location || "—")}</td><td>${sev(f.severity)}</td><td>${st(f.status)}</td>
      <td class="fw">${esc(fw(f))}</td>
    </tr>${f.fix?.diff ? `<tr class="diffrow"><td></td><td colspan="6"><pre>${esc(f.fix.diff)}</pre></td></tr>` : ""}`).join("");
  const tl = (c.reconstructedTimeline ?? []).map((s: any) =>
    `<li class="${s.fromLogs ? "seen" : "blind"}">${s.fromLogs ? "✓" : "✗"} ${esc(s.step)} <span class="exp">(${esc(s.signalExpected)})</span>${s.fromLogs ? "" : ' <b class="blindtag">BLIND SPOT</b>'}</li>`).join("");
  const rules = (c.detectionRules ?? []).map((r: any) => `<li><code>${esc(r.pattern)}</code> → ${esc(r.mapsTo)}</li>`).join("") || "<li>—</li>";
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ward · Run Report</title><style>
:root{--bg:#0b0f17;--card:#141a24;--line:#232c3a;--ink:#e6edf3;--mut:#8b98a8;--ok:#36d399;--warn:#fbbd23;--red:#f87272;--acc:#5b9dff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto}
.wrap{max-width:960px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--mut);margin:0 0 20px}
.verdict{display:inline-block;padding:8px 14px;border-radius:8px;font-weight:700;letter-spacing:.3px}
.verdict.ok{background:rgba(54,211,153,.12);color:var(--ok);border:1px solid rgba(54,211,153,.35)}
.verdict.warn{background:rgba(251,189,35,.12);color:var(--warn);border:1px solid rgba(251,189,35,.35)}
.meters{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0 24px}
.meter{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px;min-width:120px}
.meter .k{color:var(--mut);font-size:12px}.meter .v{font-size:18px;font-weight:700}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:16px 0}
.card h2{font-size:14px;text-transform:uppercase;letter-spacing:.6px;color:var(--mut);margin:0 0 12px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.4px}
.mono,.fw{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}.fw{color:var(--acc)}
.sev{padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700;text-transform:capitalize}
.sev.critical{background:rgba(248,114,114,.15);color:var(--red)}.sev.high{background:rgba(251,189,35,.15);color:var(--warn)}
.sev.medium{background:rgba(91,157,255,.15);color:var(--acc)}.sev.low{background:rgba(139,152,168,.15);color:var(--mut)}
.st{font-size:12px;font-weight:700}.st.verified{color:var(--ok)}.st.rejected{color:var(--mut)}.st.failed{color:var(--red)}
.diffrow pre{margin:0;background:#0d1320;border:1px solid var(--line);border-radius:8px;padding:10px;font-size:12px;overflow:auto;white-space:pre-wrap}
ul{margin:0;padding-left:4px;list-style:none}li{padding:6px 0;border-bottom:1px solid var(--line)}
li.blind{color:var(--warn)}.blindtag{background:rgba(251,189,35,.18);color:var(--warn);padding:1px 7px;border-radius:5px;font-size:11px;margin-left:6px}
.exp{color:var(--mut);font-size:12px}.cov{font-size:28px;font-weight:800}.cov small{font-size:13px;color:var(--mut);font-weight:500}
a.back{color:var(--acc);text-decoration:none}code{background:#0d1320;padding:2px 6px;border-radius:5px;font-size:12px}
</style></head><body><div class="wrap">
<a class="back" href="/">← live dashboard</a>
<h1>Ward · Run Report</h1>
<p class="sub">Target: <b>${esc(c.target ?? "—")}</b> · autonomous security run</p>
<div class="verdict ${vclass}">${verdict}</div>
<div class="meters">
  <div class="meter"><div class="k">Wall-clock</div><div class="v">${esc(m.wallClockS ?? "—")}s</div></div>
  <div class="meter"><div class="k">Cost</div><div class="v">$${Number(m.costUsd ?? 0).toFixed(3)}</div></div>
  <div class="meter"><div class="k">Agent steps</div><div class="v">${esc(m.steps ?? "—")}</div></div>
  <div class="meter"><div class="k">Findings</div><div class="v">${findings.length}</div></div>
  <div class="meter"><div class="k">Log coverage</div><div class="v">${cov}%</div></div>
</div>
<div class="card"><h2>Findings &amp; remediation</h2>
<table><thead><tr><th>ID</th><th>Layer</th><th>Technique</th><th>Location</th><th>Severity</th><th>Status</th><th>Frameworks</th></tr></thead>
<tbody>${rows || '<tr><td colspan="7">no findings</td></tr>'}</tbody></table></div>
<div class="card"><h2>Detective — attack reconstructed from logs alone</h2>
<p class="cov">${cov}% <small>of the attack recovered from logs · the blind spot is what monitoring missed</small></p>
<ul>${tl || "<li>—</li>"}</ul></div>
<div class="card"><h2>Detection rules added</h2><ul>${rules}</ul></div>
</div></body></html>`;
}

export interface DashboardHandle {
  server: Server;
  port: number;
  url: string;
  close: () => Promise<void>;
}

/**
 * Start the dashboard. Returns a handle once the socket is listening.
 * `port` defaults to config.dashboardPort (4100).
 */
/** A verified push to the watched repo's default branch. */
export interface PushInfo {
  repo: string;
  ref: string;
  sha: string;
  pusher: string;
  message: string;
}

export interface DashboardOptions {
  /** Called (fire-and-forget) for each verified push to the default branch. */
  onPush?: (push: PushInfo) => void;
}

/** GitHub signs the raw body with HMAC-SHA256 in X-Hub-Signature-256. */
function verifySignature(raw: Buffer, header: string | undefined, secret: string): boolean {
  if (!secret || !header?.startsWith("sha256=")) return false;
  const expected = Buffer.from("sha256=" + createHmac("sha256", secret).update(raw).digest("hex"));
  const got = Buffer.from(header);
  return got.length === expected.length && timingSafeEqual(got, expected);
}

export function startDashboard(bus: EventBus, port: number = config.dashboardPort, opts: DashboardOptions = {}): Promise<DashboardHandle> {
  const app = express();

  // GitHub push webhook → autonomous run. Registered before static so the raw body survives.
  app.post("/webhook/github", express.raw({ type: "*/*", limit: "2mb" }), (req, res) => {
    const raw: Buffer = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    if (!verifySignature(raw, req.get("x-hub-signature-256"), config.githubWebhookSecret)) {
      return res.status(401).json({ ok: false, error: "bad signature" });
    }
    const event = req.get("x-github-event");
    if (event === "ping") return res.json({ ok: true, pong: true });
    if (event !== "push") return res.status(202).json({ ok: true, ignored: `event ${event}` });

    let p: any;
    try { p = JSON.parse(raw.toString("utf8")); } catch { return res.status(400).json({ ok: false, error: "bad json" }); }
    const repo = p?.repository?.full_name ?? "";
    const defaultRef = `refs/heads/${p?.repository?.default_branch ?? "main"}`;
    // Only the watched repo's default branch. Ward's own ward/fixes-* branches must not re-trigger it.
    if (config.githubRepo && repo !== config.githubRepo) return res.status(202).json({ ok: true, ignored: `repo ${repo}` });
    if (p.ref !== defaultRef || p.deleted) return res.status(202).json({ ok: true, ignored: `ref ${p.ref}` });

    const push: PushInfo = {
      repo,
      ref: p.ref,
      sha: String(p.after ?? ""),
      pusher: p?.pusher?.name ?? "unknown",
      message: String(p?.head_commit?.message ?? "").split("\n")[0],
    };
    console.log(`[webhook] push ${repo}@${push.sha.slice(0, 7)} by ${push.pusher}: ${push.message}`);
    opts.onPush?.(push);
    res.status(202).json({ ok: true, accepted: push.sha });
  });

  // Static single page + assets. index.html is served at GET / by express.static.
  app.use(express.static(PUBLIC_DIR));

  // Explicit root so GET / always resolves even if static index is disabled.
  app.get("/", (_req, res) => {
    res.sendFile(join(PUBLIC_DIR, "index.html"));
  });

  // Human-readable run report, rendered from the latest case file.
  app.get("/report", (_req, res) => {
    try {
      res.type("html").send(renderReport());
    } catch (e: any) {
      res.status(503).type("html").send(`<body style="background:#0b0f17;color:#e6edf3;font-family:system-ui;padding:40px"><h2>Report not ready</h2><p>${esc(e?.message ?? e)}</p><a style="color:#5b9dff" href="/">← dashboard</a></body>`);
    }
  });

  // Server-Sent Events: the live stream the page consumes.
  app.get("/events", (req, res) => {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      // Disable proxy buffering so events flush immediately (nginx et al.).
      "X-Accel-Buffering": "no",
    });
    res.flushHeaders?.();

    const send = (e: WardEvent) => {
      res.write(`data: ${JSON.stringify(e)}\n\n`);
    };

    // 1) Replay everything that already happened so a late-joining browser catches up.
    const history = bus.history();
    res.write(`event: hello\ndata: ${JSON.stringify({ replay: history.length })}\n\n`);
    for (const e of history) send(e);

    // 2) Subscribe to the live stream.
    const unsubscribe = bus.subscribe(send);

    // 3) Keep-alive comment every 15s so intermediaries don't drop an idle connection.
    const keepAlive = setInterval(() => res.write(`: ping ${Date.now()}\n\n`), 15_000);

    req.on("close", () => {
      clearInterval(keepAlive);
      unsubscribe();
      res.end();
    });
  });

  // Lightweight health probe (handy for the orchestrator / smoke tests).
  app.get("/healthz", (_req, res) => res.json({ ok: true, events: bus.history().length }));

  const server = createServer(app);

  return new Promise<DashboardHandle>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, () => {
      server.off("error", reject);
      const url = `http://localhost:${port}`;
      console.log(`[dashboard] live at ${url}  (SSE at ${url}/events)`);
      resolve({
        server,
        port,
        url,
        close: () =>
          new Promise<void>((res, rej) => server.close((err) => (err ? rej(err) : res()))),
      });
    });
  });
}
