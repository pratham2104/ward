/**
 * Phase 3 — Intelligence ("Detective"). Cut off from the attack notes, the agent
 * reconstructs the incident timeline from the LOG STORE ALONE. Deterministic code
 * then scores coverage vs ground truth; unrecovered steps are detection BLIND
 * SPOTS (Class-2 findings). For each real step it emits a detection rule, and the
 * missing log becomes part of the fix set.
 */
import type { RunContext } from "../orchestrator/context.js";
import type { Finding, LogEvent, TimelineStep } from "../types.js";
import { timelineCoverage } from "../verdicts/index.js";
import { fetchTargetLogs } from "../tools/probe.js";
import { askJSON } from "../agent/ask.js";
import { mkId } from "./util.js";

const DET_SYS = `You are Ward's Detective. You did NOT see the attack. You are given ONLY raw log rows
from the application. Reconstruct, step by step, what happened in plain language — what entered, what
the app/bot did, what data moved, and where it went, as far as the logs allow. Do not invent steps the
logs don't support. Output JSON {"timeline":[{"step":"...","evidence":"<log row ref>"}]}.`;

export async function phaseDetective(ctx: RunContext): Promise<void> {
  ctx.bumpStep();
  // Use the gapped logs captured at probe time (reload-proof). These deliberately
  // omit the outbound rows — that gap is the blind spot to discover.
  let logs: LogEvent[] = (ctx.capturedLogs as LogEvent[]) ?? [];
  if (logs.length === 0) {
    const runIds = new Set<string>();
    for (const f of ctx.case.findings) if (f.evidence.probeRef) runIds.add(f.evidence.probeRef);
    for (const id of runIds) logs = logs.concat((await fetchTargetLogs(id)) as LogEvent[]);
    if (logs.length === 0) logs = (await fetchTargetLogs("*")) as LogEvent[];
  }
  ctx.log(`Detective reading ${logs.length} log row(s) — blind to its own attack notes.`);

  // Let the agent narrate what it can infer from the logs (shown on the dashboard).
  if (logs.length > 0) {
    try {
      const out = await askJSON<{ timeline: { step: string; evidence: string }[] }>(
        DET_SYS,
        "Log rows:\n" + logs.map((l) => `${l.ts} ${l.actor} ${l.eventType}: ${l.payloadSummary}`).join("\n"),
        ctx.meter,
      );
      for (const s of out.timeline ?? []) ctx.log(`  detective: ${s.step}`);
    } catch (e) {
      ctx.log(`Reconstruction narrative failed: ${(e as Error).message}`);
    }
  }

  // DETERMINISTIC coverage: a ground-truth step is "recovered" iff the gapped logs
  // actually contain a row of its expected signal type. The outbound/exfil step has
  // no log row (the deliberate gap) → it is the blind spot.
  const ground = ctx.case.groundTruthTimeline;
  const logSignals = new Set(logs.map((l) => (l as any).eventType));
  const matched: TimelineStep[] = [];
  const missed: TimelineStep[] = [];
  for (const g of ground) {
    if (g.signalExpected && logSignals.has(g.signalExpected)) matched.push({ ...g, fromLogs: true });
    else missed.push(g);
  }
  const coverage = ground.length ? matched.length / ground.length : 0;
  ctx.case.reconstructedTimeline = matched;
  ctx.case.coverageScore = coverage;
  ctx.emit({ type: "timeline", ground, reconstructed: matched, coverage });
  ctx.log(`Coverage from logs alone: ${Math.round(coverage * 100)}% (${matched.length}/${ground.length} steps).`);

  // Blind spots = ground-truth steps the logs could not show.
  for (const m of missed) {
    const f: Finding = {
      id: mkId("B"),
      layer: "code",
      technique: `detection blind spot: "${m.step}" not recorded`,
      location: "application logging",
      severity: "high",
      status: "found",
      frameworks: { owasp_llm: [], cwe: [], atlas: [], attack: ["TA0010"] },
      evidence: { detail: `expected signal: ${m.signalExpected ?? "n/a"}`, verdict: "attack step invisible in logs" },
      blindSpot: true,
    };
    ctx.case.findings.push(f);
    ctx.emit({ type: "finding", finding: f });
    ctx.case.detectionRules.push({
      forFinding: f.id,
      pattern: `alert when an outbound action (send_email/fetch_url) carries customer/canary data`,
      mapsTo: "MITRE ATT&CK T1041 (Exfiltration)",
    });
    ctx.log(`Blind spot found: ${m.step} → added detection rule.`);
  }
  if (missed.length === 0) ctx.log("Logs recorded every attack step — no blind spot this run.");
}
