/**
 * The conductor. Runs the four phases in order over a RunContext, keeps the
 * live meter ticking, persists the case, and emits phase events to the dashboard.
 * The agent never self-grades — phases call the deterministic verdict layer.
 */
import type { CaseStore, EventBus, LogStore } from "../types.js";
import { emptyCase } from "../types.js";
import { newMeter } from "../agent/llm.js";
import { makeContext, meters, type RunContext } from "./context.js";
import { phaseDiscover } from "../phases/discover.js";
import { phaseRemediate } from "../phases/remediate.js";
import { phaseDetective } from "../phases/detective.js";
import { openPullRequest, restoreTargetSource } from "../tools/pr.js";
import { notifyDone } from "../tools/notify.js";

export interface RunDeps {
  bus: EventBus;
  caseStore: CaseStore;
  logStore: LogStore;
  targetDir?: string;
}

export async function runFull(repo: string, deps: RunDeps, trigger: "manual" | "push" | "variant" = "manual") {
  // Repeatable rehearsals: a manual run starts from the clean baseline. A push/variant
  // run keeps the changed code (that's the continuous-defense trigger).
  if (trigger === "manual" && deps.targetDir) {
    const ok = await restoreTargetSource(deps.targetDir);
    if (ok) console.log("[ward] target restored to clean baseline");
  }
  // Each run is a fresh case so findings/meters don't accumulate across runs.
  const caseFile = emptyCase(repo);
  caseFile.runs.push({ trigger, started: new Date().toISOString(), result: "running" });

  const ctx = makeContext({ case: caseFile, bus: deps.bus, logStore: deps.logStore, meter: newMeter(), targetDir: deps.targetDir });
  const ticker = setInterval(() => ctx.pushMeter(), 1000);

  try {
    await phase(ctx, "Discover", () => phaseDiscover(ctx));
    await phase(ctx, "Remediate", () => phaseRemediate(ctx));
    await phase(ctx, "Intelligence", () => phaseDetective(ctx));
    // Continuous is wired by the watcher (index.ts); a manual run reports readiness.
    ctx.emit({ type: "phase", phase: "Continuous", status: "start" });
    ctx.log("Continuous watch armed: re-runs on git push / new variant.");
    ctx.emit({ type: "phase", phase: "Continuous", status: "done" });

    const pr = await openPullRequest(ctx.case, ctx.targetDir);
    ctx.log(pr.summary);

    ctx.case.meters = meters(ctx);
    ctx.case.runs[ctx.case.runs.length - 1].result = "complete";
    await deps.caseStore.save(ctx.case);
    await notifyDone(ctx.case, pr.prUrl).then((sent) => sent && ctx.log("Notification email sent."));

    clearInterval(ticker);
    ctx.emit({ type: "done", meters: ctx.case.meters, prUrl: pr.prUrl });
    return { case: ctx.case, pr };
  } catch (e) {
    clearInterval(ticker);
    ctx.log(`Run error: ${(e as Error).message}`);
    ctx.case.runs[ctx.case.runs.length - 1].result = `error: ${(e as Error).message}`;
    await deps.caseStore.save(ctx.case).catch(() => {});
    throw e;
  }
}

async function phase(ctx: RunContext, name: string, fn: () => Promise<void>) {
  if (ctx.steps > (Number(process.env.WARD_STEP_CAP) || 60)) {
    ctx.log(`Step cap reached; skipping ${name}.`);
    return;
  }
  ctx.emit({ type: "phase", phase: name, status: "start" });
  ctx.log(`── Phase: ${name} ──`);
  await fn();
  ctx.pushMeter();
  ctx.emit({ type: "phase", phase: name, status: "done" });
}
