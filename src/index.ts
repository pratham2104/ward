/**
 * Ward entry point. Wires the event bus, stores, dashboard, and the run.
 * Usage:
 *   npm run target          # (separately) start the vulnerable helpdesk bot
 *   npm run dev -- --watch   # start Ward, run once, then re-run on GitHub push (webhook) or target edits
 */
import { resolve } from "node:path";
import { watch } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { config, reportConfig } from "./config.js";
import { makeEventBus } from "./stores/eventBus.js";
import { makeCaseStore } from "./stores/caseStore.js";
import { makeLogStore } from "./stores/logStore.js";
import { runFull } from "./orchestrator/orchestrator.js";
import type { CaseStore, EventBus, LogStore } from "./types.js";
import type { PushInfo } from "./dashboard/server.js";

const pExecFile = promisify(execFile);

const REPO = process.env.WARD_TARGET_REPO || "target";
const TARGET_DIR = resolve(process.cwd(), "target");
const WATCH = process.argv.includes("--watch");

async function makeCaseStoreSafe(repo: string): Promise<CaseStore> {
  try {
    return await makeCaseStore(repo);
  } catch (e) {
    console.warn(`[index] case store cloud backend refused (${(e as Error).message}); falling back to local JSON`);
    (config as any).mongoUri = "";
    return makeCaseStore(repo);
  }
}

async function startDashboardSafe(bus: EventBus, onPush?: (p: PushInfo) => void) {
  try {
    const mod = await import("./dashboard/server.js");
    if (typeof mod.startDashboard === "function") {
      mod.startDashboard(bus, config.dashboardPort, { onPush });
      console.log(`[index] dashboard on http://localhost:${config.dashboardPort}`);
    }
  } catch (e) {
    console.warn(`[index] dashboard not available yet (${(e as Error).message}) — running headless`);
  }
}

/** Move target/ to exactly the pushed commit (what a CI checkout would do). */
async function syncTargetTo(sha: string) {
  const git = (...args: string[]) => pExecFile("git", args, { cwd: TARGET_DIR });
  await git("fetch", "--quiet", "origin", sha);
  await git("reset", "--hard", sha);
  await git("clean", "-fd", "--", "src", "tests").catch(() => {});
}

async function main() {
  reportConfig();
  const bus = makeEventBus();

  // One run at a time. Triggers that arrive mid-run collapse into one follow-up run.
  let busy = false;
  let mutedUntil = 0; // ignore our own file churn (remediate edits, PR checkout) right after a run
  let pendingPush: PushInfo | null = null;
  let deps: Parameters<typeof runFull>[1] | null = null;

  async function runPush(push: PushInfo) {
    if (!deps) { pendingPush = push; return; }
    if (busy) { pendingPush = push; console.log(`[index] run in progress — queued push ${push.sha.slice(0, 7)}`); return; }
    busy = true;
    try {
      bus.emit({ type: "continuous", trigger: `git push ${push.sha.slice(0, 7)} by ${push.pusher}: "${push.message}"` });
      await syncTargetTo(push.sha);
      await new Promise((r) => setTimeout(r, 2500)); // let the target's tsx watch reload the pushed code
      console.log(`[index] webhook push ${push.sha.slice(0, 7)} → running Ward autonomously`);
      await runFull(REPO, deps, "push");
    } catch (e) {
      console.error("[index] push run failed:", (e as Error).message);
    } finally {
      busy = false;
      mutedUntil = Date.now() + 5000;
      const next = pendingPush;
      pendingPush = null;
      if (next) void runPush(next);
    }
  }

  await startDashboardSafe(bus, WATCH ? (p) => void runPush(p) : undefined);
  const caseStore = await makeCaseStoreSafe(REPO);
  const logStore = await makeLogStore();

  deps = { bus, caseStore, logStore, targetDir: TARGET_DIR };
  console.log(`[index] running Ward against "${REPO}" (${TARGET_DIR})`);
  busy = true;
  await runFull(REPO, deps, "manual").catch((e) => console.error("[index] run failed:", e.message));
  busy = false;
  mutedUntil = Date.now() + 5000;

  if (WATCH) {
    console.log(`[index] Continuous armed: GitHub push webhook at POST /webhook/github` +
      `${config.githubWebhookSecret ? "" : " (DISABLED — set GITHUB_WEBHOOK_SECRET)"} + local edits to target/src.`);
    if (pendingPush) { const p = pendingPush; pendingPush = null; void runPush(p); }
    let timer: NodeJS.Timeout | null = null;
    watch(resolve(TARGET_DIR, "src"), { recursive: true }, () => {
      if (busy || Date.now() < mutedUntil) return;
      if (timer) clearTimeout(timer);
      timer = setTimeout(async () => {
        if (busy || Date.now() < mutedUntil) return;
        busy = true;
        bus.emit({ type: "continuous", trigger: "target code changed" });
        console.log("[index] change detected → re-running Ward (push trigger)");
        await runFull(REPO, deps!, "push").catch((e) => console.error(e.message));
        busy = false;
        mutedUntil = Date.now() + 5000;
        const next = pendingPush;
        pendingPush = null;
        if (next) void runPush(next);
      }, 800);
    });
  } else {
    process.exit(0);
  }
}

main().catch((e) => {
  console.error("[index] fatal:", e);
  process.exit(1);
});
