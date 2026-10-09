/**
 * Ward entry point. Wires the event bus, stores, dashboard, and the run.
 * Usage:
 *   npm run target          # (separately) start the vulnerable helpdesk bot
 *   npm run dev -- --watch   # start Ward, run once, then re-run on target changes
 */
import { resolve } from "node:path";
import { watch } from "node:fs";
import { config, reportConfig } from "./config.js";
import { makeEventBus } from "./stores/eventBus.js";
import { makeCaseStore } from "./stores/caseStore.js";
import { makeLogStore } from "./stores/logStore.js";
import { runFull } from "./orchestrator/orchestrator.js";
import type { CaseStore, EventBus, LogStore } from "./types.js";

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

async function startDashboardSafe(bus: EventBus) {
  try {
    const mod = await import("./dashboard/server.js");
    if (typeof mod.startDashboard === "function") {
      mod.startDashboard(bus, config.dashboardPort);
      console.log(`[index] dashboard on http://localhost:${config.dashboardPort}`);
    }
  } catch (e) {
    console.warn(`[index] dashboard not available yet (${(e as Error).message}) — running headless`);
  }
}

async function main() {
  reportConfig();
  const bus = makeEventBus();
  await startDashboardSafe(bus);
  const caseStore = await makeCaseStoreSafe(REPO);
  const logStore = await makeLogStore();

  const deps = { bus, caseStore, logStore, targetDir: TARGET_DIR };
  console.log(`[index] running Ward against "${REPO}" (${TARGET_DIR})`);
  await runFull(REPO, deps, "manual").catch((e) => console.error("[index] run failed:", e.message));

  if (WATCH) {
    console.log("[index] Continuous watch armed on target/src — edit a file to re-trigger.");
    let busy = false;
    let timer: NodeJS.Timeout | null = null;
    watch(resolve(TARGET_DIR, "src"), { recursive: true }, () => {
      if (timer) clearTimeout(timer);
      timer = setTimeout(async () => {
        if (busy) return;
        busy = true;
        bus.emit({ type: "continuous", trigger: "target code changed" });
        console.log("[index] change detected → re-running Ward (push trigger)");
        await runFull(REPO, deps, "push").catch((e) => console.error(e.message));
        busy = false;
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
