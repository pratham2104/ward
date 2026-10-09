/**
 * RunContext — the shared handle every phase receives. Carries the case file,
 * the event bus (to the dashboard), the log store, the cost meter, and helpers.
 */
import type { CaseFile, EventBus, LogEvent, LogStore, Meters, WardEvent } from "../types.js";
import type { CostMeter } from "../agent/llm.js";
import { resolve } from "node:path";

export interface RunContext {
  case: CaseFile;
  bus: EventBus;
  logStore: LogStore;
  meter: CostMeter;
  startMs: number;
  steps: number;
  targetDir: string;
  /** Gapped logs captured at probe time, handed to the Detective (reload-proof). */
  capturedLogs: LogEvent[];
  /** identifies the planted decoy (scanner-flagged but safe) so verdicts ignore it. */
  decoyMatcher: (h: { ruleId: string; path: string; line: number; message: string }) => boolean;
  emit: (e: WardEvent) => void;
  log: (line: string) => void;
  pushMeter: () => void;
  bumpStep: () => void;
}

export function makeContext(opts: {
  case: CaseFile;
  bus: EventBus;
  logStore: LogStore;
  meter: CostMeter;
  targetDir?: string;
  decoyMatcher?: (h: { ruleId: string; path: string; line: number; message: string }) => boolean;
}): RunContext {
  const ctx: RunContext = {
    case: opts.case,
    bus: opts.bus,
    logStore: opts.logStore,
    meter: opts.meter,
    startMs: Date.now(),
    steps: 0,
    targetDir: opts.targetDir ?? resolve(process.cwd(), "target"),
    capturedLogs: [],
    decoyMatcher: opts.decoyMatcher ?? ((h) => /eval/i.test(h.ruleId) || /eval/i.test(h.message)),
    emit: (e) => opts.bus.emit(e),
    log: (line) => {
      opts.bus.emit({ type: "log", line });
      console.log("[ward]", line);
    },
    pushMeter: () => {
      ctx.case.meters = meters(ctx);
      opts.bus.emit({ type: "meter", meters: ctx.case.meters });
    },
    bumpStep: () => {
      ctx.steps++;
      ctx.case.meters = meters(ctx);
    },
  };
  return ctx;
}

export function meters(ctx: RunContext): Meters {
  return {
    wallClockS: Math.round((Date.now() - ctx.startMs) / 1000),
    costUsd: Number(ctx.meter.usd.toFixed(4)),
    steps: ctx.steps,
  };
}
