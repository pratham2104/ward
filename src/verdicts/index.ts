/**
 * The verdict layer — the trust anchor. EVERY success claim comes from here,
 * from deterministic code, never from the LLM agent's opinion.
 */
import type { TimelineStep } from "../types.js";
import { runTargetTests } from "../tools/runTests.js";
import { probe, type ProbeResult } from "../tools/probe.js";
import { scan, classifyTechnique, type ScanHit } from "../tools/scan.js";

export interface Verdict {
  check: string;
  pass: boolean;
  detail: string;
}

/** Legit behaviour must still work after a fix. */
export async function testsPass(): Promise<Verdict> {
  const r = await runTargetTests();
  return { check: "tests", pass: r.passed, detail: r.summary };
}

/** Re-send a probe; a canary leaking = still vulnerable. pass = no leak. */
export async function probeBlocked(message: string): Promise<Verdict & { result: ProbeResult }> {
  const r = await probe(message);
  return {
    check: "canary",
    pass: !r.leaked,
    detail: r.leaked ? `leaked ${r.leakedCanaries.join(", ")} via ${r.outbound.map((o) => o.tool).join(",")}` : "no canary left the system",
    result: r,
  };
}

/** Scanner clean, ignoring the known decoy rule/location. pass = no real hits. */
export async function scannerClean(
  targetPath: string,
  decoyMatcher: (h: ScanHit) => boolean = () => false,
): Promise<Verdict> {
  const hits = (await scan(targetPath)).filter((h) => !decoyMatcher(h));
  return {
    check: "scanner",
    pass: hits.length === 0,
    detail: hits.length ? hits.map((h) => `${h.ruleId}@${h.path}:${h.line}`).join("; ") : "no real findings",
  };
}

/** This SPECIFIC weakness is gone: no remaining non-decoy hit classifies to `technique`. */
export async function techniqueGone(
  targetPath: string,
  technique: string,
  decoyMatcher: (h: ScanHit) => boolean = () => false,
): Promise<Verdict> {
  const hits = (await scan(targetPath)).filter((h) => !decoyMatcher(h));
  const still = hits.filter((h) => classifyTechnique(h.ruleId, h.message) === technique);
  return {
    check: "scanner",
    pass: still.length === 0,
    detail: still.length ? still.map((h) => `${h.ruleId}@${h.path}:${h.line}`).join("; ") : `${technique} no longer detected`,
  };
}

/** Detective coverage: fraction of ground-truth steps recovered from logs alone. */
export function timelineCoverage(
  ground: TimelineStep[],
  reconstructed: TimelineStep[],
): { coverage: number; matched: TimelineStep[]; missed: TimelineStep[] } {
  const recon = reconstructed.map((s) => norm(s.step));
  const matched: TimelineStep[] = [];
  const missed: TimelineStep[] = [];
  for (const g of ground) {
    if (recon.some((r) => r.includes(norm(g.step)) || norm(g.step).includes(r))) matched.push(g);
    else missed.push(g);
  }
  const coverage = ground.length ? matched.length / ground.length : 0;
  return { coverage, matched, missed };
}

function norm(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}
