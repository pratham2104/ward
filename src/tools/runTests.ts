/**
 * Runs the target's own test suite (Vitest) — one input to the verdict layer's
 * "the fix didn't break legit behaviour" check.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const pExecFile = promisify(execFile);

export interface TestResult {
  passed: boolean;
  summary: string;
}

export async function runTargetTests(): Promise<TestResult> {
  try {
    const { stdout } = await pExecFile("npm", ["run", "test:target"], {
      cwd: process.cwd(),
      maxBuffer: 16 * 1024 * 1024,
      env: { ...process.env },
    });
    return { passed: true, summary: tail(stdout) };
  } catch (e: any) {
    const out = (e?.stdout ?? "") + (e?.stderr ?? "");
    return { passed: false, summary: tail(out) || String(e?.message ?? e) };
  }
}

function tail(s: string, n = 600): string {
  return s.trim().slice(-n);
}
