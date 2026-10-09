/**
 * Semgrep wrapper. Runs the Semgrep CLI over a path and returns structured hits.
 * Semgrep is a free CLI (`brew install semgrep`); no key needed. Falls back to a
 * light built-in pattern scan if semgrep isn't installed, so the demo still runs.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";

const pExecFile = promisify(execFile);

export interface ScanHit {
  ruleId: string;
  path: string;
  line: number;
  message: string;
  severity: string;
}

/** Map a scanner hit to a Ward technique label. Shared by Discover and the verdict layer. */
export function classifyTechnique(ruleId: string, message = ""): string {
  const s = (ruleId + " " + message).toLowerCase();
  if (/sql.*inject|inject.*sql|sqli|sql.*concat|concat.*sql|tainted.*sql/.test(s)) return "sql injection";
  if (/path.*travers|directory.*travers|\btravers/.test(s)) return "path traversal";
  if (/hardcoded|hard-coded|secret|credential|password|api.?key/.test(s)) return "hardcoded secret";
  if (/\beval\b/.test(s)) return "eval (decoy)";
  if (/ssrf|request.?forgery/.test(s)) return "ssrf";
  if (/command.?inject|os.?command/.test(s)) return "command injection";
  if (/xss|cross.?site/.test(s)) return "xss";
  return ruleId;
}

export async function semgrepAvailable(): Promise<boolean> {
  try {
    await pExecFile("semgrep", ["--version"]);
    return true;
  } catch {
    return false;
  }
}

export async function scan(targetPath: string): Promise<ScanHit[]> {
  if (await semgrepAvailable()) {
    try {
      const { stdout } = await pExecFile(
        "semgrep",
        ["--config", "auto", "--json", "--quiet", targetPath],
        { maxBuffer: 32 * 1024 * 1024 },
      );
      const data = JSON.parse(stdout);
      return (data.results ?? []).map((r: any): ScanHit => ({
        ruleId: r.check_id,
        path: r.path,
        line: r.start?.line ?? 0,
        message: r.extra?.message ?? "",
        severity: r.extra?.severity ?? "INFO",
      }));
    } catch (e) {
      // fall through to builtin
    }
  }
  return builtinScan(targetPath);
}

/** Minimal fallback so the pipeline works without semgrep installed. */
async function builtinScan(targetPath: string): Promise<ScanHit[]> {
  const hits: ScanHit[] = [];
  const patterns: { id: string; re: RegExp; msg: string; sev: string }[] = [
    { id: "builtin.sqli-concat", re: /(SELECT|INSERT|UPDATE|DELETE)[^\n]*\$\{|["'`]\s*\+\s*\w+\s*\+\s*["'`]/i, msg: "Possible SQL built from string concatenation", sev: "ERROR" },
    { id: "builtin.eval", re: /\beval\s*\(/, msg: "Use of eval()", sev: "WARNING" },
    { id: "builtin.path-join-user", re: /join\([^)]*req\.|path\.join\([^)]*body/i, msg: "Possible path traversal from user input", sev: "ERROR" },
    { id: "builtin.hardcoded-secret", re: /(ADMIN_KEY|SECRET|API_KEY|PASSWORD)\s*=\s*["'][^"']{6,}/i, msg: "Possible hardcoded secret", sev: "ERROR" },
  ];
  async function walk(dir: string): Promise<void> {
    let entries;
    try { entries = await readdir(dir); } catch { return; }
    for (const name of entries) {
      if (name === "node_modules" || name === ".git" || name === "dist") continue;
      const full = join(dir, name);
      const s = await stat(full).catch(() => null);
      if (!s) continue;
      if (s.isDirectory()) await walk(full);
      else if (/\.(ts|js|mjs|cjs)$/.test(name)) {
        const text = await readFile(full, "utf8").catch(() => "");
        text.split("\n").forEach((ln, i) => {
          for (const p of patterns) if (p.re.test(ln)) hits.push({ ruleId: p.id, path: full, line: i + 1, message: p.msg, severity: p.sev });
        });
      }
    }
  }
  await walk(targetPath);
  return hits;
}
