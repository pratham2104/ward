/**
 * Output module. Produces the fix as a GitHub pull request for HUMAN approval
 * (the CI/CD-style gate). Degrades to a local patch + diff if git/GitHub isn't
 * wired, so the demo always yields something reviewable.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { writeFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { config } from "../config.js";
import type { CaseFile } from "../types.js";

const pExecFile = promisify(execFile);

export interface PrResult {
  mode: "pr" | "local";
  prUrl?: string;
  patchPath?: string;
  summary: string;
}

async function git(args: string[], cwd: string) {
  return pExecFile("git", args, { cwd, env: { ...process.env } });
}

async function isGitRepo(cwd: string): Promise<boolean> {
  try { await git(["rev-parse", "--is-inside-work-tree"], cwd); return true; } catch { return false; }
}

/** Restore the target to its pinned clean baseline tag (repeatable manual runs). */
export async function restoreTargetSource(targetDir: string): Promise<boolean> {
  if (!(await isGitRepo(targetDir))) return false;
  try {
    try {
      await git(["reset", "--hard", "ward-baseline"], targetDir);
    } catch {
      await git(["checkout", "--", "."], targetDir);
    }
    await git(["clean", "-fd", "--", "src", "tests"], targetDir).catch(() => {});
    return true;
  } catch {
    return false;
  }
}

export async function openPullRequest(
  c: CaseFile,
  targetDir = resolve(process.cwd(), "target"),
): Promise<PrResult> {
  const fixes = c.findings.filter((f) => f.fix?.diff);
  const body = prBody(c);
  const branch = `ward/fixes-${Date.now().toString(36)}`;

  // Local patch always written, as the reviewable artifact / fallback.
  await mkdir(resolve(process.cwd(), "reports"), { recursive: true });
  const patchPath = resolve(process.cwd(), "reports", `${branch.replace(/\//g, "_")}.patch`);
  await writeFile(patchPath, fixes.map((f) => `# ${f.id} ${f.technique}\n${f.fix!.diff}`).join("\n\n"), "utf8");

  const canPr = config.githubToken && config.githubRepo && (await isGitRepo(targetDir));
  if (!canPr) {
    return {
      mode: "local",
      patchPath,
      summary: `Local review mode: ${fixes.length} fix(es) written to ${patchPath}. ` +
        `(Set GITHUB_TOKEN + GITHUB_REPO and make the target a git repo to open a real PR.)`,
    };
  }

  let origBranch = "master";
  try { origBranch = (await git(["rev-parse", "--abbrev-ref", "HEAD"], targetDir)).stdout.trim(); } catch { /* ignore */ }
  try {
    await git(["checkout", "-b", branch], targetDir);
    await git(["add", "-A"], targetDir);
    await git(["-c", "user.name=Ward", "-c", "user.email=ward@local", "commit", "-m", `Ward: autonomous security fixes (${fixes.length})`], targetDir);
    const remote = `https://x-access-token:${config.githubToken}@github.com/${config.githubRepo}.git`;
    await git(["push", remote, branch], targetDir);

    const base = await defaultBranch(targetDir).catch(() => origBranch);
    const res = await fetch(`https://api.github.com/repos/${config.githubRepo}/pulls`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${config.githubToken}`,
        accept: "application/vnd.github+json",
        "content-type": "application/json",
      },
      body: JSON.stringify({ title: `Ward: autonomous security fixes (${fixes.length})`, head: branch, base, body }),
    });
    const pr: any = await res.json();
    if (!res.ok) throw new Error(pr?.message ?? `GitHub API ${res.status}`);
    return { mode: "pr", prUrl: pr.html_url, patchPath, summary: `PR opened for approval: ${pr.html_url}` };
  } catch (e) {
    return { mode: "local", patchPath, summary: `PR failed (${(e as Error).message}); local patch at ${patchPath}` };
  } finally {
    // Never leave HEAD on the fix branch — the next run restores from baseline.
    await git(["checkout", origBranch], targetDir).catch(() => {});
  }
}

async function defaultBranch(cwd: string): Promise<string> {
  const { stdout } = await git(["symbolic-ref", "refs/remotes/origin/HEAD"], cwd);
  return stdout.trim().split("/").pop() || "main";
}

function prBody(c: CaseFile): string {
  const lines = [
    "## Ward — autonomous security fixes",
    "",
    "One autonomous agent found, proved, fixed, and re-verified these weaknesses. **Human approval required before merge.**",
    "",
    "| Finding | Layer | Frameworks | Status |",
    "|---|---|---|---|",
    ...c.findings.map((f) => `| ${f.technique} (${f.id}) | ${f.layer} | ${[...f.frameworks.owasp_llm, ...f.frameworks.cwe, ...f.frameworks.atlas, ...f.frameworks.attack].join(", ")} | ${f.status} |`),
    "",
    `**Detective coverage:** ${Math.round(c.coverageScore * 100)}% · **Blind spots closed:** ${c.findings.filter((f) => f.blindSpot).length}`,
    `**Run:** ${c.meters.wallClockS}s · $${c.meters.costUsd.toFixed(2)}`,
    "",
    "🤖 Generated with [Claude Code](https://claude.com/claude-code)",
  ];
  return lines.join("\n");
}
