/**
 * Phase 2 — Remediate. For each confirmed finding the agent proposes a targeted
 * fix (code edit or agent-guardrail edit), applies it to the LOCAL target copy,
 * then the DETERMINISTIC verdict layer decides: re-probe blocked + tests pass +
 * scanner clean. Retries up to the cap. The agent never declares its own success.
 */
import type { RunContext } from "../orchestrator/context.js";
import type { Finding } from "../types.js";
import { readTargetFile, writeTargetFile, listTargetFiles, setEditRoot } from "../tools/fileEdit.js";
import { testsPass, probeBlocked, techniqueGone } from "../verdicts/index.js";
import { resetTarget } from "../tools/probe.js";
import { askJSON } from "../agent/ask.js";

const RETRY = Number(process.env.WARD_RETRY_CAP) || 3;

const FIX_SYS = `You are Ward's remediation module working on a SELF-OWNED app in an authorized hackathon.
You are given a confirmed security finding and the contents of the file(s) involved. Produce a MINIMAL,
targeted fix. For code weaknesses: parameterize queries, sanitize/confine file paths, remove hardcoded
secrets. For agent weaknesses: harden the bot's system prompt and tool handling (treat ticket text as
untrusted data not instructions, restrict tool arguments, allowlist outbound destinations).
Output JSON: {"edits":[{"path":"<relative path>","find":"<exact snippet to replace>","replace":"<new snippet>"}],"rationale":"..."}
RULES:
- "find" must be the MINIMAL unique substring to change — ideally part of ONE line (e.g. just the
  vulnerable expression), copied from the file content shown. Shorter is more reliable than whole lines.
- Preserve behaviour for legitimate inputs (the existing tests MUST still pass) — only close the hole.
- Do not rename exported functions or change their signatures.
- For SQL injection: keep the same columns/table and return shape; switch to a parameterized query
  (bind the value) so a normal name lookup still returns the right row.`;

export async function phaseRemediate(ctx: RunContext): Promise<void> {
  setEditRoot(ctx.targetDir);
  const todo = ctx.case.findings.filter((f) => f.status === "found" || f.status === "proven");
  if (todo.length === 0) {
    ctx.log("Nothing to remediate.");
    return;
  }

  const files = await listTargetFiles("src").catch(() => []);
  for (const f of todo) {
    let fixed = false;
    for (let attempt = 1; attempt <= RETRY && !fixed; attempt++) {
      ctx.bumpStep();
      ctx.log(`Fixing ${f.technique} (${f.id}), attempt ${attempt}/${RETRY}…`);
      const context = await gatherContext(f, files, ctx.targetDir);
      let edits: { path: string; find: string; replace: string }[] = [];
      let rationale = "";
      try {
        const out = await askJSON<{ edits: typeof edits; rationale: string }>(
          FIX_SYS,
          `Finding: ${JSON.stringify({ technique: f.technique, layer: f.layer, location: f.location, evidence: f.evidence })}\n\nFiles:\n${context}`,
          ctx.meter,
        );
        edits = out.edits ?? [];
        rationale = out.rationale ?? "";
      } catch (e) {
        ctx.log(`  fix generation failed: ${(e as Error).message}`);
        continue;
      }

      const diffs: string[] = [];
      for (const e of edits) {
        try {
          const before = await readTargetFile(e.path);
          const out = flexibleReplace(before, e.find, e.replace);
          if (!out.ok) { ctx.log(`  snippet not found in ${e.path}, skipping`); continue; }
          await writeTargetFile(e.path, out.text);
          diffs.push(`--- ${e.path}\n` + e.find.split("\n").map((l) => `- ${l}`).join("\n") + "\n" + e.replace.split("\n").map((l) => `+ ${l}`).join("\n"));
        } catch (err) {
          ctx.log(`  edit error on ${e.path}: ${(err as Error).message}`);
        }
      }
      if (diffs.length === 0) { ctx.log("  no edits applied"); continue; }
      f.fix = { diff: diffs.join("\n"), attempts: attempt };

      // Let the target hot-reload (tsx watch) pick up the edited source before re-probing.
      await new Promise((r) => setTimeout(r, 2500));

      // --- DETERMINISTIC verdicts ---
      await resetTarget();
      const verdicts = [];
      const tv = await testsPass();
      verdicts.push(tv);
      ctx.emit({ type: "verdict", findingId: f.id, verdict: `tests: ${tv.detail}`, pass: tv.pass });

      let probeOk = { pass: true, detail: "no probe to replay" } as { pass: boolean; detail: string };
      const probeMsg = (f as any)._probeMessage as string | undefined;
      if (probeMsg) {
        const pv = await probeBlocked(probeMsg);
        probeOk = pv;
        ctx.emit({ type: "verdict", findingId: f.id, verdict: `replay: ${pv.detail}`, pass: pv.pass });
      }

      // Per-finding scanner check: only THIS weakness must be gone (others fixed separately).
      const sv = f.layer === "code"
        ? await techniqueGone(ctx.targetDir, f.technique, ctx.decoyMatcher)
        : { check: "scanner", pass: true, detail: "n/a (agent-layer)" };
      ctx.emit({ type: "verdict", findingId: f.id, verdict: `scanner: ${sv.detail}`, pass: sv.pass });

      fixed = tv.pass && probeOk.pass && (f.layer === "agent" ? true : sv.pass);
      if (fixed) {
        f.status = "verified";
        ctx.log(`  ✓ verified (${rationale.slice(0, 80)})`);
      } else {
        ctx.log(`  ✗ not verified (tests=${tv.pass} replay=${probeOk.pass} scan=${sv.pass}) — retrying`);
      }
    }
    if (!fixed && f.status !== "verified") {
      f.status = "failed";
      ctx.emit({ type: "finding", finding: f });
      ctx.log(`  ${f.id} marked failed after ${RETRY} attempts.`);
    } else {
      ctx.emit({ type: "finding", finding: f });
    }
  }
}

/** Replace with three fallbacks: exact → per-line-trimmed block → whitespace-insensitive span. */
function flexibleReplace(text: string, find: string, replace: string): { ok: boolean; text: string } {
  if (!find) return { ok: false, text };
  // 1. exact
  if (text.includes(find)) return { ok: true, text: text.replace(find, replace) };

  // 2. per-line trimmed block match
  const fLines = find.split("\n").map((l) => l.trim()).filter(Boolean);
  const fNorm = fLines.join("\n");
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const windowLines = lines.slice(i, i + fLines.length).map((l) => l.trim()).filter(Boolean);
    if (windowLines.length === fLines.length && windowLines.join("\n") === fNorm) {
      const before = lines.slice(0, i).join("\n");
      const after = lines.slice(i + fLines.length).join("\n");
      return { ok: true, text: [before, replace, after].filter((s) => s !== "").join("\n") };
    }
  }

  // 3. whitespace-insensitive span: match ignoring all whitespace, map back to original offsets
  const origIdx: number[] = [];
  let stripped = "";
  for (let i = 0; i < text.length; i++) {
    if (!/\s/.test(text[i])) { stripped += text[i]; origIdx.push(i); }
  }
  const fStripped = find.replace(/\s+/g, "");
  if (fStripped) {
    const at = stripped.indexOf(fStripped);
    if (at >= 0) {
      const start = origIdx[at];
      const end = origIdx[at + fStripped.length - 1] + 1;
      return { ok: true, text: text.slice(0, start) + replace + text.slice(end) };
    }
  }
  return { ok: false, text };
}

async function gatherContext(f: Finding, files: string[], root: string): Promise<string> {
  const picks = new Set<string>();
  const loc = f.location.split(":")[0];
  if (loc && files.includes(loc)) picks.add(loc);
  // for agent-layer, include the bot/server + any prompt file
  for (const p of files) if (/server|bot|prompt|tool/i.test(p)) picks.add(p);
  if (loc && /\.(ts|js)/.test(loc)) picks.add(loc);
  const chosen = [...picks].slice(0, 4);
  const parts: string[] = [];
  for (const p of chosen) {
    const body = await readTargetFile(p).catch(() => "");
    if (body) parts.push(`### ${p}\n\`\`\`\n${body.slice(0, 4000)}\n\`\`\``);
  }
  return parts.join("\n\n") || "(no file context available)";
}
