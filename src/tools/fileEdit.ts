/**
 * File tools for the agent to read + fix the target's LOCAL copy.
 * Edits are confined to the target directory — the agent cannot touch Ward itself.
 */
import { readFile, writeFile, readdir, stat } from "node:fs/promises";
import { join, resolve, relative } from "node:path";

let ROOT = resolve(process.cwd(), "target");

export function setEditRoot(dir: string) {
  ROOT = resolve(dir);
}

function guard(p: string): string {
  const abs = resolve(ROOT, p);
  const rel = relative(ROOT, abs);
  if (rel.startsWith("..") || rel.includes(".." + "/")) {
    throw new Error(`refused: path escapes edit root: ${p}`);
  }
  return abs;
}

export async function readTargetFile(path: string): Promise<string> {
  return readFile(guard(path), "utf8");
}

export async function writeTargetFile(path: string, content: string): Promise<void> {
  await writeFile(guard(path), content, "utf8");
}

/** Replace exactly one occurrence of `find` with `replace` in a file. Returns a unified-ish diff. */
export async function replaceInFile(
  path: string,
  find: string,
  replace: string,
): Promise<{ ok: boolean; diff: string }> {
  const abs = guard(path);
  const before = await readFile(abs, "utf8");
  if (!before.includes(find)) return { ok: false, diff: `(not found in ${path})` };
  const after = before.replace(find, replace);
  await writeFile(abs, after, "utf8");
  const diff = [`--- ${path}`, `+++ ${path}`, ...find.split("\n").map((l) => `- ${l}`), ...replace.split("\n").map((l) => `+ ${l}`)].join("\n");
  return { ok: true, diff };
}

export async function listTargetFiles(sub = "."): Promise<string[]> {
  const out: string[] = [];
  async function walk(dir: string) {
    let entries;
    try { entries = await readdir(dir); } catch { return; }
    for (const name of entries) {
      if (["node_modules", ".git", "dist", "seed"].includes(name)) continue;
      const full = join(dir, name);
      const s = await stat(full).catch(() => null);
      if (!s) continue;
      if (s.isDirectory()) await walk(full);
      else if (/\.(ts|js|json|md|sql)$/.test(name)) out.push(relative(ROOT, full));
    }
  }
  await walk(guard(sub));
  return out;
}
