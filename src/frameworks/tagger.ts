/**
 * Ward framework tagger — deterministic technique -> standards-ID lookup.
 *
 * `tagFinding` maps a detected weakness technique (free text) to its OWASP-LLM,
 * CWE, MITRE ATLAS (names) and MITRE ATT&CK tags. `tagChain` merges several
 * techniques for the cross-layer chained attack. `coverageSummary` counts the
 * distinct ids across a set of findings for the dashboard header.
 *
 * Rules: match by keyword, case-insensitive; unknown techniques return empty
 * arrays and NEVER throw.
 */
import type { Finding, FrameworkTags, Layer } from "../types";
import { ATLAS_TACTICS, ATTACK } from "./catalog";

/** Empty, fresh tag block — each call owns its own arrays. */
function emptyTags(): FrameworkTags {
  return { owasp_llm: [], cwe: [], atlas: [], attack: [] };
}

/** A single keyword rule: if any alias is present in the technique, apply the tags. */
interface Rule {
  aliases: string[];
  apply: (t: FrameworkTags) => void;
}

const RULES: Rule[] = [
  // --- Code layer (CWE) ---
  {
    aliases: ["sql injection", "sqli"],
    apply: (t) => t.cwe.push("CWE-89"),
  },
  {
    aliases: ["path traversal", "directory traversal", "lfi"],
    apply: (t) => t.cwe.push("CWE-22"),
  },
  {
    aliases: [
      "hardcoded secret",
      "hard-coded secret",
      "hardcoded credential",
      "hard-coded credential",
      "hardcoded password",
    ],
    apply: (t) => t.cwe.push("CWE-798"),
  },
  {
    aliases: ["xss", "cross-site scripting", "cross site scripting"],
    apply: (t) => t.cwe.push("CWE-79"),
  },
  {
    aliases: ["command injection", "os command injection", "rce via command"],
    apply: (t) => t.cwe.push("CWE-78"),
  },
  {
    aliases: ["ssrf", "server-side request forgery", "server side request forgery"],
    apply: (t) => t.cwe.push("CWE-918"),
  },

  // --- Agent / LLM layer (OWASP-LLM + ATLAS) ---
  {
    aliases: ["prompt injection", "jailbreak", "indirect injection"],
    apply: (t) => {
      t.owasp_llm.push("LLM01");
      t.atlas.push(ATLAS_TACTICS.PROMPT_INJECTION);
    },
  },
  {
    aliases: ["excessive agency", "tool misuse", "tool abuse", "unauthorized tool"],
    apply: (t) => t.owasp_llm.push("LLM06"),
  },
  {
    aliases: ["system prompt leak", "system prompt leakage", "prompt leak"],
    apply: (t) => t.owasp_llm.push("LLM07"),
  },
  {
    // Data exfiltration / sensitive disclosure — OWASP LLM02 + ATT&CK + ATLAS.
    aliases: [
      "data leak",
      "data exfiltration",
      "exfiltration",
      "sensitive disclosure",
      "sensitive information disclosure",
      "data leakage",
    ],
    apply: (t) => {
      t.owasp_llm.push("LLM02");
      t.attack.push("T1041");
      t.atlas.push(ATLAS_TACTICS.EXFILTRATION_VIA_ML_INFERENCE_API);
    },
  },
];

/** Push values into `arr` that are not already present (order-preserving dedupe). */
function pushUnique(arr: string[], values: string[]): void {
  for (const v of values) if (!arr.includes(v)) arr.push(v);
}

/**
 * Map one technique to its framework tags.
 * @param technique free-text technique label (e.g. "SQL Injection", "prompt injection")
 * @param layer     "code" | "agent" — reserved for future layer-specific disambiguation
 * @param context   optional extra context string, also scanned for keywords
 */
export function tagFinding(
  technique: string,
  _layer: Layer,
  context?: string,
): FrameworkTags {
  const tags = emptyTags();
  const haystack = `${technique ?? ""} ${context ?? ""}`.toLowerCase();

  for (const rule of RULES) {
    if (rule.aliases.some((a) => haystack.includes(a))) {
      // Apply into a scratch block, then merge with dedupe so overlapping
      // rules never produce duplicate ids.
      const scratch = emptyTags();
      rule.apply(scratch);
      pushUnique(tags.owasp_llm, scratch.owasp_llm);
      pushUnique(tags.cwe, scratch.cwe);
      pushUnique(tags.atlas, scratch.atlas);
      pushUnique(tags.attack, scratch.attack);
    }
  }

  return tags;
}

/**
 * Merge the tags for several techniques into one deduped block — used for the
 * headline cross-layer CHAIN (e.g. prompt injection + excessive agency + sqli +
 * exfiltration).
 */
export function tagChain(techniques: string[]): FrameworkTags {
  const merged = emptyTags();
  for (const technique of techniques ?? []) {
    const t = tagFinding(technique, "agent");
    pushUnique(merged.owasp_llm, t.owasp_llm);
    pushUnique(merged.cwe, t.cwe);
    pushUnique(merged.atlas, t.atlas);
    pushUnique(merged.attack, t.attack);
  }
  return merged;
}

/** Merge a finding's existing tags into the running distinct-id sets. */
function collect(sets: Record<keyof FrameworkTags, Set<string>>, tags: FrameworkTags) {
  for (const id of tags.owasp_llm) sets.owasp_llm.add(id);
  for (const id of tags.cwe) sets.cwe.add(id);
  for (const id of tags.atlas) sets.atlas.add(id);
  for (const id of tags.attack) sets.attack.add(id);
}

/**
 * One-line coverage summary counting DISTINCT ids across all findings, e.g.
 * "OWASP-LLM: 4 · CWE: 3 · ATLAS: 2 · ATT&CK: 1".
 */
export function coverageSummary(findings: Finding[]): string {
  const sets: Record<keyof FrameworkTags, Set<string>> = {
    owasp_llm: new Set(),
    cwe: new Set(),
    atlas: new Set(),
    attack: new Set(),
  };
  for (const f of findings ?? []) {
    if (f?.frameworks) collect(sets, f.frameworks);
  }
  return (
    `OWASP-LLM: ${sets.owasp_llm.size} · ` +
    `CWE: ${sets.cwe.size} · ` +
    `ATLAS: ${sets.atlas.size} · ` +
    `ATT&CK: ${sets.attack.size}`
  );
}
