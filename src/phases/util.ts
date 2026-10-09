import type { Severity } from "../types.js";

let counter = 0;
export function mkId(prefix = "F"): string {
  counter += 1;
  return `${prefix}${counter}`;
}

export function severityFor(technique: string): Severity {
  const s = technique.toLowerCase();
  if (/exfil|chain|injection → /.test(s)) return "critical";
  if (/sql|path travers|ssrf|command/.test(s)) return "high";
  if (/secret|credential/.test(s)) return "high";
  if (/decoy/.test(s)) return "low";
  return "medium";
}
