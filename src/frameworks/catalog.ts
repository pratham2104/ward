/**
 * Ward framework catalog — the reference data the tagger maps detected
 * techniques onto. Typed, deterministic, display-facing.
 *
 * Accuracy note: these tables go in front of security judges. The OWASP Top 10
 * for LLM Apps (2025) list and the CWE ids below are authoritative and checked.
 * MITRE ATLAS is stored as TACTIC NAMES only (see note on ATLAS_TACTICS).
 */

/**
 * OWASP Top 10 for LLM Applications — 2025 edition.
 * Canonical id -> title map, in published order (LLM01..LLM10).
 */
export const OWASP_LLM_2025 = {
  LLM01: "Prompt Injection",
  LLM02: "Sensitive Information Disclosure",
  LLM03: "Supply Chain",
  LLM04: "Data and Model Poisoning",
  LLM05: "Improper Output Handling",
  LLM06: "Excessive Agency",
  LLM07: "System Prompt Leakage",
  LLM08: "Vector and Embedding Weaknesses",
  LLM09: "Misinformation",
  LLM10: "Unbounded Consumption",
} as const;

export type OwaspLlmId = keyof typeof OWASP_LLM_2025;

/**
 * Common CWEs Ward uses for the code-layer findings.
 * id -> short title.
 */
export const CWE = {
  "CWE-89": "SQL Injection",
  "CWE-22": "Path Traversal",
  "CWE-798": "Use of Hard-coded Credentials",
  "CWE-79": "Cross-site Scripting (XSS)",
  "CWE-78": "OS Command Injection",
  "CWE-918": "Server-Side Request Forgery (SSRF)",
} as const;

export type CweId = keyof typeof CWE;

/**
 * MITRE ATLAS — AI-specific adversarial tactics/techniques.
 *
 * ATLAS exact AML.Txxxx IDs must be verified on atlas.mitre.org before display — names only here.
 * Tag tactic/technique NAMES freely; cite a specific AML.Txxxx code only once checked.
 */
export const ATLAS_TACTICS = {
  PROMPT_INJECTION: "Prompt Injection",
  EXFILTRATION_VIA_ML_INFERENCE_API: "Exfiltration via ML Inference API",
} as const;

export type AtlasTactic =
  (typeof ATLAS_TACTICS)[keyof typeof ATLAS_TACTICS];

/**
 * MITRE ATT&CK — exfiltration side, used to label detection blind spots.
 * Includes the tactic (TA0010) and the techniques we reference.
 */
export const ATTACK = {
  TA0010: "Exfiltration",
  T1041: "Exfiltration Over C2 Channel",
} as const;

export type AttackId = keyof typeof ATTACK;
