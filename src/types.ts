/**
 * Ward shared contracts. ALL modules build to these types.
 * Parallel build agents: do not change these signatures without coordinating.
 */

export type Layer = "code" | "agent";
export type Severity = "low" | "medium" | "high" | "critical";
export type FindingStatus =
  | "found"
  | "proven"
  | "rejected"
  | "patched"
  | "verified"
  | "failed";

export interface FrameworkTags {
  owasp_llm: string[]; // e.g. ["LLM01", "LLM06"]
  cwe: string[]; // e.g. ["CWE-89"]
  atlas: string[]; // ATLAS tactic names (exact AML.Txxxx IDs flagged unverified)
  attack: string[]; // MITRE ATT&CK, exfiltration side
}

export interface Finding {
  id: string;
  layer: Layer;
  technique: string;
  location: string; // "file:line" or a tool name
  severity: Severity;
  status: FindingStatus;
  frameworks: FrameworkTags;
  evidence: { probeRef?: string; verdict?: string; detail?: string };
  fix?: { diff: string; attempts: number };
  blindSpot: boolean; // true = attack step the logs did not record
}

export interface TimelineStep {
  t: string; // ISO timestamp
  step: string;
  signalExpected?: string; // what a log SHOULD have recorded
  fromLogs?: boolean; // true if the Detective derived it from logs alone
}

export interface DetectionRule {
  forFinding: string; // Finding.id
  pattern: string; // plain if-this-then-alert description
  mapsTo: string; // framework reference
}

export interface Meters {
  wallClockS: number;
  costUsd: number;
  steps: number;
}

export interface RunRecord {
  trigger: "manual" | "push" | "alert" | "variant";
  started: string;
  result: string;
}

export interface CaseFile {
  target: { repo: string; commit?: string };
  findings: Finding[];
  groundTruthTimeline: TimelineStep[];
  reconstructedTimeline: TimelineStep[];
  coverageScore: number; // matched / total
  detectionRules: DetectionRule[];
  meters: Meters;
  runs: RunRecord[];
}

export function emptyCase(repo: string): CaseFile {
  return {
    target: { repo },
    findings: [],
    groundTruthTimeline: [],
    reconstructedTimeline: [],
    coverageScore: 0,
    detectionRules: [],
    meters: { wallClockS: 0, costUsd: 0, steps: 0 },
    runs: [],
  };
}

/** One row in the log store. The target app emits these (with intentional gaps). */
export interface LogEvent {
  ts: string;
  runId: string;
  actor: "app" | "bot" | "tool";
  eventType: "request" | "llm_turn" | "tool_call" | "db_query" | "outbound";
  payloadSummary: string;
  canaryPresent: boolean;
}

/** Live events streamed to the dashboard (SSE). */
export type WardEvent =
  | { type: "phase"; phase: string; status: "start" | "done" }
  | { type: "log"; line: string }
  | { type: "finding"; finding: Finding }
  | { type: "meter"; meters: Meters }
  | { type: "verdict"; findingId: string; verdict: string; pass: boolean }
  | {
      type: "timeline";
      ground: TimelineStep[];
      reconstructed: TimelineStep[];
      coverage: number;
    }
  | { type: "continuous"; trigger: string }
  | { type: "done"; meters: Meters; prUrl?: string };

/** Pluggable stores (real impl + fallback share the interface). */
export interface CaseStore {
  load(): Promise<CaseFile>;
  save(c: CaseFile): Promise<void>;
}
export interface LogStore {
  write(e: LogEvent): Promise<void>;
  query(runId: string): Promise<LogEvent[]>;
  init?(): Promise<void>;
}

/** The event bus the orchestrator publishes to and the dashboard subscribes to. */
export interface EventBus {
  emit(e: WardEvent): void;
  subscribe(fn: (e: WardEvent) => void): () => void;
  history(): WardEvent[];
}
