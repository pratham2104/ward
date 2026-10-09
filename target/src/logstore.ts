/**
 * LogStore — the telemetry sink the Detective (Ward Phase 3) is allowed to read.
 * Implements the shared LogStore interface from src/types.ts. Backed by a local
 * JSON file + in-memory mirror (a ClickHouse/SQLite swap is a drop-in later).
 *
 * NOTE: this sink is deliberately INCOMPLETE. The GAPS are not created here — they
 * are created by the Recorder (recorder.ts), which decides what it hands this store.
 * This class faithfully persists whatever it is given; see recorder.ts for the
 * intentional blind spot (outbound send_email/fetch_url payloads are never written).
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import type { LogEvent, LogStore } from "../../src/types";
import { LOG_PATH } from "./paths";

export class FileLogStore implements LogStore {
  private events: LogEvent[] = [];

  async init(): Promise<void> {
    if (existsSync(LOG_PATH)) {
      try {
        this.events = JSON.parse(readFileSync(LOG_PATH, "utf8")) as LogEvent[];
      } catch {
        this.events = [];
      }
    } else {
      this.events = [];
    }
  }

  async write(e: LogEvent): Promise<void> {
    this.events.push(e);
    try {
      writeFileSync(LOG_PATH, JSON.stringify(this.events, null, 2), "utf8");
    } catch {
      /* best-effort persistence; in-memory copy is authoritative for the demo */
    }
  }

  async query(runId: string): Promise<LogEvent[]> {
    if (runId === "*") return [...this.events];
    return this.events.filter((e) => e.runId === runId);
  }
}
