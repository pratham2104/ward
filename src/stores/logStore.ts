/**
 * Log store — append-only telemetry rows (LogEvent), queryable per run.
 * Backend: ClickHouse when config.clickhouseUrl is set, else better-sqlite3.
 * Pure plumbing; no security logic.
 *
 * Schema (matches LogEvent): ts, run_id, actor, event_type, payload_summary, canary_present.
 */
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { config } from "../config";
import type { LogEvent, LogStore } from "../types";

const REPORTS_DIR = resolve(process.cwd(), "reports");
const TABLE = "ward_logs";

async function makeClickHouseLogStore(): Promise<LogStore> {
  const { createClient } = await import("@clickhouse/client");
  const client = createClient({
    url: config.clickhouseUrl,
    username: config.clickhouseUser,
    password: config.clickhousePassword,
  });
  console.log(`[logStore] backend=clickhouse url=${config.clickhouseUrl} table=${TABLE}`);

  return {
    async init(): Promise<void> {
      await client.command({
        query: `
          CREATE TABLE IF NOT EXISTS ${TABLE} (
            ts              String,
            run_id          String,
            actor           String,
            event_type      String,
            payload_summary String,
            canary_present  UInt8
          ) ENGINE = MergeTree()
          ORDER BY (run_id, ts)
        `,
      });
    },
    async write(e: LogEvent): Promise<void> {
      await client.insert({
        table: TABLE,
        values: [
          {
            ts: e.ts,
            run_id: e.runId,
            actor: e.actor,
            event_type: e.eventType,
            payload_summary: e.payloadSummary,
            canary_present: e.canaryPresent ? 1 : 0,
          },
        ],
        format: "JSONEachRow",
      });
    },
    async query(runId: string): Promise<LogEvent[]> {
      const rs = await client.query({
        query: `
          SELECT ts, run_id, actor, event_type, payload_summary, canary_present
          FROM ${TABLE}
          WHERE run_id = {runId:String}
          ORDER BY ts ASC
        `,
        query_params: { runId },
        format: "JSONEachRow",
      });
      const rows = (await rs.json()) as Array<{
        ts: string;
        run_id: string;
        actor: LogEvent["actor"];
        event_type: LogEvent["eventType"];
        payload_summary: string;
        canary_present: number;
      }>;
      return rows.map((r) => ({
        ts: r.ts,
        runId: r.run_id,
        actor: r.actor,
        eventType: r.event_type,
        payloadSummary: r.payload_summary,
        canaryPresent: Number(r.canary_present) === 1,
      }));
    },
  };
}

async function makeSqliteLogStore(): Promise<LogStore> {
  mkdirSync(REPORTS_DIR, { recursive: true });
  const file = resolve(REPORTS_DIR, "logs.sqlite");
  const { default: Database } = await import("better-sqlite3");
  const db = new Database(file);
  db.pragma("journal_mode = WAL");
  console.log(`[logStore] backend=sqlite file=${file} table=${TABLE}`);

  return {
    async init(): Promise<void> {
      db.exec(`
        CREATE TABLE IF NOT EXISTS ${TABLE} (
          ts              TEXT,
          run_id          TEXT,
          actor           TEXT,
          event_type      TEXT,
          payload_summary TEXT,
          canary_present  INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_${TABLE}_run_id ON ${TABLE} (run_id, ts);
      `);
    },
    async write(e: LogEvent): Promise<void> {
      db.prepare(
        `INSERT INTO ${TABLE} (ts, run_id, actor, event_type, payload_summary, canary_present)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).run(e.ts, e.runId, e.actor, e.eventType, e.payloadSummary, e.canaryPresent ? 1 : 0);
    },
    async query(runId: string): Promise<LogEvent[]> {
      const rows = db
        .prepare(
          `SELECT ts, run_id, actor, event_type, payload_summary, canary_present
           FROM ${TABLE} WHERE run_id = ? ORDER BY ts ASC`,
        )
        .all(runId) as Array<{
        ts: string;
        run_id: string;
        actor: LogEvent["actor"];
        event_type: LogEvent["eventType"];
        payload_summary: string;
        canary_present: number;
      }>;
      return rows.map((r) => ({
        ts: r.ts,
        runId: r.run_id,
        actor: r.actor,
        eventType: r.event_type,
        payloadSummary: r.payload_summary,
        canaryPresent: Number(r.canary_present) === 1,
      }));
    },
  };
}

export async function makeLogStore(): Promise<LogStore> {
  const store = config.clickhouseUrl
    ? await makeClickHouseLogStore()
    : await makeSqliteLogStore();
  await store.init?.();
  return store;
}
