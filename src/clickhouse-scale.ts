/**
 * ClickHouse real-time-analytics-at-scale demo (ClickHouse sponsor track).
 *
 * Ward streams one telemetry row per attack step, tool call and verdict. Across a
 * FLEET of monitored AI apps that is high-volume security data. This script loads
 * a realistic fleet's worth of it into ClickHouse, then runs the analytical queries
 * that drive Ward's threat detection — showing data scale AND query latency.
 *
 *   npm run ch:scale            # load (default 1,000,000 rows) + run the queries
 *   npm run ch:scale -- 2000000 # custom row count
 *   npm run ch:scale -- query   # skip loading, just run the queries
 */
import { createClient } from "@clickhouse/client";
import { config } from "./config";

const TABLE = "ward_attack_telemetry";

const APPS = Array.from({ length: 50 }, (_, i) => `app-${String(i + 1).padStart(3, "0")}`);
const EVENTS = ["ticket_received", "llm_turn", "tool_call", "db_query", "send_email", "fetch_url", "verdict"] as const;
const TECHNIQUES = ["benign", "prompt_injection", "sql_injection", "data_exfiltration", "excessive_agency", "path_traversal"] as const;

function pick<T>(xs: readonly T[]): T {
  return xs[Math.floor(Math.random() * xs.length)];
}

async function load(client: ReturnType<typeof createClient>, total: number) {
  await client.command({
    query: `
      CREATE TABLE IF NOT EXISTS ${TABLE} (
        ts             DateTime64(3),
        app_id         LowCardinality(String),
        run_id         String,
        actor          LowCardinality(String),
        event_type     LowCardinality(String),
        technique      LowCardinality(String),
        canary_present UInt8,
        blocked        UInt8,
        latency_ms     UInt16
      ) ENGINE = MergeTree()
      ORDER BY (app_id, ts)
    `,
  });
  await client.command({ query: `TRUNCATE TABLE IF EXISTS ${TABLE}` });

  const BATCH = 100_000;
  const now = Date.now();
  let written = 0;
  const t0 = Date.now();
  while (written < total) {
    const n = Math.min(BATCH, total - written);
    const rows = new Array(n);
    for (let i = 0; i < n; i++) {
      // Realistic mix: mostly benign traffic, a minority of attacks, a slice of which exfiltrate.
      const attack = Math.random() < 0.18;
      const technique = attack ? pick(TECHNIQUES.filter((t) => t !== "benign")) : "benign";
      const event_type = pick(EVENTS);
      const exfil = technique === "data_exfiltration" && (event_type === "send_email" || event_type === "fetch_url");
      const canary_present = exfil && Math.random() < 0.7 ? 1 : 0;
      // The blind spot: outbound exfiltration rows are the LEAST likely to be blocked/caught.
      const blocked = attack ? (exfil ? (Math.random() < 0.15 ? 1 : 0) : (Math.random() < 0.6 ? 1 : 0)) : 0;
      rows[i] = {
        ts: new Date(now - Math.floor(Math.random() * 7 * 24 * 3600 * 1000)).toISOString().replace("T", " ").replace("Z", ""),
        app_id: pick(APPS),
        run_id: `run-${Math.floor(Math.random() * 20000)}`,
        actor: pick(["user", "bot", "tool", "ward"]),
        event_type,
        technique,
        canary_present,
        blocked,
        latency_ms: Math.floor(Math.random() * 1200),
      };
    }
    await client.insert({ table: TABLE, values: rows, format: "JSONEachRow" });
    written += n;
    process.stdout.write(`\r  loaded ${written.toLocaleString()} / ${total.toLocaleString()} rows…`);
  }
  console.log(`\n  ✓ loaded ${total.toLocaleString()} rows in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
}

async function timed(client: ReturnType<typeof createClient>, label: string, query: string) {
  const t0 = Date.now();
  const rs = await client.query({ query, format: "JSONEachRow" });
  const rows = (await rs.json()) as Record<string, unknown>[];
  const ms = Date.now() - t0;
  console.log(`\n▶ ${label}   (${ms} ms)`);
  for (const r of rows.slice(0, 8)) console.log("   ", JSON.stringify(r));
  return ms;
}

async function queries(client: ReturnType<typeof createClient>) {
  const total = (await (await client.query({ query: `SELECT count() AS c FROM ${TABLE}`, format: "JSONEachRow" })).json()) as { c: string }[];
  console.log(`\n=== Analytics over ${Number(total[0].c).toLocaleString()} rows ===`);

  await timed(client, "Attack intelligence — volume & canary-leak rate by technique",
    `SELECT technique,
            count() AS events,
            sum(canary_present) AS canary_leaks,
            round(100 * sum(canary_present) / count(), 2) AS leak_pct
     FROM ${TABLE} WHERE technique != 'benign'
     GROUP BY technique ORDER BY events DESC`);

  await timed(client, "Detection — DATA EXFILTRATION that was NOT blocked (the blind spot), top apps",
    `SELECT app_id,
            count() AS exfil_events,
            sum(canary_present) AS with_canary
     FROM ${TABLE}
     WHERE technique = 'data_exfiltration' AND event_type IN ('send_email','fetch_url') AND blocked = 0
     GROUP BY app_id ORDER BY exfil_events DESC LIMIT 5`);

  await timed(client, "Monitoring — unblocked-attack rate per hour (last 24h)",
    `SELECT toStartOfHour(ts) AS hour,
            countIf(blocked = 0 AND technique != 'benign') AS unblocked_attacks
     FROM ${TABLE} WHERE ts > now() - INTERVAL 24 HOUR
     GROUP BY hour ORDER BY hour DESC LIMIT 6`);

  await timed(client, "p95 tool-call latency by event type (ops health)",
    `SELECT event_type, quantile(0.95)(latency_ms) AS p95_ms, count() AS n
     FROM ${TABLE} GROUP BY event_type ORDER BY p95_ms DESC`);
}

async function main() {
  if (!config.clickhouseUrl) {
    console.error("ClickHouse not configured (CLICKHOUSE_URL). Aborting.");
    process.exit(1);
  }
  const arg = process.argv[2];
  const client = createClient({ url: config.clickhouseUrl, username: config.clickhouseUser, password: config.clickhousePassword });
  console.log(`[ch:scale] ${config.clickhouseUrl} table=${TABLE}`);
  if (arg !== "query") {
    const total = Number.isFinite(Number(arg)) && Number(arg) > 0 ? Number(arg) : 1_000_000;
    await load(client, total);
  }
  await queries(client);
  await client.close();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
