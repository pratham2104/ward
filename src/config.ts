/**
 * Ward config + env loader.
 * Loads env from (in order): WARD_ENV_FILE, ./.env, or ../../private/warden.env (dev convenience).
 * Hard requirements fail fast; optional services warn and fall back.
 */
import dotenv from "dotenv";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

const candidates = [
  process.env.WARD_ENV_FILE,
  resolve(process.cwd(), ".env"),
  resolve(process.cwd(), "../../private/warden.env"), // dev: private folder outside the repo
].filter(Boolean) as string[];

const envPath = candidates.find((p) => existsSync(p));
if (envPath) dotenv.config({ path: envPath });

function need(key: string): string {
  const v = process.env[key];
  if (!v) {
    console.error(`[config] FATAL: missing required env ${key}`);
    process.exit(1);
  }
  return v;
}
function opt(key: string, fallback = ""): string {
  return process.env[key] ?? fallback;
}

export const config = {
  envPath,

  // 1. OpenAI (hard requirement). Model ids default to known-good, override in env on the day.
  openaiKey: need("OPENAI_API_KEY"),
  wardAgentModel: opt("WARDEN_AGENT_MODEL") || "gpt-4o",
  targetBotModel: opt("TARGET_BOT_MODEL") || "gpt-4o-mini",
  anthropicKey: opt("ANTHROPIC_API_KEY"),

  // 2. GitHub (needed only at PR phase)
  githubToken: opt("GITHUB_TOKEN"),
  githubRepo: opt("GITHUB_REPO"),

  // 3. MongoDB (case store) — falls back to local JSON if absent
  mongoUri: opt("MONGODB_URI"),

  // 4. ClickHouse (logs) — falls back to SQLite if absent
  clickhouseUrl: opt("CLICKHOUSE_URL"),
  clickhouseUser: opt("CLICKHOUSE_USER", "default"),
  clickhousePassword: opt("CLICKHOUSE_PASSWORD"),

  // 5. Email notifier — optional
  resendKey: opt("RESEND_API_KEY"),
  notifyEmailTo: opt("NOTIFY_EMAIL_TO"),

  // 6. Semgrep — CLI, token optional
  semgrepToken: opt("SEMGREP_APP_TOKEN"),

  // runtime knobs
  stepCap: Number(opt("WARD_STEP_CAP", "60")),
  retryCap: Number(opt("WARD_RETRY_CAP", "3")),
  targetPort: Number(opt("TARGET_PORT", "4000")),
  dashboardPort: Number(opt("DASHBOARD_PORT", "4100")),
};

export function reportConfig() {
  const has = (v: string) => (v ? "✓" : "—");
  console.log(`[config] env: ${envPath ?? "(none found — using process env only)"}`);
  console.log(
    `[config] OpenAI ✓  GitHub ${has(config.githubToken)}  Mongo ${has(config.mongoUri)}  ` +
      `ClickHouse ${has(config.clickhouseUrl)}  Email ${has(config.resendKey)}`,
  );
  console.log(`[config] models: agent=${config.wardAgentModel} target=${config.targetBotModel}`);
  if (!config.mongoUri) console.log("[config] Mongo absent → case store falls back to local JSON");
  if (!config.clickhouseUrl) console.log("[config] ClickHouse absent → logs fall back to SQLite");
}
