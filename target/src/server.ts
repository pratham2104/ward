/**
 * The target "AI helpdesk bot" HTTP server.
 *
 * Endpoints:
 *   POST /ticket            {message}  -> {runId, reply, toolTrace}
 *   POST /reset                        -> {ok:true}   (reseed SQLite + docs to clean state)
 *   GET  /health                       -> {ok:true}
 *   GET  /_groundtruth/:runId          -> complete, accurate record of a run (verdict layer)
 *
 * This is an authorized, self-owned, deliberately-vulnerable practice fixture.
 */
import { randomUUID } from "node:crypto";
import { createServer as createHttpServer, type Server } from "node:http";
import { fileURLToPath } from "node:url";
import express from "express";
import { config } from "../../src/config";
import { runTicket } from "./bot";
import { FileLogStore } from "./logstore";
import { GroundTruthStore, Recorder } from "./recorder";
import { seedAll } from "./seed";

export function createApp() {
  const app = express();
  app.use(express.json({ limit: "1mb" }));

  const logs = new FileLogStore();
  const groundTruth = new GroundTruthStore();

  // Seed DB + docs and init the log store before serving.
  const ready = (async () => {
    seedAll();
    await logs.init();
  })();

  app.get("/health", (_req, res) => {
    res.json({ ok: true });
  });

  app.post("/reset", async (_req, res) => {
    try {
      seedAll();
      await logs.init();
      res.json({ ok: true });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err?.message ?? String(err) });
    }
  });

  app.post("/ticket", async (req, res) => {
    await ready;
    const message = req.body?.message;
    if (typeof message !== "string" || message.length === 0) {
      res.status(400).json({ error: "body.message (string) is required" });
      return;
    }
    const runId = randomUUID();
    const gtRec = groundTruth.create(runId, message);
    const recorder = new Recorder(runId, gtRec, logs);
    try {
      const { reply, toolTrace } = await runTicket(message, recorder);
      res.json({ runId, reply, toolTrace });
    } catch (err: any) {
      res.status(500).json({ runId, error: err?.message ?? String(err) });
    }
  });

  // Complete ground-truth record for a run — used by Ward's deterministic verdicts.
  app.get("/_groundtruth/:runId", (req, res) => {
    const rec = groundTruth.get(req.params.runId);
    if (!rec) {
      res.status(404).json({ error: "unknown runId" });
      return;
    }
    res.json(rec);
  });

  // The GAPPED application logs (what a real monitoring stack would have seen).
  // Ward's Detective reads THESE — intentionally missing the outbound rows — to
  // reconstruct the attack and discover the logging blind spot.
  app.get("/_logs/:runId", async (req, res) => {
    const rows = await logs.query(req.params.runId).catch(() => []);
    res.json({ runId: req.params.runId, logs: rows });
  });
  app.get("/_logs", async (_req, res) => {
    const rows = await logs.query("*").catch(() => []);
    res.json({ logs: rows });
  });

  return { app, ready };
}

export function startServer(port = config.targetPort): Server {
  const { app } = createApp();
  const server = createHttpServer(app);
  server.listen(port, () => {
    const addr = server.address();
    const p = typeof addr === "object" && addr ? addr.port : port;
    console.log(`[target] AI helpdesk bot listening on http://localhost:${p}`);
    console.log(`[target] model=${config.targetBotModel}  (deliberately-vulnerable fixture)`);
  });
  return server;
}

// Auto-start only when run directly (tsx target/src/server.ts), not when imported by tests.
const isMain = !!process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) startServer();
