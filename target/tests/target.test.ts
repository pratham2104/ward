/**
 * Legit-behavior tests for the target helpdesk bot. These are the tests Ward's
 * verdict layer runs to confirm "the fixes didn't break anything." They cover ONLY
 * normal, intended behavior — NO attack payloads.
 *
 * They run with WARD_TARGET_FAKE_LLM=1 so the bot uses a deterministic stand-in LLM:
 * offline, free, and stable. A fallback OPENAI_API_KEY is set before import so the
 * config loader never aborts even if the private env file is absent.
 */
import type { Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

process.env.OPENAI_API_KEY ||= "sk-test-fake-not-used";
process.env.WARD_TARGET_FAKE_LLM = "1";

let server: Server;
let base: string;

beforeAll(async () => {
  const { startServer } = await import("../src/server");
  server = startServer(0); // ephemeral port
  await new Promise<void>((r) => server.on("listening", () => r()));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  base = `http://127.0.0.1:${port}`;
});

afterAll(() => {
  server?.close();
});

describe("target helpdesk bot — legit behavior", () => {
  it("GET /health returns ok", async () => {
    const res = await fetch(`${base}/health`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("POST /reset reseeds to a clean state", async () => {
    const res = await fetch(`${base}/reset`, { method: "POST" });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("POST /ticket on a normal ticket returns a normal answer", async () => {
    const res = await fetch(`${base}/ticket`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ message: "Hi, what are your support hours?" }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      runId: string;
      reply: string;
      toolTrace: unknown[];
    };
    expect(typeof body.runId).toBe("string");
    expect(body.runId.length).toBeGreaterThan(0);
    expect(typeof body.reply).toBe("string");
    expect(body.reply.length).toBeGreaterThan(0);
    expect(Array.isArray(body.toolTrace)).toBe(true);
  });

  it("POST /ticket with no message is rejected", async () => {
    const res = await fetch(`${base}/ticket`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
  });

  it("GET /_groundtruth/:runId returns a complete run record", async () => {
    const ticketRes = await fetch(`${base}/ticket`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ message: "Do you offer refunds?" }),
    });
    const { runId } = (await ticketRes.json()) as { runId: string };

    const gtRes = await fetch(`${base}/_groundtruth/${runId}`);
    expect(gtRes.status).toBe(200);
    const gt = (await gtRes.json()) as {
      runId: string;
      timeline: unknown[];
      outbound: unknown[];
      leaked: boolean;
    };
    expect(gt.runId).toBe(runId);
    expect(Array.isArray(gt.timeline)).toBe(true);
    expect(gt.timeline.length).toBeGreaterThan(0);
    expect(Array.isArray(gt.outbound)).toBe(true);
    // A normal ticket leaks nothing.
    expect(gt.leaked).toBe(false);
  });

  it("GET /_groundtruth of an unknown run is a 404", async () => {
    const res = await fetch(`${base}/_groundtruth/does-not-exist`);
    expect(res.status).toBe(404);
  });
});
