/**
 * Ward mission-control dashboard — SSE server.
 *
 * startDashboard(bus, port?) stands up an Express server that:
 *   - GET /         -> the single hand-coded page (public/index.html + app.js + styles.css)
 *   - GET /events   -> a Server-Sent Events stream: replays bus.history() on connect,
 *                      then pushes every new WardEvent as it is emitted.
 *
 * The dashboard is a pure renderer. It never drives the agent; it only subscribes
 * to the EventBus the orchestrator publishes to (see src/types.ts -> WardEvent).
 */
import express from "express";
import { createServer, type Server } from "node:http";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { config } from "../config";
import type { EventBus, WardEvent } from "../types";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, "public");

export interface DashboardHandle {
  server: Server;
  port: number;
  url: string;
  close: () => Promise<void>;
}

/**
 * Start the dashboard. Returns a handle once the socket is listening.
 * `port` defaults to config.dashboardPort (4100).
 */
export function startDashboard(bus: EventBus, port: number = config.dashboardPort): Promise<DashboardHandle> {
  const app = express();

  // Static single page + assets. index.html is served at GET / by express.static.
  app.use(express.static(PUBLIC_DIR));

  // Explicit root so GET / always resolves even if static index is disabled.
  app.get("/", (_req, res) => {
    res.sendFile(join(PUBLIC_DIR, "index.html"));
  });

  // Server-Sent Events: the live stream the page consumes.
  app.get("/events", (req, res) => {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      // Disable proxy buffering so events flush immediately (nginx et al.).
      "X-Accel-Buffering": "no",
    });
    res.flushHeaders?.();

    const send = (e: WardEvent) => {
      res.write(`data: ${JSON.stringify(e)}\n\n`);
    };

    // 1) Replay everything that already happened so a late-joining browser catches up.
    const history = bus.history();
    res.write(`event: hello\ndata: ${JSON.stringify({ replay: history.length })}\n\n`);
    for (const e of history) send(e);

    // 2) Subscribe to the live stream.
    const unsubscribe = bus.subscribe(send);

    // 3) Keep-alive comment every 15s so intermediaries don't drop an idle connection.
    const keepAlive = setInterval(() => res.write(`: ping ${Date.now()}\n\n`), 15_000);

    req.on("close", () => {
      clearInterval(keepAlive);
      unsubscribe();
      res.end();
    });
  });

  // Lightweight health probe (handy for the orchestrator / smoke tests).
  app.get("/healthz", (_req, res) => res.json({ ok: true, events: bus.history().length }));

  const server = createServer(app);

  return new Promise<DashboardHandle>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, () => {
      server.off("error", reject);
      const url = `http://localhost:${port}`;
      console.log(`[dashboard] live at ${url}  (SSE at ${url}/events)`);
      resolve({
        server,
        port,
        url,
        close: () =>
          new Promise<void>((res, rej) => server.close((err) => (err ? rej(err) : res()))),
      });
    });
  });
}
