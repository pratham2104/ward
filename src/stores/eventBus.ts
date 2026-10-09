/**
 * Event bus — in-memory pub/sub for WardEvents.
 * The orchestrator publishes; the dashboard SSE endpoint subscribes.
 * Keeps a full history so late subscribers can replay what they missed.
 */
import type { EventBus, WardEvent } from "../types";

export function makeEventBus(): EventBus {
  const subscribers = new Set<(e: WardEvent) => void>();
  const log: WardEvent[] = [];

  return {
    emit(e: WardEvent): void {
      log.push(e);
      for (const fn of subscribers) {
        try {
          fn(e);
        } catch (err) {
          // One bad subscriber must not break the fan-out or the publisher.
          console.error("[eventBus] subscriber threw:", err);
        }
      }
    },
    subscribe(fn: (e: WardEvent) => void): () => void {
      subscribers.add(fn);
      return () => {
        subscribers.delete(fn);
      };
    },
    history(): WardEvent[] {
      return log.slice();
    },
  };
}
