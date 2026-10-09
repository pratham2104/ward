/**
 * Thin helpers over the LLM for the phases. askJSON returns parsed JSON (best
 * effort); askText returns a string. Both accumulate cost into the meter.
 */
import { chat, type ChatMsg, type CostMeter } from "./llm.js";

export async function askJSON<T = any>(
  system: string,
  user: string,
  meter: CostMeter,
  model?: string,
): Promise<T> {
  const messages: ChatMsg[] = [
    { role: "system", content: system + "\n\nRespond with ONLY valid JSON, no prose, no code fences." },
    { role: "user", content: user },
  ];
  const msg = await chat(messages, { meter, model, temperature: 0.3 });
  const raw = (msg.content ?? "").trim().replace(/^```(?:json)?/i, "").replace(/```$/, "").trim();
  try {
    return JSON.parse(raw) as T;
  } catch {
    const m = raw.match(/[\[{][\s\S]*[\]}]/);
    if (m) return JSON.parse(m[0]) as T;
    throw new Error("askJSON: model did not return JSON: " + raw.slice(0, 200));
  }
}

export async function askText(system: string, user: string, meter: CostMeter, model?: string): Promise<string> {
  const msg = await chat(
    [
      { role: "system", content: system },
      { role: "user", content: user },
    ],
    { meter, model },
  );
  return (msg.content ?? "").trim();
}
