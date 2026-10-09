/**
 * OpenAI wrapper for the Ward agent: tool-calling loop + token/cost accounting.
 * Cost feeds the dashboard's economics meter. Prices are per 1M tokens (USD),
 * overridable; unknown models fall back to a conservative default.
 */
import OpenAI from "openai";
import { config } from "../config.js";

const client = new OpenAI({ apiKey: config.openaiKey });

// USD per 1M tokens [input, output]. Approximate; adjust on the day if needed.
const PRICES: Record<string, [number, number]> = {
  "gpt-4o": [2.5, 10],
  "gpt-4o-mini": [0.15, 0.6],
  "gpt-4.1": [2.0, 8],
  "gpt-4.1-mini": [0.4, 1.6],
  "o4-mini": [1.1, 4.4],
};
const DEFAULT_PRICE: [number, number] = [2.5, 10];

function priceFor(model: string): [number, number] {
  if (PRICES[model]) return PRICES[model];
  const key = Object.keys(PRICES).find((k) => model.startsWith(k));
  return key ? PRICES[key] : DEFAULT_PRICE;
}

export interface CostMeter {
  usd: number;
  inputTokens: number;
  outputTokens: number;
}

export function newMeter(): CostMeter {
  return { usd: 0, inputTokens: 0, outputTokens: 0 };
}

export type ToolSpec = OpenAI.Chat.Completions.ChatCompletionTool;
export type ChatMsg = OpenAI.Chat.Completions.ChatCompletionMessageParam;

/** One model turn. Accumulates cost into `meter`. Returns the assistant message. */
export async function chat(
  messages: ChatMsg[],
  opts: { model?: string; tools?: ToolSpec[]; meter: CostMeter; temperature?: number } = {
    meter: newMeter(),
  },
): Promise<OpenAI.Chat.Completions.ChatCompletionMessage> {
  const model = opts.model ?? config.wardAgentModel;
  const res = await client.chat.completions.create({
    model,
    messages,
    tools: opts.tools,
    temperature: opts.temperature ?? 0.2,
  });
  const u = res.usage;
  if (u) {
    const [pin, pout] = priceFor(model);
    opts.meter.inputTokens += u.prompt_tokens ?? 0;
    opts.meter.outputTokens += u.completion_tokens ?? 0;
    opts.meter.usd +=
      ((u.prompt_tokens ?? 0) / 1e6) * pin + ((u.completion_tokens ?? 0) / 1e6) * pout;
  }
  return res.choices[0].message;
}

export { client as openai };
