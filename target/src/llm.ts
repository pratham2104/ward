/**
 * LLM access for the target bot. Default path is a real OpenAI call (this is what
 * Ward attacks). A deterministic FAKE path (WARD_TARGET_FAKE_LLM=1) is used by the
 * legit test suite so tests are offline, free, and stable — it never touches the
 * network and never needs a real key.
 */
import OpenAI from "openai";
import { config } from "../../src/config";

export interface LlmToolCall {
  id: string;
  name: string;
  arguments: string; // raw JSON string from the model
}
export interface LlmResult {
  content: string | null;
  toolCalls: LlmToolCall[];
}

const FAKE = process.env.WARD_TARGET_FAKE_LLM === "1";

let client: OpenAI | null = null;
function getClient(): OpenAI {
  if (!client) client = new OpenAI({ apiKey: config.openaiKey });
  return client;
}

export async function llmChat(messages: any[], tools: any[]): Promise<LlmResult> {
  if (FAKE) return fakeChat(messages);

  const resp = await getClient().chat.completions.create({
    model: config.targetBotModel,
    messages,
    tools,
    tool_choice: "auto",
    temperature: 0.2,
  });
  const m = resp.choices[0].message;
  return {
    content: m.content ?? null,
    toolCalls: (m.tool_calls ?? []).map((tc: any) => ({
      id: tc.id,
      name: tc.function.name,
      arguments: tc.function.arguments,
    })),
  };
}

/**
 * Deterministic stand-in for the tests. Returns a plain, helpful reply with no tool
 * calls — enough to prove "a normal ticket gets a normal answer" without the network.
 * It intentionally has no attack behavior; the real model provides the live surface.
 */
function fakeChat(_messages: any[]): LlmResult {
  return {
    content:
      "Thanks for contacting Acme Cloud support! Our support hours are Monday to " +
      "Friday, 9am-5pm Pacific. If there's anything else I can help with, just reply here.",
    toolCalls: [],
  };
}

export const usingFakeLlm = FAKE;
