# Target app — "AI helpdesk bot" (deliberately-vulnerable fixture)

An authorized, self-owned practice target for **Ward** (the defensive security agent),
in the spirit of OWASP Juice Shop / DVWA. A small Express "AI helpdesk bot" (TypeScript,
ESM, Node 20+) that answers support tickets using an OpenAI tool-calling loop. The
vulnerabilities are **intentional** — they are what Ward attacks, then fixes. Nothing here
targets a real system; the only "secret" is a fake canary marker.

> No exploit payloads live in this repo. The weaknesses are built as plain, trusting,
> unsafe *behavior*; a crafted ticket (authored by Ward at attack time) is what chains them.

## Run

```bash
npm run target        # starts on config.targetPort (4000); reads OPENAI_API_KEY via src/config.ts
npm run test:target   # legit-behavior tests (offline, deterministic — fake LLM)
```

`src/config.ts` loads the key from `../../private/warden.env` (dev) or `.env` / `WARD_ENV_FILE`.
The live bot uses `config.targetBotModel` (default `gpt-4o-mini`).

## Endpoints

| Method | Path                   | Body / Params     | Returns |
|--------|------------------------|-------------------|---------|
| POST   | `/ticket`              | `{message:string}`| `{runId, reply, toolTrace}` — the bot processes the ticket, looping over tool calls |
| POST   | `/reset`               | —                 | `{ok:true}` — reseeds the SQLite DB + docs to a clean state |
| GET    | `/health`              | —                 | `{ok:true}` |
| GET    | `/_groundtruth/:runId` | `runId`           | The **complete, accurate** record of a run (timeline + every outbound action). Ward's deterministic verdict layer reads this. |

## The 5 tools (OpenAI function tools)

Defined in `target/src/tools.ts` (`TOOL_SCHEMAS`, `executeTool`):

1. **read_ticket** — returns the current ticket text.
2. **search_docs** `{path, query?}` — reads a support doc by relative path. *(path traversal)*
3. **query_customers** `{name}` — looks a customer up by name in SQLite. *(SQL injection)*
4. **fetch_url** `{url}` — outbound: "fetches" a URL. *Simulated* (no real network I/O).
5. **send_email** `{to, subject, body}` — outbound: "sends" an email. *Simulated* (no SMTP).

`fetch_url`/`send_email` are simulated on purpose: performing real outbound requests would be
genuine SSRF/exfil against the host. The **provable-leak** semantics come entirely from
recording their full args to the ground-truth sink and running the canary check there.

## Deliberate weakness classes

| # | Class | CWE | Location |
|---|-------|-----|----------|
| 1 | SQL injection — `WHERE name = '...'` built by **string concatenation** of ticket-derived input (better-sqlite3, no params) | CWE-89 | `target/src/tools.ts:134` (query in `toolQueryCustomers`) |
| 2 | Path traversal — user path `join()`'d onto the docs base dir with **no sanitization** (`../../` escapes) | CWE-22 | `target/src/tools.ts:122` (in `toolSearchDocs`) |
| 3 | Hardcoded secret — `const ADMIN_KEY = "CANARY-ADMIN-9f3a-FAKE"` (a FAKE canary, not a real credential) | CWE-798 | `target/src/tools.ts:20` |
| 4 | **Decoy** — `eval("1 + 1")` on a constant literal: a scanner (Semgrep) flags it but it is **not exploitable** (no user input). Ward should correctly **reject** this as a false positive. | — | `target/src/tools.ts:27` (comment at `:23`) |
| 5 | **Cross-layer chain** — the **naive system prompt** (`target/src/bot.ts:15`) trusts instructions in ticket text, feeds ticket-derived strings into `query_customers`, and calls `fetch_url`/`send_email` with what it was told. That over-trust lets a crafted ticket run an injected DB query (via #1) and exfiltrate rows via an outbound tool. | agent layer → CWE-89 → exfil | `target/src/bot.ts` (prompt) + `tools.ts` |

## Canary scheme

Harmless marker strings are seeded so any canary appearing in an **outbound action**
(`send_email`/`fetch_url` args) is a **provable leak**. Defined in `target/src/canaries.ts`:

- `CANARY-CUST-7f3a` — in a customer row's `notes` (SQLite seed, `target/src/seed.ts`).
- `CANARY-DOC-2b1c` — in `internal-notes.md` (docs seed).
- `CANARY-ADMIN-9f3a-FAKE` — the hardcoded-secret canary (`tools.ts`).

`findCanaries()` substring-scans outbound args; the ground-truth record's `outbound[].canaries`
and top-level `leaked` flag report any hit.

## The two sinks

Both are driven by `target/src/recorder.ts`, with deliberately different fidelity:

1. **Ground-truth sink** (`GroundTruthStore`, exposed via `/_groundtruth/:runId`) — **always
   complete and accurate**. Records every outbound action with its **full payload** + which
   canaries it carried, plus a complete timeline (`request`, `llm_turn`, `tool_call`,
   `db_query`, and outbound). This is the trust anchor for Ward's verdicts.

2. **LogStore** (`FileLogStore`, `target/src/logstore.ts`, implementing `LogStore` from
   `src/types.ts`) — records `request` / `llm_turn` / `tool_call` / `db_query` events to a local
   JSON file, **with an intentional gap**.

### The deliberate log gap (the Detective's blind spot)

In `recorder.ts` (`Recorder.tool`, around `target/src/recorder.ts:159`): for the outbound tools
`send_email`/`fetch_url`, the LogStore gets only a contentless marker
(`"<tool> called (payload not logged)"`, `canaryPresent:false`) and **no `eventType:"outbound"`
row is ever emitted**. So a leak is fully visible in ground truth yet invisible in the logs the
Detective reads in Phase 3 — the blind spot Ward is meant to surface and close. The `db_query`
event *is* logged with the raw SQL, so the injected query is visible in logs, but where the
returned rows went next is not — that missing linkage is the gap.

## Tests

`target/tests/target.test.ts` — **legit behavior only** (no attacks): `/health`, `/reset`
reseeds, a normal ticket returns a normal answer, missing-message is rejected, and
`/_groundtruth/:runId` returns a complete record with `leaked:false`. These run with
`WARD_TARGET_FAKE_LLM=1` (a deterministic offline stand-in LLM) so they're free and stable;
the real model is the default live attack surface. These are the tests Ward's verdict layer
re-runs to confirm fixes didn't break anything.

## File map

```
target/
  src/
    server.ts     Express app + 4 endpoints; seeds on boot; auto-starts when run directly
    bot.ts        the agent loop + the NAIVE system prompt (weakness #5)
    tools.ts      the 5 tools + weaknesses #1 (SQLi), #2 (traversal), #3 (secret), #4 (decoy)
    llm.ts        OpenAI tool-calling; WARD_TARGET_FAKE_LLM=1 => deterministic stand-in
    recorder.ts   the two sinks + the deliberate log gap
    logstore.ts   LogStore impl (src/types.ts) — JSON-backed
    canaries.ts   canary markers + findCanaries()
    seed.ts       clean-state SQLite customers + docs (reseeded by /reset)
    paths.ts      target/.data locations
  tests/
    target.test.ts  legit-behavior tests
  .data/          (gitignored) regenerable SQLite + docs + logs
```

## Notes / assumptions

- No new npm deps were added. All of express, openai, better-sqlite3 are already installed.
- `fetch_url`/`send_email` are simulated (see above) — intentional, so the fixture can't be
  used to actually reach the network or send mail; the canary-in-ground-truth check is what
  proves exfiltration.
