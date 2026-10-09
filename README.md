# WARDEN

**An autonomous security engineer for AI apps.** Point it at a repo; it probes the app the way an
AI attacker would (agent layer + code layer), proves and fixes what it finds, re-probes until
nothing reproduces, reconstructs the attack from logs alone to catch detection blind spots, and
keeps watching — tagging every finding to OWASP-LLM / CWE / MITRE ATLAS / ATT&CK and shipping fixes
as a pull request a human approves. A live dashboard shows the whole loop with a time + cost meter.

Built for the Cyberdefense Hackathon · #SFTechWeek.

## The loop
`Discover → Remediate → Intelligence (Detective) → Continuous`

It fixes two kinds of weakness: the app being **penetrable** (data leaks) and the app being
**blind** (the attack left no trace in the logs — a detection gap WARDEN closes).

## The trust anchor
The agent never grades its own success. Every verdict — fixed / caught / clean — comes from
deterministic code: tests pass, a canary marker stays put, the scanner is clean, the log timeline
matches ground truth.

## Stack
Node + TypeScript · Express + SQLite (target app) · OpenAI (agent + target models) · Semgrep (code
scan) · ClickHouse (logs) · MongoDB (case store) · hand-coded live dashboard (SSE/WebSocket).

## Run
```
cp warden/.env.example warden/.env   # fill in your keys
npm install
npm run dev
```
Then open the dashboard, paste a target repo, and press **Run**.

## Layout
```
warden/
  orchestrator/   loop, caps, meters, event stream, case store I/O
  agent/          system + phase prompts, tool bindings
  tools/          scan, probe, file-edit, run-tests, log-query, pr, notify
  verdicts/       deterministic checks (Vitest, canary, scanner, timeline-diff)
  frameworks/     OWASP-LLM / CWE / ATLAS / ATT&CK tagging
  target/         the AI helpdesk app under test (+ tests, seed data)
  dashboard/      single-page live UI
  reports/        generated run reports
```

> Authorised, defensive use only. The target is a self-owned app built for the event; this repo
> contains no exploit payloads.
