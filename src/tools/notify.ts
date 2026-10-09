/**
 * Email notifier via Resend. Fires once a run completes. Optional: if no key,
 * it no-ops (email is first in the cut-order).
 */
import { Resend } from "resend";
import { config } from "../config.js";
import type { CaseFile } from "../types.js";

export async function notifyDone(c: CaseFile, prUrl?: string): Promise<boolean> {
  if (!config.resendKey || !config.notifyEmailTo) return false;
  const resend = new Resend(config.resendKey);
  const verified = c.findings.filter((f) => f.status === "verified").length;
  const blind = c.findings.filter((f) => f.blindSpot).length;
  const html = `
    <h2>Ward run complete — ${c.target.repo}</h2>
    <ul>
      <li><b>${c.findings.length}</b> findings · <b>${verified}</b> fixed & verified · <b>${blind}</b> detection blind spots closed</li>
      <li>Detective coverage: <b>${Math.round(c.coverageScore * 100)}%</b></li>
      <li>Time: <b>${c.meters.wallClockS}s</b> · Cost: <b>$${c.meters.costUsd.toFixed(2)}</b></li>
      ${prUrl ? `<li>PR awaiting your approval: <a href="${prUrl}">${prUrl}</a></li>` : ""}
    </ul>
    <p>Autonomous run. Fixes ship as a pull request for human approval.</p>`;
  try {
    await resend.emails.send({
      from: config.notifyEmailTo ? (process.env.NOTIFY_EMAIL_FROM || "onboarding@resend.dev") : "onboarding@resend.dev",
      to: config.notifyEmailTo,
      subject: `Ward: ${verified} fixed on ${c.target.repo} (${c.meters.wallClockS}s, $${c.meters.costUsd.toFixed(2)})`,
      html,
    });
    return true;
  } catch (e) {
    console.error("[notify] email failed:", (e as Error).message);
    return false;
  }
}
