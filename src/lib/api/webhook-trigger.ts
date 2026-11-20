import { after } from "next/server";

import { logSecurityEvent } from "../security/logging.ts";
import { WEBHOOK_EVENT_FOR_AUDIT_EVENT } from "./webhook-events.ts";

// Starts webhook deliveries soon after something happens to an envelope,
// instead of waiting for the daily sweep. The work runs after the response
// that caused it, and keeps going for a while to retry failed deliveries
// (10 seconds, 30 seconds, 90 seconds later). Deliveries still failing after
// that are retried by the next run: the next change to any envelope, a call
// to the API, or the daily sweep.
//
// This file is loaded when the server starts (src/instrumentation.ts), so
// the webhook sender, with the PDF and envelope code it needs, is loaded
// only when there is something to send.

/** How long a run keeps retrying after the response, in milliseconds. */
const RUN_BUDGET_MS = 150_000;

function logFailure(category: string, message: string, error: unknown) {
  logSecurityEvent("error", {
    category,
    message,
    metadata: { error: error instanceof Error ? error.message : "unknown" },
  });
}

function runAfterResponse(run: () => Promise<void>): void {
  try {
    after(run);
  } catch {
    // Not inside a request: nothing to wait for.
    void run();
  }
}

export function requestWebhookDispatch(): void {
  runAfterResponse(async () => {
    try {
      const { runWebhookDispatch } = await import("./webhooks.ts");

      await runWebhookDispatch({ budgetMs: RUN_BUDGET_MS });
    } catch (error) {
      logFailure("webhook_dispatch_failure", "Sending webhooks failed.", error);
    }
  });
}

/**
 * The daily sweep, after the cleanup job: sends anything still due, and
 * forgets finished deliveries and Idempotency-Keys after 30 days.
 */
export function requestDailyWebhookSweep(): void {
  runAfterResponse(async () => {
    try {
      const [{ deleteOldWebhookDeliveries, runWebhookDispatch }, envelopes] =
        await Promise.all([import("./webhooks.ts"), import("./envelopes.ts")]);

      await deleteOldWebhookDeliveries();
      await envelopes.deleteExpiredIdempotencyKeys();
      await runWebhookDispatch({ budgetMs: RUN_BUDGET_MS });
    } catch (error) {
      logFailure(
        "webhook_sweep_failure",
        "The daily webhook sweep failed.",
        error,
      );
    }
  });
}

export function registerWebhookTrigger(): void {
  globalThis.__signudocOnEnvelopeAuditEvent = ({ event }) => {
    if (WEBHOOK_EVENT_FOR_AUDIT_EVENT[event]) {
      requestWebhookDispatch();
    }
  };
}
