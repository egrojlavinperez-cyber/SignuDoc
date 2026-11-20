// Runs once when a server starts, before it handles requests.

export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    // Sends API webhooks when something happens to an envelope.
    const { registerWebhookTrigger } =
      await import("./lib/api/webhook-trigger");

    registerWebhookTrigger();
  }
}
