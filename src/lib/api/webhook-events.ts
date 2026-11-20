// Which audit events become webhooks, and the webhook each becomes. On its
// own so the server's start-up code can check an event without loading the
// webhook sender and everything it needs.

export const WEBHOOK_EVENT_FOR_AUDIT_EVENT: Readonly<Record<string, string>> = {
  completed: "envelope.completed",
  declined: "envelope.declined",
  sent: "envelope.sent",
  signed: "envelope.signer_signed",
  viewed: "envelope.viewed",
  voided: "envelope.voided",
};
