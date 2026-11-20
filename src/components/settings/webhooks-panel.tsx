"use client";

import { useEffect, useState } from "react";

import { FieldShell, ShellButton } from "@/components/shared/form-shell";

// Where this site tells another system about envelopes made through the
// API, and how those deliveries went. Administrators only.

type Endpoint = {
  createdAt: number;
  id: string;
  previousSecretExpiresAt: number | null;
  updatedAt: number;
  url: string;
};

type Delivery = {
  attempts: number;
  createdAt: number;
  envelopeId: string;
  eventType: string;
  id: string;
  lastAttemptAt: number | null;
  lastError: string | null;
  lastStatusCode: number | null;
  nextAttemptAt: number | null;
  status: "delivered" | "failed" | "pending";
};

type State = { deliveries: Delivery[]; endpoint: Endpoint | null };
type Message = { text: string; tone: "error" | "success" } | null;

function formatTime(seconds: number | null): string {
  return seconds === null
    ? "—"
    : new Date(seconds * 1000).toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
      });
}

async function fetchWebhookState(): Promise<State> {
  const response = await fetch("/api/admin/webhooks");

  if (!response.ok) {
    throw new Error("Webhooks could not be loaded.");
  }

  return (await response.json()) as State;
}

function describeResult(delivery: Delivery): string {
  if (delivery.status === "delivered") {
    return `Delivered (${String(delivery.lastStatusCode ?? "")})`;
  }

  const last = delivery.lastError ?? "Not tried yet";

  return delivery.status === "failed"
    ? `Gave up: ${last}`
    : `${last}. Next try ${formatTime(delivery.nextAttemptAt)}`;
}

export function WebhooksPanel() {
  const [state, setState] = useState<State | null>(null);
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState<"remove" | "rotate" | "save" | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [message, setMessage] = useState<Message>(null);

  useEffect(() => {
    let cancelled = false;

    fetchWebhookState()
      .then((payload) => {
        if (!cancelled) {
          setState(payload);
          setUrl((current) => current || payload.endpoint?.url || "");
        }
      })
      .catch(() => {
        if (!cancelled) {
          setMessage({ text: "Webhooks could not be loaded.", tone: "error" });
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  async function refresh() {
    try {
      setState(await fetchWebhookState());
    } catch {
      setMessage({ text: "Webhooks could not be loaded.", tone: "error" });
    }
  }

  async function act(
    action: "remove" | "rotate" | "save",
    confirmText?: string,
  ) {
    if (confirmText && !window.confirm(confirmText)) {
      return;
    }

    setBusy(action);
    setMessage(null);
    setSecret(null);
    setCopied(false);

    try {
      const response = await fetch("/api/admin/webhooks", {
        body: JSON.stringify(action === "save" ? { action, url } : { action }),
        headers: { "content-type": "application/json" },
        method: "POST",
      });
      const payload = (await response.json().catch(() => null)) as
        (State & { error?: string; secret?: string | null }) | null;

      if (!response.ok || !payload) {
        setMessage({
          text: payload?.error ?? "That could not be saved.",
          tone: "error",
        });
        return;
      }

      setState({ deliveries: payload.deliveries, endpoint: payload.endpoint });
      setUrl(payload.endpoint?.url ?? "");
      setSecret(payload.secret ?? null);
      setMessage({
        text:
          action === "remove"
            ? "Webhooks are off."
            : action === "rotate"
              ? "New signing secret made. The old one keeps working for 24 hours."
              : "Saved.",
        tone: "success",
      });
    } catch {
      setMessage({ text: "That could not be saved.", tone: "error" });
    } finally {
      setBusy(null);
    }
  }

  async function copySecret() {
    if (!secret) {
      return;
    }

    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  const endpoint = state?.endpoint ?? null;

  return (
    <div className="space-y-5 border-t border-(--border) pt-8">
      <div className="space-y-2">
        <h3 className="text-lg font-extrabold tracking-[-0.02em] text-(--fg)">
          Webhooks
        </h3>
        <p className="max-w-2xl text-sm leading-6 text-(--secondary)">
          When an envelope made with an API key is sent, opened, signed,
          completed, declined or voided, this site tells the address below. Each
          message is signed with a secret, so the receiver can check it came
          from here. A message that is not answered with success is tried again
          for up to 24 hours.
        </p>
      </div>

      {secret ? (
        <div className="notice notice-success space-y-3" role="status">
          <p className="text-sm font-semibold">
            Copy the signing secret now and store it in the receiving
            system&apos;s secret settings. It is not shown again.
          </p>
          <code className="block break-all rounded-lg bg-(--surface) px-3 py-2 font-mono text-xs text-(--fg)">
            {secret}
          </code>
          <div className="flex flex-wrap gap-3">
            <ShellButton onClick={copySecret} variant="secondary">
              {copied ? "Copied" : "Copy secret"}
            </ShellButton>
            <ShellButton onClick={() => setSecret(null)} variant="ghost">
              Done
            </ShellButton>
          </div>
        </div>
      ) : null}

      <div className="grid max-w-xl gap-4">
        <FieldShell
          helper="Where the messages go, for example https://cu-os.vercel.app/api/webhooks/signudoc"
          label="Webhook address"
          name="webhook-url"
          onChange={(event) => setUrl(event.target.value)}
          placeholder="https://"
          readOnly={false}
          value={url}
        />
        <div className="flex flex-wrap gap-3">
          <ShellButton
            disabled={url.trim().length === 0 || url.trim() === endpoint?.url}
            loading={busy === "save"}
            onClick={() => void act("save")}
          >
            {endpoint ? "Save address" : "Turn on webhooks"}
          </ShellButton>
          {endpoint ? (
            <ShellButton
              loading={busy === "rotate"}
              onClick={() =>
                void act(
                  "rotate",
                  "Make a new signing secret? The old one keeps working for 24 hours while you switch.",
                )
              }
              variant="secondary"
            >
              Rotate signing secret
            </ShellButton>
          ) : null}
          {endpoint ? (
            <ShellButton
              className="border-[rgba(180,35,24,0.35)] text-(--danger) hover:border-(--danger) hover:bg-(--danger-soft) hover:text-(--danger)"
              loading={busy === "remove"}
              onClick={() =>
                void act(
                  "remove",
                  "Turn webhooks off? Messages not yet delivered are dropped.",
                )
              }
              variant="secondary"
            >
              Turn off
            </ShellButton>
          ) : null}
        </div>
        {endpoint?.previousSecretExpiresAt ? (
          <p className="text-xs leading-5 text-(--tertiary)">
            The previous signing secret also signs messages until{" "}
            {formatTime(endpoint.previousSecretExpiresAt)}.
          </p>
        ) : null}
      </div>

      {message ? (
        <p
          className={`notice ${
            message.tone === "error" ? "notice-danger" : "notice-success"
          }`}
          role={message.tone === "error" ? "alert" : "status"}
        >
          {message.text}
        </p>
      ) : null}

      {endpoint ? (
        <div className="space-y-3">
          <div className="flex items-center justify-between gap-3">
            <h4 className="text-sm font-bold text-(--fg)">Recent deliveries</h4>
            <button
              className="text-xs font-semibold text-(--accent-ink) underline underline-offset-4"
              onClick={() => void refresh()}
              type="button"
            >
              Refresh
            </button>
          </div>
          {state && state.deliveries.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[36rem] text-left text-xs">
                <thead className="text-(--tertiary)">
                  <tr>
                    <th className="py-2 pr-3 font-semibold">Time</th>
                    <th className="py-2 pr-3 font-semibold">Event</th>
                    <th className="py-2 pr-3 font-semibold">Response</th>
                    <th className="py-2 pr-3 font-semibold">Retries</th>
                  </tr>
                </thead>
                <tbody className="text-(--secondary)">
                  {state.deliveries.map((delivery) => (
                    <tr
                      className="border-t border-(--border) align-top"
                      key={delivery.id}
                    >
                      <td className="py-2 pr-3 whitespace-nowrap">
                        {formatTime(
                          delivery.lastAttemptAt ?? delivery.createdAt,
                        )}
                      </td>
                      <td className="py-2 pr-3 font-mono">
                        {delivery.eventType}
                      </td>
                      <td
                        className={`py-2 pr-3 ${
                          delivery.status === "failed" ? "text-(--danger)" : ""
                        }`}
                      >
                        {describeResult(delivery)}
                      </td>
                      <td className="py-2 pr-3">
                        {String(Math.max(delivery.attempts - 1, 0))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-(--tertiary)">No deliveries yet.</p>
          )}
        </div>
      ) : null}
    </div>
  );
}
