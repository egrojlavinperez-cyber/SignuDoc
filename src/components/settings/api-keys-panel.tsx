"use client";

import { useEffect, useState } from "react";

import { FieldShell, ShellButton } from "@/components/shared/form-shell";
import { Checkbox } from "@/components/ui/checkbox";
import { PERMITTED_USE_PATH } from "@/lib/permitted-uses";

// API keys for the public API, for another system (such as an internal
// operating system) to send PDFs for signature. Administrators only.

type ApiKeySummary = {
  createdAt: number;
  id: string;
  lastUsedAt: number | null;
  name: string;
  ownerEmail: string | null;
  prefix: string;
  revokedAt: number | null;
};

type Message = { text: string; tone: "error" | "success" } | null;

function formatTime(seconds: number | null): string {
  return seconds === null
    ? "Never"
    : new Date(seconds * 1000).toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      });
}

export function ApiKeysPanel() {
  const [keys, setKeys] = useState<ApiKeySummary[] | null>(null);
  const [name, setName] = useState("CU-OS");
  const [confirmed, setConfirmed] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [newKey, setNewKey] = useState<{ key: string; name: string } | null>(
    null,
  );
  const [copied, setCopied] = useState(false);
  const [message, setMessage] = useState<Message>(null);

  useEffect(() => {
    let cancelled = false;

    void fetch("/api/admin/api-keys")
      .then((response) => response.json())
      .then((payload: { keys?: ApiKeySummary[] }) => {
        if (!cancelled) {
          setKeys(payload.keys ?? []);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setMessage({ text: "The keys could not be loaded.", tone: "error" });
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  async function create() {
    setIsCreating(true);
    setMessage(null);
    setNewKey(null);
    setCopied(false);

    try {
      const response = await fetch("/api/admin/api-keys", {
        body: JSON.stringify({ name, permittedUseConfirmed: confirmed }),
        headers: { "content-type": "application/json" },
        method: "POST",
      });
      const payload = (await response.json().catch(() => null)) as {
        error?: string;
        key?: string;
        summary?: ApiKeySummary;
      } | null;

      if (!response.ok || !payload?.key || !payload.summary) {
        setMessage({
          text: payload?.error ?? "The key could not be made.",
          tone: "error",
        });
        return;
      }

      const summary = payload.summary;

      setNewKey({ key: payload.key, name: summary.name });
      setKeys((current) => [summary, ...(current ?? [])]);
      setConfirmed(false);
    } catch {
      setMessage({ text: "The key could not be made.", tone: "error" });
    } finally {
      setIsCreating(false);
    }
  }

  async function revoke(key: ApiKeySummary) {
    if (
      !window.confirm(
        `Revoke "${key.name}"? Anything using it stops working at once.`,
      )
    ) {
      return;
    }

    setRevokingId(key.id);
    setMessage(null);

    try {
      const response = await fetch(`/api/admin/api-keys/${key.id}`, {
        method: "DELETE",
      });
      const payload = (await response.json().catch(() => null)) as {
        error?: string;
        summary?: ApiKeySummary;
      } | null;

      if (!response.ok || !payload?.summary) {
        setMessage({
          text: payload?.error ?? "The key could not be revoked.",
          tone: "error",
        });
        return;
      }

      const revoked = payload.summary;

      setKeys((current) =>
        (current ?? []).map((row) => (row.id === revoked.id ? revoked : row)),
      );
      setMessage({ text: `"${revoked.name}" is revoked.`, tone: "success" });
    } catch {
      setMessage({ text: "The key could not be revoked.", tone: "error" });
    } finally {
      setRevokingId(null);
    }
  }

  async function copyKey() {
    if (!newKey) {
      return;
    }

    try {
      await navigator.clipboard.writeText(newKey.key);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className="space-y-5 border-t border-(--border) pt-8">
      <div className="space-y-2">
        <h3 className="text-lg font-extrabold tracking-[-0.02em] text-(--fg)">
          API keys
        </h3>
        <p className="max-w-2xl text-sm leading-6 text-(--secondary)">
          A key lets another system, such as your internal operating system,
          send PDFs for signature and follow them through the API. It acts for
          you: envelopes it sends are yours, and their audit trail names the
          key. It stops working if you stop being an administrator. Store it
          only in that system&apos;s secret settings, never in code or chat.
        </p>
      </div>

      {newKey ? (
        <div className="notice notice-success space-y-3" role="status">
          <p className="text-sm font-semibold">
            Copy the key for &quot;{newKey.name}&quot; now. It is not shown
            again.
          </p>
          <code className="block break-all rounded-lg bg-(--surface) px-3 py-2 font-mono text-xs text-(--fg)">
            {newKey.key}
          </code>
          <div className="flex flex-wrap gap-3">
            <ShellButton onClick={copyKey} variant="secondary">
              {copied ? "Copied" : "Copy key"}
            </ShellButton>
            <ShellButton onClick={() => setNewKey(null)} variant="ghost">
              Done
            </ShellButton>
          </div>
        </div>
      ) : null}

      <div className="grid max-w-xl gap-4">
        <FieldShell
          label="Name"
          maxLength={80}
          name="api-key-name"
          onChange={(event) => setName(event.target.value)}
          placeholder="CU-OS"
          readOnly={false}
          value={name}
        />
        <label className="well block px-4 py-4">
          <span className="flex items-start gap-3">
            <Checkbox
              checked={confirmed}
              className="mt-1"
              disabled={isCreating}
              onCheckedChange={(checked) => setConfirmed(checked === true)}
            />
            <span className="text-sm leading-6 text-(--secondary)">
              I confirm that documents sent with this key are ordinary business
              agreements and not wills, court orders, legally required consumer
              disclosures, or other{" "}
              <a
                className="font-semibold text-(--accent-ink) underline underline-offset-4"
                href={PERMITTED_USE_PATH}
                rel="noreferrer"
                target="_blank"
              >
                documents that cannot be signed electronically
              </a>
              .
            </span>
          </span>
        </label>
        <ShellButton
          className="w-fit"
          disabled={!confirmed || name.trim().length === 0}
          loading={isCreating}
          onClick={create}
        >
          Create API key
        </ShellButton>
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

      {keys === null ? (
        <p className="text-sm text-(--tertiary)">Loading keys…</p>
      ) : keys.length === 0 ? (
        <p className="text-sm text-(--tertiary)">No API keys yet.</p>
      ) : (
        <ul className="grid gap-3">
          {keys.map((key) => (
            <li
              className="well flex flex-col gap-3 px-4 py-4 sm:flex-row sm:items-center sm:justify-between"
              key={key.id}
            >
              <div className="min-w-0 space-y-1 text-sm">
                <p className="font-semibold text-(--fg)">
                  {key.name}{" "}
                  {key.revokedAt !== null ? (
                    <span className="pill ml-1">Revoked</span>
                  ) : null}
                </p>
                <p className="font-mono text-xs text-(--tertiary)">
                  {key.prefix}…
                </p>
                <p className="text-xs leading-5 text-(--tertiary)">
                  Made {formatTime(key.createdAt)}
                  {key.ownerEmail ? ` by ${key.ownerEmail}` : ""} · Last used{" "}
                  {formatTime(key.lastUsedAt)}
                  {key.revokedAt !== null
                    ? ` · Revoked ${formatTime(key.revokedAt)}`
                    : ""}
                </p>
              </div>
              {key.revokedAt === null ? (
                <ShellButton
                  className="w-fit shrink-0 border-[rgba(180,35,24,0.35)] text-(--danger) hover:border-(--danger) hover:bg-(--danger-soft) hover:text-(--danger)"
                  loading={revokingId === key.id}
                  onClick={() => void revoke(key)}
                  variant="secondary"
                >
                  Revoke
                </ShellButton>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
