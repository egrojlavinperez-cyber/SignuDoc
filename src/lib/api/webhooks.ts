import { randomUUID } from "node:crypto";

import {
  getDb,
  queryMany,
  queryOne,
  withTransaction,
  type DbExecutor,
  type DbPool,
} from "../db/connection.ts";
import {
  decryptPrivateKey,
  encryptPrivateKey,
  secretKeyFor,
} from "../services/seal-identity.ts";
import { isProduction } from "../utils/env.ts";
import { getApiEnvelopeView } from "./envelopes.ts";
import { WEBHOOK_EVENT_FOR_AUDIT_EVENT } from "./webhook-events.ts";
import {
  buildWebhookSignatureHeader,
  generateWebhookSecret,
  WEBHOOK_SIGNATURE_HEADER,
} from "./webhook-signature.ts";

// Webhooks for envelopes made through the API. They are made from each
// envelope's audit trail, which is written in the same transaction as every
// change to the envelope, so nothing that happened can be missed and no
// signing code needs to know about webhooks. Each audit event of interest
// becomes one delivery, sent until the receiver answers 2xx, for up to 24
// hours. Delivery is at least once: a receiver can see one twice.

export { WEBHOOK_EVENT_FOR_AUDIT_EVENT };

/** Seconds to wait after the nth failed attempt (the last repeats). */
export const WEBHOOK_RETRY_DELAYS_SECONDS = [
  10, 30, 90, 300, 900, 1800, 3600, 7200, 14_400, 21_600, 43_200,
] as const;
export const WEBHOOK_GIVE_UP_AFTER_SECONDS = 24 * 60 * 60;
export const WEBHOOK_TIMEOUT_MS = 30_000;
const PREVIOUS_SECRET_GRACE_SECONDS = 24 * 60 * 60;
/** A claimed delivery is left alone this long by other dispatchers. */
const DELIVERY_LEASE_SECONDS = 120;
const DELIVERY_BATCH = 20;
const SECRET_CONTEXT = "signudoc-webhook-secret";

const now = () => Math.floor(Date.now() / 1000);

export class WebhookConfigError extends Error {
  readonly statusCode: number;

  constructor(message: string, statusCode = 400) {
    super(message);
    this.name = "WebhookConfigError";
    this.statusCode = statusCode;
  }
}

export function retryDelaySeconds(attempts: number): number {
  const index = Math.min(
    Math.max(attempts - 1, 0),
    WEBHOOK_RETRY_DELAYS_SECONDS.length - 1,
  );

  return WEBHOOK_RETRY_DELAYS_SECONDS[index] ?? 43_200;
}

function isPrivateHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");

  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal")
  ) {
    return true;
  }

  // IPv6 literals: loopback, unspecified, unique-local and link-local.
  if (host.includes(":")) {
    return (
      host === "::1" ||
      host === "::" ||
      /^f[cd][0-9a-f]{0,2}:/.test(host) ||
      /^fe[89ab][0-9a-f]?:/.test(host) ||
      host.startsWith("::ffff:")
    );
  }

  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);

  if (!ipv4) {
    return false;
  }

  const [a, b] = [Number(ipv4[1]), Number(ipv4[2])];

  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a >= 224
  );
}

/** An https address on the public internet (http to localhost when testing). */
export function validateWebhookUrl(
  value: unknown,
  { production = isProduction(process.env) }: { production?: boolean } = {},
): string {
  const text = typeof value === "string" ? value.trim() : "";
  let url: URL;

  try {
    url = new URL(text);
  } catch {
    throw new WebhookConfigError("Enter the full address, starting https://");
  }

  if (text.length > 2000 || url.username || url.password) {
    throw new WebhookConfigError(
      "The address must not contain a user name or password.",
    );
  }

  const local = isPrivateHostname(url.hostname);

  if (url.protocol === "https:" && !(production && local)) {
    return url.toString();
  }

  if (url.protocol === "http:" && local && !production) {
    return url.toString();
  }

  throw new WebhookConfigError(
    production && local
      ? "Webhooks go to an address on the public internet."
      : "The address must start with https://",
  );
}

export type WebhookEndpointView = {
  createdAt: number;
  id: string;
  previousSecretExpiresAt: number | null;
  updatedAt: number;
  url: string;
};

type WebhookEndpointRow = WebhookEndpointView & {
  previousSecretCiphertext: string | null;
  secretCiphertext: string;
};

async function readEndpoint(
  database: DbExecutor,
): Promise<WebhookEndpointRow | null> {
  return queryOne<WebhookEndpointRow>(
    database,
    `
      select
        id,
        url,
        secret_ciphertext as "secretCiphertext",
        previous_secret_ciphertext as "previousSecretCiphertext",
        previous_secret_expires_at as "previousSecretExpiresAt",
        created_at as "createdAt",
        updated_at as "updatedAt"
      from public.webhook_endpoints
      order by created_at asc
      limit 1
    `,
  );
}

function toView(row: WebhookEndpointRow): WebhookEndpointView {
  return {
    createdAt: row.createdAt,
    id: row.id,
    previousSecretExpiresAt:
      row.previousSecretExpiresAt && row.previousSecretExpiresAt > now()
        ? row.previousSecretExpiresAt
        : null,
    updatedAt: row.updatedAt,
    url: row.url,
  };
}

function encryptSecret(secret: string): string {
  return encryptPrivateKey(secret, secretKeyFor(SECRET_CONTEXT));
}

function decryptSecret(ciphertext: string | null): string | null {
  return ciphertext
    ? decryptPrivateKey(ciphertext, secretKeyFor(SECRET_CONTEXT))
    : null;
}

export async function getWebhookEndpoint(
  database: DbExecutor = getDb(),
): Promise<WebhookEndpointView | null> {
  const row = await readEndpoint(database);

  return row ? toView(row) : null;
}

/**
 * Sets where webhooks go. The first time, a signing secret is made and is
 * in the result (the only time it is shown). Changing the address keeps the
 * secret.
 */
export async function saveWebhookEndpoint(
  input: { url: unknown; userId: string },
  database: DbPool = getDb(),
): Promise<{ endpoint: WebhookEndpointView; secret: string | null }> {
  const url = validateWebhookUrl(input.url);
  const savedAt = now();

  return withTransaction(async (tx) => {
    await tx.query(`lock table public.webhook_endpoints in exclusive mode`);

    const existing = await readEndpoint(tx);

    if (existing) {
      await tx.query(
        `update public.webhook_endpoints set url = $2, updated_at = $3 where id = $1`,
        [existing.id, url, savedAt],
      );

      return {
        endpoint: toView({ ...existing, updatedAt: savedAt, url }),
        secret: null,
      };
    }

    const secret = generateWebhookSecret();
    const row: WebhookEndpointRow = {
      createdAt: savedAt,
      id: randomUUID(),
      previousSecretCiphertext: null,
      previousSecretExpiresAt: null,
      secretCiphertext: encryptSecret(secret),
      updatedAt: savedAt,
      url,
    };

    await tx.query(
      `
        insert into public.webhook_endpoints
          (id, url, secret_ciphertext, created_by, created_at, updated_at)
        values ($1, $2, $3, $4, $5, $6)
      `,
      [row.id, url, row.secretCiphertext, input.userId, savedAt, savedAt],
    );

    return { endpoint: toView(row), secret };
  }, database);
}

/**
 * A new signing secret. The old one still signs deliveries, alongside the
 * new one, for 24 hours, so the receiver can switch without missing any.
 */
export async function rotateWebhookSecret(
  database: DbPool = getDb(),
): Promise<{ endpoint: WebhookEndpointView; secret: string }> {
  return withTransaction(async (tx) => {
    await tx.query(`lock table public.webhook_endpoints in exclusive mode`);

    const existing = await readEndpoint(tx);

    if (!existing) {
      throw new WebhookConfigError("Save a webhook address first.", 404);
    }

    const secret = generateWebhookSecret();
    const rotatedAt = now();
    const row: WebhookEndpointRow = {
      ...existing,
      previousSecretCiphertext: existing.secretCiphertext,
      previousSecretExpiresAt: rotatedAt + PREVIOUS_SECRET_GRACE_SECONDS,
      secretCiphertext: encryptSecret(secret),
      updatedAt: rotatedAt,
    };

    await tx.query(
      `
        update public.webhook_endpoints
        set
          secret_ciphertext = $2,
          previous_secret_ciphertext = $3,
          previous_secret_expires_at = $4,
          updated_at = $5
        where id = $1
      `,
      [
        row.id,
        row.secretCiphertext,
        row.previousSecretCiphertext,
        row.previousSecretExpiresAt,
        rotatedAt,
      ],
    );

    return { endpoint: toView(row), secret };
  }, database);
}

/** Stops webhooks. Deliveries not yet made are dropped. */
export async function removeWebhookEndpoint(
  database: DbPool = getDb(),
): Promise<boolean> {
  return withTransaction(async (tx) => {
    const removed = await tx.query(`delete from public.webhook_endpoints`);

    await tx.query(
      `delete from public.webhook_deliveries where status = 'pending'`,
    );

    return (removed.rowCount ?? 0) > 0;
  }, database);
}

/** The secrets a delivery is signed with now, newest first. */
async function readSigningSecrets(row: WebhookEndpointRow): Promise<string[]> {
  const current = decryptSecret(row.secretCiphertext);

  if (!current) {
    throw new Error(
      "The webhook signing secret could not be read. It was saved under a different BETTER_AUTH_SECRET: rotate it in Settings.",
    );
  }

  const previous =
    row.previousSecretExpiresAt && row.previousSecretExpiresAt > now()
      ? decryptSecret(row.previousSecretCiphertext)
      : null;

  return previous ? [current, previous] : [current];
}

/**
 * Turns new audit events of API envelopes into deliveries. Each envelope
 * keeps the last audit event it has looked at, so each one is queued once.
 */
export async function enqueueWebhookEvents(
  database: DbPool = getDb(),
): Promise<number> {
  if (!(await readEndpoint(database))) {
    // Nothing to send to. The events stay unread, and go out once an
    // address is saved.
    return 0;
  }

  return withTransaction(async (tx) => {
    const envelopes = await queryMany<{ cursor: number; envelopeId: string }>(
      tx,
      `
        select a.envelope_id as "envelopeId", a.webhook_cursor as "cursor"
        from public.api_envelopes a
        where exists (
          select 1 from public.audit_events e
          where e.envelope_id = a.envelope_id
            and e.sequence > a.webhook_cursor
        )
        order by a.created_at asc
        limit 200
        for update of a skip locked
      `,
    );
    const queuedAt = now();
    let queued = 0;

    for (const envelope of envelopes) {
      const events = await queryMany<{
        createdAt: number;
        event: string;
        sequence: number;
      }>(
        tx,
        `
          select sequence, event, created_at as "createdAt"
          from public.audit_events
          where envelope_id = $1 and sequence > $2
          order by sequence asc
        `,
        [envelope.envelopeId, envelope.cursor],
      );
      let cursor = envelope.cursor;

      for (const event of events) {
        cursor = Math.max(cursor, event.sequence);

        const type = WEBHOOK_EVENT_FOR_AUDIT_EVENT[event.event];

        if (!type) {
          continue;
        }

        const inserted = await tx.query(
          `
            insert into public.webhook_deliveries (
              id, envelope_id, audit_sequence, event_type, occurred_at,
              next_attempt_at, created_at
            ) values ($1, $2, $3, $4, $5, $6, $6)
            on conflict (envelope_id, audit_sequence) do nothing
          `,
          [
            `evt_${randomUUID().replace(/-/g, "")}`,
            envelope.envelopeId,
            event.sequence,
            type,
            event.createdAt,
            queuedAt,
          ],
        );

        queued += inserted.rowCount ?? 0;
      }

      await tx.query(
        `update public.api_envelopes set webhook_cursor = $2 where envelope_id = $1`,
        [envelope.envelopeId, cursor],
      );
    }

    return queued;
  }, database);
}

export type WebhookFetch = (
  url: string,
  init: { body: string; headers: Record<string, string>; method: "POST" },
) => Promise<{ status: number }>;

const defaultFetch: WebhookFetch = async (url, init) => {
  const response = await fetch(url, {
    ...init,
    redirect: "manual",
    signal: AbortSignal.timeout(WEBHOOK_TIMEOUT_MS),
  });

  await response.body?.cancel().catch(() => undefined);

  return { status: response.status };
};

function describeFetchError(error: unknown): string {
  if (error instanceof Error) {
    if (error.name === "TimeoutError" || error.name === "AbortError") {
      return `No answer within ${String(WEBHOOK_TIMEOUT_MS / 1000)} seconds`;
    }

    const code = (error as Error & { cause?: { code?: unknown } }).cause?.code;

    return typeof code === "string"
      ? `Could not connect (${code})`
      : "Could not connect";
  }

  return "Could not connect";
}

/** The body of one delivery, as the receiver gets it. */
export async function buildWebhookBody(
  delivery: {
    envelopeId: string;
    eventType: string;
    id: string;
    occurredAt: number;
  },
  database: DbExecutor,
): Promise<string | null> {
  const envelope = await getApiEnvelopeView(
    delivery.envelopeId,
    null,
    database,
  );

  return envelope
    ? JSON.stringify({
        id: delivery.id,
        type: delivery.eventType,
        createdAt: new Date(delivery.occurredAt * 1000).toISOString(),
        envelope,
      })
    : null;
}

/** Sends the deliveries that are due. Returns how many were tried. */
export async function deliverDueWebhooks({
  database = getDb(),
  fetchImpl = defaultFetch,
}: { database?: DbPool; fetchImpl?: WebhookFetch } = {}): Promise<number> {
  const endpoint = await readEndpoint(database);

  if (!endpoint) {
    return 0;
  }

  const claimedAt = now();
  const due = await queryMany<{
    attempts: number;
    createdAt: number;
    envelopeId: string;
    eventType: string;
    id: string;
    occurredAt: number;
  }>(
    database,
    `
      update public.webhook_deliveries d
      set next_attempt_at = $2
      where d.id in (
        select id from public.webhook_deliveries
        where status = 'pending' and next_attempt_at <= $1
        order by next_attempt_at asc, occurred_at asc, audit_sequence asc
        limit $3
        for update skip locked
      )
      returning
        d.id,
        d.envelope_id as "envelopeId",
        d.event_type as "eventType",
        d.occurred_at as "occurredAt",
        d.attempts,
        d.created_at as "createdAt"
    `,
    [claimedAt, claimedAt + DELIVERY_LEASE_SECONDS, DELIVERY_BATCH],
  );

  if (due.length === 0) {
    return 0;
  }

  due.sort(
    (left, right) =>
      left.occurredAt - right.occurredAt || left.id.localeCompare(right.id),
  );

  const secrets = await readSigningSecrets(endpoint);

  for (const delivery of due) {
    const body = await buildWebhookBody(delivery, database);

    if (body === null) {
      // The envelope is gone (deleted): there is nothing left to tell.
      await database.query(
        `delete from public.webhook_deliveries where id = $1`,
        [delivery.id],
      );
      continue;
    }

    const attemptedAt = now();
    let statusCode: number | null = null;
    let failure: string | null = null;

    try {
      statusCode = (
        await fetchImpl(endpoint.url, {
          body,
          headers: {
            "content-type": "application/json",
            [WEBHOOK_SIGNATURE_HEADER]: buildWebhookSignatureHeader(
              body,
              secrets,
              attemptedAt,
            ),
            "user-agent": "SignuDoc-Webhooks/1",
          },
          method: "POST",
        })
      ).status;

      if (statusCode < 200 || statusCode >= 300) {
        failure = `Answered ${String(statusCode)}`;
      }
    } catch (error) {
      failure = describeFetchError(error);
    }

    const attempts = delivery.attempts + 1;

    if (failure === null) {
      await database.query(
        `
          update public.webhook_deliveries
          set
            status = 'delivered',
            attempts = $2,
            last_attempt_at = $3,
            last_status_code = $4,
            last_error = null,
            delivered_at = $3
          where id = $1
        `,
        [delivery.id, attempts, attemptedAt, statusCode],
      );
      continue;
    }

    const nextAttemptAt = attemptedAt + retryDelaySeconds(attempts);
    const givesUp =
      nextAttemptAt > delivery.createdAt + WEBHOOK_GIVE_UP_AFTER_SECONDS;

    await database.query(
      `
        update public.webhook_deliveries
        set
          status = $2,
          attempts = $3,
          last_attempt_at = $4,
          last_status_code = $5,
          last_error = $6,
          next_attempt_at = $7
        where id = $1
      `,
      [
        delivery.id,
        givesUp ? "failed" : "pending",
        attempts,
        attemptedAt,
        statusCode,
        failure.slice(0, 200),
        givesUp ? attemptedAt : nextAttemptAt,
      ],
    );
  }

  return due.length;
}

async function nextPendingAttemptAt(
  database: DbExecutor,
): Promise<number | null> {
  const row = await queryOne<{ nextAttemptAt: number | null }>(
    database,
    `
      select min(next_attempt_at) as "nextAttemptAt"
      from public.webhook_deliveries
      where status = 'pending'
    `,
  );

  return row?.nextAttemptAt ?? null;
}

type DispatchState = { again: boolean; running: Promise<void> | null };

declare global {
  var __signudocWebhookDispatch: DispatchState | undefined;
}

const sleep = (ms: number) =>
  new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });

/**
 * Queues new events and sends what is due, then, for as long as `budgetMs`
 * allows, waits for retries coming due and sends those too. One run at a
 * time per server: a call while one runs makes it go round once more.
 */
export async function runWebhookDispatch({
  budgetMs = 0,
  database = getDb(),
  fetchImpl,
}: {
  budgetMs?: number;
  database?: DbPool;
  fetchImpl?: WebhookFetch;
} = {}): Promise<void> {
  const state = (globalThis.__signudocWebhookDispatch ??= {
    again: false,
    running: null,
  });

  if (state.running) {
    state.again = true;
    return state.running;
  }

  const deadline = Date.now() + budgetMs;

  state.running = (async () => {
    try {
      for (;;) {
        state.again = false;
        await enqueueWebhookEvents(database);

        while (
          (await deliverDueWebhooks({ database, fetchImpl })) >= DELIVERY_BATCH
        ) {
          // A full batch: there may be more due.
        }

        if (state.again) {
          continue;
        }

        const next = await nextPendingAttemptAt(database);

        if (next === null) {
          return;
        }

        const waitMs = Math.max(next * 1000 - Date.now(), 1000);

        if (Date.now() + waitMs > deadline) {
          return;
        }

        await sleep(waitMs);
      }
    } finally {
      state.running = null;
    }
  })();

  return state.running;
}

export type WebhookDeliveryView = {
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

export async function listRecentWebhookDeliveries(
  database: DbExecutor = getDb(),
  limit = 25,
): Promise<WebhookDeliveryView[]> {
  return queryMany<WebhookDeliveryView>(
    database,
    `
      select
        id,
        envelope_id as "envelopeId",
        event_type as "eventType",
        status,
        attempts,
        last_attempt_at as "lastAttemptAt",
        last_status_code as "lastStatusCode",
        last_error as "lastError",
        case when status = 'pending' then next_attempt_at end as "nextAttemptAt",
        created_at as "createdAt"
      from public.webhook_deliveries
      order by created_at desc, audit_sequence desc
      limit $1
    `,
    [limit],
  );
}

/** Finished deliveries past 30 days, for the daily cleanup. */
export async function deleteOldWebhookDeliveries(
  database: DbExecutor = getDb(),
  olderThanSeconds = 30 * 24 * 60 * 60,
): Promise<number> {
  const result = await database.query(
    `
      delete from public.webhook_deliveries
      where status <> 'pending' and created_at < $1
    `,
    [now() - olderThanSeconds],
  );

  return result.rowCount ?? 0;
}
