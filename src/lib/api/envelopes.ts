import { createHash } from "node:crypto";

import { ZodError } from "zod";

import {
  getDb,
  queryMany,
  queryOne,
  withTransaction,
  type DbExecutor,
  type DbPool,
} from "../db/connection.ts";
import { getSenderEnvelopeDownload } from "../downloads.ts";
import {
  createDraftEnvelope,
  deleteDraftEnvelope,
  EnvelopeMutationError,
  replaceDraftEnvelopeFields,
  replaceDraftEnvelopeSigners,
  sendDraftEnvelope,
  voidSentEnvelope,
} from "../envelopes.ts";
import { DocumentImportError } from "../services/document-import.ts";
import { resolveAppUrl } from "../utils/env.ts";
import type { ApiPrincipal } from "./keys.ts";
import {
  createApiEnvelopeSchema,
  describeValidationError,
  MAX_API_PDF_BYTES,
  voidApiEnvelopeSchema,
  type CreateApiEnvelopeInput,
} from "./schemas.ts";

// The envelopes of the public API (/api/v1). Everything goes through the
// same functions the app's own pages use (create a draft, set its signers
// and fields, send, void), so what signers see, the sealing and the audit
// trail are the same however an envelope was made. What is added here is
// only the API's bookkeeping: which key made an envelope, the caller's
// names for its signers, and the Idempotency-Key that made it.

/** An error to answer with: its status code and a plain sentence. */
export class ApiRequestError extends Error {
  readonly statusCode: number;

  constructor(message: string, statusCode: number) {
    super(message);
    this.name = "ApiRequestError";
    this.statusCode = statusCode;
  }
}

export type ApiEnvelopeSignerView = {
  email: string;
  key: string | null;
  name: string;
  signOrder: number;
  signedAt: string | null;
  status: "declined" | "notified" | "pending" | "signed";
};

export type ApiEnvelopeView = {
  completedAt: string | null;
  createdAt: string;
  externalId: string | null;
  id: string;
  sentAt: string | null;
  signers: ApiEnvelopeSignerView[];
  status: "completed" | "declined" | "draft" | "sent" | "voided";
  title: string;
  url: string;
};

/** How long a claimed Idempotency-Key with no envelope yet is left alone. */
const IDEMPOTENCY_CLAIM_SECONDS = 120;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9_.:-]{1,200}$/;

const now = () => Math.floor(Date.now() / 1000);

function isoOrNull(seconds: number | null): string | null {
  return typeof seconds === "number"
    ? new Date(seconds * 1000).toISOString()
    : null;
}

export function envelopeUrl(envelopeId: string): string {
  const base = resolveAppUrl()?.replace(/\/+$/, "") ?? "";

  return `${base}/envelopes/${envelopeId}`;
}

export function hashApiRequestBody(body: string): string {
  return createHash("sha256").update(body, "utf8").digest("hex");
}

export function readIdempotencyKey(header: string | null): string {
  const key = header?.trim() ?? "";

  if (!key) {
    throw new ApiRequestError(
      "An Idempotency-Key header is required, so a retried request never sends twice.",
      400,
    );
  }

  if (!IDEMPOTENCY_KEY_PATTERN.test(key)) {
    throw new ApiRequestError(
      "The Idempotency-Key may use up to 200 letters, digits and . _ : -",
      400,
    );
  }

  return key;
}

/** An envelope as the API shows it, or null when this key did not make it. */
export async function getApiEnvelopeView(
  envelopeId: string,
  apiKeyId: string | null,
  database: DbExecutor = getDb(),
): Promise<ApiEnvelopeView | null> {
  const envelope = await queryOne<{
    completedAt: number | null;
    createdAt: number;
    externalId: string | null;
    id: string;
    sentAt: number | null;
    signerKeys: Record<string, string> | null;
    status: ApiEnvelopeView["status"];
    title: string;
  }>(
    database,
    `
      select
        e.id,
        e.title,
        e.status,
        e.created_at as "createdAt",
        e.sent_at as "sentAt",
        e.completed_at as "completedAt",
        a.external_id as "externalId",
        a.signer_keys as "signerKeys"
      from public.api_envelopes a
      join public.envelopes e on e.id = a.envelope_id
      where a.envelope_id = $1
        and ($2::text is null or a.api_key_id = $2)
    `,
    [envelopeId, apiKeyId],
  );

  if (!envelope) {
    return null;
  }

  const signers = await queryMany<{
    email: string;
    id: string;
    name: string;
    signOrder: number;
    signedAt: number | null;
    status: ApiEnvelopeSignerView["status"];
  }>(
    database,
    `
      select
        id,
        name,
        email,
        status,
        sign_order as "signOrder",
        signed_at as "signedAt"
      from public.signers
      where envelope_id = $1 and role = 'signer'
      order by sign_order asc, id asc
    `,
    [envelopeId],
  );

  return {
    completedAt: isoOrNull(envelope.completedAt),
    createdAt: isoOrNull(envelope.createdAt) ?? new Date(0).toISOString(),
    externalId: envelope.externalId,
    id: envelope.id,
    sentAt: isoOrNull(envelope.sentAt),
    signers: signers.map((signer) => ({
      email: signer.email,
      key: envelope.signerKeys?.[signer.id] ?? null,
      name: signer.name,
      signOrder: signer.signOrder,
      signedAt: isoOrNull(signer.signedAt),
      status: signer.status,
    })),
    status: envelope.status,
    title: envelope.title,
    url: envelopeUrl(envelope.id),
  };
}

async function requireApiEnvelope(
  principal: ApiPrincipal,
  envelopeId: string,
  database: DbExecutor,
): Promise<ApiEnvelopeView> {
  const view = await getApiEnvelopeView(envelopeId, principal.keyId, database);

  if (!view) {
    throw new ApiRequestError("Envelope not found.", 404);
  }

  return view;
}

type IdempotencyClaim =
  | { kind: "busy" }
  | { kind: "existing"; envelopeId: string }
  | { kind: "mismatch" }
  | { kind: "new" };

async function claimIdempotencyKey(
  apiKeyId: string,
  idempotencyKey: string,
  requestHash: string,
  database: DbExecutor,
): Promise<IdempotencyClaim> {
  const claimedAt = now();
  const inserted = await database.query(
    `
      insert into public.api_idempotency_keys
        (api_key_id, idempotency_key, request_hash, created_at)
      values ($1, $2, $3, $4)
      on conflict do nothing
    `,
    [apiKeyId, idempotencyKey, requestHash, claimedAt],
  );

  if (inserted.rowCount === 1) {
    return { kind: "new" };
  }

  const existing = await queryOne<{
    createdAt: number;
    envelopeId: string | null;
    requestHash: string;
  }>(
    database,
    `
      select
        request_hash as "requestHash",
        envelope_id as "envelopeId",
        created_at as "createdAt"
      from public.api_idempotency_keys
      where api_key_id = $1 and idempotency_key = $2
    `,
    [apiKeyId, idempotencyKey],
  );

  if (!existing) {
    return { kind: "busy" };
  }

  if (existing.requestHash !== requestHash) {
    return { kind: "mismatch" };
  }

  if (existing.envelopeId) {
    return { envelopeId: existing.envelopeId, kind: "existing" };
  }

  // Claimed, but no envelope was ever recorded: the request that claimed
  // it stopped part way. After a while, this one may take over.
  if (claimedAt - existing.createdAt >= IDEMPOTENCY_CLAIM_SECONDS) {
    const takenOver = await database.query(
      `
        update public.api_idempotency_keys
        set created_at = $3
        where api_key_id = $1
          and idempotency_key = $2
          and envelope_id is null
          and created_at = $4
      `,
      [apiKeyId, idempotencyKey, claimedAt, existing.createdAt],
    );

    if (takenOver.rowCount === 1) {
      return { kind: "new" };
    }
  }

  return { kind: "busy" };
}

async function releaseIdempotencyKey(
  apiKeyId: string,
  idempotencyKey: string,
  database: DbExecutor,
): Promise<void> {
  await database.query(
    `
      delete from public.api_idempotency_keys
      where api_key_id = $1 and idempotency_key = $2
    `,
    [apiKeyId, idempotencyKey],
  );
}

export function decodeApiPdf(contentBase64: string): Uint8Array {
  const cleaned = contentBase64.replace(/\s+/g, "");

  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(cleaned) || cleaned.length % 4 === 1) {
    throw new ApiRequestError(
      "document.contentBase64 is not valid base64.",
      400,
    );
  }

  const body = new Uint8Array(Buffer.from(cleaned, "base64"));

  if (body.byteLength > MAX_API_PDF_BYTES) {
    throw new ApiRequestError(
      `The PDF is ${String(Math.ceil(body.byteLength / 1024))} KB. The API takes PDFs up to ${String(MAX_API_PDF_BYTES / 1024 / 1024)} MB.`,
      413,
    );
  }

  if (Buffer.from(body.subarray(0, 5)).toString("latin1") !== "%PDF-") {
    throw new ApiRequestError("document is not a PDF.", 400);
  }

  return body;
}

/** A failure from the app's own envelope functions, as an API answer. */
function toApiError(error: unknown): unknown {
  if (error instanceof ApiRequestError) {
    return error;
  }

  if (error instanceof EnvelopeMutationError) {
    return new ApiRequestError(error.message, error.statusCode);
  }

  if (error instanceof ZodError) {
    return new ApiRequestError(describeValidationError(error), 400);
  }

  if (error instanceof DocumentImportError) {
    return new ApiRequestError(error.message, 400);
  }

  return error;
}

function apiUserAgent(principal: ApiPrincipal): string {
  return `SignuDoc API key "${principal.keyName}"`;
}

type RequestContext = {
  ipAddress?: string | null;
};

async function sendApiEnvelope(
  principal: ApiPrincipal,
  envelopeId: string,
  context: RequestContext,
  database: DbPool,
): Promise<void> {
  await sendDraftEnvelope(
    principal.user.id,
    envelopeId,
    {
      ipAddress: context.ipAddress ?? null,
      senderEmail: principal.user.email,
      senderName: principal.user.name,
      userAgent: apiUserAgent(principal),
    },
    { database },
  );
}

/**
 * POST /api/v1/envelopes. Makes the envelope from the PDF given, and sends
 * it unless told not to. The same Idempotency-Key always comes back to the
 * envelope it first made: a send that failed part way (email was down) is
 * tried again, and one that went out is never sent twice.
 */
export async function createApiEnvelope(
  principal: ApiPrincipal,
  request: {
    body: string;
    idempotencyKey: string;
    ipAddress?: string | null;
  },
  database: DbPool = getDb(),
): Promise<{ created: boolean; envelope: ApiEnvelopeView }> {
  let parsedJson: unknown;

  try {
    parsedJson = JSON.parse(request.body);
  } catch {
    throw new ApiRequestError("The request body is not valid JSON.", 400);
  }

  const parsed = createApiEnvelopeSchema.safeParse(parsedJson);

  if (!parsed.success) {
    throw new ApiRequestError(describeValidationError(parsed.error), 400);
  }

  const input = parsed.data;
  const claim = await claimIdempotencyKey(
    principal.keyId,
    request.idempotencyKey,
    hashApiRequestBody(request.body),
    database,
  );

  if (claim.kind === "mismatch") {
    throw new ApiRequestError(
      "This Idempotency-Key was already used for a different request. Use a new key for a new envelope.",
      422,
    );
  }

  if (claim.kind === "busy") {
    throw new ApiRequestError(
      "A request with this Idempotency-Key is still being handled. Try again in a moment.",
      409,
    );
  }

  if (claim.kind === "existing") {
    let view = await requireApiEnvelope(principal, claim.envelopeId, database);

    // The first request made the envelope but could not send it. Its
    // send is still owed; the draft's own check makes sure it goes once.
    if (input.send && view.status === "draft") {
      try {
        await sendApiEnvelope(principal, view.id, request, database);
      } catch (error) {
        throw toApiError(error);
      }

      view = await requireApiEnvelope(principal, view.id, database);
    }

    return { created: false, envelope: view };
  }

  let envelopeId: string;

  try {
    const pdf = decodeApiPdf(input.document.contentBase64);
    const draft = await createDraftEnvelope(
      principal.user.id,
      {
        sourcePdf: {
          body: pdf,
          contentType: "application/pdf",
          filename: input.document.fileName,
        },
        title: input.title,
      },
      { database },
    );

    envelopeId = draft.envelope.id;
  } catch (error) {
    await releaseIdempotencyKey(
      principal.keyId,
      request.idempotencyKey,
      database,
    );
    throw toApiError(error);
  }

  try {
    await setUpDraft(principal, envelopeId, input, request, database);
  } catch (error) {
    // Nothing was sent: the draft and the key go, so the request can be
    // corrected and made again.
    await deleteDraftEnvelope(principal.user.id, envelopeId, {
      database,
    }).catch(() => undefined);
    await releaseIdempotencyKey(
      principal.keyId,
      request.idempotencyKey,
      database,
    );
    throw toApiError(error);
  }

  if (input.send) {
    try {
      await sendApiEnvelope(principal, envelopeId, request, database);
    } catch (error) {
      const apiError = toApiError(error);

      // The envelope itself was refused (a 4xx): nothing went out, so the
      // draft and the key go as above. Anything else (email or storage
      // down) keeps both, and the same key sends it on a retry.
      if (
        apiError instanceof ApiRequestError &&
        apiError.statusCode >= 400 &&
        apiError.statusCode < 500
      ) {
        await deleteDraftEnvelope(principal.user.id, envelopeId, {
          database,
        }).catch(() => undefined);
        await releaseIdempotencyKey(
          principal.keyId,
          request.idempotencyKey,
          database,
        );
      }

      throw apiError;
    }
  }

  return {
    created: true,
    envelope: await requireApiEnvelope(principal, envelopeId, database),
  };
}

async function setUpDraft(
  principal: ApiPrincipal,
  envelopeId: string,
  input: CreateApiEnvelopeInput,
  request: { idempotencyKey: string },
  database: DbPool,
): Promise<void> {
  const orderedSigners = [...input.signers].sort(
    (left, right) => left.signOrder - right.signOrder,
  );
  const signerResult = await replaceDraftEnvelopeSigners(
    principal.user.id,
    envelopeId,
    {
      copyRecipients: (input.cc ?? []).map((recipient) => ({
        email: recipient.email,
        name: recipient.name,
      })),
      signers: orderedSigners.map((signer) => ({
        email: signer.email,
        name: signer.name,
      })),
    },
    database,
  );
  const savedSigners = [...signerResult.signers].sort(
    (left, right) => left.signOrder - right.signOrder,
  );
  const signerIdByKey = new Map<string, string>();
  const signerKeys: Record<string, string> = {};

  orderedSigners.forEach((signer, index) => {
    const saved = savedSigners[index];

    if (!saved || saved.email.toLowerCase() !== signer.email.toLowerCase()) {
      throw new Error("The saved signers do not match the request.");
    }

    signerIdByKey.set(signer.key, saved.id);
    signerKeys[saved.id] = signer.key;
  });

  await replaceDraftEnvelopeFields(
    principal.user.id,
    envelopeId,
    {
      fields: input.fields.map((field) => ({
        height: field.height,
        page: field.page,
        required: field.required,
        signerId: signerIdByKey.get(field.signerKey),
        type: field.type,
        width: field.width,
        x: field.x,
        y: field.y,
      })),
    },
    database,
  );

  await withTransaction(async (tx) => {
    await tx.query(
      `
        insert into public.api_envelopes
          (envelope_id, api_key_id, external_id, signer_keys, created_at)
        values ($1, $2, $3, $4, $5)
      `,
      [
        envelopeId,
        principal.keyId,
        input.externalId ?? null,
        JSON.stringify(signerKeys),
        now(),
      ],
    );
    await tx.query(
      `
        update public.api_idempotency_keys
        set envelope_id = $3
        where api_key_id = $1 and idempotency_key = $2
      `,
      [principal.keyId, request.idempotencyKey, envelopeId],
    );
  }, database);
}

export async function getApiEnvelope(
  principal: ApiPrincipal,
  envelopeId: string,
  database: DbExecutor = getDb(),
): Promise<ApiEnvelopeView> {
  return requireApiEnvelope(principal, envelopeId, database);
}

/** POST /api/v1/envelopes/{id}/void, as voiding from the envelope's page. */
export async function voidApiEnvelope(
  principal: ApiPrincipal,
  envelopeId: string,
  body: unknown,
  context: RequestContext,
  database: DbPool = getDb(),
): Promise<ApiEnvelopeView> {
  const parsed = voidApiEnvelopeSchema.safeParse(body ?? {});

  if (!parsed.success) {
    throw new ApiRequestError(describeValidationError(parsed.error), 400);
  }

  const view = await requireApiEnvelope(principal, envelopeId, database);

  if (view.status === "completed") {
    throw new ApiRequestError("already_completed", 409);
  }

  if (view.status !== "sent") {
    throw new ApiRequestError(
      `Only an envelope out for signature can be voided. This one is ${view.status}.`,
      409,
    );
  }

  try {
    await voidSentEnvelope(
      principal.user.id,
      envelopeId,
      {
        ipAddress: context.ipAddress ?? null,
        reason: parsed.data.reason ?? null,
        senderEmail: principal.user.email,
        senderName: principal.user.name,
        userAgent: apiUserAgent(principal),
      },
      { database },
    );
  } catch (error) {
    // Finished between the check above and the void.
    if (
      error instanceof EnvelopeMutationError &&
      error.statusCode === 409 &&
      (await getApiEnvelopeView(envelopeId, principal.keyId, database))
        ?.status === "completed"
    ) {
      throw new ApiRequestError("already_completed", 409);
    }

    throw toApiError(error);
  }

  return requireApiEnvelope(principal, envelopeId, database);
}

/** GET /api/v1/envelopes/{id}/signed-pdf: the sealed PDF, once complete. */
export async function getApiSignedPdf(
  principal: ApiPrincipal,
  envelopeId: string,
  database: DbExecutor = getDb(),
) {
  const view = await requireApiEnvelope(principal, envelopeId, database);

  if (view.status !== "completed") {
    throw new ApiRequestError(
      `The signed PDF exists once the envelope is completed. This one is ${view.status}.`,
      409,
    );
  }

  return getSenderEnvelopeDownload(principal.user.id, envelopeId, "signed", {
    database,
  });
}

/** Idempotency records past the 30 days they are promised for. */
export async function deleteExpiredIdempotencyKeys(
  database: DbExecutor = getDb(),
  olderThanSeconds = 30 * 24 * 60 * 60,
): Promise<number> {
  const result = await database.query(
    `delete from public.api_idempotency_keys where created_at < $1`,
    [now() - olderThanSeconds],
  );

  return result.rowCount ?? 0;
}
