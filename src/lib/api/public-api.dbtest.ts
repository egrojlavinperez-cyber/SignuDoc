import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";

import { PDFDocument } from "pdf-lib";
import type pg from "pg";

import { replaceDbPoolForTests } from "../db/connection.ts";
import { openTestDatabase } from "../db/test-database.ts";
import { ELECTRONIC_RECORDS_DISCLOSURE_VERSION } from "../electronic-records-disclosure.ts";
import type {
  EmailService,
  TransactionalEmailMessage,
} from "../services/email.ts";
import { issueSigningLink } from "../services/signing-links.ts";
import {
  getSigningPayloadForToken,
  recordSignerConsent,
  submitSigningForToken,
} from "../signing.ts";
import { normalizedRectToPdfRect } from "../utils/pdf-coords.ts";
import {
  ApiRequestError,
  createApiEnvelope,
  getApiEnvelope,
  getApiSignedPdf,
  voidApiEnvelope,
  type ApiEnvelopeView,
} from "./envelopes.ts";
import {
  authenticateApiKey,
  createApiKey,
  generateApiKey,
  revokeApiKey,
  type ApiPrincipal,
} from "./keys.ts";
import { verifyWebhookSignature } from "./webhook-signature.ts";
import {
  deliverDueWebhooks,
  enqueueWebhookEvents,
  removeWebhookEndpoint,
  rotateWebhookSecret,
  saveWebhookEndpoint,
} from "./webhooks.ts";

// The public API against a real Postgres, end to end through the same
// functions the app uses: keys, idempotency, field positions, signing
// order, voiding, the signed PDF and webhooks. Run with `npm run test:db`.

process.env.APP_URL ??= "https://sign.example.test";
process.env.EMAIL_DRIVER = "capture";

let database: pg.Pool;
let workDir: string;
let adminId: string;
let principal: ApiPrincipal;
let otherPrincipal: ApiPrincipal;
const createdUsers: string[] = [];

before(async () => {
  database = await openTestDatabase();
  replaceDbPoolForTests(database);
  workDir = await mkdtemp(path.join(tmpdir(), "signudoc-api-"));
  process.env.EMAIL_CAPTURE_DIR = path.join(workDir, "outbox");
  process.env.STORAGE_DRIVER = "local";
  process.env.STORAGE_LOCAL_DIR = path.join(workDir, "storage");
  // Webhooks from earlier runs would be sent again here.
  await removeWebhookEndpoint(database);

  adminId = await createUser("admin");

  const { key } = await createApiKey(
    { name: "CU-OS", userId: adminId },
    database,
  );
  const other = await createApiKey(
    { name: "Other", userId: adminId },
    database,
  );

  principal = (await authenticateApiKey(key, database))!;
  otherPrincipal = (await authenticateApiKey(other.key, database))!;
});

after(async () => {
  await removeWebhookEndpoint(database).catch(() => undefined);
  await database.query(`delete from public."user" where id = any($1)`, [
    createdUsers,
  ]);
  await database.end();
  await rm(workDir, { force: true, recursive: true });
});

async function createUser(role: "admin" | "user"): Promise<string> {
  const id = randomUUID();

  createdUsers.push(id);
  await database.query(
    `
      insert into public."user" (id, name, email, role, "emailVerified")
      values ($1, 'Ada Admin', $2, $3, true)
    `,
    [id, `${id}@example.test`, role],
  );

  return id;
}

let contractPdf: string | null = null;

/** A six-page US Letter contract, as base64. */
async function contractBase64(): Promise<string> {
  if (!contractPdf) {
    const document = await PDFDocument.create();

    for (let page = 0; page < 6; page += 1) {
      document.addPage([612, 792]);
    }

    contractPdf = Buffer.from(await document.save()).toString("base64");
  }

  return contractPdf;
}

async function requestBody(
  overrides: Record<string, unknown> = {},
): Promise<string> {
  const id = randomUUID().slice(0, 8);

  return JSON.stringify({
    title: `Client Services Agreement ${id}`,
    externalId: `cuos:contract:${id}`,
    document: {
      fileName: "261120_Mexico City_CSA v2.pdf",
      contentType: "application/pdf",
      contentBase64: await contractBase64(),
    },
    signers: [
      {
        key: "cu",
        name: "Ian Example",
        email: `ian-${id}@example.test`,
        signOrder: 2,
      },
      {
        key: "client",
        name: "Jane Doe",
        email: `jane-${id}@example.test`,
        signOrder: 1,
      },
    ],
    cc: [{ name: "Ops", email: `ops-${id}@example.test` }],
    fields: [
      {
        signerKey: "cu",
        type: "signature",
        page: 6,
        x: 0.1176,
        y: 0.2475,
        width: 0.3333,
        height: 0.053,
        required: true,
      },
      {
        signerKey: "cu",
        type: "date",
        page: 6,
        x: 0.1667,
        y: 0.3359,
        width: 0.2124,
        height: 0.0227,
        required: true,
      },
      {
        signerKey: "client",
        type: "signature",
        page: 6,
        x: 0.549,
        y: 0.2475,
        width: 0.3333,
        height: 0.053,
        required: true,
      },
      {
        signerKey: "client",
        type: "date",
        page: 6,
        x: 0.598,
        y: 0.3359,
        width: 0.2124,
        height: 0.0227,
        required: true,
      },
    ],
    message: null,
    send: true,
    ...overrides,
  });
}

async function create(
  body: string,
  idempotencyKey = randomUUID(),
  who: ApiPrincipal = principal,
) {
  return createApiEnvelope(who, { body, idempotencyKey }, database);
}

async function countEmails(envelopeId: string): Promise<number> {
  const result = await database.query<{ count: string }>(
    `select count(*) from audit_events where envelope_id = $1 and event = 'email_sent'`,
    [envelopeId],
  );

  return Number(result.rows[0]?.count ?? 0);
}

function recordingEmailService() {
  const sent: TransactionalEmailMessage[] = [];
  const service: EmailService = {
    async send(message) {
      sent.push(message);

      return { accepted: [message.to], messageId: "m-1", rejected: [] };
    },
    async sendBatch(messages) {
      sent.push(...messages);

      return messages.map((message) => ({
        accepted: [message.to],
        messageId: "m-1",
        rejected: [],
      }));
    },
  };

  return { sent, service };
}

/** Signs as the signer with this key: a fresh link, consent, signature. */
async function signAs(envelope: ApiEnvelopeView, signerKey: string) {
  const signer = envelope.signers.find((row) => row.key === signerKey)!;
  const signerRow = await database.query<{ id: string }>(
    `select id from signers where envelope_id = $1 and email = $2`,
    [envelope.id, signer.email],
  );
  const signerId = signerRow.rows[0]!.id;
  const link = await issueSigningLink({ expiresInSeconds: 3600 });

  await database.query(
    `update signers set signing_token_hash = $1, signing_token_expires_at = $2 where id = $3`,
    [link.tokenHash, link.exp, signerId],
  );
  await recordSignerConsent(
    link.token,
    { disclosureVersion: ELECTRONIC_RECORDS_DISCLOSURE_VERSION },
    { database },
  );
  // Opening the document, as the signing page does: this records "viewed".
  await getSigningPayloadForToken(link.token, { database });

  const fields = await database.query<{ id: string }>(
    `select id from fields where signer_id = $1 and type = 'signature'`,
    [signerId],
  );
  const { sent, service } = recordingEmailService();

  await submitSigningForToken(
    link.token,
    {
      clientTimezoneOffsetMinutes: 0,
      fields: fields.rows.map((field) => ({
        fieldId: field.id,
        inputMethod: "typed",
        type: "signature",
        value: signer.name,
      })),
    },
    { database, emailService: service },
  );

  return sent;
}

test("a missing, wrong or revoked key is refused", async () => {
  assert.equal(await authenticateApiKey(null, database), null);
  assert.equal(await authenticateApiKey(generateApiKey(), database), null);

  const { key, summary } = await createApiKey(
    { name: "Short-lived", userId: adminId },
    database,
  );

  assert.equal(
    (await authenticateApiKey(key, database))?.keyName,
    "Short-lived",
  );
  assert.ok(await revokeApiKey(summary.id, database));
  assert.equal(await authenticateApiKey(key, database), null);

  // A key stops working once its owner is no longer an administrator.
  const formerAdmin = await createUser("admin");
  const former = await createApiKey(
    { name: "Former", userId: formerAdmin },
    database,
  );

  await database.query(`update public."user" set role = 'user' where id = $1`, [
    formerAdmin,
  ]);
  assert.equal(await authenticateApiKey(former.key, database), null);
});

test("the same Idempotency-Key makes one envelope and sends one email", async () => {
  const body = await requestBody();
  const idempotencyKey = randomUUID();
  const first = await create(body, idempotencyKey);
  const second = await create(body, idempotencyKey);

  assert.equal(first.created, true);
  assert.equal(second.created, false);
  assert.equal(second.envelope.id, first.envelope.id);
  assert.equal(first.envelope.status, "sent");
  assert.equal(await countEmails(first.envelope.id), 1);

  const envelopes = await database.query(
    `select envelope_id from api_envelopes where external_id = $1`,
    [first.envelope.externalId],
  );

  assert.equal(envelopes.rowCount, 1);

  // The same key with a different request is a mistake, not a retry.
  await assert.rejects(
    create(await requestBody(), idempotencyKey),
    (error: unknown) =>
      error instanceof ApiRequestError && error.statusCode === 422,
  );
});

test("a refused request leaves nothing behind, so it can be corrected", async () => {
  const idempotencyKey = randomUUID();
  const broken = JSON.parse(await requestBody()) as {
    document: { contentBase64: string };
  };

  broken.document.contentBase64 = Buffer.from("not a pdf").toString("base64");

  await assert.rejects(
    create(JSON.stringify(broken), idempotencyKey),
    (error: unknown) =>
      error instanceof ApiRequestError && error.statusCode === 400,
  );

  // The key is free again for the corrected request.
  const fixed = await create(await requestBody(), idempotencyKey);

  assert.equal(fixed.created, true);
});

test("fields land where the request put them, measured from the top", async () => {
  const { envelope } = await create(await requestBody());
  const fields = await database.query<{
    height: number;
    page: number;
    type: string;
    width: number;
    x: number;
    y: number;
  }>(
    `
      select f.type, f.page, f.x, f.y, f.width, f.height
      from fields f join signers s on s.id = f.signer_id
      where f.envelope_id = $1 and s.sign_order = 2 and f.type = 'signature'
    `,
    [envelope.id],
  );
  const field = fields.rows[0]!;
  const page = await database.query<{ height_pt: number; width_pt: number }>(
    `select width_pt, height_pt from envelope_pages where envelope_id = $1 and page_number = 6`,
    [envelope.id],
  );
  const geometry = {
    heightPt: Number(page.rows[0]!.height_pt),
    widthPt: Number(page.rows[0]!.width_pt),
  };

  assert.deepEqual(
    {
      ...field,
      height: Number(field.height),
      width: Number(field.width),
      x: Number(field.x),
      y: Number(field.y),
    },
    {
      height: 0.053,
      page: 6,
      type: "signature",
      width: 0.3333,
      x: 0.1176,
      y: 0.2475,
    },
  );
  assert.deepEqual(geometry, { heightPt: 792, widthPt: 612 });

  // In PDF points the origin is the bottom-left corner: a field 24.75% of
  // the way down the page has its top edge 24.75% below the page's top.
  const rect = normalizedRectToPdfRect(
    {
      height: Number(field.height),
      width: Number(field.width),
      x: Number(field.x),
      y: Number(field.y),
    },
    geometry,
  );

  assert.ok(Math.abs(rect.yPt + rect.heightPt - (792 - 0.2475 * 792)) < 1e-6);
  assert.ok(Math.abs(rect.xPt - 0.1176 * 612) < 1e-6);
});

test("signers sign in signOrder: the second is emailed only after the first signs", async () => {
  const { envelope } = await create(await requestBody());

  assert.deepEqual(
    envelope.signers.map((signer) => [
      signer.key,
      signer.signOrder,
      signer.status,
    ]),
    [
      ["client", 1, "notified"],
      ["cu", 2, "pending"],
    ],
  );
  assert.equal(await countEmails(envelope.id), 1);

  const sent = await signAs(envelope, "client");
  const afterFirst = await getApiEnvelope(principal, envelope.id, database);

  assert.deepEqual(
    afterFirst.signers.map((signer) => signer.status),
    ["signed", "notified"],
  );
  assert.ok(
    sent.some((message) => message.to === afterFirst.signers[1]!.email),
    "the second signer is invited once the first has signed",
  );
});

test("a completed envelope gives its signed PDF and cannot be voided", async () => {
  const { envelope } = await create(await requestBody());

  await assert.rejects(
    getApiSignedPdf(principal, envelope.id, database),
    (error: unknown) =>
      error instanceof ApiRequestError && error.statusCode === 409,
  );

  await signAs(envelope, "client");
  await signAs(envelope, "cu");

  const completed = await getApiEnvelope(principal, envelope.id, database);

  assert.equal(completed.status, "completed");
  assert.ok(completed.completedAt);
  assert.ok(completed.signers.every((signer) => signer.signedAt !== null));

  const download = await getApiSignedPdf(principal, envelope.id, database);

  assert.equal(download.contentType, "application/pdf");

  await assert.rejects(
    voidApiEnvelope(principal, envelope.id, {}, {}, database),
    (error: unknown) =>
      error instanceof ApiRequestError &&
      error.statusCode === 409 &&
      error.message === "already_completed",
  );
});

test("voiding an envelope out for signature voids it", async () => {
  const { envelope } = await create(await requestBody());
  const voided = await voidApiEnvelope(
    principal,
    envelope.id,
    {
      reason: "Cancelled by Capture Unlimited. A revised version will follow.",
    },
    {},
    database,
  );

  assert.equal(voided.status, "voided");

  const draft = await create(await requestBody({ send: false }));

  assert.equal(draft.envelope.status, "draft");
  await assert.rejects(
    voidApiEnvelope(principal, draft.envelope.id, {}, {}, database),
    (error: unknown) =>
      error instanceof ApiRequestError && error.statusCode === 409,
  );
});

test("a key sees only the envelopes it made", async () => {
  const { envelope } = await create(await requestBody());

  await assert.rejects(
    getApiEnvelope(otherPrincipal, envelope.id, database),
    (error: unknown) =>
      error instanceof ApiRequestError && error.statusCode === 404,
  );
  await assert.rejects(
    voidApiEnvelope(otherPrincipal, envelope.id, {}, {}, database),
    (error: unknown) =>
      error instanceof ApiRequestError && error.statusCode === 404,
  );
});

type Received = { body: string; signature: string | undefined };

async function startReceiver(answers: number[]) {
  const received: Received[] = [];
  const server: Server = createServer((request: IncomingMessage, response) => {
    const chunks: Buffer[] = [];

    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      received.push({
        body: Buffer.concat(chunks).toString("utf8"),
        signature: request.headers["signudoc-signature"] as string | undefined,
      });
      response.statusCode = answers.shift() ?? 200;
      response.end();
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));

  const { port } = server.address() as AddressInfo;

  return { received, server, url: `http://127.0.0.1:${String(port)}/hook` };
}

test("webhooks are signed, retried after a failure, then delivered", async () => {
  // Envelopes from before the address existed are left out of this test.
  await database.query(`update api_envelopes set webhook_cursor = 1000000`);

  const receiver = await startReceiver([500]);

  try {
    const saved = await saveWebhookEndpoint(
      { url: receiver.url, userId: adminId },
      database,
    );
    const secret = saved.secret!;

    assert.ok(secret.startsWith("whsec_"));

    const { envelope } = await create(await requestBody());

    await signAs(envelope, "client");

    assert.ok((await enqueueWebhookEvents(database)) >= 2);
    // Queued once only, however often the queue is looked at.
    assert.equal(await enqueueWebhookEvents(database), 0);

    await deliverDueWebhooks({ database });

    const failed = await database.query<{
      attempts: number;
      next_attempt_at: number;
      status: string;
    }>(
      `
        select status, attempts, next_attempt_at
        from webhook_deliveries
        where envelope_id = $1 and last_status_code = 500
      `,
      [envelope.id],
    );

    assert.equal(failed.rowCount, 1, "the first delivery was answered 500");
    assert.equal(failed.rows[0]!.status, "pending");
    assert.equal(failed.rows[0]!.attempts, 1);
    assert.ok(
      Number(failed.rows[0]!.next_attempt_at) > Math.floor(Date.now() / 1000),
      "and is retried later",
    );

    // Its retry comes due.
    await database.query(
      `update webhook_deliveries set next_attempt_at = 0 where envelope_id = $1 and status = 'pending'`,
      [envelope.id],
    );
    await deliverDueWebhooks({ database });

    const states = await database.query<{ event_type: string; status: string }>(
      `select event_type, status from webhook_deliveries where envelope_id = $1 order by audit_sequence`,
      [envelope.id],
    );

    assert.ok(states.rows.every((row) => row.status === "delivered"));
    assert.deepEqual(
      states.rows.map((row) => row.event_type),
      ["envelope.sent", "envelope.viewed", "envelope.signer_signed"],
    );

    for (const delivery of receiver.received) {
      assert.ok(
        verifyWebhookSignature(delivery.signature, delivery.body, secret),
        "each delivery is signed with the secret",
      );

      const event = JSON.parse(delivery.body) as {
        envelope: ApiEnvelopeView;
        id: string;
        type: string;
      };

      assert.match(event.id, /^[A-Za-z0-9_-]{1,100}$/);
      assert.equal(event.envelope.id, envelope.id);
      assert.equal(event.envelope.externalId, envelope.externalId);
    }

    // A rotated secret: both sign until the old one runs out.
    const rotated = await rotateWebhookSecret(database);

    await signAs(envelope, "cu");
    await enqueueWebhookEvents(database);
    await deliverDueWebhooks({ database });

    const last = receiver.received.at(-1)!;

    assert.ok(
      verifyWebhookSignature(last.signature, last.body, rotated.secret),
    );
    assert.ok(verifyWebhookSignature(last.signature, last.body, secret));
    assert.ok(
      receiver.received.some(
        (delivery) =>
          (JSON.parse(delivery.body) as { type: string }).type ===
          "envelope.completed",
      ),
    );
  } finally {
    await new Promise<void>((resolve) =>
      receiver.server.close(() => resolve()),
    );
  }
});
