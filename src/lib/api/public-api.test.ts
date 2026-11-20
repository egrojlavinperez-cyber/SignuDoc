import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { test } from "node:test";

import { decodeApiPdf, readIdempotencyKey } from "./envelopes.ts";
import {
  API_KEY_PREFIX,
  generateApiKey,
  hashApiKey,
  readBearerApiKey,
} from "./keys.ts";
import { createApiEnvelopeSchema, MAX_API_PDF_BYTES } from "./schemas.ts";
import {
  buildWebhookSignatureHeader,
  generateWebhookSecret,
  parseWebhookSignatureHeader,
  verifyWebhookSignature,
} from "./webhook-signature.ts";
import {
  retryDelaySeconds,
  validateWebhookUrl,
  WEBHOOK_GIVE_UP_AFTER_SECONDS,
  WEBHOOK_RETRY_DELAYS_SECONDS,
} from "./webhooks.ts";

// The parts of the public API that need no database: keys, the request
// schema, webhook signatures and the retry schedule.

const validRequest = () => ({
  title: "Client Services Agreement",
  externalId: "cuos:contract:1",
  document: {
    fileName: "csa.pdf",
    contentType: "application/pdf",
    contentBase64: Buffer.from("%PDF-1.7\n").toString("base64"),
  },
  signers: [
    {
      key: "client",
      name: "Jane Doe",
      email: "jane@example.test",
      signOrder: 1,
    },
    { key: "cu", name: "Ian A", email: "ian@example.test", signOrder: 2 },
  ],
  cc: [{ name: "Ops", email: "ops@example.test" }],
  fields: [
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
  ],
  message: null,
  send: true,
});

test("API keys are long, random and kept only as a hash", () => {
  const key = generateApiKey();

  assert.ok(key.startsWith(API_KEY_PREFIX));
  assert.ok(key.length >= 40);
  assert.notEqual(generateApiKey(), key);
  assert.match(hashApiKey(key), /^[0-9a-f]{64}$/);
  assert.equal(hashApiKey(key), hashApiKey(key));
});

test("only a Bearer header holding an API key is read as one", () => {
  const key = generateApiKey();

  assert.equal(readBearerApiKey(`Bearer ${key}`), key);
  assert.equal(readBearerApiKey(`bearer ${key}`), key);
  assert.equal(readBearerApiKey(null), null);
  assert.equal(readBearerApiKey(key), null);
  assert.equal(readBearerApiKey("Bearer something-else"), null);
  assert.equal(readBearerApiKey("Basic abc"), null);
});

test("the create request takes the spec's example", () => {
  const parsed = createApiEnvelopeSchema.safeParse(validRequest());

  assert.equal(parsed.success, true, JSON.stringify(parsed.error?.issues));
});

test("the create request refuses what would make a broken envelope", () => {
  const cases: [string, (request: ReturnType<typeof validRequest>) => void][] =
    [
      ["unknown signer key", (r) => void (r.fields[0]!.signerKey = "nobody")],
      ["repeated sign order", (r) => void (r.signers[1]!.signOrder = 1)],
      ["repeated key", (r) => void (r.signers[1]!.key = "client")],
      ["off the page", (r) => void (r.fields[0]!.x = 0.9)],
      [
        "signer without a signature",
        (r) => void (r.fields = r.fields.filter((f) => f.signerKey !== "cu")),
      ],
      ["not a PDF type", (r) => void (r.document.contentType = "image/png")],
      [
        "cc that is a signer",
        (r) => void (r.cc[0]!.email = "jane@example.test"),
      ],
      [
        "text field",
        (r) => void ((r.fields[0] as { type: string }).type = "text"),
      ],
    ];

  for (const [name, change] of cases) {
    const request = validRequest();

    change(request);
    assert.equal(
      createApiEnvelopeSchema.safeParse(request).success,
      false,
      name,
    );
  }
});

test("the PDF must be base64, a PDF, and small enough to send to Vercel", () => {
  assert.equal(
    Buffer.from(decodeApiPdf(Buffer.from("%PDF-1.7 x").toString("base64")))
      .subarray(0, 5)
      .toString(),
    "%PDF-",
  );
  assert.throws(() => decodeApiPdf("not base64!"), /base64/);
  assert.throws(
    () => decodeApiPdf(Buffer.from("hello").toString("base64")),
    /not a PDF/,
  );
  assert.throws(
    () =>
      decodeApiPdf(
        Buffer.concat([
          Buffer.from("%PDF-"),
          Buffer.alloc(MAX_API_PDF_BYTES),
        ]).toString("base64"),
      ),
    /up to 3 MB/,
  );
});

test("an Idempotency-Key is required and plain", () => {
  assert.equal(
    readIdempotencyKey("  3f6c1b52-6c1e-4e0e-9a0e-5b8a7f0c2d11 "),
    "3f6c1b52-6c1e-4e0e-9a0e-5b8a7f0c2d11",
  );
  assert.throws(() => readIdempotencyKey(null), /required/);
  assert.throws(() => readIdempotencyKey("has spaces in it"), /may use/);
});

test('the signature is HMAC-SHA256 of "<t>.<raw body>" with the secret', () => {
  const secret = generateWebhookSecret();
  const body = JSON.stringify({ id: "evt_1", type: "envelope.completed" });
  const header = buildWebhookSignatureHeader(body, [secret], 1_700_000_000);
  const expected = createHmac("sha256", secret)
    .update(`1700000000.${body}`)
    .digest("hex");

  assert.equal(header, `t=1700000000,v1=${expected}`);
  assert.ok(
    verifyWebhookSignature(header, body, secret, { now: 1_700_000_100 }),
  );
  assert.ok(
    !verifyWebhookSignature(header, `${body} `, secret, {
      now: 1_700_000_100,
    }),
    "a changed body fails",
  );
  assert.ok(
    !verifyWebhookSignature(header, body, secret, { now: 1_700_001_000 }),
    "an old delivery fails",
  );
  assert.ok(
    !verifyWebhookSignature(header, body, generateWebhookSecret(), {
      now: 1_700_000_100,
    }),
    "another secret fails",
  );
});

test("while a secret is rotated, each secret signs, newest first", () => {
  const newer = generateWebhookSecret();
  const older = generateWebhookSecret();
  const body = "{}";
  const header = buildWebhookSignatureHeader(body, [newer, older], 1_000);
  const parsed = parseWebhookSignatureHeader(header);

  assert.equal(parsed?.signatures.length, 2);
  assert.ok(verifyWebhookSignature(header, body, newer, { now: 1_000 }));
  assert.ok(verifyWebhookSignature(header, body, older, { now: 1_000 }));
});

test("failed deliveries are retried with growing gaps", () => {
  assert.equal(retryDelaySeconds(1), WEBHOOK_RETRY_DELAYS_SECONDS[0]);
  assert.equal(retryDelaySeconds(2), WEBHOOK_RETRY_DELAYS_SECONDS[1]);

  for (let attempts = 2; attempts < 20; attempts += 1) {
    assert.ok(retryDelaySeconds(attempts) >= retryDelaySeconds(attempts - 1));
  }

  // Enough tries to cover the whole day before giving up.
  let elapsed = 0;
  let attempts = 0;

  while (elapsed < WEBHOOK_GIVE_UP_AFTER_SECONDS) {
    attempts += 1;
    elapsed += retryDelaySeconds(attempts);
  }

  assert.ok(attempts >= 10);
});

test("webhooks go only to https on the public internet in production", () => {
  const production = { production: true };

  assert.equal(
    validateWebhookUrl(
      "https://cu-os.vercel.app/api/webhooks/signudoc",
      production,
    ),
    "https://cu-os.vercel.app/api/webhooks/signudoc",
  );
  assert.throws(() =>
    validateWebhookUrl("http://cu-os.vercel.app/x", production),
  );
  assert.throws(() => validateWebhookUrl("https://localhost/x", production));
  assert.throws(() => validateWebhookUrl("https://10.0.0.5/x", production));
  assert.throws(() => validateWebhookUrl("https://192.168.1.2/x", production));
  assert.throws(() => validateWebhookUrl("https://[::1]/x", production));
  assert.throws(() =>
    validateWebhookUrl("https://user:pw@example.com/x", production),
  );
  assert.throws(() => validateWebhookUrl("not a url", production));
  // A hostname that merely starts with "fd" is not an IPv6 address.
  assert.equal(
    validateWebhookUrl("https://fdx.example.com/hook", production),
    "https://fdx.example.com/hook",
  );
  // A local receiver while developing.
  assert.equal(
    validateWebhookUrl("http://127.0.0.1:4000/hook", { production: false }),
    "http://127.0.0.1:4000/hook",
  );
});
