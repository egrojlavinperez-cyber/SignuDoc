import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

// Signing webhook deliveries, so the receiver can tell they came from this
// install. The header is
//
//   SignuDoc-Signature: t=<unix seconds>,v1=<hex>[,v1=<hex>]
//
// where each v1 is HMAC-SHA256 over "<t>.<raw body>", keyed with a signing
// secret: the whole secret string, "whsec_" included, as UTF-8 bytes. While
// a secret is being rotated, there is one v1 per secret, newest first.

export const WEBHOOK_SIGNATURE_HEADER = "SignuDoc-Signature";
export const WEBHOOK_SECRET_PREFIX = "whsec_";

export function generateWebhookSecret(): string {
  return `${WEBHOOK_SECRET_PREFIX}${randomBytes(32).toString("base64url")}`;
}

export function computeWebhookSignature(
  secret: string,
  timestamp: number,
  body: string,
): string {
  return createHmac("sha256", secret)
    .update(`${String(timestamp)}.${body}`, "utf8")
    .digest("hex");
}

/** The header value for a body, signed with every secret given. */
export function buildWebhookSignatureHeader(
  body: string,
  secrets: readonly string[],
  timestamp: number,
): string {
  if (secrets.length === 0) {
    throw new Error("A webhook needs at least one signing secret.");
  }

  return [
    `t=${String(timestamp)}`,
    ...secrets.map(
      (secret) => `v1=${computeWebhookSignature(secret, timestamp, body)}`,
    ),
  ].join(",");
}

export function parseWebhookSignatureHeader(
  header: string | null | undefined,
): { signatures: string[]; timestamp: number } | null {
  if (!header) {
    return null;
  }

  let timestamp: number | null = null;
  const signatures: string[] = [];

  for (const part of header.split(",")) {
    const separator = part.indexOf("=");

    if (separator <= 0) {
      continue;
    }

    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();

    if (name === "t" && /^\d{1,12}$/.test(value)) {
      timestamp = Number(value);
    } else if (name === "v1" && /^[0-9a-f]{64}$/.test(value)) {
      signatures.push(value);
    }
  }

  return timestamp === null || signatures.length === 0
    ? null
    : { signatures, timestamp };
}

/**
 * Checks a delivery the way a receiver should: a signature made with the
 * secret, over this exact body, at a time no further than `toleranceSeconds`
 * from now. Used by the tests, and a reference for receivers.
 */
export function verifyWebhookSignature(
  header: string | null | undefined,
  body: string,
  secret: string,
  {
    now = Math.floor(Date.now() / 1000),
    toleranceSeconds = 300,
  }: { now?: number; toleranceSeconds?: number } = {},
): boolean {
  const parsed = parseWebhookSignatureHeader(header);

  if (!parsed || Math.abs(now - parsed.timestamp) > toleranceSeconds) {
    return false;
  }

  const expected = Buffer.from(
    computeWebhookSignature(secret, parsed.timestamp, body),
    "hex",
  );

  return parsed.signatures.some((signature) => {
    const presented = Buffer.from(signature, "hex");

    return (
      presented.length === expected.length &&
      timingSafeEqual(presented, expected)
    );
  });
}
