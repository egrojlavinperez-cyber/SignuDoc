import { createHash, randomBytes, randomUUID } from "node:crypto";

import {
  getDb,
  queryMany,
  queryOne,
  type DbExecutor,
} from "../db/connection.ts";

// API keys for the public API (/api/v1). A key acts for the administrator
// who made it: envelopes it makes belong to that account, and stop working
// with the key once that person is no longer an administrator. Only a
// SHA-256 hash is stored. The key has 256 random bits, so a fast hash is
// enough: there is nothing to guess.

export const API_KEY_PREFIX = "sdk_";
const DISPLAY_PREFIX_LENGTH = API_KEY_PREFIX.length + 6;
const LAST_USED_RESOLUTION_SECONDS = 60;

export class ApiKeyError extends Error {
  readonly statusCode: number;

  constructor(message: string, statusCode: number) {
    super(message);
    this.name = "ApiKeyError";
    this.statusCode = statusCode;
  }
}

export type ApiKeySummary = {
  createdAt: number;
  id: string;
  lastUsedAt: number | null;
  name: string;
  ownerEmail: string | null;
  prefix: string;
  revokedAt: number | null;
};

/** Who is calling: the key, and the administrator it acts for. */
export type ApiPrincipal = {
  keyId: string;
  keyName: string;
  user: { email: string; id: string; name: string };
};

export function generateApiKey(): string {
  return `${API_KEY_PREFIX}${randomBytes(32).toString("base64url")}`;
}

export function hashApiKey(key: string): string {
  return createHash("sha256").update(key, "utf8").digest("hex");
}

/** The key from an `Authorization: Bearer <key>` header, if it is one. */
export function readBearerApiKey(header: string | null): string | null {
  const match = /^Bearer\s+(\S+)\s*$/i.exec(header ?? "");
  const key = match?.[1];

  return key && key.startsWith(API_KEY_PREFIX) && key.length <= 200
    ? key
    : null;
}

export function normalizeApiKeyName(name: unknown): string {
  const trimmed = typeof name === "string" ? name.trim() : "";

  if (trimmed.length === 0 || trimmed.length > 80) {
    throw new ApiKeyError("Give the key a name of 1 to 80 characters.", 400);
  }

  return trimmed;
}

const now = () => Math.floor(Date.now() / 1000);

/** Makes a key. The key itself is in the result and nowhere else. */
export async function createApiKey(
  input: { name: unknown; userId: string },
  database: DbExecutor = getDb(),
): Promise<{ key: string; summary: ApiKeySummary }> {
  const name = normalizeApiKeyName(input.name);
  const key = generateApiKey();
  const id = randomUUID();
  const createdAt = now();

  await database.query(
    `
      insert into public.api_keys (id, name, user_id, key_hash, key_prefix, created_at)
      values ($1, $2, $3, $4, $5, $6)
    `,
    [
      id,
      name,
      input.userId,
      hashApiKey(key),
      key.slice(0, DISPLAY_PREFIX_LENGTH),
      createdAt,
    ],
  );

  const summary = (await listApiKeys(database)).find((row) => row.id === id);

  if (!summary) {
    throw new Error("The new API key could not be read back.");
  }

  return { key, summary };
}

export async function listApiKeys(
  database: DbExecutor = getDb(),
): Promise<ApiKeySummary[]> {
  return queryMany<ApiKeySummary>(
    database,
    `
      select
        k.id,
        k.name,
        k.key_prefix as "prefix",
        k.created_at as "createdAt",
        k.last_used_at as "lastUsedAt",
        k.revoked_at as "revokedAt",
        u.email as "ownerEmail"
      from public.api_keys k
      left join public."user" u on u.id = k.user_id
      order by k.revoked_at is not null, k.created_at desc
    `,
  );
}

/** Revokes a key at once. False when there is no such key still working. */
export async function revokeApiKey(
  id: string,
  database: DbExecutor = getDb(),
): Promise<ApiKeySummary | null> {
  const result = await database.query(
    `
      update public.api_keys
      set revoked_at = $2
      where id = $1 and revoked_at is null
    `,
    [id, now()],
  );

  if (result.rowCount !== 1) {
    return null;
  }

  return (await listApiKeys(database)).find((row) => row.id === id) ?? null;
}

/**
 * The caller behind a key, or null for a missing, unknown or revoked key,
 * or one whose owner is no longer a verified administrator.
 */
export async function authenticateApiKey(
  key: string | null,
  database: DbExecutor = getDb(),
): Promise<ApiPrincipal | null> {
  if (!key) {
    return null;
  }

  const row = await queryOne<{
    email: string;
    keyId: string;
    keyName: string;
    lastUsedAt: number | null;
    name: string | null;
    userId: string;
  }>(
    database,
    `
      select
        k.id as "keyId",
        k.name as "keyName",
        k.last_used_at as "lastUsedAt",
        u.id as "userId",
        u.email,
        u.name
      from public.api_keys k
      join public."user" u on u.id = k.user_id
      where k.key_hash = $1
        and k.revoked_at is null
        and u.role = 'admin'
        and u."emailVerified" = true
    `,
    [hashApiKey(key)],
  );

  if (!row) {
    return null;
  }

  const current = now();

  if (
    row.lastUsedAt === null ||
    current - row.lastUsedAt >= LAST_USED_RESOLUTION_SECONDS
  ) {
    await database.query(
      `update public.api_keys set last_used_at = $2 where id = $1`,
      [row.keyId, current],
    );
  }

  return {
    keyId: row.keyId,
    keyName: row.keyName,
    user: {
      email: row.email,
      id: row.userId,
      name: row.name?.trim() ? row.name : row.email,
    },
  };
}
