import { NextResponse } from "next/server";

import { ApiKeyError, createApiKey, listApiKeys } from "@/lib/api/keys";
import { requireAdminSession } from "@/lib/auth/admin";
import { recordAdminActivity } from "@/lib/services/admin-activity";
import { logRouteError } from "@/lib/security/logging";
import {
  applyRateLimit,
  buildRateLimitKey,
} from "@/lib/security/route-controls";
import { getClientIpAddress, getRequestPathname } from "@/lib/security/request";

// API keys, for Settings: list them, and make one. A new key is in the
// answer to the request that made it, and never again.

const NO_STORE = { "cache-control": "private, no-store" };

export async function GET(request: Request) {
  const session = await requireAdminSession(request);

  if (session instanceof Response) {
    return session;
  }

  return NextResponse.json(
    { keys: await listApiKeys() },
    { headers: NO_STORE },
  );
}

export async function POST(request: Request) {
  const session = await requireAdminSession(request);

  if (session instanceof Response) {
    return session;
  }

  const limited = await applyRateLimit({
    category: "api_key_create",
    key: buildRateLimitKey(["api-key-create", session.user.id]),
    limit: 10,
    request,
    userId: session.user.id,
    windowMs: 60 * 60 * 1000,
  });

  if (limited) {
    return limited;
  }

  const body = (await request.json().catch(() => null)) as {
    name?: unknown;
    permittedUseConfirmed?: unknown;
  } | null;

  if (body?.permittedUseConfirmed !== true) {
    return NextResponse.json(
      {
        error:
          "Confirm that envelopes sent with this key are ordinary business agreements.",
      },
      { status: 400 },
    );
  }

  try {
    const { key, summary } = await createApiKey({
      name: body.name,
      userId: session.user.id,
    });

    await recordAdminActivity({
      event: "settings_changed",
      metadata: {
        change: "api_key_created",
        keyId: summary.id,
        name: summary.name,
      },
      request,
      user: session.user,
    });

    return NextResponse.json(
      { key, summary },
      { headers: NO_STORE, status: 201 },
    );
  } catch (error) {
    if (error instanceof ApiKeyError) {
      return NextResponse.json(
        { error: error.message },
        { status: error.statusCode },
      );
    }

    logRouteError(error, {
      category: "api_key_create_failure",
      ipAddress: getClientIpAddress(request.headers),
      message: "Unexpected failure while making an API key.",
      path: getRequestPathname(request),
      userId: session.user.id,
    });

    return NextResponse.json(
      { error: "The key could not be made. Try again." },
      { status: 500 },
    );
  }
}
