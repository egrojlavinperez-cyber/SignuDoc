import { NextResponse } from "next/server";

import { DownloadAccessError } from "../downloads.ts";
import { logRouteError } from "../security/logging.ts";
import { getClientIpAddress, getRequestPathname } from "../security/request.ts";
import {
  applyRateLimit,
  buildRateLimitKey,
} from "../security/route-controls.ts";
import { ApiRequestError } from "./envelopes.ts";
import {
  authenticateApiKey,
  readBearerApiKey,
  type ApiPrincipal,
} from "./keys.ts";
import { requestWebhookDispatch } from "./webhook-trigger.ts";

// What every /api/v1 route does first and last: find the key, count the
// request, and answer errors as { "error": "<plain sentence>" }. Nothing
// logged here contains a key, a secret, a PDF or a signer's address.

const NO_STORE = { "cache-control": "private, no-store" };

export function apiJson(body: unknown, status = 200): NextResponse {
  return NextResponse.json(body, { headers: NO_STORE, status });
}

export function apiErrorResponse(message: string, status: number) {
  return apiJson({ error: message }, status);
}

export async function authenticateApiRequest(
  request: Request,
  limit: { category: string; max: number; windowMs: number },
): Promise<ApiPrincipal | Response> {
  const principal = await authenticateApiKey(
    readBearerApiKey(request.headers.get("authorization")),
  );

  if (!principal) {
    const response = apiErrorResponse(
      "A valid API key is required: send it as Authorization: Bearer <key>.",
      401,
    );

    response.headers.set("www-authenticate", 'Bearer realm="signudoc"');
    return response;
  }

  const limited = await applyRateLimit({
    category: limit.category,
    key: buildRateLimitKey(["api", limit.category, principal.keyId]),
    limit: limit.max,
    request,
    userId: principal.user.id,
    windowMs: limit.windowMs,
  });

  if (limited) {
    limited.headers.set("cache-control", "private, no-store");
    return limited;
  }

  // Any call is a chance to send webhooks that are due for a retry.
  requestWebhookDispatch();

  return principal;
}

export function handleApiError(
  error: unknown,
  request: Request,
  principal: ApiPrincipal,
  category: string,
): Response {
  if (error instanceof ApiRequestError) {
    return apiErrorResponse(error.message, error.statusCode);
  }

  if (error instanceof DownloadAccessError) {
    return apiErrorResponse(error.message, error.statusCode);
  }

  logRouteError(error, {
    category,
    ipAddress: getClientIpAddress(request.headers),
    message: "Unexpected failure in the public API.",
    path: getRequestPathname(request),
    userId: principal.user.id,
  });

  return apiErrorResponse("Something went wrong on our side. Try again.", 500);
}
