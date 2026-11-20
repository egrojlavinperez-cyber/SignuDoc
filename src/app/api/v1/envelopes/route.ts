import { createApiEnvelope, readIdempotencyKey } from "@/lib/api/envelopes";
import {
  apiErrorResponse,
  apiJson,
  authenticateApiRequest,
  handleApiError,
} from "@/lib/api/http";
import { MAX_API_REQUEST_BYTES } from "@/lib/api/schemas";
import { getDb } from "@/lib/db/connection";
import { getClientIpAddress } from "@/lib/security/request";

// POST /api/v1/envelopes: make an envelope from a PDF and send it.

export async function POST(request: Request) {
  const principal = await authenticateApiRequest(request, {
    category: "api_envelope_create",
    max: 60,
    windowMs: 10 * 60 * 1000,
  });

  if (principal instanceof Response) {
    return principal;
  }

  try {
    const idempotencyKey = readIdempotencyKey(
      request.headers.get("idempotency-key"),
    );
    const declaredLength = Number(request.headers.get("content-length") ?? 0);

    if (declaredLength > MAX_API_REQUEST_BYTES) {
      return apiErrorResponse(
        "The request is too large. The API takes PDFs up to 3 MB.",
        413,
      );
    }

    const body = await request.text();

    if (Buffer.byteLength(body, "utf8") > MAX_API_REQUEST_BYTES) {
      return apiErrorResponse(
        "The request is too large. The API takes PDFs up to 3 MB.",
        413,
      );
    }

    const result = await createApiEnvelope(
      principal,
      {
        body,
        idempotencyKey,
        ipAddress: getClientIpAddress(request.headers),
      },
      getDb(),
    );

    return apiJson(result.envelope, result.created ? 201 : 200);
  } catch (error) {
    return handleApiError(error, request, principal, "api_envelope_create");
  }
}
