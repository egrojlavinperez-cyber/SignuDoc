import { voidApiEnvelope } from "@/lib/api/envelopes";
import {
  apiErrorResponse,
  apiJson,
  authenticateApiRequest,
  handleApiError,
} from "@/lib/api/http";
import { getDb } from "@/lib/db/connection";
import { getClientIpAddress } from "@/lib/security/request";

// POST /api/v1/envelopes/{id}/void: cancel an envelope out for signature.
// The signers are told, as when it is voided from the envelope's page.

type RouteContext = { params: Promise<{ id: string }> };

export async function POST(request: Request, context: RouteContext) {
  const principal = await authenticateApiRequest(request, {
    category: "api_envelope_void",
    max: 60,
    windowMs: 10 * 60 * 1000,
  });

  if (principal instanceof Response) {
    return principal;
  }

  try {
    const { id } = await context.params;
    const text = await request.text();
    let body: unknown = {};

    if (text.trim()) {
      try {
        body = JSON.parse(text);
      } catch {
        return apiErrorResponse("The request body is not valid JSON.", 400);
      }
    }

    return apiJson(
      await voidApiEnvelope(
        principal,
        id,
        body,
        { ipAddress: getClientIpAddress(request.headers) },
        getDb(),
      ),
    );
  } catch (error) {
    return handleApiError(error, request, principal, "api_envelope_void");
  }
}
