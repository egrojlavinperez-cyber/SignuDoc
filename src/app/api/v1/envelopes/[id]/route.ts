import { getApiEnvelope } from "@/lib/api/envelopes";
import {
  apiJson,
  authenticateApiRequest,
  handleApiError,
} from "@/lib/api/http";
import { getDb } from "@/lib/db/connection";

// GET /api/v1/envelopes/{id}: an envelope this key made, as it is now.

type RouteContext = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: RouteContext) {
  const principal = await authenticateApiRequest(request, {
    category: "api_envelope_read",
    max: 600,
    windowMs: 10 * 60 * 1000,
  });

  if (principal instanceof Response) {
    return principal;
  }

  try {
    const { id } = await context.params;

    return apiJson(await getApiEnvelope(principal, id, getDb()));
  } catch (error) {
    return handleApiError(error, request, principal, "api_envelope_read");
  }
}
