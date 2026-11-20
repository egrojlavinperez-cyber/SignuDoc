import { getApiSignedPdf } from "@/lib/api/envelopes";
import { authenticateApiRequest, handleApiError } from "@/lib/api/http";
import { getDb } from "@/lib/db/connection";
import { createDownloadResponse } from "@/lib/download-response";

// GET /api/v1/envelopes/{id}/signed-pdf: the sealed PDF of a completed
// envelope this key made.

type RouteContext = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: RouteContext) {
  const principal = await authenticateApiRequest(request, {
    category: "api_envelope_signed_pdf",
    max: 120,
    windowMs: 10 * 60 * 1000,
  });

  if (principal instanceof Response) {
    return principal;
  }

  try {
    const { id } = await context.params;

    return await createDownloadResponse(
      await getApiSignedPdf(principal, id, getDb()),
    );
  } catch (error) {
    return handleApiError(error, request, principal, "api_envelope_signed_pdf");
  }
}
