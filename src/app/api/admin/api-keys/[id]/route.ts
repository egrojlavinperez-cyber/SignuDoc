import { NextResponse } from "next/server";

import { revokeApiKey } from "@/lib/api/keys";
import { requireAdminSession } from "@/lib/auth/admin";
import { recordAdminActivity } from "@/lib/services/admin-activity";

// Revokes an API key. It stops working at once.

type RouteContext = { params: Promise<{ id: string }> };

export async function DELETE(request: Request, context: RouteContext) {
  const session = await requireAdminSession(request);

  if (session instanceof Response) {
    return session;
  }

  const { id } = await context.params;
  const revoked = await revokeApiKey(id);

  if (!revoked) {
    return NextResponse.json(
      { error: "There is no such key, or it is already revoked." },
      { status: 404 },
    );
  }

  await recordAdminActivity({
    event: "settings_changed",
    metadata: {
      change: "api_key_revoked",
      keyId: revoked.id,
      name: revoked.name,
    },
    request,
    user: session.user,
  });

  return NextResponse.json(
    { summary: revoked },
    { headers: { "cache-control": "private, no-store" } },
  );
}
