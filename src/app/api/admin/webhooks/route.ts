import { NextResponse } from "next/server";
import { z } from "zod";

import {
  getWebhookEndpoint,
  listRecentWebhookDeliveries,
  removeWebhookEndpoint,
  rotateWebhookSecret,
  saveWebhookEndpoint,
  WebhookConfigError,
} from "@/lib/api/webhooks";
import { requireAdminSession } from "@/lib/auth/admin";
import { recordAdminActivity } from "@/lib/services/admin-activity";
import { logRouteError } from "@/lib/security/logging";
import {
  applyRateLimit,
  buildRateLimitKey,
} from "@/lib/security/route-controls";
import { getClientIpAddress, getRequestPathname } from "@/lib/security/request";

// The webhook address, for Settings: see it and recent deliveries, save
// it, rotate its signing secret, or remove it. A signing secret is in the
// answer to the request that made it, and never again.

const NO_STORE = { "cache-control": "private, no-store" };

const actionSchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("save"), url: z.string() }),
  z.object({ action: z.literal("rotate") }),
  z.object({ action: z.literal("remove") }),
]);

async function currentState() {
  return {
    deliveries: await listRecentWebhookDeliveries(),
    endpoint: await getWebhookEndpoint(),
  };
}

export async function GET(request: Request) {
  const session = await requireAdminSession(request);

  if (session instanceof Response) {
    return session;
  }

  return NextResponse.json(await currentState(), { headers: NO_STORE });
}

export async function POST(request: Request) {
  const session = await requireAdminSession(request);

  if (session instanceof Response) {
    return session;
  }

  const limited = await applyRateLimit({
    category: "webhook_settings",
    key: buildRateLimitKey(["webhook-settings", session.user.id]),
    limit: 20,
    request,
    userId: session.user.id,
    windowMs: 10 * 60 * 1000,
  });

  if (limited) {
    return limited;
  }

  const parsed = actionSchema.safeParse(await request.json().catch(() => null));

  if (!parsed.success) {
    return NextResponse.json({ error: "Unknown action." }, { status: 400 });
  }

  try {
    let secret: string | null = null;

    if (parsed.data.action === "save") {
      const saved = await saveWebhookEndpoint({
        url: parsed.data.url,
        userId: session.user.id,
      });

      secret = saved.secret;
      await recordAdminActivity({
        event: "settings_changed",
        metadata: {
          change: saved.secret ? "webhook_added" : "webhook_address_changed",
          url: saved.endpoint.url,
        },
        request,
        user: session.user,
      });
    } else if (parsed.data.action === "rotate") {
      secret = (await rotateWebhookSecret()).secret;
      await recordAdminActivity({
        event: "settings_changed",
        metadata: { change: "webhook_secret_rotated" },
        request,
        user: session.user,
      });
    } else {
      await removeWebhookEndpoint();
      await recordAdminActivity({
        event: "settings_changed",
        metadata: { change: "webhook_removed" },
        request,
        user: session.user,
      });
    }

    return NextResponse.json(
      { ...(await currentState()), secret },
      { headers: NO_STORE },
    );
  } catch (error) {
    if (error instanceof WebhookConfigError) {
      return NextResponse.json(
        { error: error.message },
        { status: error.statusCode },
      );
    }

    logRouteError(error, {
      category: "webhook_settings_failure",
      ipAddress: getClientIpAddress(request.headers),
      message: "Unexpected failure while changing webhook settings.",
      path: getRequestPathname(request),
      userId: session.user.id,
    });

    return NextResponse.json(
      { error: "That could not be saved. Try again." },
      { status: 500 },
    );
  }
}
