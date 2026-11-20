import { z } from "zod";

import {
  emailSchema,
  envelopeTitleSchema,
  nameSchema,
  normalizedCoordinateSchema,
  normalizedSizeSchema,
} from "../schemas/common.ts";
import {
  MAX_COPY_RECIPIENTS_PER_ENVELOPE,
  MAX_SIGNERS_PER_ENVELOPE,
} from "../types/domain.ts";

// The request bodies of the public API (/api/v1). Kept apart from the
// schemas the app's own pages use, so the API stays the same when those
// change.

/**
 * The largest PDF the API takes inline. Vercel refuses request bodies over
 * 4.5 MB, and base64 makes a file a third bigger, so this is what fits.
 */
export const MAX_API_PDF_BYTES = 3 * 1024 * 1024;
export const MAX_API_REQUEST_BYTES = 4_400_000;
export const MAX_API_FIELDS = 200;

/** The field types the API places. Each fills in as it does in the app. */
export const apiFieldTypes = ["signature", "date", "initials", "name"] as const;

const signerKeySchema = z
  .string()
  .trim()
  .min(1)
  .max(64)
  .regex(
    /^[A-Za-z0-9_-]+$/,
    "A signer key may use only letters, digits, _ and -",
  );

const apiSignerSchema = z.object({
  key: signerKeySchema,
  name: nameSchema,
  email: emailSchema,
  signOrder: z.number().int().min(1).max(MAX_SIGNERS_PER_ENVELOPE),
});

const apiCopyRecipientSchema = z.object({
  name: nameSchema,
  email: emailSchema,
});

const apiFieldSchema = z.object({
  signerKey: signerKeySchema,
  type: z.enum(apiFieldTypes),
  page: z.number().int().positive(),
  x: normalizedCoordinateSchema,
  y: normalizedCoordinateSchema,
  width: normalizedSizeSchema,
  height: normalizedSizeSchema,
  required: z.boolean().default(true),
});

export const createApiEnvelopeSchema = z
  .object({
    title: envelopeTitleSchema,
    externalId: z.string().trim().min(1).max(200).nullable().optional(),
    document: z.object({
      fileName: z.string().trim().min(1).max(255),
      contentType: z.literal("application/pdf", {
        error: "document.contentType must be application/pdf",
      }),
      contentBase64: z.string().min(1),
    }),
    signers: z.array(apiSignerSchema).min(1).max(MAX_SIGNERS_PER_ENVELOPE),
    cc: z
      .array(apiCopyRecipientSchema)
      .max(MAX_COPY_RECIPIENTS_PER_ENVELOPE)
      .nullable()
      .optional(),
    fields: z.array(apiFieldSchema).min(1).max(MAX_API_FIELDS),
    // Accepted for the caller's convenience but not shown: the signing
    // emails stay exactly as the app sends them.
    message: z.string().max(5000).nullable().optional(),
    send: z.boolean().default(true),
  })
  .superRefine((value, ctx) => {
    const keys = new Set<string>();
    const orders = new Set<number>();
    const emails = new Set<string>();

    value.signers.forEach((signer, index) => {
      if (keys.has(signer.key)) {
        ctx.addIssue({
          code: "custom",
          message: `Signer key "${signer.key}" is used twice`,
          path: ["signers", index, "key"],
        });
      }

      if (orders.has(signer.signOrder)) {
        ctx.addIssue({
          code: "custom",
          message: `signOrder ${String(signer.signOrder)} is used twice`,
          path: ["signers", index, "signOrder"],
        });
      }

      if (emails.has(signer.email.toLowerCase())) {
        ctx.addIssue({
          code: "custom",
          message: "Each signer must have a different email address",
          path: ["signers", index, "email"],
        });
      }

      keys.add(signer.key);
      orders.add(signer.signOrder);
      emails.add(signer.email.toLowerCase());
    });

    (value.cc ?? []).forEach((recipient, index) => {
      if (emails.has(recipient.email.toLowerCase())) {
        ctx.addIssue({
          code: "custom",
          message: "A cc address is already a signer or another cc",
          path: ["cc", index, "email"],
        });
      }

      emails.add(recipient.email.toLowerCase());
    });

    value.fields.forEach((field, index) => {
      if (!keys.has(field.signerKey)) {
        ctx.addIssue({
          code: "custom",
          message: `Field signerKey "${field.signerKey}" is not one of the signers`,
          path: ["fields", index, "signerKey"],
        });
      }

      if (
        field.x + field.width > 1.000001 ||
        field.y + field.height > 1.000001
      ) {
        ctx.addIssue({
          code: "custom",
          message: "A field extends beyond its page",
          path: ["fields", index],
        });
      }
    });

    for (const signer of value.signers) {
      if (
        !value.fields.some(
          (field) =>
            field.signerKey === signer.key && field.type === "signature",
        )
      ) {
        ctx.addIssue({
          code: "custom",
          message: `Signer "${signer.key}" needs at least one signature field`,
          path: ["fields"],
        });
      }
    }
  });

export type CreateApiEnvelopeInput = z.infer<typeof createApiEnvelopeSchema>;

export const voidApiEnvelopeSchema = z.object({
  reason: z.string().trim().max(1000).nullable().optional(),
});

/** The first problem in a validation error, as one plain sentence. */
export function describeValidationError(error: z.ZodError): string {
  const issue = error.issues[0];

  if (!issue) {
    return "The request is not valid.";
  }

  const path = issue.path.map(String).join(".");

  return path ? `${path}: ${issue.message}` : issue.message;
}
