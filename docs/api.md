# Public API and webhooks

For another system of your own, such as an internal operating system, to send PDFs for signature, follow them, and fetch the signed copy. Everything goes through the same steps as the app's own pages, so signers get the same emails and signing pages, and the sealing and audit trail are the same.

## Set it up

1. **Settings → Organization → API keys.** Name the key, confirm the documents are ordinary business agreements, and create it. Copy the key (`sdk_…`) into the other system's secret settings. It is shown once; only a hash is kept. A key acts for the administrator who made it, and stops working if they stop being one. Revoke it on the same screen.
2. **Settings → Organization → Webhooks.** Enter the address to notify and turn webhooks on. Copy the signing secret (`whsec_…`) into the other system's secret settings. It is shown once. **Rotate signing secret** makes a new one; the old one keeps signing too for 24 hours. The screen lists recent deliveries.

## Endpoints

All under `/api/v1`, JSON, with `Authorization: Bearer <key>`. A missing, wrong or revoked key gets `401`. A key sees and changes only the envelopes it made. Errors are `{ "error": "<plain sentence>" }`.

### `POST /api/v1/envelopes`

Makes an envelope from a PDF and, unless `"send": false`, sends it at once (emails the first signer). Needs an `Idempotency-Key` header (up to 200 letters, digits and `. _ : -`). The same key returns the same envelope (`200`) and never sends twice; a send that failed part way (email down) is tried again by a retry with the same key. The same key with a different body gets `422`. Keys are kept 30 days.

```json
{
  "title": "Client Services Agreement",
  "externalId": "your-reference",
  "document": {
    "fileName": "csa.pdf",
    "contentType": "application/pdf",
    "contentBase64": "JVBERi0…"
  },
  "signers": [
    {
      "key": "client",
      "name": "Jane Doe",
      "email": "jane@example.com",
      "signOrder": 1
    },
    {
      "key": "cu",
      "name": "Ian Example",
      "email": "ian@example.com",
      "signOrder": 2
    }
  ],
  "cc": [{ "name": "Ops", "email": "ops@example.com" }],
  "fields": [
    {
      "signerKey": "client",
      "type": "signature",
      "page": 6,
      "x": 0.549,
      "y": 0.2475,
      "width": 0.3333,
      "height": 0.053,
      "required": true
    },
    {
      "signerKey": "client",
      "type": "date",
      "page": 6,
      "x": 0.598,
      "y": 0.3359,
      "width": 0.2124,
      "height": 0.0227,
      "required": true
    }
  ],
  "message": null,
  "send": true
}
```

- `document`: one PDF, **up to 3 MB** (Vercel refuses request bodies over 4.5 MB, and base64 adds a third).
- Signers sign one at a time in `signOrder`. Each needs at least one `signature` field.
- `fields`: `page` is 1-based; `x`, `y`, `width`, `height` are fractions of the page from its **top-left** corner. Types: `signature`, `date` (fills itself with the signing date), `initials`, `name` (fills itself with the signer's name).
- `message` is accepted and not shown: the emails stay as the app sends them.
- Answers `201` with the envelope (shape below), or `200` for a repeated Idempotency-Key.

### `GET /api/v1/envelopes/{id}`

```json
{
  "id": "…",
  "externalId": "your-reference",
  "title": "…",
  "status": "draft | sent | completed | declined | voided",
  "url": "https://<site>/envelopes/…",
  "createdAt": "ISO",
  "sentAt": "ISO|null",
  "completedAt": "ISO|null",
  "signers": [
    {
      "key": "client",
      "name": "…",
      "email": "…",
      "status": "pending | notified | signed | declined",
      "signedAt": "ISO|null",
      "signOrder": 1
    }
  ]
}
```

`notified` is the signer whose turn it is; `pending` is waiting for an earlier signer. A passed deadline does not change `status` (it stays `sent`).

### `POST /api/v1/envelopes/{id}/void`

Body `{ "reason": "…" }` (optional). Voids an envelope out for signature and tells the signers, as voiding from its page does. `409` with `{ "error": "already_completed" }` once it is completed, and `409` when it is not out for signature.

### `GET /api/v1/envelopes/{id}/signed-pdf`

The sealed PDF. `409` until the envelope is `completed`.

## Webhooks

For envelopes made through the API only. Events: `envelope.sent`, `envelope.viewed`, `envelope.signer_signed`, `envelope.completed`, `envelope.declined`, `envelope.voided`.

```json
{
  "id": "evt_…",
  "type": "envelope.completed",
  "createdAt": "ISO",
  "envelope": { "…": "same shape as GET" }
}
```

Header `SignuDoc-Signature: t=<unix seconds>,v1=<hex>` where `v1` is HMAC-SHA256 over `"<t>.<raw body>"`, keyed with the whole secret string (`whsec_…` included) as UTF-8. While a secret is being rotated there is one `v1=` per secret. Check it against the raw body, in constant time, and refuse a `t` more than 5 minutes old.

Delivery is at least once: an event can arrive twice or out of order, so keep the `evt_` ids you have handled and read the envelope with GET before acting. Answer `2xx` once handled, within 30 seconds. Anything else is retried after 10 s, 30 s, 90 s, 5 min, 15 min, 30 min, 1 h, 2 h, 4 h, 6 h and 12 h, for up to 24 hours.

**When retries run.** The first ones (up to about 2 minutes after the event) are sent straight away. Later ones go out the next time the site is busy (any change to an envelope, or any API call) and at the daily cleanup. On Vercel's Hobby plan cron jobs run once a day, so a receiver that stays down can see a late retry hours after its due time. The other system should also read envelopes it is waiting on with GET now and then, rather than rely on webhooks alone.
