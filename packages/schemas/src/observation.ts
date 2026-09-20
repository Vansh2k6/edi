import { z } from 'zod';

/**
 * What the extension observed (ARCHITECTURE.md section 5.2).
 *
 * Only fields actually available are populated; absent values are explicit nulls
 * so a consumer can tell "not available" from "empty".
 */

export const MAX_URL_LENGTH = 2048;
export const MAX_HOST_LENGTH = 253;
export const MAX_FIELD_LENGTH = 128;
export const MAX_FIELDS_PER_REQUEST = 64;
export const MAX_REDIRECT_HOPS = 20;

export const mechanismSchema = z.enum(['fetch', 'xhr', 'beacon', 'form', 'websocket', 'unsupported']);
export type Mechanism = z.infer<typeof mechanismSchema>;

/**
 * How the origin was classified. `localhost`, loopback, private and link-local
 * origins are first-class outcomes rather than being collapsed into "public",
 * because treating an internal origin as public would be a misclassification.
 */
export const originKindSchema = z.enum([
  'public',
  'localhost',
  'loopback',
  'private',
  'link_local',
  'ip_literal',
  'extension',
  'internal',
  'unknown',
]);
export type OriginKind = z.infer<typeof originKindSchema>;

export const originSchema = z.strictObject({
  /** The value as the browser reported it, before normalisation. */
  raw: z.string().max(MAX_URL_LENGTH),
  /** Canonical lowercase host, punycode-encoded, no port. */
  host: z.string().min(1).max(MAX_HOST_LENGTH),
  kind: originKindSchema,
  scheme: z.enum(['http', 'https', 'ws', 'wss', 'chrome-extension', 'other']),
  port: z.number().int().min(1).max(65535).nullable(),
  /** Registrable domain when derivable (example.com for a.b.example.com). */
  registrable_domain: z.string().min(1).max(MAX_HOST_LENGTH).nullable(),
  display: z.string().min(1).max(255),
});
export type Origin = z.infer<typeof originSchema>;

export const observedRequestSchema = z.strictObject({
  request_id: z.uuid(),
  timestamp: z.iso.datetime(),
  origin: originSchema,
  destination: z.string().min(1).max(MAX_URL_LENGTH),
  requested_data: z.array(z.string().min(1).max(MAX_FIELD_LENGTH)).max(MAX_FIELDS_PER_REQUEST),
  mechanism: mechanismSchema,
  page_context: z.strictObject({
    top_level_url: z.string().max(MAX_URL_LENGTH).nullable(),
    is_top_frame: z.boolean(),
  }),
  browser_context: z.strictObject({
    tab_id: z.number().int().nullable(),
    redirect_chain: z.array(z.string().max(MAX_URL_LENGTH)).max(MAX_REDIRECT_HOPS),
  }),
});
export type ObservedRequest = z.infer<typeof observedRequestSchema>;

/**
 * Message sent from the page world to the content script isolate.
 *
 * This is boundary 1 (ARCHITECTURE.md section 4): the page is untrusted, so the
 * field set is fixed and every field is bounded. Anything the page claims
 * (origin, permission, category) is context only and is re-derived before use.
 */
export const pageObservationMessageSchema = z.strictObject({
  channel: z.literal('pv-observe'),
  mechanism: mechanismSchema,
  url: z.string().max(MAX_URL_LENGTH),
  method: z.string().max(16),
  /** Names of the fields the page appears to be sending, best effort only. */
  field_names: z.array(z.string().min(1).max(MAX_FIELD_LENGTH)).max(MAX_FIELDS_PER_REQUEST),
  /** Page-supplied claim. Recorded as untrusted context, never used as origin. */
  page_claimed_origin: z.string().max(MAX_URL_LENGTH).nullable(),
});
export type PageObservationMessage = z.infer<typeof pageObservationMessageSchema>;
