import { z } from 'zod';

export const identityStatusSchema = z.enum(['Pending', 'Verified', 'Suspended']);
export const userTypeSchema = z.enum(['Citizen', 'Organization', 'Administrator']);

export const userSchema = z.strictObject({
  user_id: z.uuid(),
  user_name: z.string().min(1).max(150),
  email_id: z.email().max(150),
  mobile_number: z.string().max(20).nullable(),
  identity_status: identityStatusSchema,
  user_type: userTypeSchema,
});
export type User = z.infer<typeof userSchema>;

/** A third-party application that may request access through consent. */
export const applicationSchema = z.strictObject({
  application_id: z.string().min(1).max(36),
  application_name: z.string().min(1).max(150),
  /** Higher is more trusted. Drives the untrust factor in risk scoring. */
  security_rating: z.number().min(0).max(10),
});
export type Application = z.infer<typeof applicationSchema>;

/**
 * The authenticated subject of a request.
 *
 * The core derives this from the session; it is never accepted from a request
 * body or query string.
 */
export const sessionSchema = z.strictObject({
  user_id: z.uuid(),
  issued_at: z.iso.datetime(),
  expires_at: z.iso.datetime(),
  /** Device-bound public key that signed the request, for extension traffic. */
  device_key_id: z.string().min(1).max(128).nullable(),
});
export type Session = z.infer<typeof sessionSchema>;
