import { z } from 'zod';
import type { FastifyInstance } from 'fastify';
import {
  forceAllowRequestSchema,
  observedRequestSchema,
  type AuditEventInput,
  type DataCategory,
  type Decision,
} from '@pv/schemas';
import type { SessionProvider } from '../session.js';
import type { DeviceRequestContext } from '../device-auth.js';
import { authenticate, parseBody, requireIdentity, sendValidationFailure } from './support.js';
import { toWireDecision, type DecisionService, type DecisionStore } from '../decision-service.js';
import type { AuditWriter } from '../audit-writer.js';
import type { GrantIssuer } from '../gateway/grants.js';

const evaluateRequestSchema = z.strictObject({
  observation: observedRequestSchema,
});

export interface DecisionRouteDependencies {
  session: SessionProvider;
  device: DeviceRequestContext;
  decisions: DecisionService;
  store: DecisionStore;
  audit: AuditWriter;
  categories: readonly DataCategory[];
  /** Present whenever grants are configured; absent only in minimal DEV wiring. */
  grantIssuer: GrantIssuer | null;
}

function auditEventFor(
  decision: Decision,
  actor: 'owner' | 'application',
  actorRef: string | null,
  override: boolean,
  now: Date,
  extras: { reason: string | null; classifiedCategories: string[] },
): AuditEventInput {
  return {
    request_id: decision.request_id,
    timestamp: now.toISOString(),
    actor,
    actor_ref: actorRef,
    origin_domain: decision.explanation.website,
    requested_categories: [],
    domain_intelligence_summary: null,
    matched_rules: [...decision.matched_rules],
    classified_categories: extras.classifiedCategories,
    risk_level: decision.risk_level,
    decision: decision.decision,
    override,
    override_reason: extras.reason,
    policy_version: decision.policy_version,
  };
}

/**
 * The categories a stored decision judged. Decisions produced by the current
 * pipeline carry `classified_categories`; a legacy row without them names no
 * category rather than a re-derived guess.
 */
function categoriesOfDecision(decision: Decision): string[] {
  return decision.classified_categories ?? [];
}

/**
 * Decision routes (`T025`, W6.5) — the HTTP face of the decision engine.
 *
 * The extension posts each observation here and renders the returned decision;
 * Force Allow arrives at `/override`, where a critical security block is refused
 * server-side regardless of what any client sends (T027, `AGENT.md`). Every
 * decision and every override attempt is written to the owner's audit chain —
 * the override events under the owner's own actor with the stated reason — and
 * an issued override grant is single-use and scope-limited to exactly the
 * fields the decision judged.
 */
export function registerDecisionRoutes(app: FastifyInstance, dependencies: DecisionRouteDependencies): void {
  const { decisions, store, audit, grantIssuer } = dependencies;

  // T034: the dashboard's recent-requests feed. Owner-scoped through the
  // session, newest first, and paginated with a cursor so a long history
  // never loads in one response.
  app.get('/api/decisions', async (request, reply) => {
    const identity = await requireIdentity(request, reply, dependencies.session);
    if (!identity) return reply;
    const query = z
      .object({
        limit: z.coerce.number().int().min(1).max(100).default(25).optional(),
        before: z.iso.datetime().optional(),
      })
      .safeParse(request.query ?? {});
    if (!query.success) return sendValidationFailure(reply, query.error.issues.map((issue) => issue.path.join('.')));
    const limit = query.data.limit ?? 25;
    const decisionsPage = await store.listDecisions(identity.user_id, limit, query.data.before);
    const last = decisionsPage.at(-1);
    return reply.send({
      // The wire carries the shared schema's shape; storage-only fields stay
      // server-side (the dashboard validates responses with the same schema).
      decisions: decisionsPage.map(toWireDecision),
      next_cursor: decisionsPage.length === limit && last !== undefined ? last.created_at : null,
    });
  });

  app.post('/api/decisions/evaluate', async (request, reply) => {
    const authenticated = await authenticate(request, reply, dependencies);
    if (!authenticated) return reply;

    const body = parseBody(authenticated.payload, evaluateRequestSchema);
    if (!body.ok) return sendValidationFailure(reply, body.fields);

    const pipeline = await decisions.evaluate({
      user_id: authenticated.identity.user_id,
      request: body.value.observation,
    });

    const now = new Date();
    await audit.append(
      auditEventFor(pipeline.decision, 'application', authenticated.identity.user_id, false, now, {
        reason: null,
        classifiedCategories: categoriesOfDecision(pipeline.decision),
      }),
      { ownerKey: `owner:${authenticated.identity.user_id}` },
    );

    return reply.send(pipeline.decision);
  });

  app.get<{ Params: { decision_id: string } }>('/api/decisions/:decision_id', async (request, reply) => {
    const identity = await requireIdentity(request, reply, dependencies.session);
    if (!identity) return reply;
    const decision = await store.getDecision(identity.user_id, request.params.decision_id);
    if (!decision) return reply.status(404).send({ error: 'decision_not_found' });
    return reply.send(toWireDecision(decision));
  });

  app.post('/api/decisions/override', async (request, reply) => {
    const authenticated = await authenticate(request, reply, dependencies);
    if (!authenticated) return reply;

    const body = parseBody(authenticated.payload, forceAllowRequestSchema);
    if (!body.ok) return sendValidationFailure(reply, body.fields);

    const decision = await store.getDecision(authenticated.identity.user_id, body.value.decision_id);
    if (!decision) return reply.status(404).send({ error: 'decision_not_found' });

    // Server-side authority: the client may send anything, a critical security
    // block is still refused here (T027). The stored decision is not mutated —
    // the refusal is recorded as a new audit event instead.
    const refused = decision.critical_security_block || decision.override_class === 'critical';
    if (refused) {
      const event = await audit.append(
        auditEventFor(decision, 'owner', authenticated.identity.user_id, true, new Date(), {
          reason: body.value.reason,
          classifiedCategories: categoriesOfDecision(decision),
        }),
        { ownerKey: `owner:${authenticated.identity.user_id}` },
      );
      return reply.send({
        audit_id: event.audit_id,
        authorization_grant: null,
        refused: true,
        refusal_reason: 'critical_security_block',
      });
    }

    const event = await audit.append(
      auditEventFor(decision, 'owner', authenticated.identity.user_id, true, new Date(), {
        reason: body.value.reason,
        classifiedCategories: categoriesOfDecision(decision),
      }),
      { ownerKey: `owner:${authenticated.identity.user_id}` },
    );

    // W6.5: an issued override grant is scope-limited to exactly the fields the
    // decision judged, bound to this request and policy version, and redeemable
    // once (Phase 7 consumes it). Wiring without a grant issuer still answers,
    // but with no grant: it can never be a second, weaker way to get one.
    const approvedFields = [...decision.explanation.requested_data];
    const grant =
      grantIssuer === null
        ? null
        : await grantIssuer.issue({
            request_id: decision.request_id,
            user_id: authenticated.identity.user_id,
            decision_id: decision.decision_id,
            data_id: null,
            data_category_id: categoriesOfDecision(decision)[0] ?? 'UNKNOWN',
            approved_fields: approvedFields,
            recipient: decision.explanation.website,
            policy_version: decision.policy_version,
            now: new Date(),
          });

    return reply.send({
      audit_id: event.audit_id,
      authorization_grant:
        grant === null
          ? null
          : {
              grant: grant.token,
              expires_at: grant.expires_at,
              approved_fields: approvedFields,
              data_category_id: grant.grant.data_category_id,
            },
      refused: false,
      refusal_reason: null,
    });
  });
}
