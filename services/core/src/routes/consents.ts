import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { DataCategory, Rule } from '@pv/schemas';
import type { SessionProvider } from '../session.js';
import type { ConsentStore } from '../consent-store.js';
import type { AuditWriter } from '../audit-writer.js';
import type { UserPolicyStore } from '../policy-store.js';
import { requireIdentity, parseBody, sendValidationFailure } from './support.js';

/**
 * Consent management routes (W8.5, T036).
 *
 * The dashboard's consent screen reads and writes here, and the vault gateway
 * reads the same store at disclosure time - one state, never a UI copy. Every
 * mutation is audited under the owner's chain, and the grant flow exposes a
 * read-only risk preview so the client can show what granting implies before
 * the owner commits.
 */

const categoryIdSchema = z.string().min(1).max(36);

/** Collect every category a rule can act on: its scope and its condition tree. */
function categoriesTouchedBy(rule: Rule): Set<string> {
  const touched = new Set<string>(rule.scope.data_categories);
  const walk = (condition: Rule['condition']): void => {
    if (condition.op === 'category_in') {
      for (const category of condition.categories) touched.add(category);
    } else if (condition.op === 'and' || condition.op === 'or') {
      for (const operand of condition.operands) walk(operand);
    } else if (condition.op === 'not') {
      walk(condition.operand);
    }
  };
  walk(rule.condition);
  return touched;
}

export interface ConsentRouteDependencies {
  session: SessionProvider;
  consents: ConsentStore;
  userPolicy: UserPolicyStore;
  audit: AuditWriter;
  categories: readonly DataCategory[];
}

export function registerConsentRoutes(app: FastifyInstance, deps: ConsentRouteDependencies): void {
  const { session, consents, userPolicy, audit, categories } = deps;

  app.get('/api/consents', async (request, reply) => {
    const identity = await requireIdentity(request, reply, session);
    if (!identity) return reply;
    const records = await consents.listConsents(identity.user_id);
    return reply.send({ consents: records });
  });

  app.post('/api/consents/preview', async (request, reply) => {
    const identity = await requireIdentity(request, reply, session);
    if (!identity) return reply;
    const body = parseBody(request.body, z.strictObject({ data_category_id: categoryIdSchema }));
    if (!body.ok) return sendValidationFailure(reply, body.fields);
    const category = categories.find((c) => c.data_category_id === body.value.data_category_id);
    if (!category) return reply.status(404).send({ error: 'data_category_not_found' });

    const rules = await userPolicy.listUserRules(identity.user_id);
    const rulesAffecting = rules.filter((rule) => categoriesTouchedBy(rule).has(category.data_category_id));
    // Read-only: a preview changes nothing, so it writes no audit row either.
    return reply.send({
      data_category_id: category.data_category_id,
      category_name: category.category_name,
      sensitivity: category.sensitivity_level,
      rules_affecting: rulesAffecting.map((rule) => ({ rule_id: rule.rule_id, effect: rule.effect, rationale: rule.rationale })),
      note: 'Granting lets disclosures of this category rely on an active consent; revoking blocks them at disclosure time.',
    });
  });

  app.post('/api/consents', async (request, reply) => {
    const identity = await requireIdentity(request, reply, session);
    if (!identity) return reply;
    const body = parseBody(request.body, z.strictObject({ data_category_id: categoryIdSchema, consent_id: z.string().min(1).max(128).optional() }));
    if (!body.ok) return sendValidationFailure(reply, body.fields);
    const category = categories.find((c) => c.data_category_id === body.value.data_category_id);
    if (!category) return reply.status(404).send({ error: 'data_category_not_found' });

    const record = {
      user_id: identity.user_id,
      data_category_id: category.data_category_id,
      status: 'Active' as const,
      consent_id: body.value.consent_id ?? randomUUID(),
      updated_at: new Date().toISOString(),
    };
    await consents.upsertConsent(record);
    await audit.append(
      {
        request_id: null,
        timestamp: record.updated_at,
        actor: 'owner',
        actor_ref: identity.user_id,
        origin_domain: null,
        requested_categories: [category.data_category_id],
        domain_intelligence_summary: null,
        matched_rules: [],
        risk_level: null,
        decision: null,
        override: false,
        consent_id: record.consent_id,
        policy_version: 'consent-action',
      },
      { ownerKey: `owner:${identity.user_id}` },
    );
    return reply.status(201).send({ consent: record });
  });

  app.delete<{ Params: { category_id: string } }>('/api/consents/:category_id', async (request, reply) => {
    const identity = await requireIdentity(request, reply, session);
    if (!identity) return reply;
    const category = categories.find((c) => c.data_category_id === request.params.category_id);
    if (!category) return reply.status(404).send({ error: 'data_category_not_found' });
    const existing = await consents.getConsent(identity.user_id, category.data_category_id);
    if (existing === null) return reply.status(404).send({ error: 'consent_not_found' });

    const revokedAt = new Date().toISOString();
    await consents.upsertConsent({
      user_id: identity.user_id,
      data_category_id: category.data_category_id,
      status: 'Revoked',
      consent_id: existing.consent_id,
      updated_at: revokedAt,
    });
    await audit.append(
      {
        request_id: null,
        timestamp: revokedAt,
        actor: 'owner',
        actor_ref: identity.user_id,
        origin_domain: null,
        requested_categories: [category.data_category_id],
        domain_intelligence_summary: null,
        matched_rules: [],
        risk_level: null,
        decision: null,
        override: false,
        ...(existing.consent_id === null ? {} : { consent_id: existing.consent_id }),
        policy_version: 'consent-action',
      },
      { ownerKey: `owner:${identity.user_id}` },
    );
    return reply.status(204).send();
  });
}
