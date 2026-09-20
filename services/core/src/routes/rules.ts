import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  ruleIdSchema,
  userRuleInputSchema,
  type AuditEventInput,
  type Rule,
  type RuleConflictPreview,
  type UserRuleInput,
} from '@pv/schemas';
import { restrictivenessOf } from '@pv/rules';
import type { SessionProvider } from '../session.js';
import type { DeviceRequestContext } from '../device-auth.js';
import { authenticate, parseBody, requireIdentity, sendValidationFailure } from './support.js';
import {
  PolicyConflictError,
  buildUserRule,
  currentPolicyVersion,
  type UserPolicyStore,
} from '../policy-store.js';
import type { AuditWriter } from '../audit-writer.js';
import type { DecisionService } from '../decision-service.js';

/**
 * User-rule routes (`T022`, W5.4) — the HTTP face of owner policy.
 *
 * The API is deliberately thin over pieces that already exist: `buildUserRule`
 * is the only validator (the preview reports the same refusal the save would),
 * and `previewRuleConflict` reuses the evaluator's own contest semantics —
 * priority first, then restrictiveness at equal priority — so what the preview
 * predicts is what `evaluateRules` will do, not a second opinion.
 *
 * Authorization: mutations go through `authenticate`, so a device-bound session
 * must sign them; reads (`GET`, `preview`) resolve the session like every other
 * read route (DEV-04). Rules are always scoped by the session's owner: a rule id
 * in the URL that belongs to somebody else is indistinguishable from one that
 * does not exist (404).
 */

export interface RulesRouteDependencies {
  session: SessionProvider;
  device: DeviceRequestContext;
  service: DecisionService;
  userPolicy: UserPolicyStore;
  audit: AuditWriter;
}

/** Bodies are wrapped so a top-level user field can never collide with the envelope. */
const ruleRequestSchema = z.strictObject({ rule: userRuleInputSchema });

/** Two rules can only contest the same request when their scopes overlap. */
function scopesIntersect(a: Rule['scope'], b: Rule['scope']): boolean {
  const overlaps = (x: readonly string[], y: readonly string[]): boolean =>
    x.length === 0 || y.length === 0 || x.some((value) => y.includes(value));
  return (
    overlaps(a.data_categories, b.data_categories) &&
    overlaps(a.origins, b.origins) &&
    overlaps(a.applications, b.applications)
  );
}

/**
 * Static conflict analysis for the save-time preview (`T022`).
 *
 * This is a static approximation, and the wording matters: it predicts which
 * rules would contest the proposal for a request both match, not what any
 * concrete decision will be — that depends on the signals of the day. The
 * critical class never appears here because a user proposal structurally
 * cannot carry it; neutralising a critical rule is not a possibility the
 * engine permits, so the preview does not pretend to negotiate it.
 */
export function previewRuleConflict(input: {
  proposal: UserRuleInput;
  systemRules: readonly Rule[];
  userRules: readonly Rule[];
  policyVersion: string;
  rejectedReason: string | null;
}): RuleConflictPreview {
  const shadows: RuleConflictPreview['shadows'] = [];
  const neutralisedBy: string[] = [];

  for (const other of [...input.systemRules, ...input.userRules]) {
    if (!scopesIntersect(input.proposal.scope, other.scope)) continue;
    const proposalWins =
      input.proposal.priority > other.priority ||
      (input.proposal.priority === other.priority &&
        restrictivenessOf(input.proposal.effect) > restrictivenessOf(other.effect));
    const otherWins =
      other.priority > input.proposal.priority ||
      (other.priority === input.proposal.priority &&
        restrictivenessOf(other.effect) > restrictivenessOf(input.proposal.effect));
    if (proposalWins) {
      shadows.push({
        rule_id: other.rule_id,
        origin: other.origin,
        effect: other.effect,
        priority: other.priority,
        detail: `${other.rule_id} (${other.origin}, ${other.effect}) at priority ${other.priority} would no longer control the requests this rule matches`,
      });
    } else if (otherWins) {
      neutralisedBy.push(other.rule_id);
    }
  }

  shadows.sort((a, b) => b.priority - a.priority || (a.rule_id < b.rule_id ? -1 : 1));
  neutralisedBy.sort();

  return {
    shadows,
    neutralised_by: neutralisedBy,
    rejected_reason: input.rejectedReason,
    policy_version: input.policyVersion,
  };
}

/** The refusal `buildUserRule` would raise, reported without throwing. */
function rejectionReasonFor(input: UserRuleInput): string | null {
  try {
    buildUserRule(input, { policy_version: 'preview' });
    return null;
  } catch (error) {
    if (error instanceof PolicyConflictError) return error.message;
    // A schema rejection carries its own explanation (which field, which
    // bound); surfacing it beats a generic refusal. The value being echoed is
    // the proposer's own input, not another principal's secret.
    return error instanceof Error && error.message.length > 0
      ? `the rule would be refused: ${error.message}`.slice(0, 300)
      : 'the rule would be refused';
  }
}

function ruleChangeEvent(input: {
  user_id: string;
  rule_id: string | null;
  action: 'created' | 'updated' | 'deleted' | 'refused';
  policy_version: string;
  categories: readonly string[];
  now: Date;
}): AuditEventInput {
  return {
    request_id: null,
    timestamp: input.now.toISOString(),
    actor: 'owner',
    actor_ref: input.user_id,
    origin_domain: null,
    requested_categories: input.categories.slice(0, 64),
    domain_intelligence_summary:
      input.rule_id === null
        ? `a user-rule ${input.action} was refused`
        : `user rule ${input.rule_id} ${input.action}`,
    matched_rules: input.rule_id === null ? [] : [input.rule_id],
    risk_level: null,
    decision: null,
    override: false,
    policy_version: input.policy_version,
  };
}

export function registerRulesRoutes(app: FastifyInstance, dependencies: RulesRouteDependencies): void {
  const { session, device, service, userPolicy, audit } = dependencies;
  const rulesetVersion = service.ruleset.ruleset_version;

  app.post('/api/rules/preview', async (request, reply) => {
    const identity = await requireIdentity(request, reply, session);
    if (!identity) return reply;

    const body = parseBody(request.body, ruleRequestSchema);
    if (!body.ok) return sendValidationFailure(reply, body.fields);

    const [userRules, version] = await Promise.all([
      userPolicy.listUserRules(identity.user_id),
      currentPolicyVersion(userPolicy, identity.user_id, rulesetVersion),
    ]);
    return reply.send(
      previewRuleConflict({
        proposal: body.value.rule,
        systemRules: service.ruleset.rules,
        userRules,
        policyVersion: version.policy_version,
        rejectedReason: rejectionReasonFor(body.value.rule),
      }),
    );
  });

  app.get('/api/rules', async (request, reply) => {
    const identity = await requireIdentity(request, reply, session);
    if (!identity) return reply;
    return reply.send({ rules: await userPolicy.listUserRules(identity.user_id) });
  });

  app.post('/api/rules', async (request, reply) => {
    const authenticated = await authenticate(request, reply, { session, device });
    if (!authenticated) return reply;
    const body = parseBody(authenticated.payload, ruleRequestSchema);
    if (!body.ok) return sendValidationFailure(reply, body.fields);
    const userId = authenticated.identity.user_id;
    const now = new Date();

    const before = await currentPolicyVersion(userPolicy, userId, rulesetVersion);
    let rule: Rule;
    try {
      rule = buildUserRule(body.value.rule, { policy_version: before.policy_version }).rule;
    } catch (error) {
      if (error instanceof PolicyConflictError) {
        await audit.append(
          ruleChangeEvent({
            user_id: userId,
            rule_id: null,
            action: 'refused',
            policy_version: before.policy_version,
            categories: [],
            now,
          }),
          { ownerKey: `owner:${userId}` },
        );
        return reply.status(400).send({ fields: [error.field] });
      }
      throw error;
    }

    try {
      await userPolicy.insertUserRule(userId, rule, now.toISOString());
    } catch (error) {
      if (error instanceof PolicyConflictError) {
        return reply.status(409).send({ error: 'duplicate_rule_id' });
      }
      throw error;
    }

    const after = await currentPolicyVersion(userPolicy, userId, rulesetVersion);
    await audit.append(
      ruleChangeEvent({
        user_id: userId,
        rule_id: rule.rule_id,
        action: 'created',
        policy_version: after.policy_version,
        categories: rule.scope.data_categories,
        now,
      }),
      { ownerKey: `owner:${userId}` },
    );
    return reply.status(201).send({ rule, policy_version: after.policy_version });
  });

  app.put<{ Params: { rule_id: string } }>('/api/rules/:rule_id', async (request, reply) => {
    const authenticated = await authenticate(request, reply, { session, device });
    if (!authenticated) return reply;
    const userId = authenticated.identity.user_id;
    const ruleId = request.params.rule_id;
    const now = new Date();

    if (!ruleIdSchema.safeParse(ruleId).success) {
      return reply.status(400).send({ fields: ['rule_id'] });
    }
    const existing = await userPolicy.getUserRule(userId, ruleId);
    if (!existing) {
      await audit.append(
        ruleChangeEvent({
          user_id: userId,
          rule_id: null,
          action: 'refused',
          policy_version: (await currentPolicyVersion(userPolicy, userId, rulesetVersion)).policy_version,
          categories: [],
          now,
        }),
        { ownerKey: `owner:${userId}` },
      );
      return reply.status(404).send({ error: 'rule_not_found' });
    }

    const body = parseBody(authenticated.payload, ruleRequestSchema);
    if (!body.ok) return sendValidationFailure(reply, body.fields);
    if (body.value.rule.rule_id !== undefined && body.value.rule.rule_id !== ruleId) {
      return reply.status(400).send({ fields: ['rule_id'] });
    }

    const before = await currentPolicyVersion(userPolicy, userId, rulesetVersion);
    let rule: Rule;
    try {
      // The id is taken from the URL: the body cannot rename a rule into
      // somebody else's id space, and the stored row keeps its identity.
      rule = buildUserRule({ ...body.value.rule, rule_id: ruleId }, { policy_version: before.policy_version }).rule;
    } catch (error) {
      if (error instanceof PolicyConflictError) {
        return reply.status(400).send({ fields: [error.field] });
      }
      throw error;
    }

    const updated = await userPolicy.updateUserRule(userId, ruleId, rule, now.toISOString());
    if (!updated) return reply.status(404).send({ error: 'rule_not_found' });

    const after = await currentPolicyVersion(userPolicy, userId, rulesetVersion);
    await audit.append(
      ruleChangeEvent({
        user_id: userId,
        rule_id: rule.rule_id,
        action: 'updated',
        policy_version: after.policy_version,
        categories: rule.scope.data_categories,
        now,
      }),
      { ownerKey: `owner:${userId}` },
    );
    return reply.send({ rule, policy_version: after.policy_version });
  });

  app.delete<{ Params: { rule_id: string } }>('/api/rules/:rule_id', async (request, reply) => {
    const authenticated = await authenticate(request, reply, { session, device });
    if (!authenticated) return reply;
    const userId = authenticated.identity.user_id;
    const ruleId = request.params.rule_id;
    const now = new Date();

    if (!ruleIdSchema.safeParse(ruleId).success) {
      return reply.status(400).send({ fields: ['rule_id'] });
    }
    const existing = await userPolicy.getUserRule(userId, ruleId);
    if (!existing) {
      await audit.append(
        ruleChangeEvent({
          user_id: userId,
          rule_id: null,
          action: 'refused',
          policy_version: (await currentPolicyVersion(userPolicy, userId, rulesetVersion)).policy_version,
          categories: [],
          now,
        }),
        { ownerKey: `owner:${userId}` },
      );
      return reply.status(404).send({ error: 'rule_not_found' });
    }

    await userPolicy.deleteUserRule(userId, ruleId);
    const after = await currentPolicyVersion(userPolicy, userId, rulesetVersion);
    await audit.append(
      ruleChangeEvent({
        user_id: userId,
        rule_id: ruleId,
        action: 'deleted',
        policy_version: after.policy_version,
        categories: existing.scope.data_categories,
        now,
      }),
      { ownerKey: `owner:${userId}` },
    );
    return reply.send({ deleted: true, policy_version: after.policy_version });
  });
}
