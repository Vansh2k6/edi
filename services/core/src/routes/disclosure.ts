import type { FastifyInstance } from 'fastify';
import { disclosureRequestSchema } from '@pv/schemas';
import type { SessionProvider } from '../session.js';
import type { DeviceRequestContext } from '../device-auth.js';
import { authenticate, parseBody, sendValidationFailure } from './support.js';
import type { VaultGateway } from '../gateway/authorize.js';
import type { UserPolicyStore } from '../policy-store.js';

export interface DisclosureRouteDependencies {
  session: SessionProvider;
  device: DeviceRequestContext;
  gateway: VaultGateway;
  userPolicy: UserPolicyStore;
  rulesetVersion: string;
}

/**
 * The disclosure route (`T029`, W7.1) — the only HTTP door to vault data.
 *
 * The gateway is authoritative; this route adds the HTTP contract: identity
 * from the session (never the body), the owner's *current* policy version at
 * disclosure time (so a policy change after grant issuance is refused here),
 * and honest status codes for every named refusal. `local_values` may only
 * ever come from the authenticated owner's own gesture-bound fetch.
 */
export function registerDisclosureRoute(app: FastifyInstance, dependencies: DisclosureRouteDependencies): void {
  app.post('/api/disclosure', async (request, reply) => {
    const authenticated = await authenticate(request, reply, dependencies);
    if (!authenticated) return reply;

    const body = parseBody(authenticated.payload, disclosureRequestSchema);
    if (!body.ok) return sendValidationFailure(reply, body.fields);

    const policyVersion = await dependencies.userPolicy.policyEpoch(authenticated.identity.user_id).then((epoch) =>
      `${dependencies.rulesetVersion}@${epoch}`,
    );

    const outcome = await dependencies.gateway.authorizeDisclosure({
      user_id: authenticated.identity.user_id,
      grant_token: body.value.grant,
      fields: body.value.fields,
      recipient: body.value.recipient,
      policy_version: policyVersion,
      ...(body.value.local_values === undefined ? {} : { local_values: body.value.local_values }),
    });

    if (!outcome.ok) {
      return reply.status(outcome.http_status).send(outcome.failure);
    }
    return reply.send(outcome.result);
  });
}
