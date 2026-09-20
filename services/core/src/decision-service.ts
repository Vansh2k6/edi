import { randomUUID } from 'node:crypto';
import {
  summarizeSignals,
  type Consent,
  type DataCategory,
  type Decision,
  type DomainSignal,
  type IntelligenceSummary,
  type ObservedRequest,
  type Ruleset,
} from '@pv/schemas';
import {
  assessFeasibility,
  analyzeMinimization,
  classifyRequest,
  decide,
  evaluateRules,
  loadRuleset,
  type FeasibilityResult,
  type MinimizationResult,
} from '@pv/rules';
import { assessRisk, type RiskIntelligence } from '@pv/risk';
import { collectIntelligence, type DomainIntelligenceProvider, type IntelligenceCache, type ProviderRuntimeState } from '@pv/domain-intel';
import type { UserPolicyStore } from './policy-store.js';

/**
 * The decision service (`T025`, W5.6, W6.3).
 *
 * One place composes the pipeline: classify, gather signals, evaluate rules,
 * score risk, and decide. The ruleset is loaded once at startup with its
 * checksum verified; the user policy version is read per request, so a policy
 * change changes the recorded `policy_version` and produces a *new* decision
 * rather than rewriting history.
 */

export interface DecisionStore {
  insertDecision(decision: StoredDecision): Promise<void>;
  getDecision(userId: string, decisionId: string): Promise<StoredDecision | null>;
  /** Newest-first page for one owner; `before` excludes entries at/after the cursor (T034 pagination). */
  listDecisions(userId: string, limit: number, before?: string): Promise<StoredDecision[]>;
}

export interface StoredDecision extends Decision {
  user_id: string;
}

export class MemoryDecisionStore implements DecisionStore {
  readonly #rows = new Map<string, StoredDecision>();

  async insertDecision(decision: StoredDecision): Promise<void> {
    this.#rows.set(decision.decision_id, decision);
  }

  async getDecision(userId: string, decisionId: string): Promise<StoredDecision | null> {
    const row = this.#rows.get(decisionId);
    return row !== undefined && row.user_id === userId ? row : null;
  }

  async listDecisions(userId: string, limit: number, before?: string): Promise<StoredDecision[]> {
    return [...this.#rows.values()]
      .filter((row) => row.user_id === userId)
      .filter((row) => before === undefined || row.created_at < before)
      .sort((a, b) => b.created_at.localeCompare(a.created_at))
      .slice(0, limit);
  }
}

export interface DecisionIntelligence {
  providers: readonly DomainIntelligenceProvider[];
  cache: IntelligenceCache;
  state: ProviderRuntimeState;
  staleAfterSeconds: number;
  ttlSeconds: number;
}

export interface DecisionPipelineResult {
  decision: Decision;
  classification: ReturnType<typeof classifyRequest>;
  feasibility: FeasibilityResult;
  minimization: MinimizationResult;
  signals: DomainSignal[];
  summary: IntelligenceSummary;
  policy_version: string;
}

export interface DecisionServiceDependencies {
  categories: readonly DataCategory[];
  ruleset: Ruleset;
  userPolicy: UserPolicyStore;
  decisions: DecisionStore;
  intelligence: DecisionIntelligence;
  /** Advisory risk model seam (`D-007`); the deterministic implementation by default. */
  riskIntelligence?: RiskIntelligence;
  /** Live-event sink (W8.3); publish fires after the decision is recorded. */
  events?: DecisionEventSink;
}

/** The seam the SSE bus plugs into; absent means no live consumers. */
export interface DecisionEventSink {
  publishDecision(decision: StoredDecision): void;
}

/**
 * The wire shape for a decision leaving this service (list, get, SSE).
 *
 * `StoredDecision` adds `user_id` for storage scoping, but the shared client
 * schema is a strict object that refuses it - the dashboard parses every
 * response against that schema and dropped every decision as unparsable when
 * `user_id` leaked onto the wire (found in the live browser walkthrough).
 * Storage keeps the owner; the wire carries exactly the shared shape.
 */
export function toWireDecision(decision: StoredDecision): Decision {
  const { user_id: _user_id, ...wire } = decision;
  return wire;
}

export class DecisionService {
  readonly #dependencies: DecisionServiceDependencies;

  constructor(dependencies: DecisionServiceDependencies) {
    this.#dependencies = dependencies;
  }

  get ruleset(): Ruleset {
    return this.#dependencies.ruleset;
  }

  /**
   * Run the full pipeline for one observed request.
   *
   * The request is never widened and no fact is invented: a signal that could
   * not be collected stays `unknown`, and the risk model treats it as
   * uncertainty rather than as a permissive value.
   */
  async evaluate(input: {
    user_id: string;
    request: ObservedRequest;
    consent?: readonly Consent[];
    now?: Date;
  }): Promise<DecisionPipelineResult> {
    const { categories, ruleset, intelligence } = this.#dependencies;
    const now = input.now ?? new Date();

    const classification = classifyRequest(input.request, categories);
    const feasibility = assessFeasibility(input.request, classification);
    const minimization = analyzeMinimization(input.request, classification);

    const collected = await collectIntelligence({
      host: input.request.origin.host,
      providers: intelligence.providers,
      cache: intelligence.cache,
      window: { staleAfterSeconds: intelligence.staleAfterSeconds, ttlSeconds: intelligence.ttlSeconds },
      state: intelligence.state,
      now,
    });
    const signals = collected.summary.signals;

    const userRules = await this.#dependencies.userPolicy.listUserRules(input.user_id);
    const evaluation = evaluateRules(
      [...ruleset.rules, ...userRules],
      {
        request: input.request,
        classification,
        feasibility,
        signals,
        ...(input.consent === undefined ? {} : { consent_categories: consentCategories(input.consent) }),
        now,
      },
      { default_posture: ruleset.default_posture },
    );

    const risk = assessRisk(
      {
        data_categories: classification.categories.map((category) => ({
          data_category_id: category.data_category_id,
          sensitivity_level: category.sensitivity_level,
        })),
        requested_field_count: input.request.requested_data.length,
        mechanism: input.request.mechanism,
        feasibility: feasibility.outcome,
        signals,
        application: null,
        default_posture_applied: evaluation.default_posture_applied,
        classification_unknown: classification.unknown,
      },
      this.#dependencies.riskIntelligence,
    );

    const policyVersion = await currentVersion(this.#dependencies.userPolicy, input.user_id, ruleset.ruleset_version);
    const decision = decide({
      request: input.request,
      classification,
      feasibility,
      signals,
      rules: evaluation,
      risk,
      ...(input.consent === undefined ? {} : { consent: input.consent }),
      policy_version: policyVersion,
      now,
      decision_id: randomUUID(),
    });

    const stored: StoredDecision = { ...decision, user_id: input.user_id };
    await this.#dependencies.decisions.insertDecision(stored);
    // Live consumers (W8.3) hear about the decision only once it is durable
    // in the store - a stream that announces what it might not serve is a lie.
    this.#dependencies.events?.publishDecision(stored);

    return {
      decision,
      classification,
      feasibility,
      minimization,
      signals,
      summary: collected.summary,
      policy_version: policyVersion,
    };
  }

  /** Re-derive the intelligence summary recorded alongside an audit event. */
  summarize(host: string, signals: readonly DomainSignal[]): IntelligenceSummary {
    return summarizeSignals(host, signals, 'miss');
  }
}

async function currentVersion(store: UserPolicyStore, userId: string, rulesetVersion: string): Promise<string> {
  const epoch = await store.policyEpoch(userId);
  return `${rulesetVersion}@${epoch}`;
}

function consentCategories(consents: readonly Consent[]): string[] {
  return [...new Set(consents.filter((consent) => consent.consent_status === 'Active').map((consent) => consent.data_category_id))];
}

/** Load the shipped ruleset; a checksum failure stops startup (`W5.3`). */
export function loadDefaultRuleset(path: string): Ruleset {
  return loadRuleset(path);
}
