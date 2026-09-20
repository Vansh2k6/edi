# DECISION.md

# Architectural and Product Decision Register

## D-001 --- Vault Mode

**Status:** Accepted

**Decision:** The system operates in **Vault Mode only**.

**Rationale:** Personal data is controlled through a protected vault
boundary. External applications receive data only through an explicitly
authorized disclosure path.

**Consequence:** The vault gateway becomes a security-critical
component.

------------------------------------------------------------------------

## D-002 --- Inbound Security Direction

**Status:** Accepted

**Decision:** The security core focuses on **INBOUND data-access
requests**.

**Rationale:** The project needs to evaluate what external
websites/applications are attempting to obtain from the user's
personal-data environment.

**Consequence:** Request interception and origin identification are
first-class components.

------------------------------------------------------------------------

## D-003 --- Browser Extension + Dashboard

**Status:** Accepted

**Decision:** The product consists of a browser extension and a web
dashboard.

**Rationale:** Enforcement must happen close to browser activity, while
configuration, visibility, analytics, and audit require a richer
dashboard.

**Consequence:** The extension is an enforcement client, not merely a
visualization layer.

------------------------------------------------------------------------

## D-004 --- Any Personal Data Category

**Status:** Accepted

**Decision:** The system is not restricted to a single data category.

**Examples:** identity, financial, medical, location, communication,
documents, and other personal information.

**Consequence:** Data categories must be extensible rather than
hard-coded to a small fixed list.

------------------------------------------------------------------------

## D-005 --- Domain-Origin Intelligence

**Status:** Accepted

**Decision:** Domain intelligence is derived from the actual requesting
origin/domain and associated security data.

**Rationale:** The requesting website's identity is a fundamental input
to the access decision.

**Consequence:** Origin extraction must use trusted browser/request
context and must not simply accept a domain supplied by the webpage.

------------------------------------------------------------------------

## D-006 --- Domain History as a Security Signal

**Status:** Accepted

**Decision:** Domain history is a component of reputation assessment.

**Initial signals may include:** creation date/domain age and other
relevant historical/security indicators.

**Rationale:** The system should evaluate the context of the requesting
domain rather than considering only the requested permission.

**Consequence:** Domain intelligence requires source, freshness, and
uncertainty handling.

------------------------------------------------------------------------

## D-007 --- Rule-Based Security Core

**Status:** Accepted

**Decision:** Initial security decisions are rule-based.

**Rationale:** Deterministic rules are easier to inspect, test, explain,
and enforce than an opaque model during the initial implementation.

**Consequence:** AI may augment intelligence, but must not silently
become the authoritative security decision-maker.

------------------------------------------------------------------------

## D-008 --- Privacy-First Posture

**Status:** Accepted

**Decision:** When trade-offs exist, the system prefers privacy.

**Consequence:** Uncertainty around a security-critical request must not
result in automatic disclosure of vault data.

------------------------------------------------------------------------

## D-009 --- User and System Rules

**Status:** Accepted

**Decision:** The system supports both built-in security rules and
user-configurable rules.

**Examples:**

-   Never disclose financial information automatically.
-   Require approval for location.
-   Block domains with critical malicious reputation.
-   Restrict sensitive data to specific domains.

**Consequence:** Rule precedence and conflict resolution must be
deterministic.

------------------------------------------------------------------------

## D-010 --- Enforcement, Not Detection Only

**Status:** Accepted

**Decision:** The extension must enforce decisions where technically
possible.

**Rationale:** The project is a privacy-defense system, not only a
monitoring dashboard.

**Consequence:** Enforcement must occur before sensitive data is
disclosed.

------------------------------------------------------------------------

## D-011 --- Force Allow

**Status:** Accepted

**Decision:** Users can explicitly Force Allow ordinary policy blocks.

**Constraint:** Critical security blocks cannot be overridden.

**Rationale:** Users retain control while the system preserves
protection against explicitly critical threats.

**Consequence:** Every Force Allow is audited.

------------------------------------------------------------------------

## D-012 --- Temporary History

**Status:** Accepted

**Decision:** Request/security history is retained temporarily and
automatically deleted.

**Rationale:** Auditability is required, but indefinite retention
conflicts with the privacy-first objective.

**Consequence:** Retention is a product/security control rather than an
unlimited historical archive.

------------------------------------------------------------------------

## D-013 --- Hybrid Vault

**Status:** Accepted

**Decision:** The vault architecture is hybrid.

**Decision detail:** Sensitive vault data is primarily protected
locally, while remote services provide only necessary encrypted data,
metadata, intelligence, policy synchronization, or other explicitly
authorized functions.

**Rationale:** This reduces the server-side blast radius.

------------------------------------------------------------------------

## D-014 --- Federated Learning Scope

**Status:** Accepted

**Decision:** Federated learning may support both:

1.  Privacy-risk assessment improvement.
2.  Suspicious access-behavior detection.

**Constraint:** Raw personal data remains local to participating nodes.

**Consequence:** Federated learning is an enhancement to the security
intelligence layer and does not replace deterministic policy
enforcement.

------------------------------------------------------------------------

## D-015 --- IND-05 as Master Requirement

**Status:** Accepted

**Decision:** VIT-IND-05 is the master product requirement.

**Rationale:** The project is being developed against the supplied
IND-05 specification.

**Consequence:** Additional security-core capabilities are treated as
extensions unless they directly implement an IND-05 requirement.

------------------------------------------------------------------------

## D-016 --- No Judge-Driven Scope

**Status:** Accepted

**Decision:** The architecture is not optimized around a hypothetical
judging rubric.

**Rationale:** The project is being built as a real prototype rather
than a demonstration engineered only for evaluation.

------------------------------------------------------------------------

## D-017 --- Deterministic Security Authority

**Status:** Accepted

**Decision:** Deterministic policy/rule evaluation remains authoritative
for security-critical decisions.

**Rationale:** AI and probabilistic systems can provide useful signals
but should not have unilateral authority to disclose protected personal
data.

------------------------------------------------------------------------

## D-018 --- External Reputation Is Advisory

**Status:** Accepted

**Decision:** External domain/reputation providers are inputs to the
security decision, not absolute authorities.

**Rationale:** Providers can be unavailable, stale, incorrect,
compromised, or incomplete.

**Consequence:** The system records source/freshness and handles
uncertainty explicitly.

------------------------------------------------------------------------

## D-019 --- Data Minimization

**Status:** Accepted

**Decision:** External services should receive the minimum information
required.

**Example:** Prefer a hostname/domain over a complete URL when complete
URL information is unnecessary.

**Rationale:** A security service must not create a second privacy
problem while solving the first.

------------------------------------------------------------------------

## D-020 --- Prototype Completion

**Status:** Accepted

**Decision:** A feature is considered complete when it is implemented,
tested, secure, integrated, documented as required, and successfully
self-demonstrated.

**No fixed deadline or checkpoint schedule is imposed.**
