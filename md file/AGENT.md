# AGENT.md

## Purpose

This repository implements **Cyber-Defense: Personal Data Privacy Vault
Using Privacy-Preserving AI and Encryption**, aligned to VIT-IND-05.

The implementation must treat **privacy-first enforcement** as the
primary security objective. The browser extension is the enforcement
point; the web dashboard is the control, visibility, configuration, and
audit surface.

The IND-05 requirements are mandatory. Features beyond IND-05 are
allowed only when they strengthen the core without weakening its
security or privacy guarantees.

## Core Operating Model

The system operates in **Vault Mode** and evaluates inbound requests for
access to personal data.

High-level flow:

1.  Detect an inbound data-access request.
2.  Identify the requesting origin/domain using trusted browser/request
    context.
3.  Determine what personal data is being requested.
4.  Collect domain intelligence and reputation/history.
5.  Evaluate whether the request is technically and contextually
    feasible.
6.  Evaluate the request against system and user-configured rules.
7.  Prefer privacy when uncertainty exists.
8.  Enforce the resulting decision.
9.  Permit an explicit user **Force Allow** for non-critical blocks.
10. Record an auditable decision event.
11. Apply retention/deletion policy to historical records.

## Mandatory Engineering Rules

### Security

-   Never trust domain, origin, permission, data-category, or policy
    values supplied by an untrusted page.
-   Treat every external website and inbound request as untrusted until
    evaluated.
-   Never expose plaintext vault data to websites, analytics systems,
    logs, telemetry, or third-party reputation providers unless the
    approved policy explicitly requires it.
-   Send the minimum information necessary to external services. Prefer
    a hostname/domain over a complete URL.
-   Never store secrets, tokens, encryption keys, passwords, or
    plaintext personal data in source code.
-   Never commit `.env`, credentials, API keys, certificates, private
    keys, browser-extension secrets, or generated user data.
-   Use authenticated encryption for stored sensitive data.
-   Keep encryption keys separate from encrypted payloads.
-   Do not weaken TLS certificate validation.
-   Validate and normalize all external API responses before using them
    in security decisions.
-   Treat third-party reputation information as an input, not an
    unquestionable authority.
-   Fail closed for security-critical enforcement paths unless the
    product policy explicitly defines another behavior.
-   Critical security blocks cannot be overridden by Force Allow. Normal
    policy blocks can be overridden according to the product's override
    policy.
-   Never use an LLM as the final authority for a security-critical
    allow/block decision. Deterministic policy rules remain
    authoritative.

### Privacy

-   Data minimization is mandatory.
-   Collect only fields required to perform a security decision or an
    explicitly requested product function.
-   Do not retain request history indefinitely.
-   Historical records must follow the configured retention/deletion
    policy.
-   Prefer local processing for sensitive information.
-   Federated learning must not move raw personal data between
    participants.
-   Do not use production personal data for development or tests.
-   Redact personal data from logs and error messages.

### Code Quality

-   Prefer simple, deterministic, auditable code over unnecessary
    abstraction.
-   Keep security policy evaluation deterministic and testable.
-   Separate request interception, domain intelligence, policy
    evaluation, enforcement, vault access, audit, and UI concerns.
-   Avoid duplicated security logic.
-   Validate at system boundaries.
-   Use explicit types and schemas for security-sensitive objects.
-   Handle malformed, missing, stale, contradictory, and unavailable
    external data.
-   Avoid unnecessary dependencies.
-   Pin or constrain dependency versions where appropriate and review
    security advisories.

## Mandatory Test Rule

**After every feature implementation, add and run tests before
considering the feature complete.**

At minimum, test:

-   Normal/expected behavior.
-   Empty or missing input.
-   Malformed input.
-   Boundary values.
-   Unexpected external API responses.
-   Failure/timeouts.
-   Unauthorized access attempts.
-   Attempts to bypass the rule engine.
-   Conflicting rules.
-   User override behavior.
-   Sensitive-data leakage through logs/errors.
-   Relevant browser-extension permission boundaries.

Security-sensitive features require negative tests demonstrating that
prohibited behavior is rejected.

## Rule Engine Requirements

Rules must be data/configuration driven rather than hard-coded
throughout application logic.

A rule should have a stable identifier and explicit:

-   Condition.
-   Effect.
-   Priority.
-   Scope.
-   Rationale.
-   Override classification.

Every decision must retain the rules that materially affected the
decision.

The engine must be deterministic: identical normalized inputs and
identical policy state should produce the same result.

## Force Allow

Force Allow is a user-controlled override for ordinary policy decisions.

It must:

-   Be explicit.
-   Be visible to the user.
-   Be audited.
-   Never silently change permanent policy.
-   Not bypass critical security blocks.
-   Not expose more data than the approved request asks for.
-   Have clear UI indicating that the normal policy decision is being
    overridden.

## External Intelligence

Domain intelligence may include domain age/creation date, registration
information, DNS/hosting signals, reputation signals,
certificate/history information, and other approved security indicators.

External services are untrusted dependencies.

Requirements:

-   Cache results where appropriate.
-   Store retrieval time and freshness.
-   Distinguish unavailable data from safe data.
-   Never interpret missing intelligence as evidence of trust.
-   Validate response schemas.
-   Rate-limit requests.
-   Prevent external-provider failures from crashing the enforcement
    path.

## Federated Learning

Federated learning is an extension of the mandatory privacy
architecture.

Its intended uses are:

1.  Improving privacy-risk assessment patterns across participating
    nodes.
2.  Detecting suspicious data-access behavior across participating
    nodes.

Raw personal data must remain at its originating node. Model updates
must be protected and aggregated according to the approved privacy
architecture.

Federated learning must never silently replace deterministic security
rules.

## Documentation

Update the relevant documentation when behavior or architecture changes:

-   `PRD.md` for product requirements.
-   `ARCHITECTURE.md` for system structure and boundaries.
-   `DECISION.md` for consequential architectural/product decisions.
-   `TASKS.md` for implementation state and task decomposition.

Do not silently introduce a new major architectural assumption. Record
it as a decision.

## Definition of Done

A feature is complete only when:

1.  Implemented.
2.  Integrated.
3.  Securely handled at trust boundaries.
4.  Normal behavior tested.
5.  Edge cases tested.
6.  Security-negative cases tested where relevant.
7.  No known critical security defect remains.
8.  Documentation is updated when required.
9.  The feature can be self-demonstrated successfully.

A feature is not complete merely because the UI exists.

## Development Priority

When trade-offs arise, prioritize in this order:

1.  User privacy.
2.  Security enforcement correctness.
3.  Protection of vault data.
4.  Correctness and auditability.
5.  Reliability.
6.  Performance.
7.  UX convenience.
8.  Optional sophistication.

Do not sacrifice a higher-priority property merely to make a
lower-priority feature easier to implement.
