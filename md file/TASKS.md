# TASKS.md

# Cyber-Defense Implementation Tasks

## Task Rules

Every implementation task follows:

``` text
Implement
→ Test normal behavior
→ Test edge cases
→ Test security-negative behavior
→ Integrate
→ Self-demo
→ Mark complete
```

No task is complete because code merely compiles or a UI renders.

------------------------------------------------------------------------

# Phase 0 --- Repository and Security Foundation

**Status:** Implemented --- verified suites are recorded in
`IMPLEMENTATION_PLAN.md` section 10.1.

## T001 --- Repository structure

Create the project structure separating:

-   Browser extension.
-   Dashboard.
-   Security core/backend.
-   Shared schemas/types.
-   Tests.
-   Documentation.

**Acceptance criteria**

-   Components have clear boundaries.
-   No security logic is duplicated between extension and backend.

## T002 --- Configuration and secrets

Implement environment/configuration handling.

**Tests**

-   Missing required configuration.
-   Invalid configuration.
-   Secrets absent from logs.
-   Production configuration cannot accidentally use development
    secrets.

## T003 --- Shared security schemas

Define schemas for:

-   Data categories.
-   Requests.
-   Domain intelligence.
-   Rules.
-   Risk assessments.
-   Decisions.
-   Audit events.

**Tests**

-   Missing fields.
-   Invalid types.
-   Oversized fields.
-   Unexpected enum values.

------------------------------------------------------------------------

# Phase 1 --- Personal Data Vault

**Status:** Implemented --- verified suites are recorded in
`IMPLEMENTATION_PLAN.md` section 10.1.

## T004 --- Vault data model

Implement extensible personal-data categories and vault records.

## T005 --- Encryption layer

Implement authenticated encryption for sensitive vault data.

**Security tests**

-   Wrong key.
-   Tampered ciphertext.
-   Missing ciphertext.
-   Key mismatch.
-   Replay/version mismatch where applicable.
-   Plaintext not present in logs.

## T006 --- Key management boundary

Implement secure separation of keys from encrypted data.

**Tests**

-   Unauthorized component cannot retrieve key material.
-   Key errors fail safely.
-   Keys are never returned through normal API responses.

## T007 --- Vault CRUD

Implement create/read/update/delete for protected data.

**Tests**

-   Unauthorized user.
-   Unauthorized application.
-   Invalid category.
-   Empty payload.
-   Oversized payload.
-   Attempt to retrieve another user's data.

------------------------------------------------------------------------

# Phase 2 --- Browser Extension

**Status:** Implemented --- verified suites are recorded in
`IMPLEMENTATION_PLAN.md` section 10.1.

## T008 --- Minimal extension shell

Create the browser extension using the minimum required permissions.

## T009 --- Request observation

Implement supported inbound request detection.

**Tests**

-   Valid request.
-   Missing origin.
-   Malformed request.
-   Unsupported request mechanism.
-   Multiple simultaneous requests.
-   Repeated request.
-   Request cancellation.

## T010 --- Trusted origin extraction

Normalize and validate the requesting origin/domain.

**Security tests**

-   Spoofed origin fields.
-   Punycode/unicode domain handling.
-   Port changes.
-   Subdomain handling.
-   Redirects.
-   Malformed URLs.
-   Localhost/private origins.
-   Extension/internal origins.

------------------------------------------------------------------------

# Phase 3 --- Request Intelligence

**Status:** Implemented --- verified suites are recorded in
`IMPLEMENTATION_PLAN.md` section 10.1.

## T011 --- Requested-data classification

Map observed requests to personal-data categories.

**Tests**

-   Single category.
-   Multiple categories.
-   Unknown category.
-   Ambiguous request.
-   Highly sensitive category.

## T012 --- Request feasibility engine

Determine whether the observed request can technically obtain the
claimed data and whether the request fits the available
mechanism/context.

**Tests**

-   Feasible request.
-   Impossible request.
-   Unsupported mechanism.
-   Missing capability.
-   Conflicting request metadata.

## T013 --- Data minimization analysis

Determine the minimum data required for an approved request.

**Tests**

-   Request asks for more data than required.
-   Request asks for an unknown field.
-   Mixed sensitivity categories.

------------------------------------------------------------------------

# Phase 4 --- Domain Intelligence

**Status:** Implemented --- verified suites are recorded in
`IMPLEMENTATION_PLAN.md` section 10.1.

## T014 --- Domain intelligence provider interface

Create an abstraction so providers can be changed without rewriting the
rule engine.

## T015 --- Domain creation/age intelligence

Retrieve and normalize domain creation information.

**Tests**

-   Newly created domain.
-   Old domain.
-   Missing creation date.
-   Invalid date.
-   Future creation date.
-   Provider timeout.

## T016 --- Domain history signals

Add approved historical/security signals.

Possible signals:

-   Registration.
-   DNS/hosting.
-   Certificate history.
-   Reputation.
-   Abuse indicators.

Each signal must retain source and freshness.

## T017 --- Intelligence cache

Cache domain intelligence with expiration/freshness.

**Tests**

-   Fresh cache.
-   Expired cache.
-   Corrupted cache.
-   Provider unavailable.
-   Concurrent requests for same domain.

## T018 --- Provider failure handling

Implement safe handling for:

-   Timeout.
-   Rate limit.
-   Authentication failure.
-   Invalid response.
-   Provider unavailable.

No provider failure may cause silent vault disclosure.

------------------------------------------------------------------------

# Phase 5 --- Rule Engine

**Status:** Implemented --- verified suites are recorded in
`IMPLEMENTATION_PLAN.md` section 10.1. The scripted exit-demo walkthrough is
pending and demonstrated by the suites until then.

## T019 --- Rule schema

Implement configuration-driven rules with:

-   Rule ID.
-   Conditions.
-   Effect.
-   Priority.
-   Scope.
-   Reason.
-   Override classification.

## T020 --- Rule evaluator

Implement deterministic evaluation.

**Tests**

-   One matching rule.
-   No matching rules.
-   Multiple matching rules.
-   Conflicting rules.
-   Priority conflict.
-   Missing signal.
-   Stale signal.

## T021 --- Privacy-first defaults

Implement default rules that prevent unnecessary disclosure of sensitive
information.

## T022 --- User rules

Allow users to configure rules.

**Tests**

-   Invalid rule.
-   Conflicting rule.
-   Unauthorized rule modification.
-   Rule deletion.
-   Expired policy.
-   Sensitive category rule.

## T023 --- Critical security rules

Define rules that cannot be bypassed through Force Allow.

------------------------------------------------------------------------

# Phase 6 --- Risk and Decision Engine

**Status:** Implemented --- verified suites are recorded in
`IMPLEMENTATION_PLAN.md` section 10.1. The scripted exit demo is pending and
covered by the decision, risk and override suites until then.

## T024 --- Risk assessment

Produce explainable privacy-risk classification.

Inputs must be traceable to actual request/domain/policy signals.

## T025 --- Decision engine

Implement:

-   ALLOW.
-   WARN.
-   BLOCK.
-   ASK_USER.

## T026 --- Decision explanation

Every decision should expose:

-   Risk.
-   Reasons.
-   Matched rules.
-   Domain signals.
-   Requested data.
-   Policy result.

## T027 --- Force Allow

Implement explicit user override for eligible blocks.

**Security tests**

-   Normal block can be overridden.
-   Critical block cannot.
-   Override is audited.
-   Override does not permanently alter rules.
-   Override cannot expand the requested data scope.

------------------------------------------------------------------------

# Phase 7 --- Enforcement

**Status:** Implemented --- verified suites are recorded in
`IMPLEMENTATION_PLAN.md` section 10.1. The scripted exit-demo walkthrough is
pending and demonstrated by the suites until then.

## T028 --- Pre-disclosure enforcement

Ensure protected data cannot be released before authorization.

## T029 --- Vault gateway

Create the only approved path from security authorization to data
disclosure.

## T030 --- Limited disclosure

Return only authorized data.

**Tests**

-   Request asks for one field.
-   Request asks for multiple categories.
-   Unauthorized category.
-   Expanded request after authorization.
-   Authorization expiry.
-   Replayed authorization.

## T031 --- Block enforcement

Verify blocked requests are actually prevented where the browser
platform supports enforcement.

------------------------------------------------------------------------

# Phase 8 --- Dashboard

Status: implemented (W8.1--W8.8; the six surfaces ship as a first-party SPA
served by the core with cookie sessions, CSRF, SSE live decisions and a strict
CSP; verified by `scripts/tests/services/core/src/dashboard.test.ts`, `packages/ui`, and the
live browser walkthrough).

## T032 --- Dashboard foundation

Create dashboard shell and authenticated user context.

## T033 --- Vault interface

Provide protected-data management.

## T034 --- Security overview

Display:

-   Current risk.
-   Recent requests.
-   Blocks.
-   Warnings.
-   Domain intelligence.
-   Security alerts.

## T035 --- Request detail view

Display complete explainable decision context without exposing
unnecessary plaintext personal data.

## T036 --- Policy management

Allow user rule and consent configuration.

## T037 --- Domain view

Show domain history/reputation signals and their freshness.

------------------------------------------------------------------------

# Phase 9 --- Audit and Retention

## T038 --- Audit event model

Implement auditable request/decision events.

## T039 --- Audit viewer

Display recent events.

## T040 --- Retention policy

Implement automatic deletion of expired history.

**Tests**

-   Newly created event retained.
-   Expired event deleted.
-   Boundary timestamp.
-   Failed deletion retry.
-   Deleted history no longer visible through API.

------------------------------------------------------------------------

# Phase 10 --- Security Alerts

## T041 --- Alert engine

Generate alerts for suspicious or blocked access behavior.

## T042 --- Alert dashboard

Display severity, reason, timestamp, and status.

## T043 --- Alert lifecycle

Implement acknowledgement/resolution without altering immutable security
facts.

------------------------------------------------------------------------

# Phase 11 --- IND-05 Privacy-Preserving AI

## T044 --- Privacy risk AI interface

Create model abstraction for privacy-risk intelligence.

The deterministic rule engine remains authoritative for critical
enforcement.

## T045 --- Federated learning foundation

Create node/session/model-update structures aligned with IND-05.

The IND-05 specification defines federated nodes, training sessions, and
model-update history. fileciteturn0file1L250-L279

## T046 --- Federated risk learning

Prototype local learning of privacy-risk patterns.

## T047 --- Federated anomaly detection

Prototype local learning for suspicious access behavior.

## T048 --- Secure aggregation

Implement or prototype aggregation without centralizing raw personal
data.

------------------------------------------------------------------------

# Phase 12 --- Zero-Knowledge Verification

## T049 --- Verification request model

Implement verification-request records.

## T050 --- ZK proof interface

Create proof-generation/verification abstraction.

## T051 --- IND-05 proof scenario

Implement a concrete privacy-preserving verification scenario, such as
proving an attribute without exposing the underlying identity value.

------------------------------------------------------------------------

# Phase 13 --- Blockchain Audit Extension

## T052 --- Blockchain audit abstraction

Separate blockchain persistence from the core audit interface.

## T053 --- Transaction recording

Record appropriate security events without putting sensitive plaintext
on-chain.

## T054 --- Integrity verification

Verify recorded transaction integrity.

------------------------------------------------------------------------

# Phase 14 --- End-to-End Security Scenarios

## T055 --- Safe request

``` text
Trusted/known domain
→ low-risk request
→ policy permits
→ ALLOW
→ minimum data disclosed
→ audit
```

## T056 --- Sensitive request

``` text
Website
→ financial data request
→ user policy requires approval
→ ASK_USER
→ user chooses
→ audit
```

## T057 --- Suspicious new domain

``` text
New domain
→ sensitive data request
→ domain intelligence raises risk
→ BLOCK/WARN according to rules
→ explanation
→ audit
```

## T058 --- Critical malicious domain

``` text
Critical reputation signal
→ sensitive data request
→ hard BLOCK
→ Force Allow unavailable
→ alert
→ audit
```

## T059 --- Force Allow

``` text
Normal policy BLOCK
→ user selects Force Allow
→ authorization
→ minimum data disclosed
→ override audited
```

## T060 --- External provider failure

``` text
Request
→ reputation provider unavailable
→ uncertainty handled
→ privacy-first decision
→ no uncontrolled disclosure
```

------------------------------------------------------------------------

# Phase 15 --- Security Hardening

## T061 --- Threat-model review

Review:

-   Extension compromise.
-   Backend compromise.
-   Malicious website.
-   Compromised reputation provider.
-   API abuse.
-   Session theft.
-   Data leakage through logs.
-   Policy bypass.
-   Authorization replay.

## T062 --- Dependency security

Audit dependencies and remove unnecessary packages.

## T063 --- Input fuzzing

Fuzz security-sensitive parsers:

-   URLs.
-   Domains.
-   Rule expressions.
-   External provider responses.
-   Request objects.

## T064 --- Authorization review

Verify every vault access path requires appropriate authorization.

## T065 --- Privacy review

Verify:

-   No plaintext leakage.
-   Minimal telemetry.
-   Minimal external data.
-   Retention deletion.
-   Federated data locality.

------------------------------------------------------------------------

# Phase 16 --- Final Prototype

## T066 --- Full end-to-end demo

Demonstrate:

``` text
Website
→ inbound request
→ origin extraction
→ domain history
→ request classification
→ feasibility
→ privacy rules
→ risk
→ enforcement
→ optional Force Allow
→ vault disclosure
→ audit
→ retention/deletion
```

## T067 --- Documentation synchronization

Verify that:

-   `AGENT.md`
-   `ARCHITECTURE.md`
-   `DECISION.md`
-   `PRD.md`
-   `TASKS.md`

match the implemented system.

## T068 --- Final security regression

Run the complete security, edge-case, integration, and end-to-end test
suite.

## T069 --- Self-demonstration

Demonstrate the complete prototype without relying on undocumented
manual intervention.

**Definition of complete:**

-   Core flows work.
-   Security enforcement works.
-   Edge cases have tests.
-   Critical bypasses are rejected.
-   Documentation matches implementation.
-   Self-demo succeeds.
