# ARCHITECTURE.md

## 1. System

**Cyber-Defense --- Personal Data Privacy Vault Using Privacy-Preserving
AI and Encryption**

The system is a privacy-first personal data protection platform aligned
with VIT-IND-05.

The mandatory IND-05 baseline includes an encrypted personal data vault,
consent management, privacy-risk assessment, federated learning,
zero-knowledge verification, blockchain audit history, and data-leakage
alerts.

The implementation adds a security core centered on **inbound request
intelligence and domain-history-based reputation**.

## 2. Architectural Principle

> Data remains with the owner; intelligence moves without exposing raw
> data.

The system therefore separates:

-   Personal data.
-   Security intelligence.
-   Policy decisions.
-   Enforcement.
-   Audit information.

A requesting website must not receive vault data merely because it can
technically request it.

## 3. High-Level Architecture

``` text
                         USER
                          |
                 +--------+--------+
                 |                 |
          Browser Extension   Web Dashboard
                 |                 |
                 +--------+--------+
                          |
                   Security Core
                          |
        +-----------------+------------------+
        |                 |                  |
 Request Interceptor  Domain Intelligence  Policy Store
        |                 |                  |
        +-----------------+------------------+
                          |
                  Request Analyzer
                          |
              +-----------+-----------+
              |                       |
       Feasibility Engine       Risk Assessment
              |                       |
              +-----------+-----------+
                          |
                    Rule Engine
                          |
                  Decision Engine
                          |
        +-----------------+------------------+
        |                 |                  |
      ALLOW             WARN/BLOCK       USER OVERRIDE
        |                 |                  |
        +-----------------+------------------+
                          |
                    Vault Gateway
                          |
                 Encrypted Data Vault
                          |
                    Audit Service
                          |
                 Retention / Deletion
```

## 4. Trust Boundaries

### Boundary 1 --- Web Page to Extension

The page is untrusted.

The extension must not trust:

-   Page-provided identity claims.
-   Arbitrary domain values.
-   User-data representations.
-   Client-side policy claims.

### Boundary 2 --- Extension to Backend

Requests must be authenticated and validated.

The backend must assume the extension could be compromised or
manipulated and must independently validate security-sensitive state
where feasible.

### Boundary 3 --- Backend to External Intelligence Providers

External reputation/domain services are untrusted dependencies.

Their results are advisory signals and must be validated before entering
the decision engine.

### Boundary 4 --- Vault to Website

This is the critical privacy boundary.

Plaintext vault data may cross this boundary only after the decision
engine has authorized the specific data disclosure.

## 5. Core Components

### 5.1 Browser Extension

Responsibilities:

-   Observe relevant inbound data-access activity.
-   Identify trusted request origin.
-   Determine request metadata available through browser APIs.
-   Enforce approved decisions.
-   Present warnings/approval UI.
-   Support Force Allow for eligible decisions.
-   Communicate with the dashboard/security backend through
    authenticated channels.

The extension should use the minimum browser permissions required.

### 5.2 Request Interceptor

Produces a normalized request object.

Conceptually:

``` text
Request
- request_id
- timestamp
- origin
- destination
- requested_data
- mechanism
- page_context
- browser_context
```

Only fields actually available and required should be populated.

### 5.3 Domain Intelligence Service

Resolves intelligence for the requesting domain.

Possible signals:

-   Creation date/domain age.
-   Registration metadata.
-   DNS information/history.
-   Hosting/IP information.
-   Certificate history.
-   Reputation/abuse indicators.
-   Redirect information.
-   Other approved security signals.

The service must preserve source and freshness metadata.

### 5.4 Request Analyzer

Evaluates:

-   What data is requested?
-   Whether the requested data exists in the vault.
-   Whether the request mechanism can actually obtain that data.
-   Whether the requesting origin is associated with the request.
-   Whether the amount/type of data is excessive.
-   Whether the requested purpose is consistent with available context.
-   Whether policy permits the requested category.

The analyzer produces structured facts, not a final security decision.

### 5.5 Feasibility Engine

Determines whether the request is technically and contextually
plausible.

Examples:

``` text
A website cannot receive contacts through a mechanism that
does not provide contacts.

A request for location may be technically possible through a
browser permission, but still violate user policy.

A website requesting financial data without an authorized
vault capability is not entitled to receive it.
```

Feasibility does not equal permission.

### 5.6 Rule Engine

Consumes normalized facts and policy.

Inputs:

``` text
Request facts
Domain intelligence
Data sensitivity
Feasibility result
User policy
System security rules
Historical/context signals
```

Outputs:

``` text
matched_rules
risk_level
decision
reason_codes
override_class
```

### 5.7 Decision Engine

Centralizes enforcement outcomes:

-   ALLOW
-   WARN
-   BLOCK
-   ASK_USER

It must distinguish ordinary policy blocks from critical security
blocks.

### 5.8 Vault Gateway

The vault gateway is the only controlled interface through which
approved applications can obtain vault data.

The browser page must never directly access the vault database.

The gateway:

1.  Receives an approved disclosure request.
2.  Revalidates the authorization.
3.  Selects only the approved data.
4.  Applies data minimization.
5.  Releases data only to the authorized recipient.
6.  Creates an audit event.

### 5.9 Encrypted Vault

Sensitive personal data is encrypted at rest.

The architecture is hybrid:

-   Sensitive vault data is primarily protected locally.
-   Remote/backend services hold only what is necessary and approved,
    preferably as encrypted data or non-sensitive metadata.
-   Keys are kept separate from encrypted payloads.

The server must not become an implicit plaintext copy of the user's
vault.

### 5.10 Consent / Policy Store

Stores:

-   User rules.
-   Consent state.
-   Application/domain policies.
-   Permission scopes.
-   Expiry.
-   Override settings.

Consent is distinct from security reputation: a trusted domain does not
automatically receive consent.

### 5.11 Audit Service

Records security-relevant events without storing unnecessary personal
content.

A request audit record can contain:

``` text
request_id
timestamp
origin_domain
requested_categories
domain_intelligence_summary
matched_rules
risk_level
decision
override
policy_version
```

Sensitive payloads should not be copied into audit logs.

### 5.12 Retention Service

Request/audit history is not retained indefinitely.

The system keeps recent history and automatically deletes older records
according to the configured retention policy.

Deletion must cover derived records where they are no longer required.

## 6. Federated Learning Architecture

Federated learning is an extension that operates over participating
nodes.

``` text
Node A ---- local training ----\
Node B ---- local training -----+--> Secure Aggregation
Node C ---- local training ----/          |
                                          v
                                  Global Model Update
```

Raw personal data remains on each node.

Potential model targets:

-   Privacy-risk assessment improvement.
-   Suspicious access behavior detection.

The deterministic rule engine remains authoritative for critical
enforcement.

## 7. IND-05 Mapping

  IND-05 requirement              Architecture component
  ------------------------------- ---------------------------------------
  Personal encrypted data vault   Encrypted Vault + Vault Gateway
  User-controlled consent         Policy/Consent Store
  Privacy risk scoring            Risk Assessment + Rule/Scoring Engine
  Federated AI                    Federated Learning Layer
  Zero-knowledge verification     Verification Service
  Blockchain audit history        Audit/Blockchain extension
  Data leakage alerts             Security Alert subsystem
  Secure data sharing             Vault Gateway
  Access audit                    Audit Service

The IND-05 document defines these as platform features and architecture
layers. This project may implement some as a core MVP and some as staged
extensions, but they remain requirements rather than being silently
removed.

## 8. Security Decision Flow

``` text
Inbound Request
      |
      v
Normalize + Validate
      |
      v
Identify Origin
      |
      v
Collect Domain Intelligence
      |
      v
Classify Requested Data
      |
      v
Feasibility Analysis
      |
      v
User + System Policy
      |
      v
Rule Evaluation
      |
      v
Decision
      |
 +----+--------+---------+
 |    |        |         |
ALLOW WARN   BLOCK    ASK USER
 |              |         |
 v              +----+----+
Vault Gateway       |
 |               Force Allow?
 v                  |
Limited Data     YES / NO
                     |
                   Audit
```

## 9. Failure Model

-   Missing reputation data is not equivalent to a trustworthy
    reputation.
-   External API failure must not expose vault data.
-   Stale intelligence must be marked stale.
-   Invalid provider responses are rejected.
-   Security-critical unknowns fail closed.
-   User-visible explanations must distinguish "malicious", "unknown",
    "insufficient data", and "policy denied".

## 10. Performance

The enforcement path should avoid blocking the browser unnecessarily.

Use:

-   Domain-intelligence caching.
-   Timeouts.
-   Background refresh.
-   Bounded external calls.
-   Minimal payloads.
-   Deterministic local rule evaluation.

A cached reputation result must include freshness information.

## 11. Architectural Non-Goals

The architecture does not assume:

-   Every external domain is malicious.
-   Domain age alone proves trustworthiness.
-   An LLM can safely replace deterministic enforcement.
-   Blockchain is necessary for every audit event.
-   Federated learning is necessary for every decision.
-   A successful request is automatically a permitted request.
