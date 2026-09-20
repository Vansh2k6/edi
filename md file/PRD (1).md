# PRD.md

# Cyber-Defense --- Personal Data Privacy Vault

## 1. Product Definition

Cyber-Defense is a privacy-first Personal Data Privacy Vault aligned
with **VIT-IND-05: Cyber-Defense --- Personal Data Privacy Vault Using
Privacy-Preserving AI and Encryption**.

The platform protects personal information by keeping it behind a
controlled vault boundary and evaluating inbound requests from external
websites/applications before disclosure.

The IND-05 specification identifies the core problem as unauthorized
access, centralized breaches, lack of user control, privacy risks in AI
training, and excessive data sharing. fileciteturn0file1L11-L24

## 2. Product Objective

Build a working browser extension + web dashboard that:

-   Stores/protects personal data through an encrypted vault.
-   Detects inbound data-access requests.
-   Identifies the requesting origin/domain.
-   Investigates relevant domain history and reputation.
-   Understands what data is being requested.
-   Determines whether the request is technically/contextually feasible.
-   Evaluates system and user privacy rules.
-   Enforces privacy-first decisions.
-   Gives the user controlled override capability.
-   Maintains temporary auditable history.
-   Provides the IND-05 privacy-preserving AI capabilities as required
    or staged extensions.

## 3. Core Principle

> Data remains with the owner; intelligence moves without exposing raw
> data.

This principle is explicitly present in the supplied IND-05
specification. fileciteturn0file1L27-L35

## 4. Users

### Primary User

An individual who wants centralized control over personal information
while using websites and applications.

### System Actors

-   User.
-   Browser extension.
-   External website/application.
-   Security core.
-   Domain intelligence provider.
-   Vault.
-   Dashboard.
-   Federated-learning node, where enabled.

## 5. Product Surfaces

### Browser Extension

Primary responsibilities:

-   Detect inbound requests.
-   Identify requesting origin.
-   Intercept/enforce access decisions.
-   Display warnings and approval prompts.
-   Allow Force Allow where permitted.
-   Protect the vault boundary.

### Web Dashboard

Primary responsibilities:

-   Vault management.
-   Policy configuration.
-   Application/domain visibility.
-   Risk explanation.
-   Request history.
-   Audit records.
-   Security alerts.
-   Federated-learning status where enabled.
-   Privacy/security configuration.

## 6. Functional Requirements

### F01 --- Personal Encrypted Data Vault

The platform shall provide an encrypted vault for personal information.

The IND-05 specification identifies this as a required feature.
fileciteturn0file1L368-L376

The vault must support extensible data categories.

### F02 --- User-Controlled Consent and Policy

The user shall be able to configure permissions/policies for data
access.

The IND-05 specification includes permission types such as Read, Write,
Analyze, and Share. fileciteturn0file1L199-L215

### F03 --- Inbound Request Detection

The extension shall detect supported inbound requests for personal
information.

Each detected request shall be normalized into a security request
object.

### F04 --- Origin Identification

The system shall identify the requesting domain/origin using trusted
browser/request context.

### F05 --- Domain Intelligence

For a requesting domain, the system shall obtain available
security/history signals.

The initial security core shall support domain age/creation date and be
designed for additional reputation/history signals.

### F06 --- Requested Data Classification

The system shall determine the personal-data categories involved in a
request.

Examples include identity, financial, medical, location, communication,
and other personal information.

### F07 --- Request Feasibility Analysis

The system shall determine whether a request is:

-   Technically feasible through the observed mechanism.
-   Consistent with the available application/browser context.
-   Within the user's available vault capabilities.
-   Permitted by policy.

Feasibility does not itself grant permission.

### F08 --- Privacy Risk Assessment

The system shall calculate or classify privacy risk using available
request, domain, data-sensitivity, policy, and security signals.

IND-05 explicitly includes privacy risk scoring.
fileciteturn0file1L372-L374

### F09 --- Rule Engine

The system shall evaluate deterministic security rules.

Rules shall be explainable and traceable.

### F10 --- Decision Enforcement

The system shall support:

-   Allow.
-   Warn.
-   Block.
-   Ask user.

Where technically supported, a block shall prevent the protected data
from being disclosed.

### F11 --- Force Allow

The user shall be able to Force Allow ordinary policy blocks.

Critical security blocks shall not be overridable.

Every override shall be recorded.

### F12 --- Data-Minimized Disclosure

When access is approved, the system shall disclose only the authorized
requested information.

### F13 --- Audit History

The platform shall record security-relevant request and decision
information.

The IND-05 specification includes access audit management and audit
trail information. fileciteturn0file1L326-L333

### F14 --- Automatic History Deletion

Historical request/security records shall be automatically deleted after
the configured retention period.

### F15 --- Security Alerts

The platform shall surface security-relevant alerts such as suspicious
access attempts and blocked requests.

IND-05 includes data-leakage alerts. fileciteturn0file1L376-L376

### F16 --- Federated Learning

The platform shall provide an architecture for federated learning and
may implement it to improve:

-   Privacy-risk assessment.
-   Suspicious access-behavior detection.

Raw personal data shall not be centralized for training.

IND-05 identifies federated learning as a privacy-preserving AI
component. fileciteturn0file1L361-L367

### F17 --- Zero-Knowledge Verification

The platform shall support the IND-05 zero-knowledge verification
requirement.

The supplied specification gives examples such as proving age without
exposing date of birth and verifying identity without exposing an ID
number. fileciteturn0file1L295-L302

### F18 --- Blockchain Audit

The platform shall support the IND-05 blockchain audit-history
requirement.

The implementation may stage blockchain integration separately from the
core enforcement path.

## 7. Non-Functional Requirements

### Security

-   No plaintext vault leakage.
-   Strong encryption for stored sensitive data.
-   Authenticated communication.
-   Input validation at trust boundaries.
-   Least-privilege extension permissions.
-   Auditable policy decisions.
-   No critical security bypass through Force Allow.

### Privacy

-   Data minimization.
-   Local-first handling of sensitive data.
-   Temporary history retention.
-   No unnecessary third-party sharing.
-   Raw personal data remains local for federated learning.

### Reliability

-   External intelligence failure must not cause uncontrolled
    disclosure.
-   Cached intelligence must include freshness.
-   Invalid external responses must be rejected.

### Performance

-   Cache domain intelligence.
-   Use bounded network calls.
-   Keep local rule evaluation fast.
-   Avoid unnecessary processing in the browser's critical path.

### Explainability

Every non-trivial decision should expose:

-   Decision.
-   Risk.
-   Relevant domain signals.
-   Requested data.
-   Matched rules.
-   Reason codes.
-   Override state.

## 8. Security Decision Model

A decision is based on:

``` text
Request
+ Origin
+ Domain Intelligence
+ Requested Data
+ Data Sensitivity
+ Feasibility
+ User Policy
+ System Rules
+ Security Signals
```

Example:

``` text
Domain: unknown-example.com
Age: 8 days
Requested: financial information
Mechanism: supported
User policy: financial data requires approval
Reputation: no confirmed malicious finding
```

The result must be explainable and must not treat absence of malicious
evidence as proof of trust.

## 9. User Experience

A blocked request should communicate:

``` text
ACCESS BLOCKED

Website:
unknown-example.com

Requested:
Financial Information

Why:
- Sensitive data requested
- Domain is newly registered
- User policy requires approval

Matched rules:
R-FIN-01
R-DOMAIN-02

[Keep Blocked]
[Force Allow]
```

For a critical security block, Force Allow must not be presented as an
available bypass.

## 10. Data Model

The system should maintain entities corresponding to the IND-05
architecture, adapted to the actual implementation:

-   User.
-   Digital Identity.
-   Data Category.
-   Vault Data.
-   Data Metadata.
-   Encryption Key.
-   Application.
-   Consent/Policy.
-   Consent History.
-   AI Model.
-   Privacy Risk Assessment.
-   Federated Node.
-   Federated Training Session.
-   Verification Request.
-   ZK Proof Log.
-   Blockchain Transaction.
-   Security Alert.
-   Audit Trail.
-   Request.
-   Domain Intelligence.
-   Rule.
-   Decision.

The IND-05 specification defines the underlying database modules around
these categories. fileciteturn0file1L81-L90

## 11. MVP Boundary

### Core MVP

1.  Browser extension.
2.  Web dashboard.
3.  Encrypted vault.
4.  Inbound request detection.
5.  Origin/domain extraction.
6.  Domain-history intelligence.
7.  Requested-data classification.
8.  Feasibility analysis.
9.  Rule-based risk evaluation.
10. Enforced allow/warn/block/ask decisions.
11. Force Allow for eligible blocks.
12. Explainable decisions.
13. Temporary audit history.
14. Security alerts.

### IND-05 Extensions

-   Federated learning.
-   Zero-knowledge verification.
-   Blockchain audit.
-   Additional privacy-preserving AI capabilities.

These are not discarded; they are staged according to implementation
feasibility while remaining part of the master requirement.

## 12. Out of Scope for Initial Implementation

Unless later required:

-   Replacing deterministic policy enforcement with an LLM.
-   Indefinite audit retention.
-   Centralized plaintext storage of personal data.
-   Automatically trusting domains based only on age.
-   Sending complete URLs to external reputation services when a domain
    is sufficient.
-   Building a full enterprise identity-management platform.

## 13. Success Criteria

The prototype is successful when a user can:

1.  Store protected personal information.
2.  Visit a website.
3.  Trigger an inbound personal-data request.
4.  See the requesting domain identified.
5.  See relevant domain intelligence.
6.  See what information is being requested.
7.  See feasibility/risk reasoning.
8.  See the deterministic policy decision.
9.  Have the request enforced.
10. Force Allow where permitted.
11. See the resulting audit event.
12. Later observe automatic deletion of expired history.

## 14. IND-05 Alignment

The supplied IND-05 architecture defines user ecosystem, data-access
request layer, consent management, encryption, identity verification,
policy engine, personal data vault, privacy AI, audit ledger, federated
AI, secure analytics, blockchain logs, and trusted data sharing.
fileciteturn0file1L36-L69

This PRD uses that architecture as the mandatory foundation and adds the
domain-intelligence security core as the project's distinguishing
implementation direction.
