# IMPLEMENTATION_PLAN.md

# Cyber-Defense Phase Implementation Plan --- Phases 0--16

## Scope of this revision

This revision plans **Phases 0 through 16** (`T001`--`T069`). It fixes
the technology for each phase, the workstreams inside it, the tests that
prove it, and the demo that closes it.

It is a **stack-specific execution plan**, not a restatement of the
product requirements. It deliberately mirrors the phase numbering and
task identifiers already defined in `TASKS.md` so the two documents
cannot drift.

| Phase | Title | Tasks | Status in this revision |
|---|---|---|---|
| 0 | Repository and Security Foundation | T001--T003 | Planned here |
| 1 | Personal Data Vault | T004--T007 | Planned here |
| 2 | Browser Extension | T008--T010 | Planned here |
| 3 | Request Intelligence | T011--T013 | Planned here |
| 4 | Domain Intelligence | T014--T018 | Planned here |
| 5 | Rule Engine | T019--T023 | Planned here |
| 6 | Risk and Decision Engine | T024--T027 | Planned here |
| 7 | Enforcement and Vault Gateway | T028--T031 | Planned here |
| 8 | Dashboard | T032--T037 | Planned here |
| 9 | Audit and Retention | T038--T040 | Planned here |
| 10 | Security Alerts | T041--T043 | Planned here |
| 11 | IND-05 Privacy-Preserving AI | T044--T048 | Planned here |
| 12 | Zero-Knowledge Verification | T049--T051 | Planned here |
| 13 | Blockchain Audit Extension | T052--T054 | Planned here |
| 14 | End-to-End Security Scenarios | T055--T060 | Planned here (appended) |
| 15 | Security Hardening | T061--T065 | Planned here (appended) |
| 16 | Final Prototype | T066--T069 | Planned here (appended) |

Phases 14--16 were intentionally absent in earlier revisions and are
appended here using the identical phase-block format, so the document
grows forward without renumbering anything. They close the task range
of `TASKS.md` (`T001`--`T069`) and add milestone M7.

The plan covers `TASKS.md` sections "Phase 0" through "Phase 16" in
full. The milestone table in section 5 groups them as M0--M7.

---

## 1. Purpose and scope

### 1.1 What this document is

`PRD.md`, `ARCHITECTURE.md`, `DECISION.md` and `TASKS.md` are
deliberately implementation-agnostic: they define *what* the system must
do and *how it is structured*, but they name no language, framework,
database or library. This document is where those choices are made, per
phase, so that no phase is started against an undefined stack.

It contains no product requirements of its own. Where this document and
`PRD.md` disagree, the PRD wins and this document is corrected.

### 1.2 Relationship to the other documents

| Document | Owns | This plan's relationship to it |
|---|---|---|
| `PRD (1).md` | Product requirements (`F01`--`F18`), the IND-05 data model, MVP boundary | Phase goals trace back to `F##` identifiers; no new product requirements are introduced here |
| `ARCHITECTURE.md` | System structure, trust boundaries, component responsibilities, failure model | Each phase delivers one or more named components from section 5; the trust boundaries of section 4 are mapped to concrete code in section 3 |
| `DECISION.md` | Accepted architectural/product decisions (`D-001`--`D-020`) | Every stack choice that constitutes a new architectural assumption is listed in section 9 for recording as a new `D-0xx` entry |
| `TASKS.md` | Phase/task decomposition and implementation state | This plan keeps the same phase names and `T0xx` identifiers and adds stack workstreams (`W#.#`) underneath them. `TASKS.md` remains the authoritative record of what is complete |
| `AGENT.md` | Engineering rules, mandatory test rule, definition of done, documentation duties | The test requirements in every phase below are derived from the Mandatory Test Rule; section 7 restates the Definition of Done as the per-phase gate |

### 1.3 How to read a phase block

Every phase below has the same five parts:

- **Maps to** --- the `T0xx` tasks the phase is accountable for.
- **Goal** --- one sentence stating the observable outcome.
- **Stack workstreams** --- the concrete work, identified as `W#.#`,
  named after the component it lives in.
- **Deliverables** --- what exists on disk when the workstreams are done.
- **Tests** --- split into Normal, Edge and Security-negative buckets, as
  required by the Mandatory Test Rule in `AGENT.md`. Security-negative
  means *demonstrating that prohibited behavior is rejected*.
- **Exit criteria / demo** --- the artifact that proves the phase, in the
  spirit of `TASKS.md`'s "a feature is not complete because code merely
  compiles or a UI renders".

### 1.4 Non-goals of this revision

- No phase planning beyond Phase 16: `TASKS.md` ends at `T069`, so
  nothing beyond the final prototype is planned; the milestone range now
  ends at M7.
- No product/requirement changes, no edits to the four existing documents.
- No implementation code. This revision produces this file only.

---

## 2. Technology stack

### 2.1 Stack

| Layer | Technology | Rationale |
|---|---|---|
| Frontend | Next.js + React + TypeScript (App Router) | Server-side session handling keeps tokens out of browser storage; route handlers give one place to validate core responses against shared schemas |
| Browser | Chrome Extension, Manifest V3 + TypeScript | The extension is the enforcement point (`D-003`, `D-010`); MV3 is the currently shippable extension platform |
| Security core | Node.js + Fastify + TypeScript | One process owns policy evaluation, vault gateway, audit and alerts; Fastify's schema-first routing pairs directly with Zod-derived JSON Schema |
| Database | PostgreSQL | Relational integrity for consent/audit chains, row-level security for per-owner isolation, `jsonb` for explainable decision payloads |
| ORM | Drizzle | Typed SQL without a runtime query builder hiding the statements; migrations are plain SQL and reviewable |
| Validation | Zod | `AGENT.md` requires explicit schemas for security-sensitive objects; one schema definition yields runtime validation plus compile-time types at every trust boundary |
| Cache | Redis | Domain-intelligence caching with freshness (`F05`, `T017`), rate limiting, single-use authorization grants and replay protection |
| AI / Federated learning | Python + Flower + PyTorch | Federated learning requires a Python ML stack (`F16`, `T044`--`T048`); Flower supplies the federated transport and secure aggregation |
| Crypto | Node `crypto` + WebCrypto | AES-256-GCM in both runtimes with one shared blob format, so a blob written by the extension decrypts in the core and vice versa |

Three toolchains are fixed by later phases rather than here: Phase 11
uses Python + Flower + PyTorch for federated learning (already in the
table above, since the federated service ships as part of the product),
Phase 12 uses circom + snarkjs for proof generation and verification,
and Phase 13 uses an EVM-compatible chain adapter with a local
development chain. Each is pinned in its own phase and recorded as a
decision there, so a toolchain change is visible rather than silent.

### 2.2 Monorepo layout

Code is added under the existing delivery folder, beside the document
set, so the project ships as one unit:

```
EDI_PrivacyVault/EDI/
+-- md file/                     existing documents (unchanged)
+-- apps/
|   +-- dashboard/               Next.js + React + TypeScript   (Phase 8)
|   +-- extension/               Chrome MV3 + TypeScript        (Phase 2)
+-- services/
|   +-- core/                    Fastify security core          (Phase 1)
|   +-- fl/                      Python + Flower + PyTorch      (Phase 11)
+-- packages/
|   +-- schemas/                 Zod contracts, shared types    (Phase 0)
|   +-- crypto/                  AES-256-GCM envelope crypto    (Phase 1)
|   +-- rules/                   deterministic rule engine      (Phase 5)
|   +-- risk/                    explainable risk scoring       (Phase 6)
|   +-- domain-intel/            provider clients + normalizers (Phase 4)
|   +-- audit/                   hash chain + Merkle batching   (Phase 9)
|   +-- ui/                      shared React components        (Phase 8)
|   +-- zk/                      circuits + prover/verifier     (Phase 12)
|   +-- chain/                   audit anchoring adapters       (Phase 13)
+-- infra/
|   +-- docker-compose.yml       Postgres 16, Redis 7, core
|   +-- migrations/              generated SQL migrations
|   +-- kms-dev/                 local KEK shim (development only)
+-- tests/
|   +-- e2e/                     Playwright (dashboard, extension)
|   +-- security/                security-negative suites
|   +-- fl/                      pytest
+-- tooling/                     tsconfig bases, eslint, vitest, turbo
+-- scripts/                     dev, db, demo and verification scripts
```

Phases 0--4 populate `tooling`, `packages/schemas`, `infra`,
`packages/crypto`, `services/core`, `apps/extension` and
`packages/domain-intel`. Phases 5--9 add `packages/rules`,
`packages/risk`, `apps/dashboard`, `packages/ui` and `packages/audit`.
Phases 10--13 add `services/fl`, `packages/zk` and `packages/chain`.
Directories are created when their phase starts, not in advance
(`AGENT.md`: avoid unnecessary abstraction).

### 2.3 Tooling

| Concern | Choice | Notes |
|---|---|---|
| Package manager / build | pnpm workspaces + Turborepo | One lockfile, cached task graph, per-package test filters |
| Language | TypeScript, `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes` | Security code is not exempt from strictness |
| Lint / format | ESLint (flat config) + Prettier | No lint rule may be disabled inline without a comment giving the reason |
| Unit / integration tests | Vitest, plus testcontainers for Postgres and Redis | Integration tests run against real Postgres and Redis, never mocks of them |
| Browser tests | Playwright, with the extension loaded in a persistent context | Used from Phase 2 for the request/decision UI |
| Database migrations | drizzle-kit | Migrations are plain SQL, reviewed like code |
| Logging | pino with a redaction allowlist | Structured logs only; no plaintext personal data (`AGENT.md`) |
| Containers | Docker Compose | `postgres:16`, `redis:7`; healthchecks and named volumes |

Exact versions are pinned in the lockfile. The table above fixes the
majors the plan assumes; a major-version change is recorded as a
decision rather than made silently.

### 2.4 Cross-cutting standards

These apply to every phase and are not repeated per phase:

1. **Zod at every trust boundary.** Anything crossing extension -> core,
   core -> dashboard, core -> external provider, or core -> database
   boundary is parsed by a schema from `packages/schemas`. Hand-written
   duplicate types are a defect.
2. **Wire format.** JSON with `snake_case` field names, matching the
   vocabulary already used in the documents (`request_id`,
   `origin_domain`, `requested_categories`, `risk_level`, `decision`,
   `override`, `policy_version` per `ARCHITECTURE.md` section 5.11).
3. **No plaintext leakage.** Vault plaintext never reaches logs,
   telemetry, error responses, provider calls or the database. Redaction
   is configured centrally, and Phase 15 adds an automated check that
   fails a suite which logs plaintext.
4. **Fail closed.** Any error, timeout, missing signal or unparseable
   response on a security-critical path results in *no disclosure*
   (`AGENT.md`; `ARCHITECTURE.md` section 9).
5. **Unknown is not trusted.** Missing intelligence is represented as
   `unknown` with a reason; it is never collapsed into a "safe" or
   default-low value (`D-006`, `ARCHITECTURE.md` section 9).
6. **Determinism.** Policy, feasibility and risk evaluation are pure
   functions of normalized inputs plus policy state (`D-007`, `D-017`).
   Identical inputs must produce identical outputs, and this is tested.
7. **Data minimization.** Only fields required for the decision or the
   requested function are collected, logged or transmitted; prefer a
   hostname over a full URL (`D-019`).
8. **Dependency restraint.** Every added dependency is justified in the
   phase where it is introduced, with its version constrained and its
   advisories reviewed (`AGENT.md`; Phase 15, `T062`).

### 2.5 Local development

```
pnpm install
docker compose -f infra/docker-compose.yml up -d
pnpm db:migrate
pnpm dev          # core on :8080, dashboard on :3000 (from Phase 8)
pnpm test         # unit + integration
pnpm test:security  # security-negative suites
```

`.env` is never committed; `.env.example` carries every variable with
development-only placeholders. Configuration is validated at process
start by a Zod schema, so a missing or malformed variable stops the
process with a named error instead of failing later inside a security
path.

---

## 3. Trust boundaries mapped to code

`ARCHITECTURE.md` section 4 defines four boundaries. This is where each
one lives in the code and what guards it.

| Boundary | In the code | Enforcement |
|---|---|---|
| 1. Web page -> extension | Content script in the isolated world; a narrow `postMessage` bridge for values that only exist in the page's world | Page-supplied identity text is used only as *context*; origin, mechanism and requested categories are re-derived. Every message from the page is parsed by a Zod schema with a fixed field set and size limits |
| 2. Extension -> core | `apps/extension` transport -> Fastify route in `services/core` | Device-bound Ed25519 request signature, `nonce` + `timestamp` replay window, Zod-validated envelope on both ends, HTTPS only, no core route trusts a subject identifier supplied by the client |
| 3. Core -> external intelligence | `packages/domain-intel` providers | Per-provider timeout and rate limit, Zod-validated response schema, circuit breaker, results stored with `source` + `retrieved_at` + freshness, failures degrade to `unknown` |
| 4. Vault -> website | The vault gateway route in the core (added in Phase 7) | The only code path that can release data: `authorizeDisclosure()` revalidates the current decision, policy version and a single-use authorization grant, then applies minimization. Phases 1--6 build the vault, extension, intelligence and policy layers *without* any disclosure path |

Boundary 4 is called out because it is the one boundary the project can
violate without noticing. Phases 1--6 deliberately ship no disclosure
path at all; Phase 7 (`T029`) adds the gateway, and from that point every
release of data goes through it or is a defect. Phase 7 additionally
installs a static check that fails the build if any other module imports
the decryption or release helpers directly.

### 3.1 Boundaries added by Phases 11--13

`ARCHITECTURE.md` section 4 defines four boundaries. Phases 11--13
introduce three more, and they are held to the same rule: everything
crossing them is untrusted input until a shared schema validates it.

| Boundary | In the code | Enforcement |
|---|---|---|
| Core -> federated training service | `services/core` training coordinator -> `services/fl` over mTLS | Update payloads are tensors plus non-identifying metadata only; shape, dtype and magnitude bounds validated before aggregation; aggregation is robust (trimmed mean/median option) so one node cannot steer the model; model output is advisory and cannot by itself authorize disclosure |
| Client -> core proof verification | `apps/dashboard`/`apps/extension` prover -> core verifier | Only a proof plus public inputs cross this boundary --- never a witness or the underlying value. The request nonce is single-use, the circuit version is pinned, the subject is bound to the session, and a verification failure returns nothing beyond "invalid" |
| Core -> chain adapter | `packages/chain` behind the `AuditAnchor` interface | Outbound only, best-effort, never on the disclosure path: Merkle roots and non-identifying batch metadata only, signer credential from configuration, and a chain outage cannot block enforcement or affect a decision |

---

## Phase 0 --- Repository and Security Foundation

**Maps to:** `T001` (Repository structure), `T002` (Configuration and
secrets), `T003` (Shared security schemas)

**Goal:** a workspace where every later phase has a place to live, a
configuration loader that refuses to start on bad input, and one set of
Zod contracts that extension, core and dashboard all compile against.

### Stack workstreams

| ID | Component | Work |
|---|---|---|
| W0.1 | `tooling/` | pnpm workspaces + Turborepo; shared `tsconfig` base with strict flags; ESLint flat config and Prettier; Vitest workspace projects; Playwright config. Package boundaries declared so `packages/*` cannot import `apps/*` |
| W0.2 | `packages/schemas/src/config.ts` | Zod schema for all process configuration: `NODE_ENV`, `DATABASE_URL`, `REDIS_URL`, `CORE_PORT`, `LOG_LEVEL`, `KEY_PROVIDER` (`dev-shim` \| `kms`), `KEK_REF`, provider credentials, signing key material references. Loaded once at start; parse failure terminates the process with a named field error |
| W0.3 | `infra/docker-compose.yml` | Postgres 16 and Redis 7 with healthchecks and named volumes; `.env.example` with development placeholders; `scripts/dev.sh`, `scripts/db.sh` |
| W0.4 | `packages/schemas/src/` | Shared contract modules: `request.ts` (`ObservedRequest`), `domain-intel.ts` (signal envelope with `source`, `retrieved_at`, `freshness`, `confidence`, `unknown_reason`), `policy.ts` (consent + rule shapes), `risk.ts` (`RiskAssessment`), `decision.ts` (`Decision` with `decision`, `risk_level`, `reason_codes`, `matched_rules`, `override_class`), `audit.ts` (`AuditEvent` per `ARCHITECTURE.md` section 5.11), `alert.ts`, `identity.ts` (user and application shapes). Types are `z.infer` only --- no hand-maintained interfaces |
| W0.5 | `.github/workflows/` | CI: install from lockfile, lint, typecheck, unit tests, integration tests with service containers, build, `pnpm audit`, secret scan. Fails on any warning treated as error in the strict configs |
| W0.6 | `README.md`, `scripts/verify.sh` | Repo entry point linking the `md file/` documents, the stack table from section 2.1, and a single verification command that runs lint, typecheck and tests |

### Deliverables

- Installable pnpm workspace with a working Turborepo task graph.
- `packages/schemas` exporting every contract listed in W0.4, with
  inferred types and JSON Schema emission for Fastify routes.
- Zod-validated configuration loader, `.env.example`, and a documented
  list of every variable.
- Docker Compose environment for Postgres and Redis plus migration and
  dev scripts.
- Green CI pipeline and `scripts/verify.sh`.

### Tests

**Normal**

- Valid `.env` parses and yields a typed config object.
- Each schema accepts a documented, well-formed example.
- Type inference: `z.infer` output is assignable where the contract is
  consumed (compile-time assertion in the test suite).
- CI task graph runs lint, typecheck and tests for all packages.

**Edge**

- Missing, blank and whitespace-only variables are rejected with the
  offending field named.
- Malformed `DATABASE_URL`/`REDIS_URL` (wrong scheme, missing port) are
  rejected.
- Unknown enum values (`NODE_ENV`, `KEY_PROVIDER`) are rejected.
- Oversized string fields are rejected at the schema limit.
- Unknown/extra keys are rejected rather than stripped (strict object
  schemas).
- Dev placeholder secrets under `NODE_ENV=production` are rejected
  (`T002`).

**Security-negative**

- Secrets never appear in log output or error messages, including the
  parse-failure path (assertion searches captured logs for the secret
  values).
- `.env`, key material and generated data are unreachable by
  `git status` after a full dev run (gitignore verification test).
- A contract schema rejects a payload missing a security-relevant field
  (for example a `Decision` with no `matched_rules`) instead of
  defaulting it.
- Contract schemas reject an unexpected extra field, so a compromised
  client cannot smuggle unconsumed data through the core.
- No package may import another package's internals: an import-boundary
  test fails on a `packages/* -> apps/*` or cross-package deep import.

**Exit criteria / demo**

On a clean checkout: `pnpm install && docker compose up -d && pnpm
db:check && pnpm verify` succeeds; deleting `DATABASE_URL` stops the core
with a named configuration error; `NODE_ENV=production` with development
placeholders is refused. CI is green on the same commit.

---

## Phase 1 --- Personal Data Vault

**Maps to:** `T004` (Vault data model), `T005` (Encryption layer),
`T006` (Key management boundary), `T007` (Vault CRUD)

**Goal:** personal data can be stored and retrieved as authenticated
ciphertext, with keys provably separate from payloads and no API path
that returns key material or another user's data.

### Stack workstreams

| ID | Component | Work |
|---|---|---|
| W1.1 | `infra/migrations/0001_*` | Drizzle schema for the entities this phase owns: `users`, `digital_identity`, `data_category` (extensible, with `sensitivity_level`), `vault_entry` (owner, category, storage tier, ciphertext *reference*, status), `data_metadata`, `encryption_key` (wrapped DEK, KEK reference, status, rotation fields), `application` (with security rating), `consent_policy`, `consent_history`. Entities owned by later phases (`audit_event`, `security_alert`, `privacy_risk_assessment`, `request`, `decision`, `domain_intelligence`, `rule`, federated, verification, proof and blockchain tables) are added by their own phase's migration --- the entity list in `PRD.md` section 10 is the roadmap, not this phase's schema |
| W1.2 | `infra/migrations`, `drizzle.config.ts` | Generated SQL migrations, reviewed as code; row-level security policies so a session can only reach its owner's rows; indexes on owner, category, status and key reference; integration tests run migrations against a containerized Postgres and assert RLS is active |
| W1.3 | `packages/crypto` | One blob format shared by both runtimes: `[1-byte version][12-byte nonce][ciphertext + 16-byte GCM tag]`. Per-entry 256-bit DEK. Additional authenticated data binds the blob to its `data_id`, owner and category so a blob cannot be swapped between entries. Node `crypto` and WebCrypto implementations must round-trip each other's output |
| W1.4 | `packages/crypto/src/key-provider.ts` | `KeyProvider` interface (`wrapKey`, `unwrapKey`, `rotate`) with a `dev-shim` implementation (KEK in `infra/kms-dev/`, outside the app tree, gitignored) and a stub `kms` implementation that throws until Phase 15. The KEK never leaves the provider; callers only ever see wrapped material |
| W1.5 | `services/core` vault routes | Create/read/update/delete for vault entries and metadata via Zod-validated Fastify routes and Drizzle queries. Ciphertext for the local tier stays on the client; the core stores metadata, the wrapped key reference and an integrity digest. Soft delete sets status and never silently hard-deletes a consent-linked record. Every route resolves the owner from the authenticated session, never from a request field |
| W1.6 | `services/core` category registry | Data categories loaded from configuration with validated sensitivity levels (`Low`, `Medium`, `High`, `Critical`), so a new category is a configuration change rather than a code change (`D-004`) |

### Deliverables

- Migration `0001` with the Phase 1 schema, RLS policies and indexes,
  applied by `pnpm db:migrate`.
- `packages/crypto` with the shared blob format, AAD binding, key
  provider interface, dev KEK shim and rotation entry point.
- Vault CRUD + key lifecycle routes in the core, with authorization
  derived from the session.
- Category registry with extension test.

### Tests

**Normal**

- Encrypt -> decrypt round trip for the same key, including an
  empty string, multi-byte Unicode, and a payload at the size limit.
- A blob written by the Node implementation decrypts via WebCrypto and
  vice versa.
- Vault create/read/list/delete for the owning session.
- A new category added through configuration is immediately usable.
- Rotation re-wraps the DEK without changing the stored ciphertext.

**Edge**

- Wrong key id, missing ciphertext, truncated blob, and a blob whose
  version byte is from a future format all fail explicitly.
- Payload above the configured maximum is rejected before encryption.
- Unknown or retired category id is rejected.
- Deleting an already-deleted entry is idempotent and auditable.
- Concurrent create/rotate on the same key id does not corrupt the
  wrapped DEK.

**Security-negative**

- Tampering with any ciphertext byte fails the GCM tag and returns a
  generic error with no partial plaintext (`T005`).
- A blob moved to another entry fails the AAD check (`T005`).
- Key material never appears in an API response, log line, error
  payload or stack trace (`T006`).
- An unauthenticated or different-owner session cannot read, list,
  update or delete another owner's entry --- including by guessing ids
  (`T007`).
- An unauthorized application cannot reach a vault route at all; there
  is no "app scope" bypass in this phase (`T007`).
- Key-provider failure fails closed: an unwrap error yields "key
  unavailable", never a decrypt attempt with a substitute key or a
  plaintext fallback (`T006`).
- RLS is verified directly in SQL: a session restricted to another owner
  sees zero rows even with a hand-written query.

**Exit criteria / demo**

Seed a user with three entries across three categories; show ciphertext
in Postgres, decrypt one entry in the extension runtime context and one
in the core; then attempt the negative cases in front of the reviewer ---
tampered blob rejected, cross-owner read blocked, key material absent
from logs and API responses. `pnpm test:security` covers the whole
matrix.

---

## Phase 2 --- Browser Extension

**Maps to:** `T008` (Minimal extension shell), `T009` (Request
observation), `T010` (Trusted origin extraction)

**Goal:** the extension observes inbound data-access activity on a page,
derives the requesting origin from trusted browser context only, and
sends a normalized request to the core --- with a permission set no
wider than that requires.

### Stack workstreams

| ID | Component | Work |
|---|---|---|
| W2.1 | `apps/extension` | TypeScript MV3 build (Vite-based) producing a loadable unpacked extension. Manifest declares the minimum permission set: `storage`, `alarms`, `tabs`, `declarativeNetRequest`, `webNavigation`, with host access granted through optional host permissions at user request time rather than `<all_urls>` up front. No remote code, no `eval`, extension pages under a strict CSP |
| W2.2 | `apps/extension` observation | Content script in the isolated world wraps `fetch`, `XMLHttpRequest` and `navigator.sendBeacon` to produce observation events, with a narrow `postMessage` bridge for values only visible in the page's world. Events are normalized into the `ObservedRequest` schema from `packages/schemas` (`request_id`, `timestamp`, `origin`, `destination`, `requested_data`, `mechanism`, `page_context`, `browser_context`) and only fields actually available are populated. Network-level observation uses `declarativeNetRequest` where it can observe without blocking |
| W2.3 | `apps/extension` origin extraction | Origin is taken from `chrome.sender`/tab URL/`document.location` of the top frame --- never from a page-provided string. Normalization applies IDNA/punycode conversion, lower-casing, default-port removal, and explicit classification of `localhost`, private/loopback/link-local addresses, IP literals, and extension/internal origins. Redirect chains are resolved from navigation data, and the final origin is what reaches the core |
| W2.4 | `apps/extension` UI + enforcement | Warning overlay and an ASK_USER prompt rendering the explanation fields from `ARCHITECTURE.md` section 8 (website, requested data, why, matched rules). Force Allow is rendered only when `override_class` is overridable; a critical block shows the block reason and no bypass control (`F11`, `T023` arrives in Phase 5, so in this phase the control is inert and hidden by default). Blocking uses `declarativeNetRequest` rules; where the platform cannot block a mechanism, the decision is surfaced as a warning and marked "not enforceable" rather than reported as blocked (`T031` arrives in Phase 7) |
| W2.5 | `apps/extension` transport | HTTPS-only transport to the core with a device-bound Ed25519 key pair generated in WebCrypto, per-request signature, `nonce` + `timestamp` replay window, and Zod validation of the response. The key pair is non-extractable and stored in extension storage |
| W2.6 | `apps/extension` local tier | Ciphertext for the local tier is held in extension-scoped storage, keyed by `data_id`, with quota handling and an explicit "local data unavailable" state instead of a silent empty result |

### Deliverables

- Loadable MV3 extension with a documented permission allowlist.
- Observation pipeline producing normalized `ObservedRequest` events for
  `fetch`, XHR, beacon and network-level requests.
- Origin normalizer with the resolution rules of W2.3 and a fixture
  corpus of hostile inputs.
- Warning/ask-user UI wired to a core response, with the enforcement
  limits of the platform represented honestly.
- Signed, replay-protected transport to the core.

### Tests

**Normal**

- A page-initiated `fetch`, XHR and beacon each produce exactly one
  observation event with the expected mechanism value.
- A digest-authenticated (HTTPS) request from a normal public domain
  resolves to the expected normalized origin.
- A request from a subdomain of a known domain is classified as
  subdomain-of, not as the apex.
- Signed request accepted by the core; response rendered in the overlay.

**Edge**

- Malformed URL, empty origin, and a tab with no committed URL
  (`about:blank`, `chrome://`, extension origin) are handled without
  throwing.
- Punycode/Unicode domains are normalized to a single canonical form.
- Port change (`:8443`) is preserved and distinguished from the default
  port.
- Redirect chain: the origin reported is the final one, with the chain
  recorded in `browser_context`.
- Localhost, `127.0.0.1`, `::1`, private ranges and link-local addresses
  are classified as non-public origins.
- Multiple simultaneous requests each keep a distinct `request_id`;
  a repeated request is recorded as repeat, not collapsed; a cancelled
  request (aborted fetch) is recorded as cancelled with no decision.
- Unsupported mechanism produces an explicit "unsupported" observation
  rather than being silently dropped (`T009`).
- Storage quota exhaustion surfaces as a state, not a crash.

**Security-negative**

- A page-supplied origin/domain claim (spoofed `Origin` header text, a
  fake `document.domain`, a form field) never overrides the
  browser-derived origin (`T010`).
- A homoglyph domain (Cyrillic/Latin mix) is treated as the distinct
  domain it is, and never matched against the visually similar
  allowlisted domain.
- A message arriving from a non-extension sender is rejected by the
  content-script bridge schema.
- Response to the page is limited to the fixed field set; no vault
  plaintext, no policy internals, no matched-rule weights beyond the
  explanation fields leak into the page world.
- A replayed signed message (same `nonce`) is rejected, and a
  timestamp outside the window is rejected.
- The permission set is exactly the documented allowlist: a test asserts
  the built `manifest.json` contains no permission or host pattern
  beyond it (`AGENT.md`: least-privilege extension permissions).
- The extension contains no remote code, no inline script and no
  `eval`, asserted against the built bundle.

**Exit criteria / demo**

Load the unpacked extension, visit a local test page that performs a
fetch, XHR and beacon request to a synthetic destination, and show: three
observation events with normalized origins, a subdomain classified
correctly, a `localhost` origin classified as non-public, a punycode
domain canonicalized, and a spoofed-origin attempt ignored. Show the
recorded decision response rendered in the overlay, and show the manifest
permission allowlist test passing.

---

## Phase 3 --- Request Intelligence

**Maps to:** `T011` (Requested-data classification), `T012` (Request
feasibility engine), `T013` (Data minimization analysis)

**Goal:** a normalized request becomes structured facts --- which data
categories are involved, whether the observed mechanism could actually
yield them, and the minimum data that would satisfy the request --- with
no security decision made at this stage.

### Stack workstreams

| ID | Component | Work |
|---|---|---|
| W3.1 | `packages/rules/src/classify.ts` | Deterministic classification from observed request fields (endpoint path patterns, parameter names, mechanism, page context) to `requested_categories`, each with the rule or mapping that produced it. Multiple categories supported; an unmatched request produces `unknown` with a reason, never a default-low guess |
| W3.2 | `packages/rules/src/feasibility.ts` | Mechanism capability matrix: which mechanism can technically expose which category (for example, page JavaScript cannot read a file input's contents without user selection; contact data cannot arrive through a mechanism that never carries it). Output is `feasible`, `infeasible` or `indeterminate` with the reason. Feasibility never implies permission (`ARCHITECTURE.md` section 5.5) |
| W3.3 | `packages/rules/src/minimize.ts` | Minimum-field analysis per approved purpose and category: requested fields versus required fields, with excess fields reported for later data-minimized disclosure (`F12`). Mixed-sensitivity requests are reported per category, not as one aggregate |
| W3.4 | `packages/rules` structure | Pure functions with no I/O, no clock and no randomness; every input and output typed from `packages/schemas`. A fixture corpus of real-shaped observations lives beside the tests and doubles as the contract for Phase 4 domain-signal inputs |
| W3.5 | `services/core` analyzer route | Accepts a validated `ObservedRequest`, returns structured facts (classified categories, feasibility result, minimization report, distinguishing fields) and explicitly does **not** return an allow/block decision (`ARCHITECTURE.md` section 5.4) |

### Deliverables

- Classification, feasibility and minimization modules with schemas and
  fixture corpus.
- Analyzer route returning structured facts only.
- Classification mapping table documented, so adding a category mapping
  is a data change rather than a code change.

### Tests

**Normal**

- A single-category request classifies to exactly that category, with
  the producing rule recorded.
- A multi-category request returns all expected categories, each with
  its own confidence/rationale.
- A feasible request is `feasible` with the mechanism cited.
- A request asking for exactly the minimum fields reports no excess.
- A request asking for a superset reports the excess fields, per
  category.

**Edge**

- Unknown category, ambiguous request (two rules matching with equal
  specificity), and an empty `requested_data` list each return an
  explicit outcome and no decision.
- Highly sensitive category (financial, medical) classifies without
  changing the analyser's output contract.
- Impossible request: a mechanism that cannot yield the requested data
  is `infeasible`, with the missing capability named.
- Unsupported mechanism is `indeterminate` and is distinguishable from
  `infeasible`.
- Conflicting metadata (mechanism says contact, path says financial)
  yields a conflict flag rather than silently picking one.
- A request for an unknown field is reported as unknown rather than
  dropped from the minimization report.
- Determinism: identical inputs produce byte-identical facts across
  repeated runs and across process restarts.

**Security-negative**

- Classification cannot be influenced by page-supplied text: a page
  claiming a lower-sensitivity category does not change the result
  derived from the observed mechanism and fields.
- An oversized or deeply nested request payload is rejected at the
  schema boundary instead of being analyzed.
- Facts output contains no vault existence or content signal, so the
  analyzer cannot be used to probe what a user has stored.
- Minimization never *adds* a category that the request did not imply,
  and never broadens scope for later disclosure.

**Exit criteria / demo**

Feed the recorded observation corpus through the analyzer and show, side
by side: a single-category request, a multi-category request, a
conflicting-metadata request and an infeasible request --- each with its
reasoning and none with an allow/block verdict.

---

## Phase 4 --- Domain Intelligence

**Maps to:** `T014` (Provider interface), `T015` (Domain creation/age
intelligence), `T016` (Domain history signals), `T017` (Intelligence
cache), `T018` (Provider failure handling)

**Goal:** for a requesting origin, the system obtains whatever security
signals are actually available --- each with its source and freshness ---
caches them in Redis, and degrades to an explicit `unknown` state when
providers fail, without ever letting a provider failure cause
disclosure.

### Stack workstreams

| ID | Component | Work |
|---|---|---|
| W4.1 | `packages/domain-intel/src/provider.ts` | `DomainIntelligenceProvider` interface and registry. Every result is a signal envelope validated by `packages/schemas`: `value`, `source`, `retrieved_at`, `freshness`, `confidence`, `unknown_reason`. A provider can return `unknown`; it cannot return an unlabeled value |
| W4.2 | `packages/domain-intel/src/providers/` | Registered-domain creation date/age via RDAP; DNS/hosting signals; certificate-history signal from certificate transparency data; an abuse/reputation adapter behind the same interface so a provider can be replaced without touching the rule engine (`T014`). Each provider documents its freshness semantics |
| W4.3 | `services/core` intelligence cache | Redis keyed by signal type and domain, with per-signal TTL, explicit `stale` marking after the freshness horizon, single-flight locking so concurrent requests for the same domain trigger one upstream call, and negative caching that stores `unknown` with its reason. Postgres is never written from a cache miss, and the cache is never treated as an authority: a cache miss means *go fetch*, not *trust* |
| W4.4 | `services/core` failure handling | Per-provider timeout budget, bounded retry with backoff, token-bucket rate limiting, circuit breaker after repeated failures, Zod validation of every response before use, and a documented degradation ladder (freshest signal -> stale signal marked stale -> `unknown` -> continue with privacy-first posture). Provider failures are recorded with their cause and never converted into a benign-looking value (`T018`) |
| W4.5 | `services/core` observability | Structured metrics for provider latency, timeout and error rates, cache hit/stale/miss counts. Logs record the hostname required for the decision and no more (`D-019`); full URLs, paths and query strings are not logged |
| W4.6 | `services/core` `POST /api/domain-intelligence` | Validated route returning the signal set for an origin, with freshness metadata intact, plus a combined "intelligence summary" whose uncertainty is explicit |

### Deliverables

- Provider interface, registry and the four provider adapters.
- Redis cache with freshness, staleness, single-flight and negative
  caching.
- Failure-handling layer with timeout, retry, rate limit and circuit
  breaker, plus degradation ladder documentation.
- Intelligence route returning freshness-annotated signals.
- Provider metrics and a redaction-safe logging configuration.

### Tests

**Normal**

- A newly registered domain returns a creation date that the age signal
  converts to the expected age bucket.
- A long-registered domain returns the expected bucket.
- Registration, DNS, certificate-history and reputation signals each
  return a validated envelope with `source` and `retrieved_at`.
- Second request for the same domain inside the TTL is served from
  cache with identical freshness metadata and no upstream call.
- Intelligence summary distinguishes "signals available" from
  "signals unknown".

**Edge**

- Missing creation date from RDAP returns `unknown` with a reason, not
  a null-as-old value.
- Invalid date format and a future creation date are rejected/quarantined
  rather than feeding the age computation.
- Provider timeout returns `unknown` after the configured budget, with
  the request still completing.
- Expired cache entry triggers refetch; the response is marked fresh
  again only after a successful refetch.
- Corrupted cache entry (bad JSON, schema mismatch) is treated as a miss
  and overwritten.
- Provider unavailable, rate-limited and auth-failed each produce a
  distinguishable, recorded cause.
- Stale signal beyond the horizon is returned as `stale` with its
  original `retrieved_at` intact.
- Concurrent requests for the same uncached domain trigger exactly one
  upstream call (single-flight assertion).
- Invalid provider response (extra fields, wrong types, oversized body)
  is rejected by schema validation and becomes `unknown`.

**Security-negative**

- Provider failure, timeout, rate limit or invalid response never
  produces a permissive result and never causes disclosure of vault data
  (`T018`; `ARCHITECTURE.md` section 9) --- asserted across every
  failure mode with a disclosure-probe assertion.
- Missing intelligence is never mapped to "trusted"/"safe"/low risk:
  a dedicated test asserts that an all-`unknown` signal set is not
  equivalent to the lowest available risk inputs.
- External providers receive the minimum identifier required: a test
  asserts no full URL, path, query string, user identifier or vault
  reference is transmitted (`D-019`).
- Provider credentials never appear in logs, error payloads, metrics
  labels or the intelligence response.
- Cache poisoning resistance: a value written for one domain is not
  served for another; key construction is asserted against collision
  cases (subdomain vs apex, case differences, trailing dot).

**Exit criteria / demo**

Request intelligence for four domains --- a long-registered domain, a
recently registered one, a domain whose creator data is missing, and one
whose provider times out --- and show the four freshness-annotated signal
sets. Repeat the first request to show a cache hit with unchanged
freshness, then stop the provider container to show timeout handling,
circuit breaker behavior, `unknown` propagation and the absence of any
permissive fallback.

---

## Phase 5 --- Rule Engine

**Maps to:** `T019` (Rule schema), `T020` (Rule evaluator), `T021`
(Privacy-first defaults), `T022` (User rules), `T023` (Critical security
rules)

**Goal:** rules exist as versioned configuration data evaluated by one
deterministic engine, and every decision retains the rules that
materially affected it.

### Stack workstreams

| ID | Component | Work |
|---|---|---|
| W5.1 | `packages/schemas/src/policy.ts` | Rule schema: `rule_id`, `ruleset_version`, `condition` (a typed expression tree, not an evaluated string), `effect` (`allow` \| `warn` \| `block` \| `ask_user`), `priority`, `scope` (data categories, origins/domains, applications), `rationale`, `override_class` (`overridable` \| `critical`). Validated at load; a malformed rule file prevents startup rather than being skipped |
| W5.2 | `packages/rules/src/evaluate.ts` | Pure deterministic evaluator (`AGENT.md`: identical normalized inputs plus identical policy state produce the same result). Total ordering by `(priority, rule_id)`; explicit conflict resolution: highest priority wins, and equal-priority opposing effects resolve to the most restrictive effect with a `conflict` flag rather than an arbitrary pick. A rule whose required signal is absent or stale does not match and is recorded as `unevaluated` with the reason. Output: `matched_rules`, `reason_codes`, `override_class` (most restrictive among matched rules), `conflicts` |
| W5.3 | `packages/rules/ruleset/v1/` | The privacy-first default ruleset as data files (`T021`), Zod-validated at load, checksummed, and versioned. No rule conditions appear as literals in TypeScript |
| W5.4 | `services/core` rules API | User rule CRUD (`T022`): owner-scoped authorization, schema validation, a conflict preview that lists the existing rules a proposed rule would shadow, an optional expiry date, and an audit entry per change. User rules may not set `override_class: critical` --- that class is system-owned, so privilege escalation through a user rule is impossible by construction |
| W5.5 | `packages/rules/src/critical.ts` | Critical rule registry (`T023`): the rules that cannot be bypassed through Force Allow. The union is enforced inside the evaluator and surfaced to Phases 6 and 7, never only in the UI |
| W5.6 | decision policy binding | The evaluated `ruleset_version` plus the user-policy version are recorded with every decision, satisfying the `policy_version` field in `ARCHITECTURE.md` section 5.11 and making a later decision reproducible |

### Deliverables

- Rule schema, deterministic evaluator, conflict resolution and
  `unevaluated` reporting.
- Privacy-first default ruleset v1 as validated, checksummed data.
- Owner-scoped user-rule API with conflict preview, expiry and audit.
- Critical rule registry consulted by the evaluator.
- Policy versioning carried into every decision record.

### Tests

**Normal**

- Exactly one matching rule yields that rule's effect with the rule id
  in `matched_rules`.
- Multiple matching rules resolve by priority, and every matched rule is
  still reported.
- No matching rule produces the documented default posture (explicit in
  the ruleset, not an implicit fallthrough).
- A user rule that shadows nothing saves cleanly and takes effect.
- Default privacy-first rules block automatic disclosure of financial
  and medical categories as documented.

**Edge**

- Conflicting rules at equal priority produce the most restrictive
  effect plus a `conflict` flag.
- Priority conflict between a user rule and a system rule resolves by
  the documented rule, and the loser is still listed.
- A rule whose required signal is missing is `unevaluated` and does not
  affect the outcome.
- A rule whose signal is stale is `unevaluated` with `stale` as the
  reason, not silently matched.
- An expired user rule is inactive; a rule expiring between evaluation
  and disclosure is re-checked at disclosure (Phase 7).
- A malformed or unknown-effect rule file fails startup with the file and
  line named.
- Deleting a user rule leaves previous decisions unchanged and
  reproducible from their recorded versions.
- Determinism: the same facts plus the same policy state produce the same
  output across runs, across process restarts, and independent of rule
  file ordering.

**Security-negative**

- A user rule granting `critical` override class is rejected.
- A user cannot modify, disable or shadow a system critical rule
  (`T023`).
- Unauthorized rule modification (another owner's rule, or an
  application-scoped caller) is rejected and audited.
- A rule cannot widen the requested data scope: a rule that would
  authorize more fields than the request asked for is rejected at
  validation.
- Ruleset checksum mismatch is detected and reported; a modified ruleset
  cannot be loaded as if it were v1.
- A rule condition cannot reach outside its declared scope (no
  cross-owner, no vault-content condition), asserted by a scope-boundary
  test.

**Exit criteria / demo**

Evaluate four prepared requests through the engine --- allow, ask_user,
block, critical block --- showing matched rules, conflicts and the
recorded `ruleset_version` for each. Then attempt to neutralize the
critical rule with a user rule and show validation rejecting it, and
attempt to shadow it and show the conflict preview reporting the attempt.

---

## Phase 6 --- Risk and Decision Engine

**Maps to:** `T024` (Risk assessment), `T025` (Decision engine),
`T026` (Decision explanation), `T027` (Force Allow)

**Goal:** every request produces an explainable risk assessment and one
of ALLOW, WARN, BLOCK or ASK_USER, where overrides are explicit, audited,
scope-limited and impossible for critical blocks.

### Stack workstreams

| ID | Component | Work |
|---|---|---|
| W6.1 | `packages/risk` | Explainable scoring: named, constant factor weights over data sensitivity, permission/scope breadth, domain age and reputation (with freshness), feasibility result, and application security rating where an application is the requester. Score is bounded at 100, mapped to Low/Medium/High/Critical bands with an actionable recommendation per band. Missing or stale factors raise *uncertainty*; they never lower risk (`D-008`, `ARCHITECTURE.md` section 9) |
| W6.2 | `packages/risk/src/intelligence.ts` | `RiskIntelligence` interface returning an advisory score plus model identifier and version. Phase 6 ships the deterministic implementation only; the Phase 11 federated model plugs in here and remains advisory (`D-007`, `D-017`) |
| W6.3 | `packages/rules/src/decide.ts` | Decision engine (`T025`): combines rule output with the risk assessment into ALLOW, WARN, BLOCK or ASK_USER, distinguishing an ordinary policy block from a critical security block in the returned structure rather than by string convention |
| W6.4 | `packages/schemas/src/decision.ts` | Explanation payload (`T026`) shaped for the UX in `PRD.md` section 9: website, requested data, why (domain signals with freshness and unknown reasons), matched rules, risk level, feasibility, override state. Validated, and asserted to contain no vault plaintext and no personal data beyond what the explanation requires |
| W6.5 | `services/core` Force Allow | Eligibility derived from `override_class`, never from the client; requires an explicit user action with a stated reason; writes an audit event containing actor, reason, policy version and the overridden decision; issues a scope-limited, short-lived, single-use authorization grant that Phase 7 consumes. It never mutates stored rules and never expands the requested scope |
| W6.6 | `infra/migrations/0002_*` | `decision` and `privacy_risk_assessment` tables: decision outcome, risk score and band, `reason_codes`, `matched_rules`, `override_class`, `policy_version`, and references/hashes of the signal envelopes used. Snapshot hashes make a later audit able to prove which signals were in view without duplicating provider data |

### Deliverables

- `packages/risk` scoring with factor breakdown and uncertainty
  reporting, plus the advisory `RiskIntelligence` seam.
- Decision engine producing all four outcomes with critical-block
  distinction.
- Validated explanation payload consumed by the extension overlay and,
  from Phase 8, the dashboard.
- Force Allow flow with audit, scope limit and expiry.
- Migration `0002` with decision and risk-assessment records.

### Tests

**Normal**

- Each of the four scenarios yields its intended decision.
- Risk scores land in the expected band at each band boundary.
- The factor breakdown explains the score: every contributing factor is
  listed with its weight and input value.
- A non-trivial decision's explanation is complete (decision, risk,
  signals with source and freshness, requested data, matched rules,
  reason codes, override state).
- Force Allow on an overridable block grants a scope-limited grant and
  writes one audit event.

**Edge**

- All signals `unknown` produces an explicit high-uncertainty assessment,
  not a low-risk one.
- Stale signals are labeled stale inside the explanation.
- Boundary values: score exactly at 25, 50 and 75 land in the documented
  band; score above the cap is clamped to 100.
- No application in context (owner-initiated disclosure) scores without
  inventing an application rating.
- Conflicting rules from Phase 5 surface in the decision structure rather
  than being silently resolved.
- Expired Force Allow grant is refused at use.
- A decision recomputed after a ruleset change produces a different
  `policy_version` and is recorded as a new decision, not an edit.

**Security-negative**

- A critical block reports `overridable: false`, and a Force Allow request
  against it is refused by the core even when the request is hand-crafted
  to bypass the UI (`T027`).
- Force Allow cannot expand the requested scope: a grant issued for one
  field cannot be used to disclose a second field.
- Force Allow does not persist into stored rules; a second identical
  request after an override still receives the original decision.
- Replaying an override grant is rejected (consumed single-use).
- Page-supplied data cannot lower risk: a page claiming a trusted origin
  or low sensitivity does not change the assessment.
- Missing reputation data never converts into a permissive factor value.
- The explanation payload exposes no vault content and no factor inputs
  that reveal what the user has stored.

**Exit criteria / demo**

Show four decisions with full explanations, print the factor breakdown for
a High and a Critical score, then demonstrate the override rules: a
successful Force Allow on an ordinary block (audited, one field
disclosed in Phase 7), and a refused Force Allow on a critical block made
by calling the API directly rather than through the UI.

---

## Phase 7 --- Enforcement and Vault Gateway

**Maps to:** `T028` (Pre-disclosure enforcement), `T029` (Vault
gateway), `T030` (Limited disclosure), `T031` (Block enforcement)

**Goal:** no protected data leaves the vault without passing through one
revalidating gateway that releases only the authorized minimum, and
blocked requests are actually prevented wherever the browser platform
permits it --- with an honest record where it does not.

### Stack workstreams

| ID | Component | Work |
|---|---|---|
| W7.1 | `services/core/src/gateway/authorize.ts` | `authorizeDisclosure()` --- the single entry point for releasing data (`T028`). It re-derives authorization at disclosure time from the current decision, current policy version, consent state and the presented grant, rather than trusting the earlier evaluation. Everything before it in the pipeline is advisory; this function is authoritative and fails closed. A static import check fails the build if any other module imports the decryption or release helpers (`T029`) |
| W7.2 | `services/core/src/gateway/release.ts` | Minimal disclosure (`T030`): selects only the approved fields, using the Phase 3 minimization result, and releases them to the authorized recipient only. Local-tier entries are decrypted through the extension (owner-authorized, user-gesture-driven); server-tier entries decrypt in the core through the `KeyProvider`. Every release writes an audit event. This phase adds the `audit_event` table it depends on as migration `0003`; Phase 9 extends it with hash-chaining, retention and the viewer |
| W7.3 | `services/core/src/gateway/grants.ts` | Authorization grants: short-lived signed tokens bound to `request_id`, subject, data category, the specific approved fields, recipient and expiry, with a `jti` recorded in Postgres and consumed single-use in Redis (`SET NX` + TTL). Expiry, replay, scope expansion and use-after-revocation are rejected at the gateway, not at the caller |
| W7.4 | `apps/extension` enforcement | Applies the decision before disclosure: `declarativeNetRequest` rules for network-level blocks, and content-script level blocking where the mechanism allows. Where the platform cannot prevent the request, the extension reports `enforced: false` with the mechanism and the decision is surfaced as a warning marked "not enforceable" instead of a claimed block (`D-025`) |
| W7.5 | `apps/extension` + core attestation | The extension returns an enforcement attestation (`enforced`, mechanism, timestamp, rule id), and only an attested block is recorded as enforced. An unattested "block" is stored as unenforced so the audit cannot overstate protection (`T031`) |

### Deliverables

- `authorizeDisclosure()` as the only disclosure path, with the import
  guard that keeps it that way.
- Minimal-disclosure release covering both storage tiers, with audit on
  every release.
- Single-use, scope-bound, expiring authorization grants with replay and
  revocation handling.
- Extension enforcement for the mechanisms it can enforce, plus honest
  `enforced: false` reporting for the ones it cannot.
- Enforcement attestation carried into the audit record.

### Tests

**Normal**

- A request approved for one field discloses exactly that field, once.
- A request approved for several categories discloses each approved
  category and no others.
- Owner path discloses through the extension decryption bridge; a
  server-tier entry discloses through the core key provider.
- An application path with an active consent discloses and records the
  consent id used.
- A blocked request is prevented at the network level and recorded as
  enforced with its attestation.

**Edge**

- Grant used after expiry is refused.
- Grant issued under a policy version that has since changed is refused
  on revalidation and the refusal is recorded.
- Two concurrent uses of the same grant result in exactly one success.
- Grant for a vault entry deleted in the meantime is refused.
- Consent revoked between decision and disclosure causes refusal, proving
  the gateway does not trust stale evaluation.
- Unenforceable mechanism records `enforced: false` and surfaces a
  warning rather than a block.
- Disclosure of a local-tier entry whose blob is unavailable fails with an
  explicit "local data unavailable" state rather than an empty success.

**Security-negative**

- An unauthorized category is refused and audited (`T030`).
- A request expanded after authorization (more fields, other category,
  different recipient) is refused and audited.
- A replayed grant is refused and the replay attempt is recorded.
- A grant cannot be minted for a critical block at all.
- Direct access to the release or decryption helpers outside
  `authorizeDisclosure()` fails the import-boundary check, so a future
  shortcut cannot be added without deleting a test.
- A block whose enforcement is unconfirmed never reports as enforced, and
  a page retrying the blocked request still receives no data.
- A refused disclosure never returns partial data and never logs the
  plaintext it would have released.
- The recipient receives no data-minimization metadata (approved field
  names, rule ids) beyond what the explanation requires.

**Exit criteria / demo**

End-to-end: a page requests a financial field, the decision is ASK_USER,
the user approves, exactly one field is disclosed and one audit row is
written. Then replay the grant (refused), revoke consent mid-flight
(refused), block a request at the network level and show the attestation,
and attempt a critical-block override directly against the API (refused).

---

## Phase 8 --- Dashboard

**Maps to:** `T032` (Dashboard foundation), `T033` (Vault interface),
`T034` (Security overview), `T035` (Request detail view), `T036` (Policy
management), `T037` (Domain view)

**Goal:** the owner can see and control the vault, their policy, recent
requests, risk and domain signals in a browser interface that never
becomes a second plaintext copy of the vault.

### Stack workstreams

| ID | Component | Work |
|---|---|---|
| W8.1 | `apps/dashboard` shell + session | Next.js App Router (`T032`): session established through an httpOnly, `Secure`, `SameSite=Lax` cookie issued by the core, route middleware guarding authenticated areas, CSRF token required for every mutation, and no tokens in `localStorage`. Server components read through the core with Zod validation on the response. Real JWT/session hardening remains Phase 15 work |
| W8.2 | vault interface (`T033`) | Metadata listing (category, tier, status, timestamps), category filter, upload of entries encrypted client-side before they leave the browser, reveal behind an explicit user gesture plus re-authentication, soft delete with audit. Keys are never transmitted to the core |
| W8.3 | security overview (`T034`) | Current risk, recent requests, blocks, warnings, domain-intelligence freshness and open alerts, with live updates over a server-sent-events stream from the core |
| W8.4 | request detail (`T035`) | The complete explainable decision: signals with source and freshness, matched rules, reason codes, feasibility, minimization result and override state --- rendered without exposing vault plaintext the owner did not choose to reveal |
| W8.5 | policy management (`T036`) | Consent list with grant/revoke and a risk preview shown *before* granting; user-rule editor with the Phase 5 conflict preview and expiry; critical rules shown read-only; every mutation audited |
| W8.6 | domain view (`T037`) | Per-domain signal table: value, source, `retrieved_at`, freshness, confidence and explicit unknown reasons, so "unknown" is visually distinct from "clean" |
| W8.7 | `packages/ui` | Shared components and risk/severity tokens reused by the extension overlay, so the same decision reads identically in both surfaces |
| W8.8 | telemetry and CSP policy | No third-party scripts, no analytics, no client-side error reporting that could carry personal data; strict Content-Security-Policy and security headers served by the dashboard |

### Deliverables

- Authenticated dashboard shell with cookie session, middleware guard and
  CSRF protection.
- Vault, overview, request detail, policy and domain screens.
- Shared UI package used by dashboard and extension overlay.
- SSE stream for live decisions and alerts.
- Documented no-telemetry policy plus enforced CSP and security headers.

### Tests

**Normal**

- Each screen renders its data from the core with validated responses.
- Consent grant then revoke updates state and writes audit entries.
- Rule save shows the conflict preview and persists the rule.
- Reveal requires the explicit gesture and re-authentication.
- A new decision appears in the overview through the SSE stream.

**Edge**

- Empty vault, no requests yet, and no alerts each render an explicit
  empty state rather than a spinner or an error.
- A domain whose provider failed renders `unknown` with the reason, not a
  blank or "safe" badge.
- Long audit and request lists paginate without loading everything.
- Session expiry mid-flow redirects to login and preserves no partial
  mutation.
- Local-tier entry with an unavailable blob renders the availability
  state.

**Security-negative**

- The dashboard cannot read another owner's rows: assertions at both the
  API and SQL layers.
- No vault plaintext appears in server logs, client console output or
  error traces (log-search assertion across the suite).
- A mutation without a valid CSRF token is rejected.
- Injected script is blocked by CSP, and rule rationales, domain names
  and decision reasons are rendered escaped (XSS probe).
- Reveal without re-authentication is refused.
- The client bundle contains no secrets, and a page-load network
  assertion shows zero third-party requests.
- The SSE stream is authenticated per session; another session cannot
  subscribe to a different owner's events.

**Exit criteria / demo**

Walk all six surfaces, show a blocked request's full explanation, grant
and then revoke a consent with the resulting audit entries, and show an
injected script blocked by CSP with the network tab recording no
third-party calls.

---

## Phase 9 --- Audit and Retention

**Maps to:** `T038` (Audit event model), `T039` (Audit viewer),
`T040` (Retention policy)

**Goal:** security-relevant events are recorded tamper-evidently, and
historical records are automatically deleted under the configured
retention policy with the deletion itself visible rather than silent.

### Stack workstreams

| ID | Component | Work |
|---|---|---|
| W9.1 | `infra/migrations/0004_*` | Audit model (`T038`) as an append-only table carrying the fields in `ARCHITECTURE.md` section 5.11: `request_id`, `timestamp`, actor, `origin_domain`, `requested_categories`, `domain_intelligence_summary`, `matched_rules`, `risk_level`, `decision`, `override`, `policy_version`, plus `prev_hash` and `entry_hash` forming a per-actor hash chain. No sensitive payloads are copied into audit rows (`D-019`) |
| W9.2 | `packages/audit` + viewer API | Chain construction and verification utilities, a paginated read-only viewer API and dashboard route (`T039`), and a verification endpoint that reports the first broken link with its record and timestamp |
| W9.3 | `services/core` retention worker | Retention policy per record type, validated from configuration (`T040`); a repeatable BullMQ job on Redis; deletion in bounded batches with retry and backoff; derived records (decisions, request records, signal snapshot hashes) deleted alongside the records they derive from; a tombstone row recording counts and the deleted range --- never content --- so the trail shows deletion happened; foreign-key-safe ordering (`F14`) |
| W9.4 | retention observability | Job status, last successful run and deleted counts exposed; repeated failure raises an alert rather than silently stopping future runs |
| W9.5 | immutability guards | Audit rows are insert-only for the application role: `UPDATE`/`DELETE` are revoked at the database level and only the retention role may delete expired rows. Immutability is enforced by the database, not by convention in application code |

### Deliverables

- Migration `0004`: audit table, hash chain, database-level permission
  guards.
- Chain builder, verifier and read-only viewer with verification
  endpoint.
- Retention worker with configuration-validated policy, batch deletion,
  retry and tombstones.
- Documented retention windows per record type and their configuration
  keys.

### Tests

**Normal**

- An event written by each subsystem (decision, override, disclosure,
  block, consent change) records all required fields.
- A chain of events verifies successfully.
- Records older than the retention window are deleted; records inside it
  are retained, and the tombstone records what was removed.
- The viewer lists events newest-first with working filters.

**Edge**

- A record whose timestamp is exactly on the retention boundary follows
  the documented inclusive/exclusive rule.
- Retention with an empty result set completes without error.
- More rows than the batch size causes correct looping rather than one
  partial pass.
- Two retention workers cannot run concurrently (lock assertion).
- A retention policy of zero or an unparseable value is rejected at
  configuration time.
- Clock skew between worker and database does not make an in-window
  record eligible for deletion.
- A chain written across a retention deletion still verifies for the
  surviving records, and the tombstone explains the gap.

**Security-negative**

- The application role cannot `UPDATE` or `DELETE` an audit row --- the
  database refuses it, and the attempt is logged.
- A row tampered with directly in SQL is detected, with the first broken
  link reported.
- Deleted history is no longer visible through any API, including by
  identifier lookup with a previously captured id.
- Derived records are not left readable after their parent is deleted.
- A failed deletion run retries, surfaces the failure, and does not
  silently skip the batch.
- Audit rows contain no plaintext personal data and no full URLs, verified
  by a column-level assertion.
- The retention job cannot be triggered by an unauthenticated or
  application-scoped caller to erase evidence mid-incident.

**Exit criteria / demo**

Generate traffic covering decision, override, disclosure and block events,
show the chain verifying, then tamper with one row directly in SQL and
show verification naming the broken link. Then run the worker against a
shortened retention window and show that expired records disappear from
the API, a tombstone records the deletion, and an injected deletion error
is retried and surfaced.

---

## Phase 10 --- Security Alerts

**Maps to:** `T041` (Alert engine), `T042` (Alert dashboard), `T043`
(Alert lifecycle)

**Goal:** suspicious or blocked access behaviour produces an alert the
owner can see and act on --- in both surfaces --- with a lifecycle that
never rewrites the security facts the alert is about.

### Stack workstreams

| ID | Component | Work |
|---|---|---|
| W10.1 | `services/core/src/alerts/engine.ts` | Alert generation (`T041`) from signals that already exist: critical block, override granted, repeated blocked attempts for one origin inside a Redis sliding window, High/Critical risk consent request, provider-failure storm, audit chain verification failure, and retention-job failure. Each generator emits a fingerprint; idempotent per `(fingerprint, window)` so a repeat raises the occurrence count instead of a new row |
| W10.2 | `infra/migrations/0005_*` | `security_alert` table (`packages/schemas/src/alert.ts` is already defined in Phase 0): `alert_type`, `severity`, description without personal data, `status`, `fingerprint`, `occurrence_count`, `first_seen`, `last_seen`, references to the related decision/audit records, and acknowledgement/resolution fields carrying actor and timestamp |
| W10.3 | alert surfaces (`T042`) | Dashboard list and detail (severity, reason, timestamp, status, related decision, occurrence count, unread count) pushed live over the Phase 8 SSE stream, plus an extension badge and a high/critical notification. Notification payloads carry an alert id, type and severity only --- detail is fetched from the core after authentication, because OS notification services are outside our boundary |
| W10.4 | alert lifecycle (`T043`) | Acknowledge, resolve and reopen as explicit states with actor, timestamp and optional reason, each transition audited. The referenced decision, risk assessment and audit rows are immutable and are never edited, hidden or deleted by an alert transition; resolving an alert is a statement about the alert, not about the underlying event |
| W10.5 | alert delivery limits | Per-owner rate limiting on notifications, dedupe on the fingerprint, and a bounded notification queue so a decision storm cannot flood the user's OS notifications. `AGENT.md` least-surprise applies: an alert is advisory and its failure never affects enforcement |

### Deliverables

- Alert engine with the documented generator set, fingerprints and dedupe
  windows.
- Migration `0005` with the alert lifecycle columns.
- Dashboard and extension alert surfaces with live push.
- Lifecycle state machine with audit on every transition.
- Notification payload schema that excludes personal data.

### Tests

**Normal**

- Each generator source produces an alert with the intended severity and
  a link to its originating decision.
- Repeated identical blocks inside the window collapse into one alert
  with `occurrence_count` incremented.
- Acknowledge then resolve records both transitions with actors and
  timestamps.
- A new alert appears in the dashboard without a page reload (SSE).
- Extension badge count tracks unread high/critical alerts.

**Edge**

- A repeat arriving after the dedupe window creates a new alert, and the
  transition rules for a resolved-then-recurring alert follow the
  documented state machine.
- Alert volume above the notification rate limit is queued and coalesced
  rather than dropped silently.
- An alert whose related record was removed by Phase 9 retention renders
  the tombstone reference instead of a dangling link.
- Retention-job failure and audit-verification failure both raise alerts
  themselves, without recursing.
- Clock skew between the core and the dedupe window does not merge two
  genuinely distinct events or split one event.
- A user with alerts disabled still receives critical security alerts;
  the setting applies to non-critical severities only.

**Security-negative**

- Alert descriptions, notification payloads and stored rows contain no
  vault plaintext, no personal data and no full URLs (assertion over
  stored columns and over the exact bytes pushed to notifications).
- An application-scoped or anonymous caller cannot acknowledge, resolve
  or enumerate another owner's alerts.
- Acknowledging or resolving does not modify the underlying decision,
  risk assessment or audit row, verified by comparing hashes before and
  after.
- Domain names, rule rationales and reason codes rendered in alert text
  are escaped, so a hostile domain name cannot inject script into the
  dashboard (XSS probe).
- An alert-engine failure cannot change an enforcement outcome: with the
  engine forced to throw, a critical block is still enforced, a
  disclosure still requires a valid grant, and no alert failure causes a
  permissive fallback.

**Exit criteria / demo**

Trigger a critical block, an override, repeated blocked attempts and a
provider-failure storm; show four alerts with correct severities, the
repeats collapsed into one alert with a count, a live push into the
dashboard, an acknowledged-then-resolved lifecycle with audit entries,
and the hash-check proving the underlying decision did not change.

---

## Phase 11 --- IND-05 Privacy-Preserving AI

**Maps to:** `T044` (Privacy risk AI interface), `T045` (Federated
learning foundation), `T046` (Federated risk learning), `T047`
(Federated anomaly detection), `T048` (Secure aggregation)

**Goal:** risk intelligence can be trained across participating nodes
without moving raw personal data, and the trained model informs risk
while remaining advisory so the deterministic engine stays authoritative.

### Stack workstreams

| ID | Component | Work |
|---|---|---|
| W11.1 | `services/core/src/risk/intelligence.ts` | The `RiskIntelligence` seam from Phase 6 gains its real implementations: `deterministic` (default and always authoritative for enforcement) and `model_backed` (advisory score with model id, version and confidence). Selection is configuration-driven, and an unavailable or unhealthy FL service falls back to deterministic without degrading enforcement or availability |
| W11.2 | `infra/migrations/0006_*` | Federated structures (`T045`): `federated_node` (organization, node type, location, security level), `federated_training_session` (model, node, start/end, accuracy, status), `model_update_history` (version, source, performance change, date) and `ai_model` (name, type, algorithm, framework, version). Node registration uses an operator-controlled credential; a node identity is never self-asserted from a request |
| W11.3 | `services/fl` | Python service (`T045`--`T047`): Flower server plus a client runner, with PyTorch models for the two documented targets --- a risk classifier over features derived from rule-engine decisions (sensitivity, permission scope, domain signals with freshness, feasibility, application rating) and an anomaly detector (autoencoder) over access-behaviour features. Features are computed locally on each node from that node's own records; only model updates leave. `docker-compose` runs two simulated nodes for development |
| W11.4 | secure aggregation (`T048`) | Flower secure aggregation over an mTLS channel, with per-update clipping and noise under a documented privacy budget, payload validation (shape, dtype, magnitude) that rejects out-of-bounds updates before aggregation, and a robust aggregation option (trimmed mean/median) so a single node cannot steer the global model |
| W11.5 | promotion, rollback and explanation | An update is evaluated on held-out local validation data before any promotion; promotion is a deliberate, audited action producing a versioned artifact with a rollback path. Model influence appears in the decision explanation as a labeled model-derived factor with its version, so a user can see when a model contributed |
| W11.6 | privacy assertions | No raw personal data, per-user record or vault identifier may appear in an update, log, metric or artifact. Enforced by payload schema plus tests that inspect serialized updates and canary values planted in local training data |

### Deliverables

- Two `RiskIntelligence` implementations behind one interface, with
  deterministic fallback.
- Python federated service with a risk classifier, an anomaly detector and
  a two-node development topology.
- Secure aggregation with clipping, noise, bounds checking and robust
  aggregation.
- Versioned model artifacts with audited promotion and rollback.
- Federated and model tables via migration `0006`.

### Tests

**Normal**

- A two-node round completes, and the session, model version and accuracy
  are recorded.
- Secure aggregation produces a global update from per-node updates.
- The anomaly detector flags a synthetic suspicious access pattern at the
  documented threshold and does not flag a benign baseline.
- The model-backed implementation produces a score and confidence that
  appear in the explanation with the model version.
- Rollback to the previous model version restores the prior scoring
  behavior.

**Edge**

- A node dropping out mid-round does not fail the round (aggregation
  proceeds with the remaining nodes and records the dropout).
- A malformed and an out-of-bounds update are each rejected before
  aggregation, with the offending node identified.
- An empty local dataset and a single-node round both complete safely.
- FL service unavailable or unhealthy falls back to deterministic scoring,
  and enforcement is unchanged.
- Server/client model version mismatch aborts the round rather than
  mixing versions.
- Retraining with no new data does not degrade the promoted model.
- Prolonged node absence expires its registration and blocks its updates.

**Security-negative**

- Raw personal data never leaves a node: update payloads contain only
  tensors and non-identifying metadata, and a canary record planted in a
  node's local data appears in no update, log, metric or artifact.
- A malicious node cannot force an ALLOW: bounds plus robust aggregation
  reject the attempt, and model output alone never authorizes disclosure.
- A model cannot override, downgrade or suppress a critical block, tested
  by driving the model to its most permissive output while a critical
  rule is active.
- Model artifacts and updates contain no personal data or vault
  identifiers (payload inspection).
- An unregistered or impersonating node is rejected at mTLS and at
  registration validation.
- Replaying a previous round's update within a session is rejected.
- The FL service cannot read vault ciphertext or request plaintext: its
  credential grants access only to the agreed feature/update channel.

**Exit criteria / demo**

Run a two-node round in `docker-compose` and show the aggregated global
model update with per-node contributions, then prove locality by
inspecting an update payload for the canary record and finding nothing.
Then set the model's output to its most permissive and demonstrate that a
critical block is still enforced and a high-risk consent request still
produces its normal decision.

---

## Phase 12 --- Zero-Knowledge Verification

**Maps to:** `T049` (Verification request model), `T050` (ZK proof
interface), `T051` (IND-05 proof scenario)

**Goal:** a user can prove a property of their data --- age at least a
threshold, or an identity attribute --- to a verifier without revealing
the underlying value, and the acceptance is recorded without storing the
secret.

### Stack workstreams

| ID | Component | Work |
|---|---|---|
| W12.1 | `infra/migrations/0007_*` | `verification_request` (`T049`): verifier/application, claim type, requested predicate and public threshold, single-use nonce/challenge, expiry, subject commitment, status. `zk_proof_log`: request reference, circuit id and version, circuit hash, proof hash, verification result, verifier identity, timestamp. Neither table holds a witness, the underlying value, or a raw proof-of-identity number |
| W12.2 | `packages/zk` | circom circuits (`T050`) for the chosen predicates (age threshold from a date-of-birth commitment, identity attribute equality/range), with compiled artifacts pinned by circuit hash and a recorded trusted-setup transcript. Proving happens client-side in a WASM worker via snarkjs; the verification interface is a stateless `verifyProof(request, proof)` in the core |
| W12.3 | IND-05 scenario (`T051`) | End-to-end age verification: the date of birth stays in the vault as ciphertext (Phase 1), the client builds the witness in memory from the decrypted value only when the owner authorizes it, proving happens locally, and only the proof plus public inputs cross the boundary. The verifier learns the predicate result and nothing else |
| W12.4 | proof hygiene | The witness is never persisted, logged or sent; worker memory is released after proving; proof size and generation time are bounded by a documented budget; a failed proof returns a generic failure that does not distinguish which constraint failed, and cannot be used as a value-enumeration oracle |
| W12.5 | replay and subject binding | The request nonce is consumed single-use in Redis, expiry is enforced at verification time, public inputs include a subject commitment checked against the authenticated session, and the circuit version is verified --- so a proof from one request or one subject cannot be presented as another |

### Deliverables

- Migration `0007` with verification request and proof log tables.
- Circuits, pinned artifacts and recorded setup provenance.
- Client-side prover (WASM worker) and stateless core verifier.
- The end-to-end age-verification flow.
- Replay, expiry and subject-binding controls.

### Tests

**Normal**

- Age at or above the threshold proves and verifies; below the threshold
  fails verification.
- An identity-attribute predicate round-trips successfully.
- The proof log records circuit id, version, hash and result.
- A second verification request with a fresh nonce requires a fresh
  proof.
- The verifier sees only the predicate result and a session-bound subject
  commitment.

**Edge**

- Boundary dates: exactly at the threshold, one day before, leap-day
  births, and a birth date near a UTC/local date boundary.
- Expired request, unknown circuit version, mismatched circuit hash and
  malformed proof are each rejected explicitly.
- Proving failure (out of memory or worker crash) surfaces cleanly and
  leaves no partial state.
- A large but valid range predicate stays inside the documented proving
  time and size budget on the slowest supported client profile.
- Verification request deleted by retention behaves per policy, and the
  proof log entry remains explainable via its tombstone reference.

**Security-negative**

- The underlying value (date of birth or attribute) appears in no proof,
  request, log line, database column or network payload --- asserted by
  payload inspection and a log search, including the proving path.
- A proof generated for one request cannot be replayed into another
  (nonce binding), and one generated for subject A is rejected for
  subject B (commitment binding).
- Tampered proof, tampered public input, or a proof for a different
  circuit version fails verification.
- The verification endpoint does not leak which constraint failed, and
  repeated probing cannot distinguish "invalid proof" from "value does
  not satisfy the predicate" beyond the single boolean outcome.
- The verifier cannot reconstruct the underlying value from stored
  artifacts, and the proof log contains no witness material.
- Server-assisted proving is refused by design: a request that would send
  a witness or the underlying value to the core is rejected, because it
  would defeat the privacy claim (`D-013` blast-radius intent).
- Callers cannot enumerate valid verification requests or another
  subject's requests.

**Exit criteria / demo**

Prove age at least 18 from a vaulted date of birth and verify it, then
show the same request failing for a date below the threshold, show a
replayed proof and a mismatched-subject proof each rejected, and inspect
the network payload to show that only the proof and public inputs crossed
--- never the date of birth.

---

## Phase 13 --- Blockchain Audit Extension

**Maps to:** `T052` (Blockchain audit abstraction), `T053`
(Transaction recording), `T054` (Integrity verification)

**Goal:** audit history gains an external integrity anchor --- periodic
Merkle roots of the audit chain recorded on a chain --- so modification
becomes detectable from outside this database, without sensitive data
ever leaving it.

### Stack workstreams

| ID | Component | Work |
|---|---|---|
| W13.1 | `packages/chain` | `AuditAnchor` interface (`T052`) with three implementations: `noop` (default/off), `local_chain` (development, a local EVM node) and `remote_chain` (chain of record). Chain persistence is thereby separated from the core audit interface, and the core imports only the adapter interface --- the import-boundary check from Phase 7 is extended to chain clients |
| W13.2 | Merkle batching (`T053`) | Per-epoch batching of audit entry hashes into a Merkle tree; the batch root plus non-identifying metadata (epoch, count, range, previous root --- so anchors chain to each other) is what gets submitted. `blockchain_transaction` (migration `0008`) records tx hash, epoch, status, confirmation state and the locally stored copy of the same root. One anchor per epoch is enforced by a uniqueness constraint, making submission idempotent |
| W13.3 | integrity verification (`T054`) | `verifyAuditIntegrity(epoch \| record)` recomputes the Merkle path from the audit rows to the recorded root, confirms the anchor transaction and its confirmations, and verifies anchor chaining between epochs. It reports the first inconsistent record with expected versus actual values rather than a bare failure |
| W13.4 | failure isolation | Anchoring is best-effort and never on the disclosure path: a chain outage, unconfirmed transaction or bad nonce leaves enforcement, blocking and disclosure gating untouched. Anchors retry with backoff and expose a `pending` or `failed` state; a failed anchor is visible to the owner rather than silently absent |
| W13.5 | signer custody | Signer credentials come from configuration (KMS in production; a development key file outside the tree and gitignored), nonce management is single-writer, and the private key never appears in logs or artifacts. Chain id, contract address and deployment id are pinned in configuration |
| W13.6 | retention reconciliation | Retention deletion proceeds unchanged (`D-012`): on-chain artifacts are hashes only and carry no personal data, and the tombstone recorded in Phase 9 lets an auditor distinguish "deleted by policy" from "tampered". This is the deliberate resolution of the immutability tension and is recorded as `D-036` |

### Deliverables

- `AuditAnchor` interface with noop, local and remote adapters.
- Merkle batching with chained epoch anchors and transaction records
  (migration `0008`).
- Integrity verification across records and epochs with precise failure
  reporting.
- Failure isolation so the chain can never affect enforcement.
- Signer custody and pinned chain configuration.

### Tests

**Normal**

- A batch of N audit rows produces a root equal to an independently
  recomputed Merkle root.
- The anchor transaction is recorded and confirmed against the local
  development chain.
- A record's Merkle path verifies against the recorded root.
- Epoch chaining verifies: each anchor's previous root matches the prior
  epoch's root.
- Verification passes for a record whose epoch was anchored before a
  retention deletion and whose own record survives.

**Edge**

- An epoch with no rows is explicitly skipped rather than anchoring an
  empty root.
- A batch boundary landing exactly at the retention cutoff still verifies.
- A transaction left unconfirmed for a long period stays `pending`,
  retries, and later confirms once without creating a duplicate anchor.
- Submitting the same epoch twice is idempotent (uniqueness constraint).
- A chain reorg causes re-verification against the confirmed block rather
  than a false pass.
- Anchoring disabled by configuration makes verification report "not
  anchored", distinct from "verified".
- Records deleted by retention leave a verification result explained by
  the tombstone, not a dangling failure.

**Security-negative**

- No sensitive data reaches the chain: an assertion inspects the exact
  bytes submitted and confirms only roots, hashes and non-identifying
  batch metadata --- no ciphertext, plaintext, personal identifiers,
  full URLs, domain-to-user mappings or decision detail.
- A modified audit row breaks Merkle verification and is reported with
  the first inconsistent record named.
- Replacing the chain's data while rebuilding the local store does not
  pass verification, because anchor chaining and the locally stored roots
  must agree with the confirmed chain state.
- The signer key never appears in logs, artifacts, metrics or error
  output, and a missing or malformed credential fails the anchor rather
  than falling back to an unauthenticated submission.
- A chain outage, rejection or timeout cannot cause disclosure and cannot
  prevent a block from being enforced: with the chain down, decisions and
  disclosures behave identically (verified by a side-by-side run).
- An unauthenticated caller cannot trigger anchoring, change the chain
  configuration, or mark an anchor verified.
- On-chain anchoring cannot be used to confirm whether a given user has
  any audit history, because no identifier is submitted.

**Exit criteria / demo**

Anchor two epochs of audit rows to the local development chain, verify a
record by Merkle path and verify anchor chaining, then tamper with one
audit row and show verification naming the first inconsistent record.
Finally, stop the chain node, generate traffic, and show that decisions,
blocks and disclosure gating are unchanged while the anchor is reported
as pending rather than silently lost.

---

## Phase 14 --- End-to-End Security Scenarios

**Maps to:** `T055` (Safe request), `T056` (Sensitive request), `T057`
(Suspicious new domain), `T058` (Critical malicious domain), `T059`
(Force Allow), `T060` (External provider failure)

**Goal:** every security behavior built in Phases 0--13 is proven as a
whole-system scenario --- a real request traveling the full pipeline to a
correct decision, disclosure, alert or refusal --- so the guarantee is
demonstrated at the product boundary, not only in per-phase suites.

### Stack workstreams

| ID | Component | Work |
|---|---|---|
| W14.1 | `tests/e2e/` harness | Scenario runner that boots the real application in-process (the Phase 0--4 demo mechanism) and, where the browser is the boundary, drives the built extension over CDP (the `scripts/e2e-*` harness). One scenario = one reproducible script with named assertions |
| W14.2 | scenario fixtures | Deterministic fixture set: a known-good domain, a newly registered domain, a domain with a critical reputation signal, an offline provider, and a resident user with rules and consent pre-seeded. Reputation and age signals are injected, never fetched |
| W14.3 | `T055`--`T057` scenarios | Safe request ends in ALLOW with minimum disclosure and an audit row; sensitive financial request ends in ASK_USER, the user's choice is honored and audited; a new domain requesting sensitive data ends in BLOCK or WARN per rules with the full explanation surfaced |
| W14.4 | `T058` scenario | A critical reputation signal produces a hard BLOCK: no Force Allow control in the overlay, an override attempt refused server-side, an alert raised, and the audit row showing `override: true` on the refusal |
| W14.5 | `T059` scenario | An ordinary policy BLOCK overridden by Force Allow: authorization grant issued, exactly the approved fields disclosed, the override audited with owner, reason and decision linkage |
| W14.6 | `T060` scenario | With the reputation provider down, the decision carries explicit `unknown` signals and privacy-first uncertainty handling; no disclosure occurs that would not have occurred with complete information |

### Deliverables

- Six runnable, repeatable scenario scripts under `tests/e2e/`, wired
  into the verification command and CI.
- Deterministic fixture corpus with injected intelligence signals.
- A scenario report naming the decision, disclosure scope, alert and
  audit linkage for each scenario.

### Tests

The scenarios **are** the tests; each is written in the
Normal/Edge/Security-negative shape:

**Normal**

- `T055`: ALLOW path discloses only the approved fields and files one
  audit event linked to the decision.
- `T056`: ASK_USER surfaces to the owner, both outcomes (approve/deny)
  are audited, and no data moves before the choice.

**Edge**

- `T057`: rules land on the BLOCK/WARN boundary deterministically for
  identical inputs (replay twice, identical result).
- `T060`: partial provider failure (one provider up, one down) yields
  mixed fresh/unknown signals, not a wholesale downgrade or a crash.

**Security-negative**

- `T058`: the critical block offers no Force Allow control, the direct
  API override is refused with `critical_security_block`, and no grant
  is issued.
- `T059`: Force Allow cannot exceed the approved scope; a second use of
  the grant is refused as consumed.
- Every scenario asserts no plaintext, key material or full URL reaches
  logs or error responses.

**Exit criteria / demo**

Run the six scenarios as one command against a clean in-process core:
each prints its decision chain (origin → signals → rules → risk →
decision → disclosure/alert/audit) and the run is green, including the
refusals --- on this project a rejected request is the feature.

---

## Phase 15 --- Security Hardening

**Maps to:** `T061` (Threat-model review), `T062` (Dependency
security), `T063` (Input fuzzing), `T064` (Authorization review), `T065`
(Privacy review)

**Goal:** the system is attacked on paper and in harnesses before anyone
else does it --- every documented threat gets a named mitigation and a
named test, and the open privacy items deferred from earlier phases are
formally closed.

### Stack workstreams

| ID | Component | Work |
|---|---|---|
| W15.1 | threat-model review (`T061`) | One section per documented threat: extension compromise, backend compromise, malicious website, compromised reputation provider, API abuse, session theft, log leakage, policy bypass, authorization replay. Each records the attack path, the mitigation, and the test that proves it; gaps become tracked work items, not footnotes |
| W15.2 | dependency security (`T062`) | `pnpm audit` (or `npm audit`) gating in CI with a documented waiver list; unused dependencies removed; versions pinned per `AGENT.md`; advisories reviewed and dispositioned in writing |
| W15.3 | input fuzzing (`T063`) | Property-based fuzzing of the security-sensitive parsers: URL/origin normalization, domain handling, rule expressions, external provider responses, and request objects. Invariants: parsers never throw on untrusted input, never widen a value, and always reject with a named reason |
| W15.4 | authorization review (`T064`) | A route-by-route matrix: every vault, decision, disclosure and override path maps to its authorization requirement (session, device signature, grant, owner binding), each with a negative test proving the path fails closed without it |
| W15.5 | privacy review (`T065`) | Verified: no plaintext leakage (log assertions at the fd level, per the Phase 0 log-privacy mechanism), minimal telemetry, minimal external data, retention deletion with tombstones, federated data locality. This review also closes the three items earlier phases deferred here: the legal/incident hold versus automatic deletion, timing-correlation blurring for chain anchors, and the erasure implications of on-chain hashes. Outcomes are recorded as decisions in `DECISION.md` |

### Deliverables

- Threat-model document with per-threat mitigation and test traceability.
- CI-gated dependency audit with waiver list and advisory review notes.
- Fuzzing harness over the five parser families, wired into CI.
- Authorization matrix covering every access path, with negative tests.
- Privacy review record with the three deferred items dispositioned.

### Tests

**Normal**

- Every threat in `T061` names at least one passing test; the matrix is
  generated from the suite so drift is visible.
- The fuzz harness runs a fixed seed in CI and reports properties held.

**Edge**

- Fuzz inputs at boundary sizes (maximum URL, maximum rule nesting,
  maximum envelope body) are rejected or bounded, never truncated into
  a different meaning.
- A dependency waiver expires: the CI gate fails again when a waived
  advisory is superseded.

**Security-negative**

- Fuzzing finds no input that crashes a parser, widens an origin, or
  turns a rejection into a silent accept; any such finding is a defect.
- Every authorization path refuses without its prerequisite: no session,
  wrong owner, missing signature, replayed nonce, consumed or foreign
  grant --- each demonstrated, not assumed.
- The privacy review reruns the log-leakage and locality assertions
  against the final build, not a earlier revision.

**Exit criteria / demo**

Present the threat model and, for each threat, run the named test live.
Show the authorization matrix and demonstrate two arbitrary rows
refusing without credentials. Show the fuzz report clean at the pinned
seed, the dependency gate passing with its waiver list, and the privacy
review closing the three deferred decisions with `DECISION.md` updated.

---

## Phase 16 --- Final Prototype

**Maps to:** `T066` (Full end-to-end demo), `T067` (Documentation
synchronization), `T068` (Final security regression), `T069`
(Self-demonstration)

**Goal:** one command demonstrates the complete system --- from an
inbound website request to audited, policy-driven disclosure and
deletion --- and the documents, tests and implementation agree.

### Stack workstreams

| ID | Component | Work |
|---|---|---|
| W16.1 | full demo (`T066`) | A scripted, repeatable demo walking the whole chain: website → inbound request → origin extraction → domain history → classification → feasibility → privacy rules → risk → enforcement → optional Force Allow → vault disclosure → audit → retention/deletion. Built from the Phase 14 harness; no undocumented manual steps |
| W16.2 | documentation sync (`T067`) | Each of `AGENT.md`, `ARCHITECTURE.md`, `DECISION.md`, `PRD.md` and `TASKS.md` is checked statement-by-statement against the implementation; every drift is fixed in the doc or flagged as a decision; `TASKS.md` status is reconciled with the actual task states |
| W16.3 | final security regression (`T068`) | The complete suite runs: unit, integration, security-negative, the Phase 14 scenarios, the fuzz corpus and the extension bundle/manifest guards --- green in one run, with no known critical security defect open (`AGENT.md` Definition of Done) |
| W16.4 | self-demonstration (`T069`) | The demo runs on a clean checkout with only documented commands and configuration from `.env.example`; refusals are shown as prominently as successes; the run ends with the Definition-of-complete checklist from `TASKS.md` |

### Deliverables

- One-command full demo script and its transcript.
- Synchronized document set with reconciled task status.
- A single regression run covering every suite in the repository.
- The completed self-demonstration checklist.

### Tests

**Normal**

- The demo's every step asserts its own outcome; a step without an
  assertion is a defect in the demo.
- The regression run reproduces green from a clean checkout.

**Edge**

- The demo includes an empty-vault user, a fresh ruleset state and a
  provider outage segment, so it proves behavior at unset state too.

**Security-negative**

- The demo's refusal segments (tampered payload, replayed envelope,
  unregistered key, critical-block override, expired grant) run against
  the final build and still refuse.
- Documentation sync confirms no document promises a guarantee the test
  suite does not enforce.

**Exit criteria / demo**

`npm run verify && npm run demo` on a clean checkout: the full
scenario chain prints end to end, every refusal refuses, the complete
regression suite is green, and the six-point Definition of complete
from `T069` is checked off with pointers to the evidence.

---

## 5. Milestones M0--M7

| Milestone | Phases | Demoable state |
|---|---|---|
| **M0 --- Foundation** | Phase 0 | Clean checkout installs, containers start, migrations run, `pnpm verify` passes, CI green; bad configuration stops the process by name; contract schemas reject malformed and over-permissive payloads |
| **M1 --- Encrypted vault** | Phase 1 | A user's three entries exist as ciphertext with metadata in Postgres; decryption works in both runtimes; tampered blob, cross-owner read and key-material exposure attempts all fail visibly |
| **M2 --- Observation and intelligence** | Phases 2--4 | The extension observes page requests, derives origins from trusted context only, and the core returns classified facts plus freshness-annotated domain intelligence --- including the `unknown` and provider-failure paths |
| **M3 --- Policy and enforcement** | Phases 5--7 | A request is evaluated against versioned rules into ALLOW/WARN/BLOCK/ASK_USER with a full explanation; an approved disclosure releases exactly the authorized fields through one gateway; a replayed grant is refused; a critical block cannot be overridden even by calling the API directly; an unenforceable block is recorded as unenforced rather than claimed |
| **M4 --- Visibility and lifecycle** | Phases 8--9 | The owner manages vault, consent and rules from the dashboard with a risk preview before granting; recent requests, blocks and domain signals are inspectable with freshness; the audit chain verifies and reports a tampered row; retention deletes expired records and leaves a tombstone |
| **M5 --- Alerts and privacy-preserving AI** | Phases 10--11 | A critical block, an override and repeated attempts raise deduplicated alerts with a working acknowledge/resolve lifecycle; a two-node federated round completes with secure aggregation while raw data provably stays local, and the model drives risk but cannot change an enforcement outcome |
| **M6 --- Verification and external anchoring** | Phases 12--13 | Age at least 18 is proven from a vaulted date of birth and verified without the date crossing the network, with replay and subject-mismatch rejected; audit epochs are anchored to a chain, a tampered row is detected by Merkle verification, and a dead chain leaves enforcement untouched |
| **M7 --- Verified prototype** | Phases 14--16 | All six end-to-end security scenarios run green in one command, including the refusal paths; the threat model names a passing test per threat, the fuzz corpus holds at the pinned seed, and the dependency audit gates CI; one command demos the whole chain on a clean checkout while the complete regression suite and the synchronized document set confirm the prototype is done |

**Sequencing.** Phases 0 and 1 are strictly sequential. Phase 2 depends
only on the Phase 0 contracts, so extension work can proceed in parallel
with Phase 1 once W0.4 lands. Phases 3 and 4 are independent of each
other; both depend on the Phase 0 schemas and Phase 4's cache depends on
the Postgres/Redis environment from Phase 0. Phases 5, 6 and 7 are
strictly sequential because each consumes the previous phase's output
(rules -> decision -> disclosure). Phase 8's shell and non-policy screens
can start once the Phase 6 decision payload is frozen, but the policy and
request-detail screens need Phases 5--7 live. Phase 9 needs Phase 7's
audit writes, so it follows Phase 7 rather than Phase 8. Phase 10 needs
Phases 6--7 (the decision, override and disclosure signals it alerts on)
and Phase 8 for its surfaces. Phase 11 needs Phase 6 (the risk features
that become training inputs) and its own Python toolchain, which is
pinned at the start of that phase. Phase 12 needs Phase 1 (a vaulted date
of birth) and the Phase 5/6 policy that decides who may request
verification. Phase 13 needs Phase 9's chain and viewer. Phases 11, 12
and 13 are mutually independent and may run in parallel once Phase 9 is
done.

**Phases 14--16 continue from M6 and are strictly final.** Phase 14
runs after everything it exercises, so it follows Phases 0--13 (its
browser scenarios additionally need the Phase 8 dashboard and the
extension pipeline). Phase 15 runs after Phase 14 so the threat model
can cite the scenario harness as evidence. Phase 16 is last by
definition: it demonstrates the completed system and reconciles the
documents with the implementation.

---

## 6. Traceability matrix (Phases 0--16)

| IND-05 requirement | PRD feature | Tasks | Phase | Components | Test suites |
|---|---|---|---|---|---|
| Personal encrypted data vault | F01 | T004--T007 | 1 | `packages/crypto`, `services/core` vault routes, `infra/migrations` | `packages/crypto` unit; vault integration; security-negative matrix |
| Secure data sharing (disclosure path) | F12 | T028--T031 | 7 | `authorizeDisclosure()`, release, grants | gateway suite; disclosure security-negative matrix |
| User-controlled consent | F02 | T022, T036 | 5, 8 | user-rule API, dashboard policy UI | `services/core/src/rules.test.ts` (user-rule API); dashboard policy tests (Phase 8) |
| Decision enforcement | F10 | T025, T031 | 6, 7 | decision engine, extension enforcement + attestation | decision suite; enforcement tests |
| Force Allow | F11 | T027 | 6 | Force Allow flow + audit | `services/core/src/force-allow.test.ts` |
| Decision explanation | --- (F10 support) | T026 | 6 | explanation payload | `packages/rules/src/decide.test.ts` (explanation section) |
| Inbound request detection | F03 | T008, T009 | 2 | `apps/extension` observation | extension unit + Playwright |
| Origin identification | F04 | T010 | 2 | origin normalizer | hostile-input fixture corpus |
| Domain intelligence | F05 | T014--T018 | 4 | `packages/domain-intel`, Redis cache | provider, cache and failure suites |
| Requested-data classification | F06 | T011 | 3 | `packages/rules` classify | classification suite |
| Feasibility analysis | F07 | T012 | 3 | `packages/rules` feasibility | feasibility suite |
| Data minimization | --- (F12 prerequisite) | T013 | 3 | `packages/rules` minimize | minimization suite |
| Privacy risk scoring | F08 | T024 | 6 | `packages/risk`, `RiskIntelligence` seam | `packages/risk/src/assess.test.ts` incl. uncertainty cases |
| Deterministic rule evaluation | F09 | T019--T023 | 5 | `packages/rules` evaluator, ruleset v1 | `packages/rules/src/evaluate.test.ts` |
| Access audit | F13 | T038, T039 | 9 | `packages/audit`, viewer API | audit model + chain verification tests |
| Automatic history deletion | F14 | T040 | 9 | retention worker, tombstones | retention suite incl. boundary and retry |
| Data leakage alerts | F15 | T041--T043 | 10 | alert engine, dashboard + extension surfaces | alert engine, dedupe and lifecycle suites |
| Federated AI | F16 | T044--T048 | 11 | `services/fl`, `RiskIntelligence` model adapter | FL round, locality and poisoning suites |
| Zero-knowledge verification | F17 | T049--T051 | 12 | `packages/zk`, core verifier | circuit, replay and witness-leak suites |
| Blockchain audit history | F18 | T052--T054 | 13 | `packages/chain`, Merkle batching | anchoring, integrity and isolation suites |
| Repository/tooling foundation | --- | T001--T003 | 0 | monorepo, config loader, `packages/schemas` | contract and configuration suites |

---

## 7. Definition of Done (per-phase gate)

Restated from `AGENT.md` as the gate a phase must clear before its tasks
are marked complete in `TASKS.md`:

1. Implemented, and integrated with the phases before it.
2. Every trust boundary the phase touches is validated by a shared
   schema.
3. Normal behavior tested.
4. Edge cases tested: empty, missing, malformed, boundary, conflicting
   and unavailable input.
5. Security-negative cases tested, demonstrating prohibited behavior is
   rejected.
6. No known critical security defect remains open.
7. Fail-closed behavior verified on every failure path the phase owns.
8. Documentation updated where behavior or structure changed
   (`DECISION.md` entries from section 9, and `TASKS.md` status).
9. The phase's exit demo runs on a clean checkout without undocumented
   manual steps.

A phase is not complete because its code compiles or its UI renders.

---

## 8. Risks and open decisions (Phases 0--16)

| Risk | Impact | Handling in this plan |
|---|---|---|
| MV3 cannot block every mechanism; blocking `webRequest` is unavailable | A "block" could be reported where disclosure was not actually prevented | Enforcement is described honestly per mechanism; unenforceable mechanisms are surfaced as warnings marked "not enforceable" (W2.4), and real enforcement is completed by `T031` in Phase 7 |
| MV3 service worker suspension interrupts an in-flight decision | Missed or delayed decision on a request the user is waiting for | Observation state is persisted to extension storage; `chrome.alarms` re-arms work; the overlay renders a definite state rather than hanging |
| IDNA/homoglyph and private-origin edge cases in origin normalization | Trusting a visual look-alike, or misclassifying an internal origin | Dedicated normalization rules and a hostile fixture corpus (W2.3, Phase 2 security-negative tests) |
| Redis mistaken for an authority | Stale or forged cache data influencing a decision | Cache-only role stated explicitly, freshness/staleness always carried to the consumer, Postgres is the only store of record (W4.3, section 9 D-026) |
| Dev KEK shim reaching a shipped build | Key custody assumption silently weakened | The shim lives outside the app tree in `infra/kms-dev/`, is gitignored, and `KEY_PROVIDER` validation refuses non-development environments; a real KMS implementation is required before any deployment phase |
| External provider cost, rate limits and terms | Intelligence unavailable or expensive at volume | Timeout/retry/rate-limit budgets, cache-first reads, pluggable providers, and an explicit `unknown` result path (W4.4) |
| Local-first ciphertext versus browser storage quotas | Silent data loss or empty-looking vault | Explicit quota and unavailable states in the extension (W2.6), and metadata in Postgres records that a local entry exists even when its blob cannot be read |
| Three consumers (extension, core, dashboard) drifting from one schema package | Trust boundaries validating different shapes | One schema package, JSON Schema emission for Fastify, and contract tests that fail when a consumer diverges (W0.4, section 2.4) |
| Contract mappings mis-classify a request | Wrong categories driving a later decision | Classification returns the producing mapping, is deterministic, and its corpus is reviewed as test data (W3.1) |
| Confusion between "unknown" and "safe" in UI or scoring | Users and later rules over-trust missing data | `unknown_reason` is mandatory in the signal envelope; a test asserts an all-`unknown` set is not equivalent to lowest risk (Phase 4) |
| User rules producing surprising or contradictory decisions | A user could unintentionally weaken their own protection, or two rules could disagree | Total ordering by `(priority, rule_id)`, most-restrictive resolution with a `conflict` flag, a conflict preview before saving, and a critical class users cannot assign (Phase 5) |
| Force Allow becoming a de facto bypass | The override path could erode the protection it is meant to be an exception to | Critical rules are non-overridable server-side (not merely hidden in the UI), grants are scope-limited, single-use and expiring, the override is audited, and it never persists into stored rules (Phase 6, D-030) |
| Authorization grant replay, or use after consent revocation | Disclosure after the owner withdrew permission --- the most serious possible failure | Single-use consumption in Redis, full revalidation at disclosure time, and explicit concurrency plus revoke-mid-flight tests (Phase 7, D-030) |
| Enforcement honesty depends on extension attestation | A "blocked" record could overstate protection | Only attested blocks are recorded as enforced; unattested ones are stored as unenforced and surfaced as "not enforceable" warnings (Phase 7, D-025) |
| The dashboard re-centralizing plaintext | A control surface quietly becoming the second copy of the vault that D-013 exists to prevent | Client-side encryption before upload, reveal only behind an explicit gesture plus re-authentication, no third-party scripts or telemetry, strict CSP (Phase 8, D-032) |
| Audit hash chain is tamper-evident only inside this database | An attacker with full database control could rebuild the chain, so it detects modification but not wholesale replacement | Accepted for Phases 5--9 and recorded as an open item: external anchoring is Phase 13's subject, and until then the chain's guarantee is scoped to modification detection |
| Retention deletion versus evidence needed during an incident | Automatic deletion could remove records someone is actively reviewing | Windows are configuration-driven rather than hard-coded, deletions leave tombstones, and a legal/incident hold remains an open decision for the Phase 15 privacy review |
| SSE stream crossing session boundaries | Live decisions and alerts are the most sensitive stream in the dashboard | The stream is authenticated per session and tested for cross-session subscription attempts (Phase 8) |
| Audit volume growth versus query performance | Slow review screens and growing storage as history accumulates | Bounded pagination, indexed filters, and retention from the start rather than after the fact (Phases 8--9) |
| Federated update poisoning | A participating node could steer the global model toward permissive scoring | Payload bounds validation, robust aggregation (trimmed mean/median), clipping plus noise, and the fact that model output alone can never authorize disclosure (Phase 11, D-034) |
| Anomaly detector false positives | Alerts the owner learns to ignore, which is worse than no alerts | Thresholds tuned against a benign baseline, dedupe by fingerprint, alerts remain advisory and never trigger automatic enforcement (Phases 10--11) |
| Model drift or an over-trusted model | Silent degradation of risk quality, or a model creeping toward authority | Versioned artifacts, held-out validation before promotion, audited promotion with rollback, model influence labeled in the explanation, deterministic engine authoritative (Phase 11, D-017) |
| Federated node identity and topology left ambiguous | Unclear who participates, and in production, unclear whose data is in scope | Node registration with operator-controlled credentials, expiry for absent nodes, two simulated nodes in development; production topology is an open decision for the deployment phase (Phase 11) |
| ZK trusted-setup provenance | A compromised or unknown setup would invalidate every proof | Circuit hash and setup transcript pinned in configuration, mismatch fails startup, setup provenance recorded with the circuit version (Phase 12, D-035) |
| Proving cost on low-end clients | Verification unusable on a phone browser, pushing users toward unsafe shortcuts | Circuit size budget, WASM worker proving, documented performance target on the slowest supported profile; server-assisted proving is rejected because it would break the privacy claim (Phase 12) |
| Proof replay or subject substitution | Proving one property could be reused as another person's or another request's proof | Single-use nonce, expiry, circuit-version pinning and a session-bound subject commitment checked at verification (Phase 12) |
| On-chain metadata is public by nature | An observer can see *that* a system anchored a batch and when, though not what it contained | Only roots, counts and epoch ranges are submitted, no identifiers; fixed-cadence or padded batches to blur timing correlation remains an open item for the Phase 15 privacy review (Phase 13, D-036) |
| Chain cost, availability and finality | Anchoring could fail, stall or cost more than expected | Local development chain, best-effort anchoring with retry and visible pending state, confirmation waiting before "anchored", and no dependency of enforcement on the chain (Phase 13) |
| Retention versus anchored hashes | Deleted records leave permanent hashes on a public chain | Deliberate and recorded: hashes carry no personal data and tombstones explain deleted ranges (`D-036`); the erasure implications are reviewed in Phase 15 |
| Signer key custody for anchoring | A leaked signer key would let an attacker forge anchors | Credentials from configuration (KMS in production, gitignored development key file outside the tree), single-writer nonce management, no key material in logs or artifacts, rotation supported (Phase 13) |
| Python/Flower toolchain pinned late | Toolchain surprises at the start of Phase 11 | Acknowledged and explicit: Phase 0 fixes TypeScript tooling only; the Python toolchain is chosen and pinned at the start of Phase 11, and this plan does not pretend to know it earlier |

---

## 9. Decisions to record in `DECISION.md`

`AGENT.md` requires that a new major architectural assumption is recorded
as a decision rather than introduced silently. The following entries
should be added to `DECISION.md` when Phase 0 starts. Identifier numbers
continue from `D-020`.

| Proposed ID | Decision | Rationale | Consequence |
|---|---|---|---|
| D-021 | Adopt the stack in section 2.1: Next.js + React + TypeScript dashboard, MV3 TypeScript extension, Node.js + Fastify + TypeScript security core, PostgreSQL, Drizzle, Zod, Redis, and Python + Flower + PyTorch for federated learning | One typed language across the enforcement path keeps shared schemas honest; Python is required only where ML tooling demands it | Implementation is fixed per phase; changing a layer is itself a decision. `T001`'s separation of extension, dashboard, security core, shared schemas, tests and documentation is satisfied by the monorepo layout in section 2.2 |
| D-022 | Local-first vault posture: ciphertext for sensitive categories is held locally, Postgres stores metadata, policy, consent and wrapped-key references | Implements `D-013` and `ARCHITECTURE.md` section 5.9: the server must not become an implicit plaintext copy of the vault | The extension must handle local storage quotas and availability states; server-side reads consume metadata only |
| D-023 | Zod schemas in `packages/schemas` are the single source of truth for every trust boundary; wire format is JSON `snake_case` matching the documented field vocabulary | `AGENT.md` requires explicit schemas for security-sensitive objects; one definition prevents boundary drift | Hand-written duplicate types are a defect; contract tests gate schema changes |
| D-024 | Envelope encryption with AES-256-GCM, per-entry DEK wrapped by a `KeyProvider`, blob format `[version][nonce][ciphertext+tag]`, AAD binding blob identity, and Node/WebCrypto parity | Implements `T005`/`T006` and keeps key material separate from payloads | Rotation and KMS migration happen behind the provider interface; the development shim is never deployable |
| D-025 | MV3 enforcement is best-effort by mechanism: `declarativeNetRequest` for network-level blocks, with unenforceable mechanisms surfaced as warnings marked "not enforceable" | The platform cannot block all mechanisms; claiming otherwise would misrepresent protection (`D-010`) | Enforcement claims in UI and documentation are scoped per mechanism, completed by `T031` |
| D-026 | Redis is a cache and ephemeral coordination store only (intelligence freshness, rate limits, single-flight, later single-use authorization grants); Postgres holds the only durable state | Prevents a cache failure or stale entry from influencing an enforcement outcome | Cache misses are always resolved upstream; no durable record may exist only in Redis |
| D-027 | Adopt a workspaces monorepo with per-layer packages and an import-boundary rule | Delivers `T001` boundaries as enforceable structure rather than convention | Cross-layer imports fail CI; each package's public surface is explicit. Amended during implementation to npm workspaces without an orchestrator (DEV-03) |
| D-028 | Domain intelligence signals carry mandatory `source`, `retrieved_at`, `freshness` and `unknown_reason`; absence of data is never evidence of trust | Implements `D-006`, `D-018` and `ARCHITECTURE.md` section 9 | Consumers must handle `unknown` explicitly; no default-benign signal values exist |
| D-029 | Rules and user policy are versioned data with a recorded `ruleset_version` and `policy_version`, and a user rule can never carry the critical override class | Implements `T019`, `T022`, `T023` and the deterministic precedence required by `D-009` | Every decision is reproducible from its recorded versions; rule changes are audited; critical classification is system-owned |
| D-030 | Disclosure requires a short-lived, single-use, scope-bound authorization grant that is revalidated at disclosure time against current policy and consent | Implements `T028`--`T030` and `D-010` | Grants expire, replay is rejected, and revocation takes effect mid-flight; no disclosure path may skip revalidation |
| D-031 | Audit records are append-only and hash-chained, with immutability enforced by database permissions, and are removed only by the retention role under policy with a tombstone | Implements `F13`, `F14` and `D-012` | Tampering is detectable within the database; because external anchoring is not yet in place, the chain does not survive total database replacement --- recorded as an open item in section 8 |
| D-032 | The dashboard is a control and visibility surface only: client-side encryption, reveal behind an explicit gesture plus re-authentication, and no third-party scripts or telemetry | Extends `D-013`'s server-blast-radius intent and pre-empts the `T065` privacy review | Dashboard features may not require sending plaintext or keys to the server; adding telemetry is itself a decision |
| D-033 | Alerts are advisory records over immutable security facts, with a deduplicated fingerprint and an audited acknowledge/resolve/reopen lifecycle that never edits the decision, assessment or audit rows behind them | Implements `T041`--`T043`; `ARCHITECTURE.md` section 5.11 requires audit records to stay intact | An alert transition cannot rewrite history; an alert engine failure cannot alter an enforcement outcome |
| D-034 | Federated learning is advisory only: secure aggregation, clipping and noise, robust aggregation, and raw data that never leaves a node. Model output may inform risk but can never by itself authorize disclosure or override a critical rule | Implements `F16`, `D-014` and `D-017` | A model change cannot change enforcement on its own; participation requires an operator-controlled node credential and a versioned, rollback-capable artifact |
| D-035 | Zero-knowledge verification uses pinned circom circuits with a recorded trusted setup, client-side proving, and a stateless server verifier bound to a single-use request nonce and a session-bound subject commitment | Implements `F17`, `T049`--`T051`; `PRD.md` gives proving age without exposing date of birth as the example scenario | Only a proof and public inputs cross the boundary; server-assisted proving is refused by design because it would require transmitting the witness |
| D-036 | On-chain audit anchoring submits only Merkle roots and non-identifying batch metadata, is best-effort and never on the enforcement path, and does not change retention: records are still deleted under policy, with tombstones explaining deleted ranges | Implements `F18` and reconciles it with `D-012`'s temporary-retention requirement | Hashes remain on chain after the records are deleted, which carries no personal data but does limit erasure guarantees --- reviewed again in Phase 15 |

---

## 10. Implementation status: Phases 0--4

This section records what is actually built in this repository, so a reader can
tell the plan apart from the code. It is updated as phases land; Phases 7--16 are
planned but not implemented.

### 10.1 Delivered

| Phase | Delivered | Verified by |
|---|---|---|
| 0 | npm-workspaces monorepo, base TypeScript config split between the core and the DOM-typed extension, `packages/schemas` holding every boundary contract as Zod, the config loader with fail-closed validation, `infra/categories.json`, migration `0001_init.sql`, CI workflow, secret scan | `config.test.ts`, `contracts.test.ts`, `scripts/tests/tests/security/*` (all suites centralized under `scripts/tests/`) |
| 1 | `packages/crypto` blob format v1 with AAD binding and Node/WebCrypto parity, `KeyProvider` with a dev-shim and a refusing KMS stub, Drizzle schema plus SQL migration with row-level security, memory and Postgres repositories, vault routes | `crypto.test.ts`, `core.test.ts`, `secrets-and-migrations.test.ts` |
| 2 | MV3 manifest with least privilege, origin/host normalisation in `packages/schemas`, page-hook and content-script observation, decision overlay, local-tier store, device-signed request envelopes shared by both runtimes, core-side verification with a device key registry and nonce store | `extension.test.ts`, `envelope.test.ts`, `device-auth.test.ts`, `extension-bundle.test.ts` |
| 3 | Data-driven classification registry and mappings, feasibility assessment, minimisation analysis, `POST /api/analyze` returning facts and no decision | `rules.test.ts`, `core.test.ts` |
| 4 | Provider registry (RDAP, DNS, certificate history, reputation), signal envelopes with mandatory freshness and `unknown_reason`, freshness cache with Redis and in-process implementations, retry/timeout/rate-limit/circuit-breaker policy | `domain-intel.test.ts`, `core.test.ts` |
| 5 | Rule schema and typed condition tree, deterministic evaluator with total `(priority, rule_id)` ordering, most-restrictive conflict resolution, `unevaluated` reporting, ruleset v1 as checksummed data, critical-rule registry, owner policy store with versioned epochs, and the owner-scoped user-rule API with evaluator-faithful conflict preview, expiry and per-change audit | `packages/rules/src/evaluate.test.ts` (evaluator, ruleset integrity, escalation negatives), `decisions.test.ts`, `services/core/src/rules.test.ts` (user-rule API) |
| 6 | Deterministic risk scoring over the named constant factor table with non-zero unknown floors and uncertainty raising, advisory `RiskIntelligence` seam that may only raise a score, decision-engine escalation ladder (risk escalates, rules stay authoritative) with structural critical-block marking, decisions carrying their judged categories, Force Allow issuing single-use scope-limited grants bound to the decision and policy version, override audit events under the owner actor with the stated reason, migration `0002` with `decision`, `privacy_risk_assessment` and `audit_event` tables, and `GRANT_SECRET` required in production | `packages/risk/src/assess.test.ts` (bands, uncertainty, advisory, negatives), `packages/rules/src/decide.test.ts` (ladder, four outcomes, critical structure, conflicts, explanation), `services/core/src/force-allow.test.ts` (grants, refusal, audit), `secrets-and-migrations.test.ts` (migration 0002), `config.test.ts` |
| 7 | The vault gateway as the single disclosure path: `authorizeDisclosure()` revalidating the grant, owner binding, disclosure-time consent state and policy version before releasing the approved minimum; refusals audited under the owner's chain with the named reason; single-use grants restorable when a release fails for curable reasons; server-tier release decrypting through the `KeyProvider` under the client's recorded seal binding (`pv_seal_data_id`); HMAC release receipts; `getServerTierEntry` on both repositories; the `/api/disclosure` route composing the owner's current policy version; the T029 import-boundary guard on runtime imports with the composition root as the sole composer; extension enforcement planning plus attestation records; migration `0003` with attestation columns and the disclosure-refusal audit channel | `services/core/src/gateway/authorize.test.ts` (minimal disclosure, revalidation, security negatives, receipts), `services/core/src/disclosure.test.ts` (HTTP path, refusals audited), `extension.test.ts` (enforcement planning, attestation), `import-boundaries.test.ts` (T029 guard), `secrets-and-migrations.test.ts` (migration 0003) |
| 8 | The dashboard as a first-party SPA served by the core: signed httpOnly cookie sessions with logout revocation and a double-submit CSRF guard (W8.1); the owner-scoped paginated decisions list (T034); the shared `ConsentStore` backing both the consent API (list, risk preview, grant, revoke, all audited) and the gateway's disclosure-time check so the two cannot disagree (W8.5); owner reveal through `revealForOwner` on the gateway - re-auth confirmed, audited, honest `local_data_unavailable` for local-tier entries (T033); the per-owner `DecisionEventBus` with an SSE stream authenticated by the session (W8.3); the request-detail view contract; the static shell with a strict first-party CSP, `frame-ancestors 'none'` and traversal-safe asset serving (W8.8); `packages/ui` verdict tokens shared by the overlay and the dashboard (W8.7); `SESSION_SECRET`/`DASHBOARD_OWNER_SECRET`/`DASHBOARD_OWNER_USER_ID` required in production | `services/core/src/dashboard.test.ts` (session, CSRF, list, consents, reveal, stream scoping, CSP, traversal), `packages/ui/src/verdict.test.ts`, `config.test.ts` (web-secret refusals), `apps/dashboard/src/main.test.ts` (no innerHTML, no localStorage, first-party bundle guard) |

`npm run demo` walks the Phase 0--4 exit demos in one runnable transcript, and
`npm run verify` runs typecheck, the full suite, the extension bundle guard and
the secret scan. The Phase 5 exit demo (allow, ask_user, block, critical block;
rejected critical-class user rule; shadow-attempt preview) is covered by the
route and evaluator suites pending its scripted walkthrough. The Phase 6 exit
demo (four explained decisions, a High and a Critical factor breakdown, an
audited Force Allow with its grant, and a refused Force Allow on a critical
block called directly against the API) is covered by the decision, risk and
override suites pending its scripted walkthrough. The Phase 7 exit demo (an
ASK_USER approval disclosing exactly one field, a replayed grant refused, consent
revoked mid-flight refused, a network-level block carrying its attestation, and a
critical-block override refused) is covered by the gateway, disclosure and
override suites pending its scripted walkthrough. The Phase 8 exit demo (login
with cookie + CSRF, the overview receiving a live decision over SSE, a full
request explanation, grant-then-revoke consent with its audit rows, a re-auth
gated reveal, and an unknown domain rendered as unknown-with-reason) is covered
by the dashboard, gateway and consent suites plus the live browser walkthrough
recorded with the phase delivery.

### 10.2 Deviations from the plan, and why

| ID | Planned | Actual | Reason and effect |
|---|---|---|---|
| DEV-01 | Extension-only WebCrypto transport | Signed envelopes live in `packages/envelope`, shared by the extension and the core | One canonical encoding cannot drift between signer and verifier; the package is WebCrypto-only, so it still runs in a browser worker. The import-boundary test permits exactly this one extra dependency for the extension |
| DEV-02 | PostgreSQL and Redis required for local development | Each has an in-process fallback used when its URL is unset | Docker is not available in the development environment and the plan's own goal is a stack that runs on a bare checkout. `DATABASE_URL` unset selects the Postgres-shaped memory repository rather than skipping it |
| DEV-03 | pnpm + Turborepo (D-027) | npm workspaces, no orchestrator | pnpm is not installed in the development environment and the workspace is small enough that the orchestrator would add configuration without removing work. `D-027` is amended to npm workspaces; revisit if build times grow |
| DEV-04 | "Zod-validated envelope on both ends" for every request | Envelopes are verified wherever a device-signed body is accepted. GET requests carry no signature | The signed payload travels inside the envelope, so a GET has nothing to sign. Signing a canonical request line for reads is deferred to the phase that introduces real session authentication; until then reads rely on the session, which is already the case for the dashboard |
| DEV-05 | Device registration implied but not scheduled | `POST /api/devices` exists only while the development header session is in use, and binds a key to the authenticated user; re-registering a key id under another user or public key is refused | Verification would otherwise be vacuous (an unregistered key must be refused, so no signed request could ever succeed). Real authentication replaces the route and the provider together |
| DEV-06 | W8.1 names Next.js App Router for the dashboard | A zero-dependency TypeScript SPA served by the core itself (esbuild bundle, same discipline as the extension), with the cookie/CSRF/SSE/CSP contracts of W8.1/W8.8 unchanged | Next.js would add a second toolchain and a component ecosystem to a repo whose verify pipeline is `tsc` + vitest, while weakening W8.8: a framework hydration pipeline is harder to prove third-party-free than a bundle the repo builds and scans itself. The product contract (authenticated shell, server-validated data, no tokens in `localStorage`, strict CSP) is delivered verbatim; revisit if the dashboard grows server-rendered surfaces |

### 10.3 Open items at the end of Phase 4

- Step-up re-authentication before a forced override, and unlock policy for
  sensitive reveals, belong to the dashboard and enforcement phases.
- `encryption_key` and `vault_entry` reads return metadata only; there is still
  no route that returns a blob, which is correct until the Phase 7 gateway exists.
  Two consequences are deliberate and temporary: a locked account has no recovery
  path, and key rotation cannot verify that a re-wrapped entry still decrypts
  until the gateway's revalidation exists.
- The extension posts to `/api/decisions/evaluate` and `/api/decisions/override`,
  which arrive in Phases 6 and 7. Until then those calls return 404, and the
  extension degrades to an unenforced warning rather than claiming a block.
- The nonce store is in-process. A multi-instance deployment needs the Redis
  implementation behind the same interface, because replay protection that holds
  per process does not hold across a deployment.

### 10.4 Decisions taken during implementation

The following are new, and belong in `DECISION.md` alongside `D-020`. They are
listed here because the register itself is a separate document.

| Proposed ID | Decision | Rationale | Consequence |
|---|---|---|---|
| D-037 | A signed request carries its payload inside the envelope (`{ signed: { ... } }`) rather than beside it in a header | A header-duplicated body is capped by the server's header size limit and leaves a second copy of the payload that no signature covers | The route acts on exactly the value the signature covered; large blobs are unaffected; the wrapper is validated as a strict object so a second copy is a validation error |
| D-038 | A device key is bound to the user who registered it, and verification requires that binding to match the session | A valid signature from a key registered to somebody else is not evidence about this session | Key ids cannot be moved between users; registration refuses a conflicting key id rather than overwriting it |
| D-039 | Verifying a request is a precondition of reading its body: the payload the route validates is the payload the signature covered | Validating a differently-shaped body after verifying a signature would make verification decorative | Every device-facing route authenticates before parsing, never the reverse |

---

## Appendix A --- Task coverage in this revision

Every task identifier for Phases 0--16 is listed below with the phase and
the workstreams that own it, so no identifier is silently dropped or
invented. Identifiers not listed here would be out of scope for this
revision and remain owned by `TASKS.md`.

| Task | Title | Phase | Where |
|---|---|---|---|
| T001 | Repository structure | 0 | W0.1, W0.6, section 2.2, D-027 |
| T002 | Configuration and secrets | 0 | W0.2, Phase 0 tests |
| T003 | Shared security schemas | 0 | W0.4, section 2.4 |
| T004 | Vault data model | 1 | W1.1, W1.2 |
| T005 | Encryption layer | 1 | W1.3, Phase 1 security-negative tests |
| T006 | Key management boundary | 1 | W1.4, Phase 1 tests |
| T007 | Vault CRUD | 1 | W1.5, Phase 1 tests |
| T008 | Minimal extension shell | 2 | W2.1 |
| T009 | Request observation | 2 | W2.2, Phase 2 tests |
| T010 | Trusted origin extraction | 2 | W2.3, Phase 2 security-negative tests |
| T011 | Requested-data classification | 3 | W3.1 |
| T012 | Request feasibility engine | 3 | W3.2 |
| T013 | Data minimization analysis | 3 | W3.3 |
| T014 | Domain intelligence provider interface | 4 | W4.1, W4.2 |
| T015 | Domain creation/age intelligence | 4 | W4.2, Phase 4 tests |
| T016 | Domain history signals | 4 | W4.2 |
| T017 | Intelligence cache | 4 | W4.3, Phase 4 tests |
| T018 | Provider failure handling | 4 | W4.4, Phase 4 security-negative tests |
| T019 | Rule schema | 5 | W5.1, W5.3, D-029 |
| T020 | Rule evaluator | 5 | W5.2, Phase 5 tests |
| T021 | Privacy-first defaults | 5 | W5.3 |
| T022 | User rules | 5 | W5.4, Phase 5 security-negative tests |
| T023 | Critical security rules | 5 | W5.5, W5.6, Phase 5 security-negative tests |
| T024 | Risk assessment | 6 | W6.1, W6.2, W6.6 |
| T025 | Decision engine | 6 | W6.3 |
| T026 | Decision explanation | 6 | W6.4, Phase 6 tests |
| T027 | Force Allow | 6 | W6.5, Phase 6 security-negative tests |
| T028 | Pre-disclosure enforcement | 7 | W7.1 |
| T029 | Vault gateway | 7 | W7.1, W7.2, D-030 |
| T030 | Limited disclosure | 7 | W7.2, W7.3, Phase 7 security-negative tests |
| T031 | Block enforcement | 7 | W7.4, W7.5 |
| T032 | Dashboard foundation | 8 | W8.1 |
| T033 | Vault interface | 8 | W8.2 |
| T034 | Security overview | 8 | W8.3 |
| T035 | Request detail view | 8 | W8.4 |
| T036 | Policy management | 8 | W8.5 |
| T037 | Domain view | 8 | W8.6 |
| T038 | Audit event model | 9 | W9.1, W9.5, D-031 |
| T039 | Audit viewer | 9 | W9.2 |
| T040 | Retention policy | 9 | W9.3, W9.4, Phase 9 tests |
| T041 | Alert engine | 10 | W10.1, W10.2, D-033 |
| T042 | Alert dashboard | 10 | W10.3 |
| T043 | Alert lifecycle | 10 | W10.4, W10.5, Phase 10 security-negative tests |
| T044 | Privacy risk AI interface | 11 | W11.1 |
| T045 | Federated learning foundation | 11 | W11.2, W11.3, D-034 |
| T046 | Federated risk learning | 11 | W11.3, W11.5 |
| T047 | Federated anomaly detection | 11 | W11.3, Phase 11 tests |
| T048 | Secure aggregation | 11 | W11.4, Phase 11 security-negative tests |
| T049 | Verification request model | 12 | W12.1, D-035 |
| T050 | ZK proof interface | 12 | W12.2, W12.4 |
| T051 | IND-05 proof scenario | 12 | W12.3, W12.5, Phase 12 security-negative tests |
| T052 | Blockchain audit abstraction | 13 | W13.1 |
| T053 | Transaction recording | 13 | W13.2, W13.4, D-036 |
| T054 | Integrity verification | 13 | W13.3, Phase 13 security-negative tests |

**Planned in the appended Phases 14--16.** Listed individually so
coverage remains mechanically checkable; the workstreams that own each
identifier are in the phase blocks above:

| Task | Title | Phase | Where |
|---|---|---|---|
| T055 | Safe request | 14 | W14.3, Phase 14 Normal tests |
| T056 | Sensitive request | 14 | W14.3, Phase 14 Normal tests |
| T057 | Suspicious new domain | 14 | W14.3, Phase 14 Edge tests |
| T058 | Critical malicious domain | 14 | W14.4, Phase 14 security-negative tests |
| T059 | Force Allow | 14 | W14.5, Phase 14 security-negative tests |
| T060 | External provider failure | 14 | W14.6, Phase 14 Edge tests |
| T061 | Threat-model review | 15 | W15.1, Phase 15 Normal tests |
| T062 | Dependency security | 15 | W15.2, Phase 15 Edge tests |
| T063 | Input fuzzing | 15 | W15.3, Phase 15 security-negative tests |
| T064 | Authorization review | 15 | W15.4, Phase 15 security-negative tests |
| T065 | Privacy review | 15 | W15.5, Phase 15 security-negative tests |
| T066 | Full end-to-end demo | 16 | W16.1, Phase 16 Normal tests |
| T067 | Documentation synchronization | 16 | W16.2, Phase 16 security-negative tests |
| T068 | Final security regression | 16 | W16.3, Phase 16 Normal tests |
| T069 | Self-demonstration | 16 | W16.4, Phase 16 Edge tests |

With this table, every task identifier `T001`--`T069` is owned by a
named phase and workstream; none is silently dropped or invented.
