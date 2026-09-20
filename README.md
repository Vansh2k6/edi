# Cyber-Defense Personal Data Privacy Vault

A zero-trust personal data firewall and envelope-encrypted privacy vault designed to intercept, analyze, gate, and audit inbound data access requests from web applications.

---

## Table of Contents
1. [Overview & Security Architecture](#overview--security-architecture)
2. [Quickstart & Run Instructions](#quickstart--run-instructions)
3. [Default Development Credentials](#default-development-credentials)
4. [File & Directory Guide](#file--directory-guide)
5. [End-to-End Workflow & Pipeline](#end-to-end-workflow--pipeline)

---

## Overview & Security Architecture

The **Privacy Vault** acts as a secure reverse-proxy and authorization layer between client browsers and web services requesting Personal Identifiable Information (PII):

* **Zero-Trust Ingress**: Every observation from the browser extension is cryptographically signed with an Ed25519 device key and validated against anti-replay nonces.
* **Envelope Encryption**: Vault entries are sealed using AES-256-GCM under Data Encryption Keys (DEKs) wrapped by Key Encryption Keys (KEKs) with Additional Authenticated Data (AAD) binding.
* **Data-Driven Policy & Minimisation**: Requests are classified against a data category registry. Excess fields are flagged for minimisation, and domain intelligence scores incoming request risks.
* **Tamper-Evident Auditing**: Decisions and accesses are committed to an append-only SHA-256 hash-chained audit ledger.
* **Owner Dashboard**: A reactive single-page dashboard connected via Server-Sent Events (SSE) for real-time monitoring and policy enforcement.

---

## Quickstart & Run Instructions

### 1. Prerequisites
* **Node.js**: `v22.0.0` or higher (`node --version`)
* **npm**: `v10.0.0` or higher

*(Note: PostgreSQL and Redis are optional. In development, the system runs with in-memory repositories and in-process caches with zero Docker requirements).*

### 2. Clone & Install
```bash
git clone <repository-url>
cd EDI
npm install
```

### 3. Environment Configuration
Create a `.env` file from the example template:
```bash
cp .env.example .env
```

### 4. Running the Project

#### Option A: Run the End-to-End Workflow Demo
Executes in-process verification across contracts, signed transport, classification, domain intelligence, and envelope-encrypted vault storage:
```bash
npm run demo
```

#### Option B: Run Core Backend & Web Dashboard
1. Build the dashboard SPA:
   ```bash
   npm run build:dashboard
   ```
2. Start the core server:
   ```bash
   npm run dev:core
   ```
3. Open your browser and navigate to:
   ```
   http://localhost:8080/#/login
   ```
4. Log in using the **Owner Secret** listed below.

#### Option C: Build and Load the Browser Extension
1. Build the extension bundle:
   ```bash
   npm run build:extension
   ```
2. Open Google Chrome and visit `chrome://extensions`.
3. Enable **Developer mode** (toggle in the top-right corner).
4. Click **Load unpacked** and select the folder:
   ```
   apps/extension/dist
   ```

---

## Default Development Credentials

When running in `NODE_ENV=development`:

| Credential | Default Value | Notes |
| :--- | :--- | :--- |
| **Dashboard Owner Secret** | `dev-only-owner-secret-not-for-production` | Master password entered on `/#/login` |
| **Dashboard Owner User ID** | `11111111-1111-4111-8111-111111111111` | UUID identifying the owner account |
| **Session Cookie Secret** | `dev-only-web-secret-not-for-production-0000000` | Used for HMAC signing httpOnly session cookies |
| **Key Encryption Ref (KEK)**| `dev-only-placeholder` | Dev-shim AES-KW key wrapper |

---

## File & Directory Guide

### Root & Infrastructure
* `package.json`: Monorepo workspace configuration, dependency declarations, and build scripts.
* `tsconfig.json` / `tsconfig.base.json`: TypeScript compiler options and workspace path mappings.
* `.env.example`: Documented configuration template with production and development defaults.
* `infra/categories.json`: Data category registry defining sensitivity levels, retention rules, and field mappings.
* `infra/docker-compose.yml`: Optional Docker container definitions for Postgres and Redis.
* `infra/migrations/0001_init.sql`: SQL migration script creating database tables and indexes.

---

### Scripts
* `scripts/demo.ts`: Complete end-to-end workflow demo script demonstrating the full security pipeline in-process.

---

### Packages (`packages/*`)

#### `packages/crypto` (Envelope Encryption & Key Management)
* `src/aad.ts`: Generates canonical AAD buffers binding data IDs, user IDs, and categories to ciphertexts.
* `src/blob.ts`: Binary serializer for `[version][nonce][ciphertext+tag]` sealed data blobs.
* `src/cipher.ts`: `NodeCipher` (Node.js `crypto`) and `WebSubtleCipher` (Browser `crypto.subtle`) AES-GCM engines.
* `src/keys.ts`: Key provider implementations (`DevShimKeyProvider` for local KEKs and KMS stubs).
* `src/seal.ts`: High-level sealing and unsealing functions for strings and byte buffers.
* `src/zeroize.ts`: Memory hygiene utility to overwrite sensitive byte buffers with zeroes.
* `src/index.ts`: Public export interface for cryptographic utilities.

#### `packages/envelope` (Signed Transport & Anti-Replay)
* `src/canonical.ts`: Deterministic, canonical JSON stringifier for reproducible signatures.
* `src/envelope.ts`: Ed25519 signing and verification functions for HTTP request envelopes.
* `src/keys.ts`: Device key-pair generation (`createDeviceKeyPair`) and base64url converters.
* `src/index.ts`: Public export interface for envelope transport.

#### `packages/schemas` (Strict Validation Contracts)
* `src/alert.ts`: Zod validation schemas for security alerts and transition requests.
* `src/audit-api.ts`: API request and response schemas for audit log queries and verification reports.
* `src/audit.ts`: Schema definitions for audit event records, action types, and hash-chain hashes.
* `src/config.ts`: Environment configuration schema with strict validation and no-leak error reporting.
* `src/contracts.ts`: Canonical types for vault entries, classifications, and domain signals.
* `src/decision.ts`: Schemas for decisions (`ALLOW`, `WARN`, `ASK_USER`, `BLOCK`), overrides, and grants.
* `src/domain-intel.ts`: Schemas for domain signals, intelligence summaries, and provider failure records.
* `src/envelope.ts`: Zod schemas for signed transport envelopes and device key registration.
* `src/observation.ts`: Schemas for intercepted web requests (`ObservedRequest`, origin, destination).
* `src/policy.ts`: Schemas for user policy rules, permissions, postures, and consent records.
* `src/vault.ts`: Schemas for encrypted vault entries, metadata listings, and key wrapping records.
* `src/index.ts`: Public export interface for all Zod schemas.

#### `packages/domain-intel` (Domain Intelligence & Reputation)
* `src/cache.ts`: `MemoryIntelligenceCache` and Redis cache adapters with TTL and staleness tracking.
* `src/dga.ts`: Domain Generation Algorithm (DGA) heuristic analysis and entropy scoring.
* `src/reputation.ts`: Domain reputation provider adapter with timeout and retry mechanisms.
* `src/service.ts`: Domain intelligence orchestrator managing providers with an automated degradation ladder.
* `src/index.ts`: Public export interface for domain intelligence.

#### `packages/rules` (Classification & Decision Engine)
* `src/classify.ts`: Classification engine matching observed fields against data categories (`CAT-*`).
* `src/decide.ts`: Decision engine combining deterministic policy rules and risk scores into verdicts.
* `src/evaluate.ts`: Evaluator testing active user rules against observed requests and classifications.
* `src/feasibility.ts`: Feasibility engine checking if the HTTP mechanism is compatible with requested data.
* `src/loader.ts`: Loads and verifies the SHA-256 checksum of the bundled JSON ruleset.
* `src/minimization.ts`: Analyzes requested fields against required fields to detect excess data collection.
* `src/index.ts`: Public export interface for rules and classification.

#### `packages/risk` (Multi-Factor Risk Assessment)
* `src/assess.ts`: Composite risk engine aggregating factor scores into overall risk categories.
* `src/factors.ts`: Individual risk calculators (sensitivity, domain trust, mechanism risk, scope expansion).
* `src/index.ts`: Public export interface for risk scoring.

#### `packages/audit` (Tamper-Evident Audit Ledger)
* `src/chain.ts`: Append-only SHA-256 hash chaining ensuring audit log integrity.
* `src/retention.ts`: Data retention manager enforcing policy-based record expiration.
* `src/tombstone.ts`: Cryptographic tombstone generator for maintaining hash chain continuity upon pruning.
* `src/index.ts`: Public export interface for audit logging.

#### `packages/ui` (Shared Presentation Primitives)
* `src/index.ts`: UI badge formatters, sensitivity color tokens, and verdict styling helpers.

---

### Services (`services/*`)

#### `services/core` (Security Core Backend)
* `src/app.ts`: Fastify application factory assembling route modules, security hooks, and error handlers.
* `src/audit-writer.ts`: Atomic append-only writer for hash-chained audit records.
* `src/categories.ts`: Loads and validates category definitions from the category registry JSON.
* `src/config.ts`: Loads and parses server configuration from environment variables.
* `src/consent-store.ts`: Storage provider for active and historical user consents.
* `src/decision-service.ts`: Composes the end-to-end decision pipeline (classify -> intel -> rules -> risk -> decide).
* `src/device-auth.ts`: In-memory device key registry and anti-replay nonce validator.
* `src/event-bus.ts`: Event emitter broadcasting decision updates to SSE subscribers.
* `src/keys.ts`: Key provider factory wiring dev-shim or KMS providers.
* `src/policy-store.ts`: User policy repository managing active rules, postures, and versions.
* `src/server.ts`: Bootstrap entry point starting the HTTP and SSE server on port 8080.
* `src/session.ts`: Authentication session providers (cookie-based, static test, dev-header).
* `src/web-session.ts`: Owner dashboard session issuer, CSRF token generator, and brute-force login throttle.
* `src/db/client.ts`: PostgreSQL Drizzle ORM client factory.
* `src/db/schema.ts`: Database schema definitions for entries, audit logs, policies, and device keys.
* `src/gateway/authorize.ts`: Middleware validating Ed25519 envelope signatures and nonces.
* `src/repositories/vault-repository.ts`: Repository interfaces and implementations (`MemoryVaultRepository`, `PostgresVaultRepository`).
* `src/routes/auth.ts`: Authentication endpoints (`/api/auth/login`, `/api/auth/session`, `/api/auth/logout`).
* `src/routes/consents.ts`: Consent management endpoints (`/api/consents`).
* `src/routes/decisions.ts`: Decision query, evaluation, and force-allow override endpoints (`/api/decisions`).
* `src/routes/devices.ts`: Device key registration endpoints (`/api/devices`).
* `src/routes/disclosure.ts`: Vault gateway disclosure authorization and data release endpoints (`/api/disclosure`).
* `src/routes/health.ts`: Health check endpoint (`/api/health`).
* `src/routes/intel.ts`: Domain intelligence query endpoints (`/api/domain-intelligence`).
* `src/routes/policy.ts`: Policy rules and default posture endpoints (`/api/policy`).
* `src/routes/rules.ts`: Classification and analysis endpoint (`/api/analyze`).
* `src/routes/stream.ts`: Server-Sent Events endpoint (`/api/stream`) for real-time dashboard updates.
* `src/routes/vault.ts`: Encrypted vault entry storage and metadata listing endpoints (`/api/vault/entries`).

---

### Applications (`apps/*`)

#### `apps/dashboard` (Owner Web UI)
* `src/api.ts`: Typed fetch client for the Core REST API and session management.
* `src/dom.ts`: Reactive DOM building helpers and event binding utilities.
* `src/main.ts`: SPA router and session bootstrap managing view transitions.
* `src/stream.ts`: SSE EventSource client receiving live decision and audit events.
* `src/views.ts`: View renderers for Overview, Vault, Requests, Policy, Domains, and Login.
* `public/index.html`: Dashboard single-page HTML shell.
* `public/styles.css`: Dark-mode cyber-defense design system styling.

#### `apps/extension` (Manifest V3 Web Extension)
* `src/background.ts`: Service worker managing background alarms, state sync, and messaging.
* `src/content.ts`: Injected content script intercepting form submissions and API calls.
* `src/dom.ts`: Injected DOM utilities for rendering in-page privacy warnings.
* `src/interceptor.ts`: Request listener observing network requests and data attributes.
* `src/manifest.json`: Manifest V3 configuration with least-privilege permissions.
* `src/popup.html`: Extension popup action HTML markup.
* `src/popup.ts`: Interactive popup UI displaying page privacy status and quick toggles.
* `src/rules.ts`: Extension-side rule cache and lightweight evaluation engine.
* `src/storage.ts`: Chrome storage wrapper for device keys and settings.

---

## End-to-End Workflow & Pipeline

```
1. Browser Observation
   └── Intercepts requested fields, origin domain, and transmission mechanism.

2. Cryptographic Signing
   └── Packs observation into an envelope signed with the client's Ed25519 private key.

3. Gateway Verification
   └── Verifies signature, validates device key registration, and checks nonce against replay.

4. Classification & Minimisation
   └── Maps fields to data categories and identifies excess fields.

5. Domain Intelligence & Risk Scoring
   └── Fetches domain reputation signals and calculates multi-factor risk scores.

6. Deterministic Policy Evaluation
   └── Matches user rules against facts to produce final outcome (ALLOW, WARN, ASK_USER, BLOCK).

7. Real-Time Streaming & Tamper-Evident Audit
   └── Emits event to SSE stream and commits entry to SHA-256 hash-chained audit ledger.
```
