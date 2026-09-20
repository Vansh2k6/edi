/**
 * @pv/schemas - the single source of truth for every trust boundary.
 *
 * ARCHITECTURE.md defines four trust boundaries; this package defines the shape
 * of everything that crosses any of them. Consumers validate with these schemas
 * and infer their TypeScript types from them (`z.infer`), so a hand-written
 * duplicate type is a defect (D-023).
 */
export * from './config.js';
export * from './host.js';
export * from './identity.js';
export * from './vault.js';
export * from './observation.js';
export * from './envelope.js';
export * from './domain-intel.js';
export * from './policy.js';
export * from './risk.js';
export * from './decision.js';
export * from './audit.js';
export * from './audit-api.js';
export * from './alert.js';
