import { sql } from 'drizzle-orm';
import {
  boolean,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';

/**
 * Phase 1 tables (T004).
 *
 * Entities owned by later phases are added by their own migration, not here:
 * the entity list in PRD.md section 10 is the roadmap, not this phase's schema.
 *
 * Nothing in this schema holds vault plaintext or key material: `vault_entry`
 * keeps metadata, a digest and a *wrapped* data key (D-022).
 */

export const users = pgTable(
  'users',
  {
    user_id: uuid('user_id').primaryKey().defaultRandom(),
    user_name: text('user_name').notNull(),
    email_id: text('email_id').notNull(),
    mobile_number: text('mobile_number'),
    identity_status: text('identity_status').notNull().default('Pending'),
    user_type: text('user_type').notNull().default('Citizen'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [uniqueIndex('users_email_id_key').on(table.email_id)],
);

export const dataCategories = pgTable('data_category', {
  data_category_id: text('data_category_id').primaryKey(),
  category_name: text('category_name').notNull(),
  sensitivity_level: text('sensitivity_level').notNull(),
  active: boolean('active').notNull().default(true),
});

export const encryptionKeys = pgTable(
  'encryption_key',
  {
    key_id: uuid('key_id').primaryKey().defaultRandom(),
    user_id: uuid('user_id')
      .notNull()
      .references(() => users.user_id, { onDelete: 'cascade' }),
    algorithm: text('algorithm').notNull().default('AES-256-GCM'),
    kek_ref: text('kek_ref').notNull(),
    key_status: text('key_status').notNull().default('Active'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    rotated_at: timestamp('rotated_at', { withTimezone: true }),
  },
  (table) => [index('encryption_key_user_idx').on(table.user_id, table.key_status)],
);

export const vaultEntries = pgTable(
  'vault_entry',
  {
    data_id: uuid('data_id').primaryKey().defaultRandom(),
    user_id: uuid('user_id')
      .notNull()
      .references(() => users.user_id, { onDelete: 'cascade' }),
    data_category_id: text('data_category_id')
      .notNull()
      .references(() => dataCategories.data_category_id, { onDelete: 'restrict' }),
    encryption_key_id: uuid('encryption_key_id')
      .notNull()
      .references(() => encryptionKeys.key_id, { onDelete: 'restrict' }),
    /** 'local' keeps the ciphertext on the client; only a digest lives here. */
    storage_tier: text('storage_tier').notNull(),
    /** Present only for the server tier. */
    ciphertext: text('ciphertext'),
    integrity_digest: text('integrity_digest').notNull(),
    /** base64 of the wrapped data-encryption key. Never plaintext key material. */
    wrapped_dek: text('wrapped_dek').notNull(),
    storage_location: text('storage_location'),
    client_metadata: jsonb('client_metadata').notNull().default(sql`'{}'::jsonb`),
    data_status: text('data_status').notNull().default('Active'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('vault_entry_owner_idx').on(table.user_id, table.data_status),
    index('vault_entry_category_idx').on(table.data_category_id),
    index('vault_entry_key_idx').on(table.encryption_key_id),
  ],
);

export const applications = pgTable('application', {
  application_id: text('application_id').primaryKey(),
  application_name: text('application_name').notNull(),
  /** 0-10, higher is more trusted; drives the untrust factor in risk scoring. */
  security_rating: integer('security_rating').notNull().default(0),
  active: boolean('active').notNull().default(true),
});

export const consents = pgTable(
  'consent_policy',
  {
    consent_id: uuid('consent_id').primaryKey().defaultRandom(),
    user_id: uuid('user_id')
      .notNull()
      .references(() => users.user_id, { onDelete: 'cascade' }),
    application_id: text('application_id')
      .notNull()
      .references(() => applications.application_id, { onDelete: 'cascade' }),
    data_category_id: text('data_category_id')
      .notNull()
      .references(() => dataCategories.data_category_id, { onDelete: 'restrict' }),
    permission_type: text('permission_type').notNull(),
    expiry_date: text('expiry_date'),
    consent_status: text('consent_status').notNull().default('Pending'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index('consent_owner_idx').on(table.user_id, table.consent_status)],
);

export const consentHistory = pgTable('consent_history', {
  history_id: uuid('history_id').primaryKey().defaultRandom(),
  consent_id: uuid('consent_id')
    .notNull()
    .references(() => consents.consent_id, { onDelete: 'cascade' }),
  action: text('action').notNull(),
  changed_by: text('changed_by'),
  changed_at: timestamp('changed_at', { withTimezone: true }).notNull().defaultNow(),
});
