import type { Mechanism } from '@pv/schemas';

/**
 * Data-driven tables (W3.1, W3.2, W3.3).
 *
 * Everything a security analyst needs to change lives here as data: adding a
 * category mapping, a mechanism capability or a minimum field set is a data
 * change, not a code change. No mapping is expressed as a branch in TypeScript.
 */

export type EvidenceStrength = 'strong' | 'weak';
export type EvidenceSource = 'field' | 'path';

export interface ClassificationMapping {
  mapping_id: string;
  data_category_id: string;
  strength: EvidenceStrength;
  /** Matched against request field names (lowercase, exact for strong). */
  field_patterns: string[];
  /** Matched against the destination path, as a substring. */
  path_patterns: string[];
}

/**
 * Field and path vocabulary. Exact field names are strong evidence; substrings
 * inside a field name or path are weak evidence.
 */
export const CLASSIFICATION_MAPPINGS: readonly ClassificationMapping[] = [
  {
    mapping_id: 'M-CREDENTIAL-01',
    data_category_id: 'CAT-CREDENTIAL',
    strength: 'strong',
    field_patterns: ['password', 'passwd', 'passphrase', 'otp', 'totp', 'cvv', 'pin', 'security_answer'],
    path_patterns: ['/login', '/signin', '/auth', '/password'],
  },
  {
    mapping_id: 'M-IDENTITY-01',
    data_category_id: 'CAT-IDENTITY',
    strength: 'strong',
    field_patterns: ['full_name', 'aadhaar', 'passport_number', 'date_of_birth', 'dob'],
    path_patterns: ['/kyc', '/identity'],
  },
  {
    mapping_id: 'M-CONTACT-01',
    data_category_id: 'CAT-CONTACT',
    strength: 'strong',
    field_patterns: ['email', 'phone', 'mobile_number', 'alternate_phone'],
    path_patterns: ['/newsletter', '/contact'],
  },
  {
    mapping_id: 'M-FINANCIAL-01',
    data_category_id: 'CAT-FINANCIAL',
    strength: 'strong',
    field_patterns: ['iban', 'account_number', 'card_number', 'monthly_income', 'salary'],
    path_patterns: ['/payment', '/billing', '/loan'],
  },
  {
    mapping_id: 'M-MEDICAL-01',
    data_category_id: 'CAT-MEDICAL',
    strength: 'strong',
    field_patterns: ['diagnosis', 'prescription', 'blood_group', 'medical_history'],
    path_patterns: ['/health', '/clinic', '/medical'],
  },
  {
    mapping_id: 'M-LOCATION-01',
    data_category_id: 'CAT-LOCATION',
    strength: 'strong',
    field_patterns: ['latitude', 'longitude', 'gps', 'home_address'],
    path_patterns: ['/geo', '/nearby'],
  },
  {
    mapping_id: 'M-DOCUMENTS-01',
    data_category_id: 'CAT-DOCUMENTS',
    strength: 'strong',
    field_patterns: ['document', 'attachment', 'upload_file', 'scan'],
    path_patterns: ['/upload', '/documents'],
  },
  {
    mapping_id: 'M-CONTACT-02',
    data_category_id: 'CAT-CONTACT',
    strength: 'weak',
    field_patterns: ['contact', 'reach', 'notify'],
    path_patterns: ['/subscribe', '/profile'],
  },
  {
    mapping_id: 'M-IDENTITY-02',
    data_category_id: 'CAT-IDENTITY',
    strength: 'weak',
    field_patterns: ['name', 'user', 'profile'],
    path_patterns: ['/signup', '/register', '/account'],
  },
  {
    mapping_id: 'M-FINANCIAL-02',
    data_category_id: 'CAT-FINANCIAL',
    strength: 'weak',
    field_patterns: ['amount', 'wallet', 'txn'],
    path_patterns: ['/checkout', '/wallet'],
  },
  {
    mapping_id: 'M-MEDICAL-02',
    data_category_id: 'CAT-MEDICAL',
    strength: 'weak',
    field_patterns: ['symptom', 'medication'],
    path_patterns: ['/patient'],
  },
  {
    mapping_id: 'M-LOCATION-02',
    data_category_id: 'CAT-LOCATION',
    strength: 'weak',
    field_patterns: ['city', 'zip', 'postal'],
    path_patterns: ['/delivery', '/store'],
  },
];

/**
 * Capabilities a mechanism can actually provide.
 *
 * `page_api` means a browser API available to the page can yield the value;
 * `vault_capability` means only an authorized vault disclosure could.
 */
export const MECHANISM_CAPABILITIES: Record<Mechanism, readonly string[]> = {
  form: ['user_input', 'file_selection'],
  fetch: ['user_input', 'page_api'],
  xhr: ['user_input', 'page_api'],
  beacon: ['user_input'],
  websocket: ['user_input', 'page_api'],
  unsupported: [],
};

export interface CategoryProfile {
  /** At least one of these capabilities must be available for a request to be feasible. */
  any_of: readonly string[];
  /** Fields sufficient to satisfy a minimal request for this category. */
  minimum_fields: readonly string[];
  /** Every field name this category recognises. */
  known_fields: readonly string[];
}

export const CATEGORY_PROFILES: Record<string, CategoryProfile> = {
  'CAT-IDENTITY': {
    any_of: ['user_input', 'page_api', 'vault_capability'],
    minimum_fields: ['full_name'],
    known_fields: ['full_name', 'date_of_birth', 'aadhaar', 'passport_number', 'nationality'],
  },
  'CAT-CONTACT': {
    any_of: ['user_input', 'page_api', 'vault_capability'],
    minimum_fields: ['email'],
    known_fields: ['email', 'phone', 'mobile_number', 'alternate_phone', 'postal_address'],
  },
  'CAT-FINANCIAL': {
    // A page cannot read a bank account from the browser: financial data can only
    // arrive from the user or from an authorized vault disclosure.
    any_of: ['user_input', 'vault_capability'],
    minimum_fields: ['account_number'],
    known_fields: ['account_number', 'iban', 'card_number', 'monthly_income', 'salary', 'credit_score'],
  },
  'CAT-MEDICAL': {
    any_of: ['user_input', 'vault_capability'],
    minimum_fields: ['blood_group'],
    known_fields: ['blood_group', 'diagnosis', 'prescription', 'medical_history', 'allergy'],
  },
  'CAT-LOCATION': {
    any_of: ['page_api', 'vault_capability'],
    minimum_fields: ['coarse_location'],
    known_fields: ['coarse_location', 'latitude', 'longitude', 'gps', 'home_address', 'city', 'postal'],
  },
  'CAT-DOCUMENTS': {
    any_of: ['file_selection', 'vault_capability'],
    minimum_fields: ['document'],
    known_fields: ['document', 'attachment', 'upload_file', 'scan'],
  },
};
