import { observedRequestSchema, type DataCategory, type Mechanism, type ObservedRequest } from '@pv/schemas';

/** The category registry a deployment ships with (a configuration change, not code). */
export const FIXTURE_CATEGORIES: readonly DataCategory[] = [
  { data_category_id: 'CAT-CREDENTIAL', category_name: 'Credentials', sensitivity_level: 'Critical' },
  { data_category_id: 'CAT-IDENTITY', category_name: 'Identity', sensitivity_level: 'High' },
  { data_category_id: 'CAT-CONTACT', category_name: 'Communication', sensitivity_level: 'Low' },
  { data_category_id: 'CAT-FINANCIAL', category_name: 'Financial', sensitivity_level: 'Critical' },
  { data_category_id: 'CAT-MEDICAL', category_name: 'Medical', sensitivity_level: 'Critical' },
  { data_category_id: 'CAT-LOCATION', category_name: 'Location', sensitivity_level: 'Medium' },
  { data_category_id: 'CAT-DOCUMENTS', category_name: 'Documents', sensitivity_level: 'High' },
];

export interface ObservationOverrides {
  mechanism?: Mechanism;
  requested_data?: string[];
  destination?: string;
  host?: string;
  kind?: ObservedRequest['origin']['kind'];
  top_level_url?: string | null;
  request_id?: string;
  timestamp?: string;
}

/**
 * Build a valid observation. Defaults describe a public site asking a page-level
 * fetch for contact fields.
 */
export function observation(overrides: ObservationOverrides = {}): ObservedRequest {
  const host = overrides.host ?? 'shop.example.com';
  const kind = overrides.kind ?? 'public';
  return observedRequestSchema.parse({
    request_id: overrides.request_id ?? crypto.randomUUID(),
    timestamp: overrides.timestamp ?? new Date('2026-03-01T10:00:00.000Z').toISOString(),
    origin: {
      raw: `https://${host}/profile`,
      host,
      kind,
      scheme: 'https',
      port: null,
      registrable_domain: 'example.com',
      display: host,
    },
    // A neutral path on purpose: the fixture must not inject category evidence
    // through the destination unless a test asks for it.
    destination: overrides.destination ?? 'https://shop.example.com/api/collect',
    requested_data: overrides.requested_data ?? ['email'],
    mechanism: overrides.mechanism ?? 'fetch',
    page_context: {
      top_level_url: overrides.top_level_url === undefined ? `https://${host}/profile` : overrides.top_level_url,
      is_top_frame: true,
    },
    browser_context: { tab_id: 1, redirect_chain: [] },
  });
}
