/**
 * The dashboard views (T032--T037).
 *
 * One module per surface would be tidier; they share so much scaffolding
 * (cards, empty states, pill rows) that one file keeps the design system
 * consistent across all six. Every dynamic string is rendered through the
 * `el()` helper - textContent only.
 */

import {
  decisionSchema,
  intelligenceSummarySchema,
  ruleSchema,
  vaultEntrySchema,
  type Decision,
  type DomainSignal,
  type Rule,
  type VaultEntry,
} from '@pv/schemas';
import { api, ApiError, setCsrfToken } from './api.js';
import { clear, el, fmtTime, verdictPill } from './dom.js';

/**
 * Re-render the current surface into the live host.
 *
 * Handlers used to call `rerender(el('div'))` - a detached node - so a
 * successful mutation refetched and rendered into nothing while the stale
 * table stayed on screen (found in the live browser walkthrough).
 */
type Render = () => void;

function card(title?: string): { root: HTMLElement; body: HTMLElement } {
  const root = el('section', { class: 'card' });
  if (title !== undefined) root.append(el('h2', { text: title }));
  return { root, body: root };
}

function emptyState(message: string): HTMLElement {
  return el('div', { class: 'empty', text: message });
}

function errorNotice(error: unknown): HTMLElement {
  const notice = el('div', { class: 'notice', attrs: { 'data-tone': 'error' } });
  notice.textContent = error instanceof ApiError ? `Request failed: ${error.code}` : 'Something went wrong.';
  return notice;
}

/* --------------------------------------------------------------- login --- */

export function renderLogin(onLoggedIn: () => void, host: HTMLElement): void {
  clear(host);
  const wrap = el('div', { class: 'login' });
  const box = card();
  box.body.append(el('h1', { text: 'Sign in' }));
  box.body.append(el('p', { class: 'lede', text: 'The dashboard is the owner\u2019s private console for the vault.' }));
  const input = el('input', { attrs: { type: 'password', autocomplete: 'current-password', placeholder: 'Owner secret' } });
  const submit = el('button', { class: 'btn btn-primary', text: 'Sign in' });
  const error = el('div');
  submit.onclick = async () => {
    error.replaceChildren();
    submit.setAttribute('disabled', '');
    try {
      const session = await api.login(input.value);
      setCsrfToken(session.csrf_token);
      onLoggedIn();
    } catch (err) {
      error.append(errorNotice(err));
    } finally {
      submit.removeAttribute('disabled');
    }
  };
  input.onkeydown = (event) => {
    if (event.key === 'Enter') submit.click();
  };
  box.body.append(el('label', { text: 'Owner secret' }), input, submit, error);
  wrap.append(box.root);
  host.append(wrap);
}

/* ------------------------------------------------------------ overview --- */

export async function renderOverview(host: HTMLElement): Promise<void> {
  clear(host);
  host.append(el('h1', { text: 'Security overview' }));
  try {
    const page = await api.listDecisions(10, null);
    const decisions = page.decisions.map((d) => decisionSchema.parse(d));
    const recent = card('Recent requests');
    if (decisions.length === 0) {
      recent.body.append(emptyState('No requests observed yet. Once the extension sees traffic, decisions appear here live.'));
    } else {
      const table = decisionsTable(decisions);
      recent.body.append(table);
      recent.body.append(
        el('p', { class: 'muted', text: page.next_cursor === null ? 'End of recent history.' : 'More history available in Requests.' }),
      );
    }
    host.append(recent.root);

    const live = card('Live stream');
    const liveList = el('div');
    live.body.append(el('p', { class: 'lede', text: 'New decisions arrive as they are recorded.' }), liveList);
    host.append(live.root);
    startStream(liveList);
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) throw err;
    host.append(errorNotice(err));
  }
}

function decisionsTable(decisions: readonly Decision[]): HTMLElement {
  const table = el('table');
  const head = el('tr');
  for (const label of ['Verdict', 'Website', 'Risk', 'When']) head.append(el('th', { text: label }));
  const thead = el('thead'); thead.append(head); table.append(thead);
  const tbody = el('tbody');
  for (const decision of decisions) {
    const row = el('tr', { attrs: { 'data-decision-id': decision.decision_id } });
    const verdictCell = el('td');
    verdictCell.append(verdictPill(decision.decision));
    row.append(
      verdictCell,
      el('td', { text: decision.explanation.website }),
      el('td', { text: `${decision.risk_score} (${decision.risk_level})` }),
      el('td', { text: fmtTime(decision.created_at) }),
    );
    tbody.append(row);
  }
  table.append(tbody);
  return table;
}

function startStream(list: HTMLElement): () => void {
  const source = new EventSource('/api/stream', { withCredentials: true });
  source.addEventListener('decision', (event) => {
    try {
      const decision = decisionSchema.parse(JSON.parse((event as MessageEvent<string>).data));
      const row = el('div', { class: 'notice' });
      row.style.display = 'flex';
      row.style.gap = '10px';
      row.style.alignItems = 'center';
      const pill = verdictPill(decision.decision);
      row.append(pill, el('span', { text: `${decision.explanation.website} \u00b7 ${fmtTime(decision.created_at)}` }));
      row.style.cursor = 'pointer';
      row.onclick = () => location.assign(`/#/requests/${decision.decision_id}`);
      list.prepend(row);
      while (list.children.length > 8) list.lastElementChild?.remove();
    } catch {
      // A malformed frame is dropped, never rendered.
    }
  });
  source.onerror = () => source.close();
  return () => source.close();
}

/* -------------------------------------------------------------- vault --- */

export async function renderVault(host: HTMLElement): Promise<void> {
  clear(host);
  host.append(el('h1', { text: 'Vault' }));
  try {
    const { entries } = await api.listEntries();
    const parsed = entries.map((e) => vaultEntrySchema.parse(e));
    const box = card();
    if (parsed.length === 0) {
      box.body.append(emptyState('The vault is empty. Entries added by the owner\u2019s client appear here as metadata only.'));
    } else {
      const table = el('table');
      const head = el('tr');
      for (const label of ['Category', 'Tier', 'Status', 'Created', '']) head.append(el('th', { text: label }));
      const thead = el('thead'); thead.append(head); table.append(thead);
      const tbody = el('tbody');
      for (const entry of parsed) tbody.append(vaultRow(entry));
      table.append(tbody);
      box.body.append(table);
    }
    box.body.append(el('p', { class: 'muted', text: 'Keys never reach the core. Reveal decrypts server-tier values only after your explicit confirmation, and every reveal is audited.' }));
    host.append(box.root);
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) throw err;
    host.append(errorNotice(err));
  }
}

function vaultRow(entry: VaultEntry): HTMLElement {
  const row = el('tr');
  row.append(
    el('td', { text: entry.data_category_id, class: 'mono' }),
    el('td', { text: entry.storage_tier }),
    el('td', { text: entry.data_status }),
    el('td', { text: fmtTime(entry.created_at) }),
  );
  const actions = el('td', { class: 'actions' });
  if (entry.storage_tier === 'server' && entry.data_status === 'Active') {
    const reveal = el('button', { class: 'btn btn-secondary', text: 'Reveal' });
    reveal.onclick = async () => {
      // The explicit gesture. The server still refuses without confirm: true,
      // which the client sends only from this handler - re-auth as intent.
      try {
        const result = (await api.revealEntry(entry.data_id, true)) as { values: Record<string, string> };
        const shown = el('tr');
        const cell = el('td', { attrs: { colspan: '5' } });
        const kv = el('dl', { class: 'kv' });
        for (const [key, value] of Object.entries(result.values)) {
          kv.append(el('dt', { text: key }), el('dd', { text: value, class: 'mono' }));
        }
        cell.append(kv);
        shown.append(cell);
        row.after(shown);
      } catch (err) {
        const failed = el('tr');
        const cell = el('td', { attrs: { colspan: '5' } });
        cell.append(errorNotice(err));
        failed.append(cell);
        row.after(failed);
      }
    };
    actions.append(reveal);
  } else {
    actions.append(el('span', { class: 'muted', text: 'held on your device' }));
  }
  row.append(actions);
  return row;
}

/* ----------------------------------------------------------- requests --- */

export async function renderRequests(host: HTMLElement): Promise<void> {
  clear(host);
  host.append(el('h1', { text: 'Requests' }));
  try {
    const pageSize = 25;
    let cursor: string | null = null;
    const listCard = card();
    const tableWrap = el('div');
    const more = el('button', { class: 'btn btn-secondary', text: 'Load more' });
    const loadMore = async (): Promise<void> => {
      const page = await api.listDecisions(pageSize, cursor);
      const decisions = page.decisions.map((d) => decisionSchema.parse(d));
      if (tableWrap.querySelector('table') === null) tableWrap.append(decisionsTable(decisions));
      else {
        const tbody = tableWrap.querySelector('tbody');
        if (tbody !== null) for (const d of decisions) tbody.append(decisionsRow(d));
      }
      cursor = page.next_cursor;
      if (cursor === null) more.setAttribute('disabled', '');
    };
    more.onclick = () => void loadMore();
    await loadMore();
    if (tableWrap.querySelector('tbody')?.children.length === 0) {
      listCard.body.append(emptyState('No requests yet.'));
    } else {
      listCard.body.append(tableWrap, more);
    }
    host.append(listCard.root);
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) throw err;
    host.append(errorNotice(err));
  }
}

function decisionsRow(decision: Decision): HTMLElement {
  const row = el('tr', { attrs: { 'data-decision-id': decision.decision_id } });
  const verdictCell = el('td');
  verdictCell.append(verdictPill(decision.decision));
  row.append(verdictCell, el('td', { text: decision.explanation.website }), el('td', { text: `${decision.risk_score} (${decision.risk_level})` }), el('td', { text: fmtTime(decision.created_at) }));
  return row;
}

export async function renderRequestDetail(host: HTMLElement, decisionId: string): Promise<void> {
  clear(host);
  host.append(el('h1', { text: 'Request detail' }));
  try {
    const detail = decisionSchema.parse(await api.getDecision(decisionId));
    const explanation = detail.explanation;
    const box = card();
    const head = el('div');
    head.style.display = 'flex';
    head.style.gap = '12px';
    head.style.alignItems = 'center';
    head.append(verdictPill(detail.decision), el('strong', { text: explanation.website }));
    box.body.append(head, el('p', { class: 'mono muted', text: detail.decision_id }));

    const kv = el('dl', { class: 'kv' });
    kv.append(el('dt', { text: 'Requested' }), el('dd', { text: explanation.requested_data.join(', ') || '(none)' }));
    kv.append(el('dt', { text: 'Risk' }), el('dd', { text: `${detail.risk_score} (${detail.risk_level})` }));
    kv.append(el('dt', { text: 'Reason codes' }), el('dd', { text: detail.reason_codes.join(', ') || '(none)', class: 'mono' }));
    kv.append(el('dt', { text: 'Matched rules' }), el('dd', { text: explanation.matched_rules.join(', ') || '(none)', class: 'mono' }));
    kv.append(el('dt', { text: 'Policy version' }), el('dd', { text: explanation.policy_version, class: 'mono' }));
    kv.append(el('dt', { text: 'Overridden' }), el('dd', { text: explanation.overridden ? 'yes' : 'no' }));
    box.body.append(kv);

    if (explanation.why.length > 0) {
      box.body.append(el('h2', { text: 'Why' }));
      const list = el('ul');
      for (const reason of explanation.why) list.append(el('li', { text: reason }));
      box.body.append(list);
    }
    if (explanation.domain_signals.length > 0) {
      box.body.append(el('h2', { text: 'Domain signals' }), signalTable(explanation.domain_signals));
    }
    host.append(box.root);
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) throw err;
    host.append(errorNotice(err));
  }
}

/* ------------------------------------------------------------- policy --- */

export async function renderPolicy(host: HTMLElement): Promise<void> {
  clear(host);
  host.append(el('h1', { text: 'Policy' }));
  try {
    const { consents } = (await api.listConsents()) as { consents: Array<{ data_category_id: string; status: string; updated_at: string }> };
    const categories = ['CAT-IDENTITY', 'CAT-CONTACT', 'CAT-FINANCIAL', 'CAT-HEALTH', 'CAT-LOCATION', 'CAT-BEHAVIORAL'];
    const consentCard = card('Consents');
    const consentTable = el('table');
    const chead = el('tr');
    for (const label of ['Category', 'Status', 'Updated', '']) chead.append(el('th', { text: label }));
    const cthead = el('thead'); cthead.append(chead); consentTable.append(cthead);
    const cbody = el('tbody');
    const drawn = new Set<string>();
    for (const consent of consents) {
      drawn.add(consent.data_category_id);
      cbody.append(consentRow(consent.data_category_id, consent.status, () => void renderPolicy(host)));
    }
    for (const category of categories) {
      if (!drawn.has(category)) cbody.append(consentRow(category, 'Not granted', () => void renderPolicy(host)));
    }
    consentTable.append(cbody);
    consentCard.body.append(
      el('p', { class: 'lede', text: 'Granting lets disclosures of a category rely on an active consent. Use Preview to see what granting implies before you commit.' }),
      consentTable,
    );
    host.append(consentCard.root);

    const rulesCard = card('Your rules');
    const { rules } = await api.listRules();
    const parsed = rules.map((r) => ruleSchema.parse(r));
    if (parsed.length === 0) {
      rulesCard.body.append(emptyState('No user rules yet. System rules are listed read-only in the ruleset and cannot be edited here.'));
    } else {
      const table = el('table');
      const rhead = el('tr');
      for (const label of ['Rule', 'Effect', 'Priority', 'Rationale', 'Expires', '']) rhead.append(el('th', { text: label }));
      const rthead = el('thead'); rthead.append(rhead); table.append(rthead);
      const tbody = el('tbody');
      for (const rule of parsed) tbody.append(ruleRow(rule, () => void renderPolicy(host)));
      table.append(tbody);
      rulesCard.body.append(table);
    }
    host.append(rulesCard.root);
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) throw err;
    host.append(errorNotice(err));
  }
}

function consentRow(category: string, status: string, rerender: Render): HTMLElement {
  const row = el('tr');
  row.append(el('td', { text: category, class: 'mono' }));
  const statusCell = el('td');
  const pill = el('span', { class: 'pill', text: status });
  pill.style.background = status === 'Active' ? '#E7F5EC' : status === 'Revoked' ? '#FBEAE8' : '#EAF1FB';
  pill.style.color = status === 'Active' ? '#1B7F4B' : status === 'Revoked' ? '#B3372E' : '#1D4ED8';
  statusCell.append(pill);
  row.append(statusCell);
  row.append(el('td', { text: status === 'Not granted' ? '\u2014' : fmtTime(new Date().toISOString()) }));
  const actions = el('td', { class: 'actions' });
  if (status === 'Active') {
    const revoke = el('button', { class: 'btn btn-secondary', text: 'Revoke' });
    revoke.onclick = async () => {
      try {
        await api.revokeConsent(category);
        rerender();
      } catch (err) {
        actions.append(errorNotice(err));
      }
    };
    actions.append(revoke);
  } else {
    const preview = el('button', { class: 'btn btn-ghost', text: 'Preview' });
    const grant = el('button', { class: 'btn btn-primary', text: 'Grant' });
    preview.onclick = async () => {
      try {
        const result = (await api.previewConsent(category)) as { sensitivity: string; rules_affecting: Array<{ rule_id: string; effect: string }>; note: string };
        const detail = el('div', { class: 'notice' });
        detail.append(
          el('div', { text: `Sensitivity: ${result.sensitivity}` }),
          el('div', { text: `Rules affecting this category: ${result.rules_affecting.map((r) => `${r.rule_id} (${r.effect})`).join(', ') || 'none of your rules'}` }),
          el('div', { class: 'muted', text: result.note }),
        );
        const detailRow = el('tr'); const detailCell = el('td', { attrs: { colspan: '4' } }); detailCell.append(detail); detailRow.append(detailCell); row.after(detailRow);
      } catch (err) {
        actions.append(errorNotice(err));
      }
    };
    grant.onclick = async () => {
      try {
        await api.grantConsent(category);
        rerender();
      } catch (err) {
        actions.append(errorNotice(err));
      }
    };
    actions.append(preview, ' ', grant);
  }
  row.append(actions);
  return row;
}

function ruleRow(rule: Rule, rerender: Render): HTMLElement {
  const row = el('tr');
  row.append(
    el('td', { text: rule.rule_id, class: 'mono' }),
    el('td', { text: rule.effect }),
    el('td', { text: String(rule.priority) }),
    el('td', { text: rule.rationale }),
    el('td', { text: rule.expires_at === null ? '\u2014' : fmtTime(rule.expires_at) }),
  );
  const actions = el('td', { class: 'actions' });
  // Critical rules are system-authored and read-only everywhere (D-029).
  if (rule.origin === 'user' && rule.override_class !== 'critical') {
    const remove = el('button', { class: 'btn btn-ghost', text: 'Delete' });
    remove.onclick = async () => {
      try {
        await api.deleteRule(rule.rule_id);
        rerender();
      } catch (err) {
        actions.append(errorNotice(err));
      }
    };
    actions.append(remove);
  } else {
    actions.append(el('span', { class: 'muted', text: 'read-only' }));
  }
  row.append(actions);
  return row;
}

/* ------------------------------------------------------------- domain --- */

export async function renderDomains(host: HTMLElement): Promise<void> {
  clear(host);
  host.append(el('h1', { text: 'Domain intelligence' }));
  const lookupCard = card();
  const input = el('input', { attrs: { placeholder: 'example.com', 'aria-label': 'Domain to inspect' } });
  const go = el('button', { class: 'btn btn-primary', text: 'Inspect' });
  const results = el('div');
  go.onclick = async () => {
    clear(results);
    try {
      const { summary, failures } = await api.domainIntelligence(input.value.trim());
      const parsed = intelligenceSummarySchema.parse(summary);
      results.append(el('h2', { text: parsed.host }));
      if (parsed.all_unknown) {
        results.append(emptyState('No provider could resolve this domain. Unknown is not clean: no signal here vouches for it.'));
      } else {
        results.append(signalTable(parsed.signals));
      }
      const counts = el('p', { class: 'muted' });
      counts.textContent = `available ${parsed.available_count} \u00b7 stale ${parsed.stale_count} \u00b7 unknown ${parsed.unknown_count} \u00b7 cache ${parsed.cache_state}`;
      results.append(counts);
      if (Array.isArray(failures) && failures.length > 0) {
        results.append(el('p', { class: 'muted', text: `${failures.length} provider(s) reported failures for this lookup.` }));
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) throw err;
      results.append(errorNotice(err));
    }
  };
  input.onkeydown = (event) => {
    if (event.key === 'Enter') go.click();
  };
  lookupCard.body.append(el('p', { class: 'lede', text: 'Signals with source, retrieval time, freshness and confidence. Unknown signals state their reason - they are never rendered as safe.' }), el('div', { text: '' }));
  const row = el('div');
  row.style.display = 'flex';
  row.style.gap = '10px';
  row.append(input, go);
  lookupCard.body.append(row, results);
  host.append(lookupCard.root);
}

function signalTable(signals: readonly DomainSignal[]): HTMLElement {
  const table = el('table');
  const head = el('tr');
  for (const label of ['Signal', 'Value', 'Source', 'Retrieved', 'Freshness', 'Confidence']) head.append(el('th', { text: label }));
  const thead = el('thead'); thead.append(head); table.append(thead);
  const tbody = el('tbody');
  for (const signal of signals) {
    const row = el('tr');
    const unknown = signal.freshness === 'unknown';
    row.append(
      el('td', { text: signal.type, class: 'mono' }),
      el('td', { text: unknown ? `unknown \u2014 ${signal.unknown_reason ?? ''}` : JSON.stringify(signal.value), class: unknown ? '' : 'mono' }),
      el('td', { text: signal.source }),
      el('td', { text: fmtTime(signal.retrieved_at) }),
      el('td', { text: signal.freshness }),
      el('td', { text: `${Math.round(signal.confidence * 100)}%` }),
    );
    tbody.append(row);
  }
  table.append(tbody);
  return table;
}

