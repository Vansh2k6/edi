import type { DecisionView } from './decision-view.js';

/**
 * Decision overlay (PRD.md section 9).
 *
 * The Force Allow control is only rendered when the view model says the decision
 * is overridable. That is presentation only - the core refuses an override of a
 * critical block regardless of what any client sends (T027).
 */

const ROOT_ID = 'pv-decision-overlay';

function element<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  text?: string,
  className?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text; // textContent, never innerHTML
  if (className !== undefined) node.className = className;
  return node;
}

export function renderOverlay(view: DecisionView, onForceAllow: () => void, onDismiss: () => void): void {
  document.getElementById(ROOT_ID)?.remove();

  const root = element('div');
  root.id = ROOT_ID;
  root.setAttribute('role', 'alertdialog');
  // The Quiet Institution: Card White surface, blue-cast shadow, 16px radius
  // (the design system's card ladder - no sharp 90-degree edges).
  root.style.cssText =
    'position:fixed;z-index:2147483647;right:16px;bottom:16px;max-width:380px;padding:16px;' +
    'background:#FFFFFF;color:#132B50;border:1px solid #C7D8F0;border-radius:16px;' +
    'box-shadow:0 1px 2px rgba(19,43,80,0.06),0 12px 32px rgba(31,90,184,0.14);' +
    'font:13px/1.5 Inter, "Segoe UI", system-ui, sans-serif';

  // The verdict pill comes from the shared token module (W8.7), so the
  // overlay's verdict is pixel-identical to the dashboard's.
  const pill = element('span', view.verdict.label);
  pill.style.cssText = `display:inline-block;border-radius:999px;padding:4px 12px;font:600 0.6875rem/1.2 Inter, "Segoe UI", system-ui, sans-serif;letter-spacing:0.08em;text-transform:uppercase;background:${view.verdict.background};color:${view.verdict.foreground}`;
  root.append(pill);
  root.append(element('p', view.website));
  root.append(element('p', view.website));

  if (view.requested.length > 0) {
    root.append(element('div', `Requested: ${view.requested.join(', ')}`));
  }
  const why = element('ul');
  for (const reason of view.reasons) why.append(element('li', reason));
  root.append(why);

  if (view.matched_rules.length > 0) {
    root.append(element('div', `Matched rules: ${view.matched_rules.join(', ')}`));
  }
  if (view.enforcement_note !== null) {
    // Reported plainly rather than implying the request was actually stopped.
    root.append(element('p', view.enforcement_note));
  }

  const actions = element('div');
  const dismiss = element('button', 'Keep blocked');
  dismiss.onclick = onDismiss;
  actions.append(dismiss);

  if (view.can_force_allow && view.force_allow_label !== null) {
    const override = element('button', view.force_allow_label);
    override.onclick = onForceAllow;
    actions.append(override);
  }

  root.append(actions);
  document.documentElement.append(root);
}

export function clearOverlay(): void {
  document.getElementById(ROOT_ID)?.remove();
}
