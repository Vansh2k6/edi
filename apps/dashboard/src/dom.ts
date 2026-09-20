/**
 * DOM construction helpers (W8.8 XSS rule).
 *
 * Every rendered string enters the document through `textContent`; the app
 * never assigns `innerHTML`. Rule rationales, domain names and decision
 * reasons are attacker-influenced data in the display path, and the security
 * tests probe exactly this.
 */

import { verdictFor } from '@pv/ui';

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  options: { text?: string; class?: string; attrs?: Record<string, string> } = {},
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (options.text !== undefined) node.textContent = options.text;
  if (options.class !== undefined) node.className = options.class;
  for (const [name, value] of Object.entries(options.attrs ?? {})) {
    node.setAttribute(name, value);
  }
  return node;
}

export function clear(node: HTMLElement): void {
  node.replaceChildren();
}

export function fmtTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString();
}

/** A decision outcome -> the shared design-system verdict pill (W8.7). */
export function verdictPill(outcome: string): HTMLElement {
  const span = el('span', { class: 'pill' });
  if (outcome === 'BLOCK' || outcome === 'ASK_USER' || outcome === 'WARN' || outcome === 'ALLOW') {
    const verdict = verdictFor(outcome);
    span.textContent = verdict.label;
    span.style.background = verdict.background;
    span.style.color = verdict.foreground;
  } else {
    // Unknown outcome: a neutral pill, never a wrong verdict.
    span.textContent = outcome;
    span.style.background = '#EAF1FB';
    span.style.color = '#1D4ED8';
  }
  return span;
}
