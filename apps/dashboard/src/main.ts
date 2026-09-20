/**
 * Dashboard entry (T032).
 *
 * Session bootstrap on load, a hash router for the six surfaces, and one
 * rule: a 401 from any view drops the user at login with no partial
 * mutation preserved.
 */

import { api, ApiError, setCsrfToken } from './api.js';
import { clear, el } from './dom.js';
import { renderDomains, renderLogin, renderOverview, renderPolicy, renderRequestDetail, renderRequests, renderVault } from './views.js';

const view = document.getElementById('view') as HTMLElement;
const nav = document.getElementById('nav') as HTMLElement;
const logoutButton = document.getElementById('logout') as HTMLButtonElement;

const ROUTES = [
  { hash: '#/overview', label: 'Overview' },
  { hash: '#/vault', label: 'Vault' },
  { hash: '#/requests', label: 'Requests' },
  { hash: '#/policy', label: 'Policy' },
  { hash: '#/domains', label: 'Domains' },
] as const;

function drawNav(current: string): void {
  clear(nav);
  for (const route of ROUTES) {
    const button = el('button', { text: route.label, attrs: { type: 'button' } });
    if (route.hash === current || (current.startsWith('#/requests/') && route.hash === '#/requests')) {
      button.setAttribute('aria-current', 'page');
    }
    button.onclick = () => location.assign(`/${route.hash}`);
    nav.append(button);
  }
}

async function route(): Promise<void> {
  const hash = location.hash || '#/overview';
  drawNav(hash.split('/').slice(0, 2).join('/') === '#/requests' ? '#/requests' : hash);
  const guarded = async (render: () => Promise<void>): Promise<void> => {
    try {
      await render();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        location.assign('/#/login');
        return;
      }
      view.replaceChildren();
      view.append(el('div', { class: 'notice', attrs: { 'data-tone': 'error' }, text: 'Something went wrong loading this view.' }));
    }
  };

  if (hash === '#/login') {
    renderLogin(
      () => {
        // The form's success callback is the authed transition for this load;
        // without unhiding here the Log out control only appeared after the
        // next full reload (found by the browser E2E).
        logoutButton.hidden = false;
        location.assign('/#/overview');
      },
      view,
    );
    return;
  }
  if (hash === '#/vault') return guarded(() => renderVault(view));
  if (hash === '#/requests') return guarded(() => renderRequests(view));
  if (hash.startsWith('#/requests/')) {
    const id = hash.slice('#/requests/'.length);
    return guarded(() => renderRequestDetail(view, id));
  }
  if (hash === '#/policy') return guarded(() => renderPolicy(view));
  if (hash === '#/domains') return guarded(() => renderDomains(view));
  return guarded(() => renderOverview(view));
}

logoutButton.onclick = () => {
  void api
    .logout()
    .catch(() => undefined)
    .then(() => {
      setCsrfToken(null);
      location.assign('/#/login');
    });
};

async function bootstrap(): Promise<void> {
  try {
    const session = await api.session();
    setCsrfToken(session.csrf_token);
    logoutButton.hidden = false;
    await route();
  } catch {
    logoutButton.hidden = true;
    renderLogin(
      () => {
        logoutButton.hidden = false;
        location.assign('/#/overview');
      },
      view,
    );
  }
}

window.addEventListener('hashchange', () => {
  void route();
});

void bootstrap();
