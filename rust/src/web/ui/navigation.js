// SPDX-License-Identifier: LGPL-3.0-only
(() => {
  const drawer = document.getElementById('mobile-navigation');
  const trigger = document.querySelector('.mobile-toggle');
  if (typeof drawer.showModal !== 'function') return;

  const compact = matchMedia('(max-width: 920px)');
  trigger.addEventListener('click', () => {
    drawer.showModal();
    trigger.setAttribute('aria-expanded', 'true');
  });
  drawer.addEventListener('close', () => {
    trigger.setAttribute('aria-expanded', 'false');
  });
  drawer.addEventListener('click', event => {
    if (event.target === drawer) drawer.close();
  });
  drawer.querySelector('nav').addEventListener('click', event => {
    if (event.target.closest('a')) drawer.close();
  });
  compact.addEventListener('change', () => {
    if (!compact.matches && drawer.open) drawer.close();
  });
  document.documentElement.classList.add('navigation-ready');
})();

(() => {
  const notice = document.querySelector('[data-update-notice] a');
  const panel = document.querySelector('[data-update-phase]');
  if (!notice && !panel) return;
  const pending = ['queued', 'checking', 'install_queued', 'installing'];
  const refresh = Boolean(panel && pending.includes(panel.dataset.updatePhase));
  const route = '/settings/updates';
  let attempts = refresh ? 150 : 18;

  async function check(automatic) {
    try {
      const response = automatic
        ? await fetch(route, { method: 'POST', body: new URLSearchParams({ action: 'auto' }) })
        : await fetch(route + '/status');
      if (response.redirected || response.status === 401 || response.status === 403) return;
      if (response.ok) {
        const { phase, available } = await response.json();
        if (notice) notice.hidden = !available || pending.includes(phase);
        if (!pending.includes(phase)) {
          if (refresh || (panel && !automatic)) location.reload();
          return;
        }
      }
    } catch {
      // The web service may be restarting while APT replaces the package.
    }
    if (--attempts > 0) setTimeout(() => check(false), refresh ? 7000 : 5000);
  }

  check(!refresh);
})();

(() => {
  const table = document.querySelector('[data-image-progress-table]');
  const activeRows = '[data-state="pending"], [data-state="downloading"]';
  if (!table?.querySelector(activeRows)) return;

  const url = new URL('/api/images-status', location.origin);
  url.search = location.search;

  async function poll() {
    try {
      const response = await fetch(url, { cache: 'no-store' });
      if (response.redirected || [401, 403, 404].includes(response.status)) return;
      if (response.ok) {
        const next = new DOMParser().parseFromString(await response.text(), 'text/html')
          .querySelector('[data-image-progress-table]');
        if (!next) return;
        for (const row of next.querySelectorAll('[data-image-id]')) {
          const current = table.querySelector(`[data-image-id="${CSS.escape(row.dataset.imageId)}"]`);
          if (!current) continue;
          current.dataset.state = row.dataset.state;
          for (const column of ['[data-download-status]', '[data-download-percent]']) {
            current.querySelector(column).textContent = row.querySelector(column).textContent;
          }
        }
        if (!next.querySelector(activeRows)) return;
      }
    } catch {
      // Keep the last known progress visible during a temporary outage.
    }
    setTimeout(poll, 2500);
  }

  setTimeout(poll, 1000);
})();
