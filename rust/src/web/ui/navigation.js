// SPDX-License-Identifier: LGPL-3.0-only
(() => {
  const drawer = document.getElementById('mobile-navigation');
  const trigger = document.querySelector('.mobile-toggle');
  if (typeof drawer?.showModal !== 'function' || !trigger) return;

  const compact = matchMedia('(max-width: 920px)');
  trigger.addEventListener('click', () => {
    drawer.showModal();
    trigger.setAttribute('aria-expanded', 'true');
  });
  drawer.addEventListener('close', () => {
    trigger.setAttribute('aria-expanded', 'false');
    const profile = drawer.querySelector('.profile-menu[open]');
    if (profile) profile.open = false;
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
  const menus = document.querySelectorAll('.profile-menu');
  for (const menu of menus) {
    menu.addEventListener('keydown', event => {
      if (event.key !== 'Escape' || !menu.open) return;
      event.preventDefault();
      event.stopPropagation();
      menu.open = false;
      menu.querySelector('summary').focus();
    });
    menu.addEventListener('focusout', event => {
      if (event.relatedTarget && !menu.contains(event.relatedTarget)) menu.open = false;
    });
  }
  document.addEventListener('pointerdown', event => {
    for (const menu of menus) {
      if (!menu.contains(event.target)) menu.open = false;
    }
  });
})();

(() => {
  const notice = document.querySelector('[data-update-notice] a');
  const panel = document.querySelector('[data-update-phase]');
  if (!notice && !panel) return;
  const pending = ['queued', 'checking', 'install_queued', 'installing'];
  let refresh = Boolean(panel && pending.includes(panel.dataset.updatePhase));
  const route = '/settings/updates';
  let attempts = panel ? 150 : 18;
  const form = panel?.querySelector('[data-update-check]');
  const progress = panel?.querySelector('[data-update-progress]');
  const message = progress?.querySelector('[data-update-message]');
  const button = form?.querySelector('button');
  let submitting = false;
  let observedPending = refresh;

  function showCheck() {
    progress.hidden = false;
    form?.setAttribute('aria-busy', 'true');
    button?.setAttribute('aria-disabled', 'true');
  }

  form?.addEventListener('submit', event => {
    if (submitting || observedPending) {
      event.preventDefault();
      return;
    }
    submitting = true;
    showCheck();
  });

  async function check(automatic) {
    try {
      const response = automatic
        ? await fetch(route, { method: 'POST', body: new URLSearchParams({ action: 'auto' }) })
        : await fetch(route + '/status', { cache: 'no-store' });
      if (response.redirected || response.status === 401 || response.status === 403) return;
      if (response.ok) {
        const { phase, available } = await response.json();
        if (notice) notice.hidden = !available || pending.includes(phase);
        if (!pending.includes(phase)) {
          if (panel && observedPending && !submitting) location.reload();
          return;
        }
        if (panel) {
          observedPending = true;
          refresh = true;
          showCheck();
          if (phase === 'install_queued' || phase === 'installing') {
            message.textContent = 'Installation des paquets en cours…';
          }
        }
      }
    } catch {
      // The web service may be restarting while APT replaces the package.
    }
    if (--attempts > 0) setTimeout(() => check(false), refresh ? 7000 : 5000);
    else if (panel && observedPending) {
      progress.querySelector('[role=progressbar]').hidden = true;
      message.textContent = 'La vérification de l’état attend une réponse. Actualisez cette page pour réessayer.';
      if (form) {
        const reload = document.createElement('a');
        reload.href = route;
        reload.textContent = 'Actualiser l’état';
        progress.append(reload);
      }
    }
  }

  check(!refresh);
})();

(() => {
  let section = document.querySelector('[data-image-progress]');
  const active = '[data-state="pending"], [data-state="downloading"], [data-state="deleting"]';
  if (!section?.querySelector(active)) return;

  const url = new URL('/api/images-status', location.origin);
  url.search = location.search;

  async function poll() {
    try {
      const response = await fetch(url, { cache: 'no-store' });
      if (response.redirected || [401, 403, 404].includes(response.status)) return;
      if (response.ok) {
        const next = new DOMParser().parseFromString(await response.text(), 'text/html')
          .querySelector('[data-image-progress]');
        if (!next) return;
        const rows = [...next.querySelectorAll('[data-image-id]')];
        const existing = [...section.querySelectorAll('[data-image-id]')];
        if (rows.map(row => row.dataset.imageId).join() !== existing.map(row => row.dataset.imageId).join()) {
          if (section.contains(document.activeElement)) {
            setTimeout(poll, 2500);
            return;
          }
          section.replaceWith(next);
          section = next;
        } else {
          for (const [index, row] of rows.entries()) {
            const current = existing[index];
            const stateChanged = current.dataset.state !== row.dataset.state;
            if (stateChanged && current.querySelector('[data-image-actions]')?.contains(document.activeElement)) {
              setTimeout(poll, 2500);
              return;
            }
            current.dataset.state = row.dataset.state;
            for (const part of ['[data-download-status]', '[data-image-details]', '[data-image-actions]']) {
              const source = row.querySelector(part);
              const target = current.querySelector(part);
              if (source && target && (part !== '[data-image-actions]' || stateChanged) &&
                  source.innerHTML !== target.innerHTML) {
                target.replaceChildren(...source.childNodes);
              }
            }
          }
        }
        if (!section.querySelector(active)) return;
      }
    } catch {
      // Keep the last known progress visible during a temporary outage.
    }
    setTimeout(poll, 2500);
  }

  setTimeout(poll, 1000);
})();

(() => {
  let list = document.getElementById('activity-list');
  const freshness = document.querySelector('[data-activity-refresh]');
  if (!list || !freshness) return;

  const url = new URL('/activity/list', location.origin);
  url.search = location.search;

  async function refresh() {
    try {
      if (!document.hidden && !list.contains(document.activeElement)) {
        url.searchParams.set('sig', list.dataset.sig);
        const response = await fetch(url, { cache: 'no-store' });
        if (response.redirected || [401, 403, 404].includes(response.status)) return;
        if (response.status === 200) {
          const next = new DOMParser().parseFromString(await response.text(), 'text/html')
            .getElementById('activity-list');
          if (next && !list.contains(document.activeElement)) {
            list.replaceWith(next);
            list = next;
          }
        }
        if (response.ok) {
          const utc = new Date().toISOString().slice(11, 19);
          freshness.textContent = `Dernière actualisation à ${utc} UTC`;
        }
      }
    } catch {
      // Leave the latest results visible and try again.
    }
    setTimeout(refresh, 5000);
  }

  setTimeout(refresh, 5000);
})();
