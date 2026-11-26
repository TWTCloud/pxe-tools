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
  const route = '/settings/updates';
  const actions = panel?.querySelectorAll('[data-update-action]') ?? [];
  const progress = panel?.querySelector('[data-update-progress]');
  const message = panel?.querySelector('[data-update-message]');
  const deadline = Date.now() + (panel ? 26 * 60_000 : 90_000);
  let phase = panel?.dataset.updatePhase;
  let submitting = false;

  function announce(text) {
    progress.hidden = false;
    if (message.textContent !== text) message.textContent = text;
  }

  for (const action of actions) {
    action.addEventListener('submit', event => {
      if (submitting || pending.includes(phase)) {
        event.preventDefault();
        return;
      }
      submitting = true;
      for (const form of actions) form.querySelector('button').disabled = true;
      const installing = action.dataset.updateAction === 'install';
      panel.querySelector('[data-update-title]').textContent =
        installing ? 'Installation en cours' : 'Vérification en cours';
      panel.querySelector('[data-update-description]').textContent =
        installing ? 'La console se reconnecte après le redémarrage des services.' : '';
      announce(installing ? 'Installation planifiée…' : 'Vérification planifiée…');
    });
  }

  function stop(messageText) {
    if (!panel || !pending.includes(phase)) return;
    progress.querySelector('[role=progressbar]').hidden = true;
    announce(messageText);
  }

  async function poll(automatic) {
    if (submitting) return;
    try {
      const response = automatic
        ? await fetch(route, { method: 'POST', body: new URLSearchParams({ action: 'auto' }) })
        : await fetch(route + '/status', { cache: 'no-store' });
      if (response.redirected || [401, 403].includes(response.status)) {
        stop('Reconnectez-vous pour consulter le résultat de la mise à jour.');
        return;
      }
      if (response.ok) {
        const update = await response.json();
        if (notice) notice.hidden = !update.available || pending.includes(update.phase);
        if (panel && pending.includes(phase)) {
          if (!pending.includes(update.phase)) {
            location.reload();
            return;
          }
          phase = update.phase;
          announce(update.message);
        }
        if (!pending.includes(update.phase)) return;
      }
    } catch {
      // The HTTP service can be temporarily unavailable while APT replaces it.
      if (panel && phase === 'installing') announce('Reconnexion à la console…');
    }
    if (Date.now() < deadline) setTimeout(() => poll(false), 5000);
    else stop('La console attend encore une réponse. Actualisez l’état pour reprendre le suivi.');
  }

  if (notice || pending.includes(phase)) poll(Boolean(notice));
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
  const form = document.querySelector('[data-catalog-selection]');
  if (!form) return;
  const submit = form.querySelector('button[type="submit"]');
  function update() {
    const count = form.querySelectorAll('input[name="image"]:checked').length;
    submit.disabled = count === 0;
    submit.textContent = count ? `Télécharger la sélection (${count})` : 'Télécharger la sélection';
  }
  form.addEventListener('change', update);
  window.addEventListener('pageshow', update);
  update();
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

(() => {
  const panel = document.querySelector('[data-media-job]');
  if (!panel) return;

  async function refresh() {
    try {
      const response = await fetch(panel.dataset.mediaJob, { cache: 'no-store' });
      if (response.redirected || [401, 403, 404].includes(response.status)) return;
      if (response.ok) {
        const { status, message, progress_percent } = await response.json();
        if (status !== panel.dataset.mediaState) {
          location.reload();
          return;
        }
        const label = panel.querySelector('[role="status"]');
        if (message && message !== label.textContent) label.textContent = message;
        panel.querySelector('progress').value = progress_percent;
        panel.querySelector('span').textContent = progress_percent + ' %';
      }
    } catch {
      // Keep showing the last reported progress until the console responds again.
    }
    setTimeout(refresh, 2500);
  }

  setTimeout(refresh, 1000);
})();
