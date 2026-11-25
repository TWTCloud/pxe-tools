// SPDX-License-Identifier: LGPL-3.0-only
(() => {
  const catalog = document.querySelector('[data-image-catalog]');
  const downloads = document.querySelector('[data-image-downloads]');
  const ready = document.querySelector('[data-image-ready]');
  const retry = document.querySelector('[data-image-retry]');
  const feedback = document.querySelector('[data-image-feedback]');
  let previousDownloads;

  function updateCatalog(state) {
    if (catalog.dataset.imageCatalog === state.catalog_version) return;
    const open = catalog.querySelector('details')?.open;
    const selected = new Set([...catalog.querySelectorAll('input:checked')].map(input => input.name));
    catalog.innerHTML = state.catalog;
    const choices = catalog.querySelector('details');
    if (choices && open) choices.open = true;
    for (const input of catalog.querySelectorAll('input[type="checkbox"]')) {
      if (selected.has(input.name)) input.checked = true;
    }
    catalog.dataset.imageCatalog = state.catalog_version;
  }

  async function poll() {
    try {
      const response = await fetch('/init/images/status', { cache: 'no-store' });
      if (response.redirected || [401, 403, 404].includes(response.status)) {
        feedback.textContent = 'Ouvrez de nouveau cette étape pour reprendre le suivi.';
        return;
      }
      if (!response.ok) throw new Error('État du téléchargement indisponible');
      const state = await response.json();
      updateCatalog(state);
      if (previousDownloads !== state.downloads) {
        downloads.innerHTML = state.downloads;
        previousDownloads = state.downloads;
      }
      ready.hidden = !state.ready;
      retry.hidden = !state.retry;
      feedback.textContent = '';
      if (!state.active) return;
    } catch {
      feedback.textContent = 'Le suivi est momentanément indisponible. Nouvelle tentative en cours…';
    }
    setTimeout(poll, 2000);
  }

  if (downloads.dataset.active === 'yes') setTimeout(poll, 1000);
})();
