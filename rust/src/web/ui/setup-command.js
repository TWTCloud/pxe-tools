// SPDX-License-Identifier: LGPL-3.0-only
(() => {
  const fragment = new URLSearchParams(location.hash.slice(1));
  if (fragment.has('code')) {
    history.replaceState(history.state, '', location.pathname + location.search);
    const [code, duplicate] = fragment.getAll('code');
    if (duplicate === undefined && /^(?:[a-f0-9]{4}(?:-[a-f0-9]{4}){2}|[a-f0-9]{12}|[a-f0-9]{48})$/i.test(code)) {
      const next = document.getElementById('setup-continue');
      const input = document.getElementById('setup-code');
      if (next) next.hash = 'code=' + encodeURIComponent(code);
      if (input) {
        input.value = code;
        document.getElementById('setup-code-prefilled').hidden = false;
      }
    }
  }

  const field = document.getElementById('setup-command');
  const button = document.getElementById('copy-setup-command');
  const feedback = document.getElementById('setup-command-feedback');
  if (!field || !button || !feedback) return;

  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(field.value);
      feedback.textContent = 'Commande copiée.';
    } catch {
      field.focus();
      field.select();
      feedback.textContent = 'Commande sélectionnée. Vous pouvez la copier.';
    }
  });
  button.hidden = false;
})();
