// SPDX-License-Identifier: LGPL-3.0-only
(() => {
  const field = document.getElementById('setup-command');
  const button = document.getElementById('copy-setup-command');
  const feedback = document.getElementById('setup-command-feedback');

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
