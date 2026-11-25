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
