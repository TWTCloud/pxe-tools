// Bandeau horizontal à flèches pour les listes d'onglets qui débordent.
// La barre de défilement native est masquée : une flèche et un fondu
// apparaissent seulement du côté où des éléments restent cachés.
(() => {
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const scrollBehavior = () => (reducedMotion.matches ? 'auto' : 'smooth');

  const enhance = (strip) => {
    const track = strip.querySelector('[data-scroll-strip-track]');
    if (!track) return;

    const syncOverflow = () => {
      const maxScroll = track.scrollWidth - track.clientWidth;
      strip.toggleAttribute('data-overflow-start', track.scrollLeft > 1);
      strip.toggleAttribute('data-overflow-end', track.scrollLeft < maxScroll - 1);
    };

    // Ne fait défiler que le bandeau : scrollIntoView() déplacerait aussi la page.
    const reveal = (item, behavior) => {
      const inset = parseFloat(getComputedStyle(track).scrollPaddingInlineStart) || 0;
      const trackBox = track.getBoundingClientRect();
      const itemBox = item.getBoundingClientRect();
      let delta = 0;
      if (itemBox.left < trackBox.left + inset) delta = itemBox.left - trackBox.left - inset;
      else if (itemBox.right > trackBox.right - inset) delta = itemBox.right - trackBox.right + inset;
      if (delta !== 0) track.scrollBy({ left: delta, behavior });
    };

    strip.addEventListener('click', (event) => {
      const arrow = event.target.closest('[data-scroll-strip-nav]');
      if (arrow) {
        const direction = arrow.dataset.scrollStripNav === 'prev' ? -1 : 1;
        track.scrollBy({ left: direction * track.clientWidth * 0.8, behavior: scrollBehavior() });
        return;
      }
      const item = event.target.closest('button, a');
      if (item && track.contains(item)) reveal(item, scrollBehavior());
    });

    let pendingFrame = 0;
    track.addEventListener('scroll', () => {
      if (pendingFrame) return;
      pendingFrame = requestAnimationFrame(() => { pendingFrame = 0; syncOverflow(); });
    }, { passive: true });
    // Les onglets s'élargissent après coup (police web, logos chargés en lazy)
    // sans que le bandeau change de taille : on observe aussi chaque élément.
    const resizeObserver = new ResizeObserver(syncOverflow);
    resizeObserver.observe(track);
    for (const item of track.children) resizeObserver.observe(item);

    const current = track.querySelector('.active, [aria-current="page"]');
    if (current) {
      reveal(current, 'auto');
      // La police web élargit les onglets après ce premier calcul.
      document.fonts?.ready.then(() => reveal(current, 'auto'));
    }
    syncOverflow();
  };

  document.querySelectorAll('[data-scroll-strip]').forEach(enhance);
})();
