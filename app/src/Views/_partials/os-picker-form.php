<?php
use Admin\View;
use Admin\Catalog\DistroCatalogInterface;
/**
 * Picker OS riche (onglets par distro, tableau version × arch) — partagé
 * entre Paramètres › Systèmes (settings/images/add.php) et l'étape 4 du
 * wizard d'onboarding (init/wizard/images.php). Mécanique identique dans les
 * deux contextes ; seule la destination du submit et sa disponibilité
 * changent (le wizard ne doit jamais bloquer la progression, même sans
 * sélection — cf. $require_selection).
 *
 * @var array<string, DistroCatalogInterface> $distros
 * @var array<string, array<int, array<string, array{codename:?string, channel:?string, archs:array<string,array<string,mixed>>}>>> $grouped
 * @var array<string, int> $counts
 * @var string $form_action
 * @var string $submit_label       HTML autorisé (ex : icône + texte).
 * @var string $submit_class
 * @var bool   $require_selection  Si false, le bouton submit reste actif même
 *                                 à 0 ligne cochée (skip explicitement permis).
 * @var string $empty_tab_hint     Message affiché dans un onglet dont le
 *                                 catalogue n'a encore aucune entrée.
 * @var ?string $back_href         Si fourni (wizard), la barre d'actions passe
 *                                 en pied de formulaire avec un bouton Retour,
 *                                 comme les autres étapes de l'assistant.
 */
$submit_label      = $submit_label ?? (View::icon('download') . ' Télécharger sélection');
$submit_class      = $submit_class ?? 'btn btn-secondary';
$require_selection = $require_selection ?? true;
$empty_tab_hint    = $empty_tab_hint ?? null;
$back_href         = $back_href ?? null;

// Premier onglet = distro qui a le plus d'entrées en cache, à égalité la première
// dans l'ordre du catalogue (Debian en tête). Sinon « debian » par défaut.
$defaultTab = 'debian';
$defaultCount = 0;
foreach (array_keys($distros) as $code) {
    if (($counts[$code] ?? 0) > $defaultCount) {
        $defaultCount = $counts[$code];
        $defaultTab = $code;
    }
}
$tabActive = static fn(string $code): string => $code === $defaultTab ? ' active' : '';
$tabHidden = static fn(string $code): string => $code === $defaultTab ? '' : ' hidden';

$renderActionBar = static function (string $placementClass) use ($back_href, $submit_class, $submit_label, $require_selection): void { ?>
  <div class="picker-action-bar<?= $placementClass ?>">
    <span class="picker-count-label">
      <span id="picker-count" aria-live="polite">0</span> image(s) sélectionnée(s)
    </span>
    <div class="picker-action-buttons">
      <?php if ($back_href !== null): ?>
        <a href="<?= View::e($back_href) ?>" class="btn btn-secondary"><span class="btn-arrow">←</span> Retour</a>
      <?php endif; ?>
      <button type="submit" id="picker-submit" class="<?= View::e($submit_class) ?>"<?= $require_selection ? ' disabled' : '' ?>>
        <?= $submit_label ?>
      </button>
    </div>
  </div>
<?php };
?>
<form method="post" action="<?= View::e($form_action) ?>" id="picker-form" data-require-selection="<?= $require_selection ? '1' : '0' ?>">
  <?php if ($back_href === null) $renderActionBar(''); ?>

  <div class="scroll-strip" data-scroll-strip>
    <button type="button" class="scroll-strip__nav scroll-strip__nav--prev" data-scroll-strip-nav="prev" tabindex="-1" aria-hidden="true">
      <?= View::icon('chevron-left') ?>
    </button>
    <nav class="tabs picker-tabs scroll-strip__track" data-scroll-strip-track aria-label="Filtrer le catalogue par distribution">
      <?php foreach ($distros as $code => $d):
        $n = $counts[$code] ?? 0;
      ?>
        <button type="button" aria-pressed="<?= $code === $defaultTab ? 'true' : 'false' ?>" aria-controls="catalog-<?= View::e($code) ?>"
           class="tab<?= $tabActive($code) ?>" data-tab="<?= View::e($code) ?>">
          <?= View::distroLogo($code) ?>
          <?= View::e($d->label()) ?>
          <?php if ($n > 0): ?>
            <span class="picker-tab-count"><?= $n ?></span>
          <?php endif; ?>
        </button>
      <?php endforeach; ?>
    </nav>
    <button type="button" class="scroll-strip__nav scroll-strip__nav--next" data-scroll-strip-nav="next" tabindex="-1" aria-hidden="true">
      <?= View::icon('chevron-right') ?>
    </button>
  </div>

  <?php foreach ($distros as $code => $d): ?>
    <div id="catalog-<?= View::e($code) ?>" data-tab-content="<?= View::e($code) ?>"<?= $tabHidden($code) ?>>
      <?php View::partial('settings/images/_picker_tab', [
          'distro_code'     => $code,
          'distro_label'    => $d->label(),
          'archs'           => $d->archs(),
          'majors'          => $grouped[$code] ?? [],
          'empty_tab_hint'  => $empty_tab_hint,
      ]); ?>
    </div>
  <?php endforeach; ?>

  <?php if ($back_href !== null) $renderActionBar(' picker-action-bar--footer'); ?>
</form>

<script src="/scroll-strip.js?v=<?= @filemtime(__DIR__ . '/../../../public/scroll-strip.js') ?: time() ?>" defer></script>
<script>
(() => {
  // ----- Tabs (réutilise le pattern de machines/show.php) -----
  const tabs  = document.querySelectorAll('.picker-tabs .tab[data-tab]');
  const panes = document.querySelectorAll('[data-tab-content]');
  const activateTab = (id) => {
    tabs.forEach(t => { t.classList.toggle('active', t.dataset.tab === id); t.setAttribute('aria-pressed', String(t.dataset.tab === id)); });
    panes.forEach(p => { p.hidden = p.dataset.tabContent !== id; });
  };
  document.addEventListener('click', e => {
    const el = e.target.closest('.picker-tabs [data-tab]');
    if (!el) return;
    e.preventDefault();
    activateTab(el.dataset.tab);
    history.replaceState(null, '', '#' + el.dataset.tab);
  });
  const hash = location.hash.replace('#', '');
  if (hash && [...tabs].some(t => t.dataset.tab === hash)) activateTab(hash);

  // ----- Master toggles + compteur -----
  const form    = document.getElementById('picker-form');
  if (!form) return;
  const count   = document.getElementById('picker-count');
  const submit  = document.getElementById('picker-submit');
  const requireSelection = form.dataset.requireSelection === '1';

  const refresh = () => {
    const rows = form.querySelectorAll('input.picker-row-check:checked').length;
    count.textContent = rows;
    if (requireSelection) submit.disabled = rows === 0;

    // Pour chaque master : indeterminate si row checks ne sont pas tous = master state.
    form.querySelectorAll('input.picker-master-check').forEach(m => {
      const sel = `input.picker-row-check[data-distro="${m.dataset.distro}"][data-major="${m.dataset.major}"][data-arch="${m.dataset.arch}"]`;
      const rowChecks = form.querySelectorAll(sel);
      if (rowChecks.length === 0) return;
      const checked = [...rowChecks].filter(c => c.checked).length;
      if (checked === 0) {
        m.checked = false; m.indeterminate = false;
      } else if (checked === rowChecks.length) {
        m.checked = true; m.indeterminate = false;
      } else {
        m.checked = false; m.indeterminate = true;
      }
    });
  };

  // Master toggle → propage à toutes les row checks
  form.addEventListener('change', e => {
    const m = e.target.closest('input.picker-master-check');
    if (m) {
      const sel = `input.picker-row-check[data-distro="${m.dataset.distro}"][data-major="${m.dataset.major}"][data-arch="${m.dataset.arch}"]`;
      form.querySelectorAll(sel).forEach(c => { c.checked = m.checked; });
    }
    refresh();
  });

  refresh();
})();
</script>
