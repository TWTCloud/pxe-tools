<?php
use Admin\View; use Admin\Ui\DeviceTerminology as Term;

$step      = $step ?? 4;
$title     = 'Systèmes d\'exploitation';
$wide      = true;   // le picker (tableau version × arch) a besoin de plus de place que 640px

/** @var array $distros */
/** @var array $grouped */
/** @var array $counts */
$totalEntries = array_sum($counts);

$contentRender = function () use ($distros, $grouped, $counts, $totalEntries) {
?>
  <header><h2 style="margin:0;">Systèmes d'exploitation</h2></header>

  <p class="muted">
    Cochez les versions à télécharger ; vous pourrez compléter ce choix dans
    <strong>Paramètres › Systèmes</strong>. La version actuelle de <strong>Debian</strong>
    est toujours incluse : <?= View::e(Term::format('elle sert à la découverte et au dépannage des {many}.')) ?>
  </p>

  <?php if ($totalEntries === 0): ?>
    <p class="muted">
      <?= View::icon('package') ?>
      Le catalogue se met à jour en arrière-plan (cela peut prendre jusqu'à une
      minute) — vous pourrez choisir des versions précises depuis
      <strong>Paramètres › Systèmes</strong> une fois prêt. En attendant, Debian
      (version actuelle) sera préparée automatiquement.
    </p>
    <form method="post" action="/init/images">
      <div class="wizard-actions">
        <a href="/init/network" class="btn btn-secondary"><span class="btn-arrow">←</span> Retour</a>
        <button type="submit" class="btn btn-primary">Continuer <span class="btn-arrow">→</span></button>
      </div>
    </form>
  <?php else: ?>
    <?php View::partial('_partials/os-picker-form', [
        'distros'            => $distros,
        'grouped'            => $grouped,
        'counts'             => $counts,
        'form_action'        => '/init/images',
        'submit_label'       => 'Continuer <span class="btn-arrow">→</span>',
        'submit_class'       => 'btn btn-primary',
        'require_selection'  => false,
        'back_href'          => '/init/network',
        'empty_tab_hint'     => 'Le catalogue se met à jour en arrière-plan — vous pourrez ajouter cette version plus tard depuis Paramètres › Systèmes.',
    ]); ?>
  <?php endif; ?>
<?php };
include __DIR__ . '/_layout.php';
