<?php
use Admin\View; use Admin\Ui\DeviceTerminology as Term;
$title = 'Bienvenue';
$centerOnPage = true;
$contentRender = function () { ?>
  <img class="wizard-brand" src="/favicon.svg" alt="" width="56" height="56">
  <h2 style="margin-top:0;text-align:center;">Bienvenue sur PXE Tools</h2>

  <p style="text-align:center;">
    <?= View::e(Term::format('Cet outil installe et gère des systèmes d’exploitation sur vos {many}')) ?>
    directement par le réseau, sans clé USB ni DVD. Tout se fait automatiquement,
    en démarrage sécurisé, depuis cette interface.
  </p>

  <div class="wizard-actions actions-center">
    <a href="/init/db" class="btn btn-primary">Commencer <span class="btn-arrow">→</span></a>
  </div>
<?php };
include __DIR__ . '/_layout.php';
