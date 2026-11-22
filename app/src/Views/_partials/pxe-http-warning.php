<?php
// Bandeau commun à l'assistant et à la console : seul un conflit demande une
// action. Les autres états restent visibles dans la Vue d'ensemble et sur la
// page de diagnostic /init/port-80.
$diagnosis = \Admin\Util\PxeHttpReadiness::diagnose();
if ($diagnosis['state'] === 'conflict'):
    \Admin\View::partial('_partials/pxe-http-status', ['diagnosis' => $diagnosis]);
    if (getenv('PXE_SERVICE_MANAGER') === 'systemd' && \Admin\Auth::user() !== null):
?>
<p><a href="/init/port-80">Vérifier le port HTTP de démarrage</a></p>
<?php endif; endif; ?>
