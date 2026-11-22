<?php
// $conflictOnly (assistant) : avant l'activation PXE, un port libre, en démarrage
// ou indéterminé est attendu ; seul un conflit demande une action.
$diagnosis = \Admin\Util\PxeHttpReadiness::diagnose();
$visible = ($conflictOnly ?? false)
    ? $diagnosis['state'] === 'conflict'
    : !in_array($diagnosis['state'], ['ready', 'not_configured'], true);
if ($visible):
    \Admin\View::partial('_partials/pxe-http-status', ['diagnosis' => $diagnosis]);
    if (getenv('PXE_SERVICE_MANAGER') === 'systemd' && \Admin\Auth::user() !== null):
?>
<p><a href="/init/port-80">Vérifier le port HTTP de démarrage</a></p>
<?php endif; endif; ?>
