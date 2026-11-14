<?php
$diagnosis = \Admin\Util\PxeHttpReadiness::diagnose();
if ($diagnosis['state'] !== 'ready'):
    \Admin\View::partial('_partials/pxe-http-status', ['diagnosis' => $diagnosis]);
    if (getenv('PXE_SERVICE_MANAGER') === 'systemd' && \Admin\Auth::user() !== null):
?>
<p><a href="/init/port-80">Vérifier le port HTTP de démarrage</a></p>
<?php endif; endif; ?>
