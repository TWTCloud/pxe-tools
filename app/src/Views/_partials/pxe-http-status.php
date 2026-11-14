<?php
use Admin\View;
$state = $diagnosis['state'];
$message = match ($state) {
    'free' => 'Le port HTTP de démarrage est libre sur les adresses requises. Le service PXE n’est pas encore démarré.',
    'ready' => 'Le contrôle HTTP de démarrage reçoit la réponse attendue sur le port 80. Cela ne confirme pas encore un démarrage PXE complet.',
    'starting' => 'Le processus HTTP de PXE Tools écoute ; sa réponse de contrôle n’est pas encore confirmée.',
    'conflict' => 'Un autre service occupe une adresse nécessaire au HTTP de démarrage' . (!empty($diagnosis['service']) ? ' : ' . $diagnosis['service'] : '') . '.',
    'not_configured' => 'Le HTTP de démarrage n’est pas encore configuré. La console d’administration reste disponible sur son propre port.',
    default => 'L’état du port HTTP de démarrage est indéterminé. Les informations accessibles ne permettent pas de confirmer son fonctionnement ou un conflit.',
};
?>
<p class="<?= $state === 'conflict' ? 'flash flash-warning' : 'muted' ?>" <?= $state === 'conflict' ? 'role="status"' : '' ?>><?= View::e($message) ?></p>
