<?php
use Admin\View;
$title = 'HTTP de démarrage';
$contentRender = function () use ($job, $diagnosis, $nonce, $missingConsent, $identityUnavailable) {
    $state = $diagnosis['state'];
?>
<h2>HTTP de démarrage sur le port 80</h2>
<p>Les machines téléchargent leurs fichiers de démarrage sur le port 80. La console d’administration utilise son propre port, généralement 8080.</p>
<?php View::partial('_partials/pxe-http-status', ['diagnosis' => $diagnosis]); ?>
<?php if ($diagnosis['address'] !== ''): ?><p>Adresse vérifiée : <code><?= View::e($diagnosis['address']) ?>:80</code>, ainsi que l’accès local nécessaire au service.</p><?php endif; ?>
<?php if ($diagnosis['listeners'] !== []): ?><p>Écoutes concernées : <?= View::e(implode(', ', array_map(static fn(array $listener): string => ($listener['family'] === 6 ? '[' . $listener['address'] . ']' : $listener['address']) . ':80', $diagnosis['listeners']))) ?>.</p><?php endif; ?>
<?php if ($identityUnavailable): ?><p class="flash flash-warning" role="alert">L’occupant du port a changé ou son identité ne peut plus être vérifiée. Aucune action n’a été demandée. Examinez le nouveau diagnostic.</p><?php endif; ?>
<?php if ($missingConsent): ?><p class="flash flash-warning" role="alert">L’arrêt nécessite votre confirmation explicite. Aucune action n’a été demandée.</p><?php endif; ?>
<?php if (is_array($job)): ?>
<p>Dernière demande : <a href="/jobs/<?= (int)$job['id'] ?>"><?= View::e((string)$job['status']) ?></a>.</p>
<?php if (in_array($job['status'], ['pending', 'running'], true)): ?><p>Rechargez cette page pour actualiser le diagnostic et le résultat.</p><?php endif; ?>
<?php if ($job['status'] === 'failed'): ?><p>La demande a échoué ou a été refusée. Consultez son résultat avant toute autre intervention.</p><?php endif; ?>
<?php if ($job['status'] === 'success'): ?><p>L’arrêt demandé a été confirmé à la fin du traitement. Le diagnostic ci-dessus décrit l’état actuel ; l’activation de PXE reste une décision distincte.</p><?php endif; ?>
<?php endif; ?>
<?php if ($nonce !== null): ?>
<h3>Arrêter temporairement nginx.service</h3>
<p>Le service <strong>nginx.service</strong> occupe l’adresse nécessaire à PXE Tools. Son arrêt interrompra tous les sites et services qu’il dessert. Ses fichiers et son démarrage automatique seront conservés : il peut redémarrer au prochain démarrage de l’hôte.</p>
<form method="post" action="/init/port-80">
<input type="hidden" name="preview" value="<?= View::e($nonce) ?>">
<label><input type="checkbox" name="confirm_stop_nginx" value="1" required> Je confirme l’arrêt temporaire de nginx.service et l’interruption des sites qu’il dessert.</label>
<button type="submit" class="btn btn-danger">Vérifier à nouveau puis arrêter nginx.service</button>
</form>
<p class="muted">Pour remettre ce service en route manuellement après avoir arrêté le service HTTP PXE : <code>sudo systemctl start nginx.service</code>.</p>
<?php elseif (in_array($state, ['unknown', 'conflict'], true)): ?>
<p>Les droits actuels ne permettent pas de proposer un arrêt vérifié, ou le service concerné ne correspond pas à l’action prévue. Un administrateur peut examiner <code>sudo ss -ltnp '( sport = :80 )'</code> et l’unité systemd concernée. Décidez ensuite s’il faut conserver ce service, changer son adresse d’écoute ou l’arrêter temporairement.</p>
<?php endif; ?>
<p><a href="/init/port-80">Actualiser le diagnostic</a> · <a href="/init/network">Retour à la configuration réseau</a></p>
<?php };
include __DIR__ . '/_layout.php';
