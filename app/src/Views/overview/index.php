<?php
use Admin\InitGuard;
use Admin\View;
$http = match ($overview['http_state']) {
    'ready' => ['Disponible', 'success', 'HTTP PXE répond sur l’adresse configurée'],
    'not_requested' => ['Non demandé', 'neutral', 'Démarrage désactivé dans la configuration ; état non confirmé'],
    'unexpected' => ['À vérifier', 'warning', 'HTTP PXE répond alors que le démarrage est désactivé dans la configuration'],
    'free' => ['Non disponible', 'warning', 'Aucun service HTTP PXE détecté sur le port 80'],
    'conflict' => ['Conflit', 'warning', 'Le port 80 est occupé par un autre service'],
    'starting' => ['Démarrage', 'neutral', 'Le service HTTP PXE démarre'],
    'not_configured' => ['À configurer', 'neutral', 'Adresse PXE non configurée'],
    default => ['Non confirmé', 'neutral', 'Le contrôle HTTP PXE ne permet pas de conclure'],
};
?>
<div class="overview">
  <h1 class="sr-only">Vue d’ensemble</h1>
  <div class="overview-summary" aria-label="Configuration réseau et images">
    <section class="overview-tile"><h2>Interface réseau</h2><strong><?= View::e($overview['interface'] ?: 'À configurer') ?></strong><span class="overview-mono"><?= View::e($overview['address'] ?: 'Adresse non renseignée') ?></span></section>
    <section class="overview-tile"><h2>Mode de démarrage</h2><strong><?= View::e($overview['mode']) ?></strong><span><?= $overview['mode'] === 'Proxy DHCP' ? 'Le DHCP existant attribue les adresses' : 'Configuration enregistrée' ?></span></section>
    <section class="overview-tile"><h2>Images de démarrage</h2><strong><?= (int)$overview['ready_count'] ?> disponible<?= $overview['ready_count'] > 1 ? 's' : '' ?></strong><a href="/settings/images">Gérer les images</a></section>
  </div>
  <div class="overview-panels">
    <section class="overview-panel" aria-labelledby="overview-services-title">
      <header><h2 id="overview-services-title">Services</h2><a href="/settings">Paramètres</a></header>
      <div class="overview-row"><strong>Console</strong><span>Cette page répond</span><span class="overview-state is-success">Accessible</span></div>
      <div class="overview-row"><strong>HTTP PXE</strong><span><?= View::e($http[2]) ?></span><span class="overview-state is-<?= View::e($http[1]) ?>"><?= View::e($http[0]) ?></span></div>
      <div class="overview-row"><strong>Proxy DHCP</strong><span>Configuration enregistrée</span><span class="overview-state is-neutral"><?= $overview['pxe_enabled'] === 'off' ? 'Non demandé' : ($overview['pxe_enabled'] !== 'on' ? 'Indéterminé' : ($overview['proxy_enabled'] === 'on' ? 'Demandé' : ($overview['proxy_enabled'] === 'off' ? 'Non demandé' : 'Indéterminé'))) ?></span></div>
      <div class="overview-row"><strong>Worker</strong><span>Acquisition et traitements</span><span class="overview-state is-neutral">Non confirmé</span></div>
      <p class="overview-note">La configuration du proxy ne confirme pas à elle seule que le service répond.</p>
    </section>
    <section class="overview-panel" aria-labelledby="overview-activity-title">
      <header><h2 id="overview-activity-title">Activité récente</h2><a href="/activity">Tout voir</a></header>
      <?php if ($overview['activity'] === []): ?><p class="overview-empty">Aucune opération enregistrée pour le moment.</p><?php else: ?>
      <ul class="overview-list"><?php foreach ($overview['activity'] as $item):
        $label = match ($item['type']) {
            'install', 'install_only', 'reinstall' => 'Installation', 'wipe', 'wipe_only' => 'Effacement des disques',
            'disktest' => 'Test des disques', 'discovery' => 'Inventaire',
            default => InitGuard::JOB_TITLES[$item['type']] ?? $item['type'],
        };
        $status = match ($item['status']) {
            'pending' => 'En attente', 'running' => 'En cours', 'success' => 'Réussie',
            'failed' => 'Échec', 'skipped' => 'Ignorée', 'cancelled', 'aborted' => 'Clôturée',
            default => (string)$item['status'],
        };
      ?><li><a href="<?= View::e($item['url']) ?>"><span><strong><?= View::e($label) ?></strong><small><?= View::e($item['target'] ?: 'Appliance') ?> · <?= View::e($status) ?></small></span><time><?= View::e($item['updated_at'] ?: '') ?> UTC</time></a></li><?php endforeach ?></ul>
      <?php endif ?>
    </section>
    <section class="overview-panel overview-panel-wide" aria-labelledby="overview-files-title">
      <header><h2 id="overview-files-title">Fichiers de démarrage</h2><a href="/settings/images">Gérer les images</a></header>
      <?php if ($overview['images'] === []): ?><p class="overview-empty">Aucune image demandée. <a href="/settings/images/add">Parcourir le catalogue</a></p><?php else: ?>
      <ul class="overview-files"><?php foreach ($overview['images'] as $image):
        $available = ($image['status'] ?? '') === 'downloaded' && !empty($image['files_available']);
        $enabled = (int)($image['enabled'] ?? 0) === 1;
        $state = match ((string)($image['status'] ?? '')) {
          'downloaded' => !$available ? 'Fichiers absents ou illisibles' : ($enabled ? 'Disponible' : 'Désactivée'),
          'downloading' => 'Téléchargement en cours', 'failed' => 'Échec du téléchargement',
          default => $enabled ? 'En attente' : 'Désactivée',
        };
        $label = ucfirst((string)$image['distro']) . ' ' . (($image['version_full'] ?? '') ?: $image['version']);
      ?><li><strong><?= View::e($label) ?></strong><code><?= View::e($image['arch']) ?></code><span class="overview-state is-<?= $available && $enabled ? 'success' : 'neutral' ?>"><?= View::e($state) ?></span></li><?php endforeach ?></ul>
      <?php endif ?>
    </section>
  </div>
</div>
