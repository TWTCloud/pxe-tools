<?php
use Admin\View;
use Admin\Models\Setting;
$step = $step ?? 5;
$stepLabel = 'Validation';
$title = 'Validation';
$contentRender = function () use ($step, $stepLabel) {
    include __DIR__ . '/_progress.php';
    $enabled = Setting::get(Setting::KEY_PXE_ENABLED, 'on') === 'on';
    $proxy = Setting::get(Setting::KEY_DHCP_PROXY_ENABLED, 'off') === 'on';
?>
<h2>Confirmer la configuration</h2>
<p><?= $enabled ? 'La console est configurée. En terminant, vous demandez le démarrage des services PXE sur le réseau ci-dessous.' : 'La console est configurée. En terminant, vous gardez les services de démarrage PXE arrêtés.' ?></p>
<dl>
  <dt>Interface réseau</dt><dd><code><?= View::e(Setting::get(Setting::KEY_PXE_INTERFACE, '') ?: 'À configurer avant l’activation PXE') ?></code></dd>
  <dt>Adresse du serveur</dt><dd><code><?= View::e(Setting::get(Setting::KEY_PXE_IP, '') ?: 'À configurer') ?></code></dd>
  <dt>Réseau autorisé</dt><dd><code><?= View::e(Setting::get(Setting::KEY_PXE_SUBNET, '') ?: 'À configurer') ?></code></dd>
  <dt>Démarrage réseau</dt><dd><?= !$enabled ? 'Désactivé — console uniquement' : ($proxy ? 'À activer avec le DHCP existant — proxy DHCP sans attribution d’adresses' : 'À activer avec votre DHCP déjà configuré — HTTP et TFTP, sans proxy DHCP') ?></dd>
  <dt>Console d’administration</dt><dd><?= Setting::get(Setting::KEY_HTTPS_ENABLED, 'off') === 'on' ? 'HTTPS après application' : 'HTTP local ou chiffrement par votre reverse proxy' ?></dd>
</dl>
<p class="muted"><?= $enabled ? 'Le résultat des traitements confirmera l’application de la configuration. Il faudra ensuite vérifier une image disponible et le démarrage d’une machine sur ce réseau ; la fin de l’assistant ne prouve pas à elle seule que PXE fonctionne.' : 'Vous pourrez activer PXE dans Paramètres › Réseau PXE, puis appliquer la configuration. Les systèmes peuvent être téléchargés pendant que vous préparez le réseau.' ?></p>
<form method="post" action="/init/complete">
  <div class="wizard-actions">
    <a href="/init/images" class="btn btn-secondary">Retour</a>
    <button type="submit" class="btn btn-primary"><?= $enabled ? 'Terminer et activer les services PXE' : 'Terminer avec la console uniquement' ?></button>
  </div>
</form>
<?php };
include __DIR__ . '/_layout.php';
