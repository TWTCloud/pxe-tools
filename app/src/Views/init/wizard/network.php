<?php
use Admin\View; use Admin\Ui\DeviceTerminology as Term;
use Admin\Util\NetworkDetector;
$step = $step ?? 3;
$stepLabel = 'Réseau';
$interfaces = $interfaces ?? [];
$current = $current ?? [];
$settingsFlow = $settingsFlow ?? false;
$errorMsg = match ($error ?? null) {
    'select_address' => Term::format('Choisissez une adresse détectée sur le réseau des {many}. Si elle a changé, rechargez cette page. Vous pouvez aussi préparer uniquement la console.'),
    'missing' => 'Renseignez l’interface et l’adresse dans les paramètres avancés, ou utilisez une adresse détectée.',
    'missing_subnet', 'invalid_subnet' => 'Indiquez le réseau autorisé au format IPv4/CIDR, par exemple 192.0.2.0/24.',
    'subnet_mismatch' => 'L’adresse du serveur n’appartient pas au réseau autorisé. Corrigez-le ou utilisez la confirmation avancée si ce routage est volontaire.',
    'invalid_ip' => 'L’adresse du serveur doit être une adresse IPv4 valide.',
    'missing_proxy', 'invalid_cidr' => 'Indiquez le réseau d’annonce du proxy DHCP au format IPv4/CIDR, par exemple 192.0.2.0/24.',
    'invalid_interface' => 'Le nom de l’interface réseau est invalide.',
    'unknown_interface' => 'Cette interface n’est pas détectée sur cet hôte. Choisissez une interface détectée ou vérifiez la configuration avancée.',
    'interface_ip_mismatch' => 'Cette adresse n’est pas affectée à l’interface choisie. Corrigez-la ou confirmez explicitement le cas avancé.',
    'network_mismatch' => 'L’adresse du serveur n’appartient pas au réseau d’annonce du proxy DHCP. Vérifiez le routage dans les paramètres avancés.',
    'save_failed' => 'La configuration n’a pas été enregistrée. Vérifiez la disponibilité de la base puis réessayez.',
    'confirm_network' => 'Vérifiez et enregistrez le réseau de cet hôte avant de continuer.',
    null => null,
    default => 'Choisissez un mode de configuration et une utilisation du démarrage réseau valides.',
};
$title = 'Réseau';
$contentRender = function () use ($interfaces, $current, $errorMsg, $step, $stepLabel, $settingsFlow) {
    if (!$settingsFlow) include __DIR__ . '/_progress.php';
    $choices = NetworkDetector::addressChoices($interfaces);
    $selected = null;
    foreach ($choices as $choice) if ($choice['value'] === ($current['network_address'] ?? '')) $selected = $choice;
    $manual = ($current['network_mode'] ?? 'detected') === 'manual';
    $role = $current['pxe_role'] ?? 'console';
?>
<style>
.network-section { margin-block: 1.75rem; }
.network-choice { display: grid; grid-template-columns: auto 1fr; column-gap: .65rem; margin-block: .85rem; align-items: start; }
.network-choice input { margin-top: .25rem; }
.network-choice small { display: block; margin-top: .2rem; font-weight: 400; }
.network-summary { display: grid; grid-template-columns: minmax(7rem, .8fr) minmax(0, 1.2fr); gap: .45rem 1rem; padding-block: .85rem; margin-block: .8rem; border-block: 1px solid var(--color-divider); }
.network-summary dt, .network-summary dd { margin: 0; overflow-wrap: anywhere; }
.network-summary dt { color: var(--color-text-secondary); }
.network-advanced summary { cursor: pointer; font-weight: 600; padding-block: .75rem; }
.network-advanced label { margin-block: .8rem; }
@media(max-width: 420px) { .network-summary { grid-template-columns: 1fr; gap: .2rem; } .network-summary dd { margin-bottom: .45rem; } }
</style>
<header><h2 style="margin:0"><?= View::e(Term::format('Le réseau de vos {many}')) ?></h2></header>
<p><?= View::e(Term::format('Choisissez la connexion utilisée par les {many} à installer.')) ?> L’adresse du serveur et leur réseau sont déduits de cette connexion.</p>
<?php if ($errorMsg): ?><p class="flash flash-error" id="network-error" tabindex="-1" role="alert" data-persistent><?= View::e($errorMsg) ?></p><?php endif; ?>
<form method="post" action="<?= $settingsFlow ? '/init/network?from=settings' : '/init/network' ?>" id="network-form">
  <section class="network-section" aria-label="Connexion réseau">
    <label class="network-choice"><input type="radio" name="network_mode" value="detected" <?= !$manual ? 'checked' : '' ?>><span>Utiliser le réseau détecté</span></label>
    <div id="network-detected" class="network-detected">
      <label for="network-address"><?= View::e(Term::format('Connexion vers les {many}')) ?></label>
      <select name="network_address" id="network-address" aria-describedby="network-detection-help">
        <option value="">Choisir une connexion et son adresse</option>
        <?php foreach ($choices as $choice): ?>
        <option value="<?= View::e($choice['value']) ?>" <?= $selected !== null && $choice['value'] === $selected['value'] ? 'selected' : '' ?>><?= View::e($choice['interface'] . ' · ' . $choice['address'] . ' · ' . $choice['type'] . ' · ' . ($choice['state'] === 'up' ? 'active' : 'inactive')) ?></option>
        <?php endforeach; ?>
      </select>
      <p class="muted" id="network-detection-help"><?= $choices === [] ? 'Aucune IPv4 utilisable n’est détectée. Branchez et configurez la connexion sur cet hôte, puis rechargez la page. La console peut être préparée dès maintenant.' : ($selected === null ? Term::format('Plusieurs connexions ou une interface particulière demandent votre choix. Sélectionnez celle qui rejoint le réseau local des {many}.') : Term::format('Vérifiez que cette connexion rejoint bien le réseau local des {many}. L’adresse doit rester stable pour retrouver ce serveur.')) ?></p>
      <dl class="network-summary" aria-label="Résumé du réseau détecté" aria-live="polite">
        <dt>Interface</dt><dd id="summary-interface"><?= View::e($selected['interface'] ?? 'À choisir') ?></dd>
        <dt>Adresse du serveur</dt><dd id="summary-ip"><?= View::e($selected['ip'] ?? 'À choisir') ?></dd>
        <dt><?= View::e(Term::format('Réseau des {many}')) ?></dt><dd id="summary-cidr"><?= View::e($selected['cidr'] ?? 'À choisir') ?></dd>
      </dl>
      <p id="interface-note" class="muted" role="status"></p>
    </div>
  </section>

  <fieldset class="network-section">
    <legend>Quand activer le démarrage réseau ?</legend>
    <label class="network-choice"><input type="radio" name="pxe_role" value="console" <?= $role === 'console' ? 'checked' : '' ?>><span>Plus tard — préparer la console<small class="muted">La console reste accessible. Les services de démarrage HTTP, TFTP et proxy DHCP de PXE Tools restent arrêtés après application.</small></span></label>
    <label class="network-choice"><input type="radio" name="pxe_role" value="proxy" <?= $role === 'proxy' ? 'checked' : '' ?>><span><?= View::e(Term::format('Permettre aux {many} de démarrer sur ce serveur')) ?><small class="muted">Cas courant avec une box ou un routeur : votre DHCP continue d’attribuer les adresses IP. PXE Tools fournit les indications de démarrage avec un proxy DHCP, sans distribuer d’adresses. Choisissez ce mode si votre DHCP n’annonce pas déjà un autre serveur PXE.</small></span></label>
    <label class="network-choice"><input type="radio" name="pxe_role" value="external" <?= $role === 'external' ? 'checked' : '' ?>><span>Mon réseau annonce déjà ce serveur PXE<small class="muted">Vous avez configuré les indications de démarrage sur votre DHCP. PXE Tools sert les fichiers HTTP et TFTP ; son proxy DHCP reste désactivé.</small></span></label>
    <p class="muted" id="network-activation-note"><?= $settingsFlow ? 'Enregistrer conserve ce choix. Utilisez ensuite « Appliquer la configuration » dans les paramètres pour démarrer ou arrêter ces services.' : 'Les services seront démarrés ou arrêtés après la validation finale de l’assistant. Enregistrer cette étape ne les active pas.' ?></p>
  </fieldset>

  <details class="network-section network-advanced" id="network-advanced" <?= $manual ? 'open' : '' ?>>
    <summary>Paramètres avancés et accès à la console</summary>
    <p class="muted">Pour un réseau routé, une adresse annoncée différente ou une configuration reprise d’un autre hôte. Vos valeurs sont conservées lorsque vous changez de mode.</p>
    <label class="network-choice"><input type="radio" name="network_mode" value="manual" <?= $manual ? 'checked' : '' ?>><span>Utiliser ces valeurs réseau manuelles</span></label>
    <label for="pxe-interface">Interface réseau<input name="pxe_interface" id="pxe-interface" list="detected-interface-names" value="<?= View::e($current['pxe_interface'] ?? '') ?>" placeholder="enp1s0"></label>
    <datalist id="detected-interface-names"><?php foreach ($interfaces as $interface): ?><option value="<?= View::e($interface['name']) ?>"><?= View::e(NetworkDetector::typeLabel($interface) . ' · ' . implode(', ', $interface['ipv4'])) ?></option><?php endforeach; ?></datalist>
    <label for="pxe-ip"><?= View::e(Term::format('Adresse du serveur annoncée aux {many}')) ?><input name="pxe_ip" id="pxe-ip" value="<?= View::e($current['pxe_ip'] ?? '') ?>" placeholder="192.0.2.10" inputmode="decimal"></label>
    <label for="pxe-subnet">Réseau des clients autorisés<input name="pxe_subnet" id="pxe-subnet" value="<?= View::e($current['pxe_subnet'] ?? '') ?>" placeholder="192.0.2.0/24"><small class="muted">Limite l’accès aux menus, aux configurations d’installation et aux signaux PXE.</small></label>
    <label for="dhcp-proxy-cidr">Réseau d’annonce du proxy DHCP<input name="dhcp_proxy_cidr" id="dhcp-proxy-cidr" value="<?= View::e($current['dhcp_proxy_cidr'] ?? '') ?>" placeholder="192.0.2.0/24"><small class="muted">Utilisé uniquement avec le proxy DHCP. Ce réseau d’annonce peut différer du réseau autorisé dans une installation routée ; il ne s’agit pas d’une réserve d’adresses à distribuer.</small></label>
    <label class="network-choice"><input type="checkbox" name="network_override" id="network-override" <?= !empty($current['network_override']) ? 'checked' : '' ?>><span>Autoriser des valeurs absentes de la détection<small class="muted">Je confirme que l’interface, l’adresse et le routage sont configurés sur cet hôte. Cette option permet l’enregistrement ; elle n’ajoute aucune adresse et ne crée aucune route. Les services vérifient encore leurs propres conditions de démarrage.</small></span></label>
    <button type="button" class="btn btn-secondary btn-sm" id="copy-detected-network">Copier le réseau détecté dans ces champs</button>
    <fieldset class="network-section">
      <legend>Accès à la console</legend>
      <label class="network-choice"><input type="checkbox" name="https_enabled" id="https-enabled" <?= !empty($current['https_enabled']) ? 'checked' : '' ?>><span>Activer HTTPS sur le port <?= (int)(getenv('ADMIN_PORT') ?: 8443) ?><small class="muted">Après application, le port HTTP <?= (int)(getenv('ADMIN_HTTP_PORT') ?: 8080) ?> redirige vers HTTPS. Le certificat auto-signé doit être vérifié. <?= View::e(Term::format('Le port 80 utilisé pour le démarrage des {many} est distinct de la console.')) ?></small></span></label>
    </fieldset>
  </details>
  <div class="wizard-actions">
    <a href="<?= $settingsFlow ? '/settings' : '/init/admin' ?>" class="btn btn-secondary"><?= $settingsFlow ? 'Retour aux paramètres' : 'Retour' ?></a>
    <button type="submit" class="btn btn-primary"><?= $settingsFlow ? 'Enregistrer' : 'Continuer' ?></button>
  </div>
</form>
<script>
(function () {
  const choices = <?= json_encode(array_column($choices, null, 'value'), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
  const form = document.getElementById('network-form');
  const select = document.getElementById('network-address');
  function update() {
    const choice = choices[select.value];
    const manual = form.elements.network_mode.value === 'manual';
    [['interface', 'interface'], ['ip', 'ip'], ['cidr', 'cidr']].forEach(([id, key]) => {
      document.getElementById('summary-' + id).textContent = choice ? choice[key] : 'À choisir';
    });
    document.getElementById('interface-note').textContent = !choice ? '' : choice.state !== 'up'
      ? 'Cette interface est inactive. Vérifiez le câble et sa configuration avant d’activer PXE.'
      : choice.type === 'Wi-Fi' ? <?= json_encode(Term::format('Pour démarrer les {many}, préférez une connexion Ethernet au même réseau local.'), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>
      : ['Pont réseau', 'Tunnel / VPN', 'Réseau interne / conteneur'].includes(choice.type)
        ? <?= json_encode(Term::format('Vérifiez que cette interface rejoint les {many} : un réseau interne ou un VPN ne transporte pas forcément leur démarrage.'), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?> : '';
    if (manual) document.getElementById('network-advanced').open = true;
  }
  form.querySelectorAll('[name="network_mode"]').forEach(input => input.addEventListener('change', update));
  select.addEventListener('change', update);
  document.getElementById('copy-detected-network').addEventListener('click', () => {
    const choice = choices[select.value];
    if (!choice) return;
    document.getElementById('pxe-interface').value = choice.interface;
    document.getElementById('pxe-ip').value = choice.ip;
    document.getElementById('pxe-subnet').value = choice.cidr;
    document.getElementById('dhcp-proxy-cidr').value = choice.cidr;
    document.getElementById('network-override').checked = false;
  });
  if (document.getElementById('network-error')) document.getElementById('network-error').focus();
  update();
})();
</script>
<?php };
include __DIR__ . '/_layout.php';
