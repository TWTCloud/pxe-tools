<?php use Admin\View; use Admin\Ui\DeviceTerminology as Term; ?>
<header class="row-flex-spread mb-1">
  <h2><?= View::e(ucfirst(Term::format('{nouveau}')) . ' (saisie manuelle)') ?></h2>
  <a href="/admin/inventaire" class="btn btn-secondary">← Retour</a>
</header>

<div class="card">
  <p class="muted">
    <?= View::e(Term::format('Normalement, les {many} apparaissent automatiquement après leur premier démarrage PXE.')) ?>
    <?= View::e(Term::format('Cette page permet d’ajouter manuellement {un} si son adresse MAC est déjà connue.')) ?>
  </p>
  <form method="post" action="/admin/inventaire">
    <label>
      Adresse MAC <span class="required-marker">*</span>
      <input type="text" name="mac" required placeholder="02:00:00:00:00:01" pattern="[0-9a-fA-F:.\-]+" aria-required="true">
      <small class="form-hint">Formats acceptés : <code>aa:bb:cc:dd:ee:ff</code>, <code>aa-bb-cc-dd-ee-ff</code>, <code>aabbccddeeff</code></small>
    </label>

    <label>
      Nom d'hôte <span class="muted">(optionnel)</span>
      <input type="text" name="hostname" placeholder="hostname">
    </label>

    <div class="actions mt-4 justify-end">
      <button type="submit" class="btn btn-primary">Créer</button>
    </div>
  </form>
</div>
