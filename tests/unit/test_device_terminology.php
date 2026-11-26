<?php
declare(strict_types=1);
require __DIR__ . '/../../app/src/Ui/DeviceTerminology.php';
use Admin\Ui\DeviceTerminology as Term;

$examples = [
    'Ajouter {un}' => 'Ajouter un appareil',
    'Inventaire {dun} {decouvert}' => 'Inventaire d’un appareil découvert',
    'Ouvrir la fiche {du}' => 'Ouvrir la fiche de l’appareil',
    'Les {many} {selectionnes} sont {installees}' => 'Les appareils sélectionnés sont installés',
];
foreach ($examples as $template => $expected) {
    if (Term::format($template) !== $expected) {
        throw new RuntimeException("Incorrect device terminology: $template");
    }
}
echo "Device terminology and French agreement: OK\n";
