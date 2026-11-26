<?php
declare(strict_types=1);

namespace Admin\Ui;

/** Shared UI copy for an individual device or a group of devices. */
final class DeviceTerminology
{
    private const FORMS = [
        '{one}' => 'appareil',
        '{many}' => 'appareils',
        '{One}' => 'Appareil',
        '{Many}' => 'Appareils',
        '{un}' => 'un appareil',
        '{dun}' => 'd’un appareil',
        '{decouvert}' => 'découvert',
        '{le}' => 'l’appareil',
        '{du}' => 'de l’appareil',
        '{au}' => 'à l’appareil',
        '{ce}' => 'cet appareil',
        '{nouveau}' => 'nouvel appareil',
        '{aucun}' => 'aucun appareil',
        '{premiers}' => 'premiers appareils',
        '{selectionne}' => 'sélectionné',
        '{selectionnes}' => 'sélectionnés',
        '{installe}' => 'installé',
        '{installees}' => 'installés',
        '{cree}' => 'créé',
        '{supprime}' => 'supprimé',
        '{mis_a_jour}' => 'mis à jour',
    ];

    public static function format(string $template): string
    {
        return strtr($template, self::FORMS);
    }
}
