<?php
declare(strict_types=1);

namespace Admin\Ui;

use Admin\Models\Setting;

/** Shared UI vocabulary. Only authored templates should be passed to format(). */
final class DeviceTerminology
{
    public const OPTIONS = [
        'machine' => 'Machine',
        'client' => 'Client PXE',
        'ordinateur' => 'Ordinateur',
        'serveur' => 'Serveur',
    ];

    private const FORMS = [
        'machine' => ['one'=>'machine','many'=>'machines','One'=>'Machine','Many'=>'Machines','un'=>'une machine','le'=>'la machine','du'=>'de la machine','au'=>'à la machine','ce'=>'cette machine','nouveau'=>'nouvelle machine','aucun'=>'aucune machine','premiers'=>'premières machines','selectionne'=>'sélectionnée','selectionnes'=>'sélectionnées','installe'=>'installée','installees'=>'installées','cree'=>'créée','supprime'=>'supprimée','mis_a_jour'=>'mise à jour'],
        'client' => ['one'=>'client PXE','many'=>'clients PXE','One'=>'Client PXE','Many'=>'Clients PXE','un'=>'un client PXE','le'=>'le client PXE','du'=>'du client PXE','au'=>'au client PXE','ce'=>'ce client PXE','nouveau'=>'nouveau client PXE','aucun'=>'aucun client PXE','premiers'=>'premiers clients PXE','selectionne'=>'sélectionné','selectionnes'=>'sélectionnés','installe'=>'installé','installees'=>'installés','cree'=>'créé','supprime'=>'supprimé','mis_a_jour'=>'mis à jour'],
        'ordinateur' => ['one'=>'ordinateur','many'=>'ordinateurs','One'=>'Ordinateur','Many'=>'Ordinateurs','un'=>'un ordinateur','le'=>"l’ordinateur",'du'=>"de l’ordinateur",'au'=>"à l’ordinateur",'ce'=>'cet ordinateur','nouveau'=>'nouvel ordinateur','aucun'=>'aucun ordinateur','premiers'=>'premiers ordinateurs','selectionne'=>'sélectionné','selectionnes'=>'sélectionnés','installe'=>'installé','installees'=>'installés','cree'=>'créé','supprime'=>'supprimé','mis_a_jour'=>'mis à jour'],
        'serveur' => ['one'=>'serveur','many'=>'serveurs','One'=>'Serveur','Many'=>'Serveurs','un'=>'un serveur','le'=>'le serveur','du'=>'du serveur','au'=>'au serveur','ce'=>'ce serveur','nouveau'=>'nouveau serveur','aucun'=>'aucun serveur','premiers'=>'premiers serveurs','selectionne'=>'sélectionné','selectionnes'=>'sélectionnés','installe'=>'installé','installees'=>'installés','cree'=>'créé','supprime'=>'supprimé','mis_a_jour'=>'mis à jour'],
    ];

    public static function selected(): string
    {
        static $cached = null;
        if ($cached !== null) return $cached;
        $value = Setting::get(Setting::KEY_UI_DEVICE_TERM, 'machine');
        return $cached = isset(self::FORMS[$value]) ? $value : 'machine';
    }

    public static function format(string $template, ?string $selection = null): string
    {
        $forms = self::FORMS[$selection ?? self::selected()] ?? self::FORMS['machine'];
        $replacements = [];
        foreach ($forms as $key => $value) $replacements['{' . $key . '}'] = $value;
        return strtr($template, $replacements);
    }
}
