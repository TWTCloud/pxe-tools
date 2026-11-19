<?php
declare(strict_types=1);
require __DIR__ . '/../../app/src/Ui/DeviceTerminology.php';
use Admin\Ui\DeviceTerminology as Term;
$expected = [
    'machine' => ['une machine','la machine','de la machine','cette machine','nouvelle machine','machines','installées'],
    'client' => ['un client PXE','le client PXE','du client PXE','ce client PXE','nouveau client PXE','clients PXE','installés'],
    'ordinateur' => ['un ordinateur','l’ordinateur','de l’ordinateur','cet ordinateur','nouvel ordinateur','ordinateurs','installés'],
    'serveur' => ['un serveur','le serveur','du serveur','ce serveur','nouveau serveur','serveurs','installés'],
];
foreach ($expected as $key => $forms) {
    $actual = Term::format('{un}|{le}|{du}|{ce}|{nouveau}|{many}|{installees}', $key);
    if ($actual !== implode('|',$forms)) throw new RuntimeException("Incorrect forms: $key: $actual");
}
if (Term::format('{one}|{many}', 'invalid') !== 'machine|machines') throw new RuntimeException('invalid choice must fall back');
echo "Device terminology and French agreement: OK\n";
