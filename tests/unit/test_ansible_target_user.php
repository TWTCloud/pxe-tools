<?php
declare(strict_types=1);
require __DIR__ . '/../../app/src/Util/AnsibleConfiguration.php';
use Admin\Util\AnsibleConfiguration;

foreach (['ansible', 'automation', '_svc', 'deploy-01', str_repeat('a', 32)] as $valid) {
    if (AnsibleConfiguration::validateTargetUser($valid) !== $valid) throw new RuntimeException("rejected: $valid");
}
if (AnsibleConfiguration::validateTargetUser('  automation ') !== 'automation') throw new RuntimeException('must trim');
foreach (['', 'root', 'Automation', '1user', 'a b', 'a.b', "a\nb", 'a;id', str_repeat('a', 33)] as $invalid) {
    try {
        AnsibleConfiguration::validateTargetUser($invalid);
    } catch (InvalidArgumentException) {
        continue;
    }
    throw new RuntimeException('accepted: ' . json_encode($invalid));
}
echo "Ansible target user validation: OK\n";
