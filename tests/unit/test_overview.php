<?php
declare(strict_types=1);
require __DIR__ . '/../../app/src/Models/Overview.php';
use Admin\Models\Overview;
function check(bool $condition, string $message): void { if (!$condition) throw new RuntimeException($message); }
$network = ['pxe_enabled'=>'on', 'dhcp_proxy_enabled'=>'on', 'pxe_interface'=>'eth0', 'pxe_ip'=>'192.0.2.10'];
$images = [
    ['enabled'=>1,'status'=>'downloaded','files_available'=>true],
    ['enabled'=>0,'status'=>'downloaded','files_available'=>true],
    ['enabled'=>1,'status'=>'downloaded','files_available'=>false],
    ['enabled'=>1,'status'=>'pending','files_available'=>true],
];
$result = Overview::fromSources($network, ['state'=>'ready'], $images, array_fill(0, 8, []));
check($result['mode'] === 'Proxy DHCP', 'proxy mode');
check($result['http_state'] === 'ready', 'observed HTTP state');
check($result['ready_count'] === 1, 'only enabled downloaded images with readable files are counted');
check(count($result['activity']) === 5, 'activity is bounded');
$disabled = Overview::fromSources(array_replace($network, ['pxe_enabled'=>'off']), ['state'=>'ready'], [], []);
check($disabled['http_state'] === 'unexpected' && $disabled['mode'] === 'Console uniquement', 'observed HTTP must not be concealed when configuration is off');
$disabledUnknown = Overview::fromSources(array_replace($network, ['pxe_enabled'=>'off']), ['state'=>'unknown'], [], []);
check($disabledUnknown['http_state'] === 'not_requested', 'a disabled configuration does not prove that a service has stopped');
$invalid = Overview::fromSources(array_replace($network, ['pxe_enabled'=>'bad']), ['state'=>'ready'], [], []);
check($invalid['http_state'] === 'unknown' && $invalid['mode'] === 'Configuration indéterminée', 'invalid state must fail closed');
$legacy = Overview::fromSources($network, ['state'=>'not_configured'], [], []);
check($legacy['http_state'] === 'unknown', 'environment configuration is not a confirmed absence');
$external = Overview::fromSources(array_replace($network, ['dhcp_proxy_enabled'=>'off']), [], [], []);
check($external['mode'] === 'DHCP externe' && $external['http_state'] === 'unknown', 'external DHCP and unknown health');
echo "Overview truth and edge cases: OK\n";
