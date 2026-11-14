<?php
declare(strict_types=1);
require __DIR__ . '/../../app/src/Util/NetworkDetector.php';
require __DIR__ . '/../../app/src/Util/NetworkConfiguration.php';
use Admin\Util\NetworkDetector as Detector;
use Admin\Util\NetworkConfiguration as Configuration;
function check(bool $condition, string $message): void { if (!$condition) throw new RuntimeException($message); }
function rejected(array $post, array $interfaces, string $code): void {
    try { Configuration::validate($post, $interfaces); } catch (InvalidArgumentException $e) { check($e->getMessage() === $code, 'Wrong error: ' . $e->getMessage()); return; }
    throw new RuntimeException('Expected rejection: ' . $code);
}
$lan = ['name'=>'ens18', 'state'=>'up', 'type'=>'wired', 'wireless'=>false, 'mac'=>'52:54:00:01:02:03', 'ipv4'=>['192.0.2.17/23']];
$legacyEnv = ['PXE_INTERFACE'=>'old0', 'PXE_IP'=>'192.0.2.77', 'DHCP_MODE'=>'proxy', 'DHCP_PROXY_NETWORK'=>'192.0.2.0', 'DHCP_PROXY_NETMASK'=>'255.255.255.0'];
$legacy = Configuration::effectiveValues([], $legacyEnv);
check($legacy['pxe_enabled'] === 'on' && $legacy['pxe_interface'] === 'old0' && $legacy['pxe_ip'] === '192.0.2.77' && $legacy['dhcp_proxy_enabled'] === 'on', 'Legacy effective env retained');
$empty = Configuration::effectiveValues(['pxe_interface'=>'','pxe_ip'=>'','dhcp_proxy_enabled'=>'off','pxe_enabled'=>'off'], $legacyEnv);
check($empty['pxe_interface'] === '' && $empty['pxe_ip'] === '' && $empty['dhcp_proxy_enabled'] === 'off' && $empty['pxe_enabled'] === 'off', 'Explicit empty/off overrides legacy environment');
$other = array_replace($lan, ['name'=>'ens19', 'ipv4'=>['198.51.100.5/24']]);
$vpn = array_replace($other, ['name'=>'wg0', 'type'=>'tunnel']);
$bridge = array_replace($lan, ['name'=>'br0', 'type'=>'bridge']);
$internal = array_replace($other, ['name'=>'docker0', 'type'=>'internal']);
check(Detector::suggestedAddress([$lan]) === 'ens18|192.0.2.17/23', 'VM Ethernet suggested');
check(Detector::suggestedAddress([$lan, $other]) === '', 'Two LANs need choice');
check(Detector::suggestedAddress([$bridge]) === '', 'Bridge requires explicit choice');
check(Detector::suggestedAddress([$vpn, $internal]) === '', 'No tunnel/container autochoice');
check(Detector::suggestedAddress([$lan, $vpn, $internal]) === 'ens18|192.0.2.17/23', 'Prefer unambiguous LAN over VPN');
check(Detector::suggestedAddress([array_replace($lan, ['ipv4'=>['192.0.2.17/23','192.0.2.18/23']])]) === '', 'Multiple IPv4s need choice');
check(Detector::suggestedAddress([array_replace($lan, ['ipv4'=>['169.254.1.2/16','192.0.2.17/23']])]) === 'ens18|192.0.2.17/23', 'Ignore link-local address');
check(Detector::addressChoices([array_replace($lan, ['ipv4'=>['127.0.0.1/8','0.0.0.0/0','224.0.0.1/24']])]) === [], 'No unusable IPv4s');
check(Detector::addressChoices([$bridge])[0]['type'] === 'Pont réseau', 'Bridge remains selectable');
$detected = ['network_mode'=>'detected','network_address'=>'ens18|192.0.2.17/23','pxe_role'=>'proxy',
    'pxe_ip'=>'203.0.113.99', 'pxe_subnet'=>'0.0.0.0/0', 'dhcp_proxy_cidr'=>'0.0.0.0/0','network_override'=>'1'];
$values = Configuration::validate($detected, [$lan]);
check($values['pxe_ip'] === '192.0.2.17' && $values['pxe_subnet'] === '192.0.2.0/23', 'Server-derived coherent address/subnet');
check($values['dhcp_proxy_network'] === '192.0.2.0' && $values['dhcp_proxy_netmask'] === '255.255.254.0', 'Server-derived proxy network');
check($values['network_override'] === 'off' && $values['pxe_enabled'] === 'on', 'Detection ignores forged override');
rejected($detected, [$other], 'select_address');
rejected(array_replace($detected, ['network_address'=>'ens18|192.0.2.17/24']), [$lan], 'select_address');
rejected(array_replace($detected, ['network_address'=>'']), [$lan], 'select_address');
$console = Configuration::validate(['network_mode'=>'detected','network_address'=>'','pxe_role'=>'console'], []);
check($console['pxe_enabled'] === 'off' && $console['pxe_ip'] === '', 'Console works without IPv4');
$external = Configuration::validate(array_replace($detected, ['pxe_role'=>'external']), [$lan]);
check($external['pxe_enabled'] === 'on' && $external['dhcp_proxy_enabled'] === 'off', 'External DHCP activation explicit');
$manual = ['network_mode'=>'manual','pxe_interface'=>'not-here','pxe_ip'=>'203.0.113.2','pxe_subnet'=>'198.51.100.0/24',
    'dhcp_proxy_cidr'=>'192.0.2.0/23','pxe_role'=>'proxy','network_override'=>'1'];
$advanced = Configuration::validate($manual, [$lan]);
check($advanced['pxe_subnet'] === '198.51.100.0/24' && $advanced['dhcp_proxy_network'] === '192.0.2.0', 'Distinct advanced networks retained');
$noOverride = $manual; unset($noOverride['network_override']); rejected($noOverride, [$lan], 'unknown_interface');
$stored = ['pxe_interface'=>'ens18','pxe_ip'=>'192.0.2.17','pxe_subnet'=>'192.0.2.0/23','dhcp_proxy_cidr'=>'198.51.100.0/24', 'network_override'=>false, 'dhcp_proxy_enabled'=>false, 'pxe_enabled'=>'off'];
$current = Configuration::formState($stored, [$lan]);
check($current['network_mode'] === 'manual' && $current['pxe_role'] === 'console', 'Existing divergent range retained even off');
$stored['dhcp_proxy_cidr']='192.0.2.0/23';
check(Configuration::formState($stored, [$lan])['network_mode'] === 'detected', 'Matching values use detection');
check(Configuration::formState($stored, [$other])['network_mode'] === 'manual', 'Transferred host requires revalidation');
rejected(['network_mode'=>[]], [$lan], 'invalid_mode');
echo "OK network detection, derived validation, activation and preserved advanced settings\n";
