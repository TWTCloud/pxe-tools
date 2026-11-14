<?php
declare(strict_types=1);
namespace Admin\Util;

use InvalidArgumentException;

final class NetworkConfiguration
{
    /** Existing custom values stay in advanced mode until the operator chooses detection. */
    public static function formState(array $stored, array $interfaces): array
    {
        $current = $stored;
        $hasNetwork = ($stored['pxe_interface'] ?? '') !== '' || ($stored['pxe_ip'] ?? '') !== '' || ($stored['pxe_subnet'] ?? '') !== '';
        $current['pxe_role'] = ($stored['pxe_enabled'] ?? ($hasNetwork ? 'on' : 'off')) === 'off'
            ? 'console' : (!empty($stored['dhcp_proxy_enabled']) ? 'proxy' : 'external');
        $current['network_address'] = '';
        foreach (NetworkDetector::addressChoices($interfaces) as $choice) {
            if ($choice['interface'] === ($stored['pxe_interface'] ?? '') && $choice['ip'] === ($stored['pxe_ip'] ?? '')
                && $choice['cidr'] === ($stored['pxe_subnet'] ?? '')
                && (($stored['dhcp_proxy_cidr'] ?? '') === '' || $choice['cidr'] === $stored['dhcp_proxy_cidr'])
                && empty($stored['network_override'])) {
                $current['network_address'] = $choice['value'];
            }
        }
        $current['network_mode'] = $hasNetwork && $current['network_address'] === '' ? 'manual' : 'detected';
        if (!$hasNetwork) $current['network_address'] = NetworkDetector::suggestedAddress($interfaces);
        return $current;
    }

    /** @return array<string,string> Validated settings; does not mutate state. */
    public static function validate(array $post, array $interfaces): array
    {
        foreach (['network_mode', 'network_address', 'pxe_role', 'pxe_interface', 'pxe_ip', 'pxe_subnet', 'dhcp_proxy_cidr'] as $key) {
            if (isset($post[$key]) && !is_string($post[$key])) throw new InvalidArgumentException('invalid_mode');
        }
        $mode = $post['network_mode'] ?? 'manual'; // Legacy clients use the advanced fields.
        if (!in_array($mode, ['detected', 'manual'], true)) throw new InvalidArgumentException('invalid_mode');
        $role = $post['pxe_role'] ?? (isset($post['dhcp_proxy_enabled']) ? 'proxy' : 'external');
        if (!in_array($role, ['console', 'proxy', 'external'], true)) throw new InvalidArgumentException('invalid_role');
        if ($mode === 'detected') {
            $choice = null;
            foreach (NetworkDetector::addressChoices($interfaces) as $detected) {
                if ($detected['value'] === ($post['network_address'] ?? null)) $choice = $detected;
            }
            if ($choice === null && !($role === 'console' && ($post['network_address'] ?? '') === '')) {
                throw new InvalidArgumentException('select_address');
            }
            // Re-derived on POST from the current host, without trusting hidden IP/subnet fields.
            $post['pxe_interface'] = $choice['interface'] ?? '';
            $post['pxe_ip'] = $choice['ip'] ?? '';
            $post['pxe_subnet'] = $choice['cidr'] ?? '';
            $post['dhcp_proxy_cidr'] = $choice['cidr'] ?? '';
            unset($post['network_override']);
        }
        $iface = trim((string)($post['pxe_interface'] ?? ''));
        $ip = trim((string)($post['pxe_ip'] ?? ''));
        $proxy = $role === 'proxy';
        $override = isset($post['network_override']);
        if ($role === 'console' && $iface === '' && $ip === '' && trim((string)($post['pxe_subnet'] ?? '')) === '') {
            return ['pxe_interface' => '', 'pxe_ip' => '', 'dhcp_proxy_enabled' => 'off', 'pxe_subnet' => '',
                'https_enabled' => isset($post['https_enabled']) ? 'on' : 'off', 'network_override' => 'off', 'pxe_enabled' => 'off'];
        }
        if ($iface === '' || $ip === '') throw new InvalidArgumentException('missing');
        if (!preg_match('/^[a-zA-Z0-9_.:-]{1,64}$/D', $iface)) throw new InvalidArgumentException('invalid_interface');
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) throw new InvalidArgumentException('invalid_ip');
        $selected = null;
        foreach ($interfaces as $detected) if ($detected['name'] === $iface) $selected = $detected;
        if ($selected === null && !$override) throw new InvalidArgumentException('unknown_interface');
        $addresses = array_map(static fn(string $cidr): string => explode('/', $cidr)[0], $selected['ipv4'] ?? []);
        if (!$override && !in_array($ip, $addresses, true)) throw new InvalidArgumentException('interface_ip_mismatch');
        $subnet = $post['pxe_subnet'] ?? '';
        if (!is_string($subnet) || trim($subnet) === '') throw new InvalidArgumentException('missing_subnet');
        $accessNetwork = NetworkDetector::parseCidr(trim($subnet));
        if ($accessNetwork === null) throw new InvalidArgumentException('invalid_subnet');
        if (!$override && (ip2long($ip) & ip2long($accessNetwork['netmask'])) !== ip2long($accessNetwork['network'])) {
            throw new InvalidArgumentException('subnet_mismatch');
        }
        $values = ['pxe_interface' => $iface, 'pxe_ip' => $ip, 'dhcp_proxy_enabled' => $proxy ? 'on' : 'off',
            'pxe_subnet' => $accessNetwork['network'] . '/' . $accessNetwork['prefix'],
            'https_enabled' => isset($post['https_enabled']) ? 'on' : 'off', 'network_override' => $override ? 'on' : 'off',
            'pxe_enabled' => $role === 'console' ? 'off' : 'on'];
        if ($proxy || trim((string)($post['dhcp_proxy_cidr'] ?? '')) !== '') {
            $cidr = trim((string)($post['dhcp_proxy_cidr'] ?? ''));
            if ($cidr === '') throw new InvalidArgumentException('missing_proxy');
            $parsed = NetworkDetector::parseCidr($cidr);
            if ($parsed === null) throw new InvalidArgumentException('invalid_cidr');
            if ($proxy && !$override && (ip2long($ip) & ip2long($parsed['netmask'])) !== ip2long($parsed['network'])) {
                throw new InvalidArgumentException('network_mismatch');
            }
            $values['dhcp_proxy_network'] = $parsed['network'];
            $values['dhcp_proxy_netmask'] = $parsed['netmask'];
        }
        return $values;
    }
}
