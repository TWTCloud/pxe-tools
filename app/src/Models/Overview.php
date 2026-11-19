<?php
declare(strict_types=1);

namespace Admin\Models;

/** Read-only presentation of configuration and separately observed evidence. */
final class Overview
{
    public static function fromSources(array $network, array $http, array $images, array $activity): array
    {
        $pxe = $network['pxe_enabled'] ?? '';
        $proxy = $network['dhcp_proxy_enabled'] ?? '';
        $mode = match (true) {
            $pxe === 'off' => 'Console uniquement',
            $pxe !== 'on' => 'Configuration indéterminée',
            $proxy === 'on' => 'Proxy DHCP',
            $proxy === 'off' => 'DHCP externe',
            default => 'Configuration indéterminée',
        };
        $observedHttp = (string)($http['state'] ?? 'unknown');
        $httpState = $pxe === 'off' ? ($observedHttp === 'ready' ? 'unexpected' : 'not_requested')
            : ($pxe === 'on' ? $observedHttp : 'unknown');
        if ($httpState === 'not_configured' && !empty($network['pxe_ip'])) $httpState = 'unknown';
        $readyImages = array_values(array_filter($images, static fn(array $image): bool =>
            (int)($image['enabled'] ?? 0) === 1 && ($image['status'] ?? '') === 'downloaded'
            && ($image['files_available'] ?? false) === true));
        return [
            'interface' => trim((string)($network['pxe_interface'] ?? '')),
            'address' => trim((string)($network['pxe_ip'] ?? '')),
            'mode' => $mode,
            'pxe_enabled' => $pxe,
            'proxy_enabled' => $proxy,
            'http_state' => $httpState,
            'ready_count' => count($readyImages),
            'images' => array_slice($images, 0, 5),
            'activity' => array_slice($activity, 0, 5),
        ];
    }
}
