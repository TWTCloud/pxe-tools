<?php
declare(strict_types=1);
namespace Admin\Util;

use Admin\Models\Setting;

final class PxeHttpReadiness
{
    public static function diagnose(): array
    {
        static $cached = null;
        if ($cached !== null) return $cached;
        $address = Setting::get(Setting::KEY_PXE_IP, '') ?? '';
        $base = ['state' => 'unknown', 'address' => $address, 'can_stop' => false, 'service' => null, 'listeners' => []];
        if (!filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return $cached = array_replace($base, ['state' => 'not_configured']);
        $local = false;
        foreach (NetworkDetector::listInterfaces() as $interface) {
            foreach ($interface['ipv4'] as $cidr) if (explode('/', $cidr, 2)[0] === $address) $local = true;
        }
        // A configuration copied from another host must not turn a local port
        // check into a request to that old host. Keep its state indeterminate.
        if (!$local) return $cached = $base;
        if (!is_callable('shell_exec')) return $cached = $base;
        $script = __DIR__ . '/../../port80_diagnostic.py';
        $manager = getenv('PXE_SERVICE_MANAGER') === 's6' ? 's6' : 'systemd';
        $raw = @shell_exec('/usr/bin/python3 ' . escapeshellarg($script) . ' ' . escapeshellarg($address) . ' ' . $manager . ' 2>/dev/null');
        $diagnosis = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($diagnosis) || !in_array($diagnosis['state'] ?? '', ['free', 'ready', 'starting', 'conflict', 'unknown', 'not_configured'], true)) return $cached = $base;
        return $cached = array_replace($base, $diagnosis);
    }

    public static function unavailable(): bool
    {
        if (Setting::get(Setting::KEY_PXE_ENABLED, 'on') === 'off') return true;
        $file = getenv('PXE_HTTP_READY_FILE');
        // Keep the existing preflight contract when the runtime publishes a
        // marker; its absence is never interpreted as proof of a conflict.
        return is_string($file) && $file !== '' && (!str_starts_with($file, '/') || !is_file($file));
    }
}
