<?php
declare(strict_types=1);

namespace Admin\Controllers;

use Admin\Models\ActivityQuery;
use Admin\Models\OsImage;
use Admin\Models\Overview;
use Admin\Models\Setting;
use Admin\Util\NetworkConfiguration;
use Admin\Util\PxeHttpReadiness;
use Admin\View;

final class OverviewController
{
    public function index(array $params): void
    {
        $stored = [];
        foreach (['pxe_interface', 'pxe_ip', 'pxe_enabled', 'dhcp_proxy_enabled', 'dhcp_proxy_network', 'dhcp_proxy_netmask'] as $key) {
            $value = Setting::get($key);
            if ($value !== null) $stored[$key] = $value;
        }
        $environment = [];
        foreach (['PXE_INTERFACE', 'PXE_IP', 'ORCHESTRATOR_IP', 'DHCP_MODE', 'DHCP_PROXY_NETWORK', 'DHCP_PROXY_NETMASK'] as $key) {
            $value = getenv($key);
            if ($value !== false && $value !== '') $environment[$key] = $value;
        }
        $network = NetworkConfiguration::effectiveValues($stored, $environment);
        $images = OsImage::all();
        foreach ($images as &$image) {
            $image['files_available'] = false;
            if (($image['status'] ?? '') === OsImage::STATUS_DOWNLOADED) {
                try { $image['files_available'] = OsImage::filesAvailable($image); }
                catch (\Throwable $e) { /* Invalid paths cannot be reported as available. */ }
            }
        }
        unset($image);
        $activity = ActivityQuery::search([]);
        $overview = Overview::fromSources($network, PxeHttpReadiness::diagnose(), $images, $activity['items']);
        View::render('overview/index', ['overview' => $overview], 'Vue d’ensemble · PXE Tools');
    }
}
