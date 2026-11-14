<?php
declare(strict_types=1);
namespace Admin\Controllers;

use Admin\Auth;
use Admin\Util\ApplianceJobs;
use Admin\Util\PxeHttpReadiness;
use Admin\View;

final class NativePortController
{
    private function permitted(): bool
    {
        if (getenv('PXE_SERVICE_MANAGER') !== 'systemd' || Auth::user() === null) {
            http_response_code(403);
            echo 'Action non disponible.';
            return false;
        }
        return true;
    }

    public function form(array $params): void
    {
        if (!$this->permitted()) return;
        $diagnosis = PxeHttpReadiness::diagnose();
        $nonce = null;
        unset($_SESSION['port80_preview']);
        if (!empty($diagnosis['can_stop']) && $diagnosis['state'] === 'conflict') {
            $nonce = bin2hex(random_bytes(24));
            $_SESSION['port80_preview'] = ['nonce' => $nonce, 'diagnosis' => $diagnosis, 'created' => time()];
        }
        $jobs = ApplianceJobs::tracked('native_port_job_ids');
        View::partial('init/wizard/port-80', ['job' => $jobs === [] ? null : $jobs[count($jobs) - 1],
            'diagnosis' => $diagnosis, 'nonce' => $nonce,
            'missingConsent' => isset($_GET['consent']), 'identityUnavailable' => isset($_GET['identity'])]);
    }

    public function submit(array $params): void
    {
        if (!$this->permitted()) return;
        if (($_POST['confirm_stop_nginx'] ?? null) !== '1') {
            header('Location: /init/port-80?consent=missing');
            return;
        }
        $preview = $_SESSION['port80_preview'] ?? null;
        unset($_SESSION['port80_preview']);
        $nonce = $_POST['preview'] ?? null;
        $current = PxeHttpReadiness::diagnose();
        $valid = is_array($preview) && is_string($nonce) && hash_equals($preview['nonce'], $nonce)
            && time() - $preview['created'] <= 300 && !empty($current['can_stop']) && $current['state'] === 'conflict';
        foreach (['pid', 'start', 'boot', 'fingerprint', 'address', 'service'] as $key) {
            $valid = $valid && ($preview['diagnosis'][$key] ?? null) === ($current[$key] ?? null);
        }
        if (!$valid || ($current['service'] ?? '') !== 'nginx.service') {
            header('Location: /init/port-80?identity=changed');
            return;
        }
        // A fixed service action with a fresh socket/process snapshot. The
        // privileged worker verifies all evidence independently before stop.
        $consent = implode(':', ['nginx-consent-v2', $current['pid'], $current['start'], time(),
            $current['boot'], $current['address'], $current['fingerprint']]);
        ApplianceJobs::enqueue(['system:release_nginx_port' => $consent], [], 'native_port_job_ids');
        header('Location: /init/port-80');
    }
}
