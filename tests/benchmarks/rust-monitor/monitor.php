<?php
// SPDX-License-Identifier: LGPL-3.0-only
declare(strict_types=1);

use Admin\Db;
use Admin\Models\ActionCheckpoints;

date_default_timezone_set('UTC');
$source = getenv('PXE_BENCH_APP');
if ($source === false || !is_dir($source . '/src')) {
    throw new RuntimeException('Checkout PXE Tools requis.');
}

if (PHP_SAPI === 'cli' && ($argv[1] ?? '') === '--catalog') {
    require $source . '/src/Models/ActionCheckpoints.php';
    echo json_encode(ActionCheckpoints::CATALOG, JSON_THROW_ON_ERROR);
    exit;
}

require $source . '/src/Db.php';
// Db::CONFIG_PATH prime sur les variables d’environnement dans le produit.
$fixture = getenv('PXE_DB_PATH');
if (file_exists(Db::CONFIG_PATH) || is_link(Db::CONFIG_PATH)
    || $fixture === false || basename($fixture) !== 'fixture.sqlite'
    || !is_file($fixture) || (Db::config()['path'] ?? '') !== $fixture) {
    http_response_code(503);
    exit('Base de fixture requise.');
}

require $source . '/public/index.php';
