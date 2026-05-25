<?php

declare(strict_types=1);

include_once __DIR__ . '/../login.php';
include_once __DIR__ . '/../connection.config.php';

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

if (!isset($link) || !($link instanceof mysqli)) {
    echo json_encode([]);
    exit;
}

$lastId = (int) ($_GET['id'] ?? 0);

$sql  = 'SELECT id, click_id, country, payout, currency_symbol, network, traffic, conversion_date FROM leadreport WHERE id > ?';
$stmt = mysqli_prepare($link, $sql);

if (!$stmt) {
    echo json_encode([]);
    mysqli_close($link);
    exit;
}

mysqli_stmt_bind_param($stmt, 'i', $lastId);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

if (!$result || mysqli_num_rows($result) === 0) {
    echo json_encode([]);
    mysqli_close($link);
    exit;
}

$rows = [];
while ($row = mysqli_fetch_assoc($result)) {
    $country = strtoupper((string) ($row['country'] ?? ''));
    if ($country === 'INVALID IP ADDRESS.') {
        $country = '';
    }

    $rawClickId = (string) ($row['click_id'] ?? '');
    if (!mb_check_encoding($rawClickId, 'UTF-8')) {
        $rawClickId = mb_convert_encoding($rawClickId, 'UTF-8', 'ISO-8859-1');
    }
    $clickId = strtoupper($rawClickId);

    $rows[] = [
        'id'              => (int) $row['id'],
        'click_id'        => $clickId,
        'audio'           => '/realtime/asd.mp3',
        'img'             => '/dist/notify.svg',
        'country'         => $country,
        'payout'          => ((string) ($row['currency_symbol'] ?? '$')) . number_format((float) ($row['payout'] ?? 0), 2),
        'network'         => strtoupper((string) ($row['network'] ?? '')),
        'traffic'         => strtoupper((string) ($row['traffic'] ?? '')),
        'conversion_date' => (string) ($row['conversion_date'] ?? ''),
    ];
}

mysqli_free_result($result);
mysqli_stmt_close($stmt);
mysqli_close($link);

echo json_encode($rows, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
