<?php

declare(strict_types=1);

include_once __DIR__ . '/../login.php';
include_once __DIR__ . '/../connection.config.php';

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

if (!isset($_GET['date'])) {
    echo json_encode([]);
    exit;
}

if (!isset($link) || !($link instanceof mysqli)) {
    echo json_encode([]);
    exit;
}

$dateParam = $_GET['date'] === '2' ? 'yesterday' : 'today';
$conversionDate = date('Y-m-d', strtotime($dateParam));

$topClickId = '';

$stmt = mysqli_prepare(
    $link,
    'SELECT click_id FROM leadreport WHERE conversion_date = ?
     GROUP BY click_id ORDER BY SUM(payout) DESC LIMIT 1'
);

if ($stmt instanceof mysqli_stmt) {
    mysqli_stmt_bind_param($stmt, 's', $conversionDate);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if ($result instanceof mysqli_result) {
        $row = mysqli_fetch_assoc($result);
        if (is_array($row)) {
            $topClickId = (string) ($row['click_id'] ?? '');
        }
        mysqli_free_result($result);
    }

    mysqli_stmt_close($stmt);
}

mysqli_close($link);

if ($topClickId === '') {
    echo json_encode([]);
    exit;
}

$escaped = htmlspecialchars(strtoupper($topClickId), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$html = '<strong><img style="width:20px;height:20px;vertical-align:middle;" src="/dist/fox.svg">'
    . $escaped . '</strong>';

echo json_encode([['click_id' => $html]], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
