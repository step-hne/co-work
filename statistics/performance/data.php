<?php

declare(strict_types=1);

include_once __DIR__ . '/../login.php';
require_once __DIR__ . '/../connection.config.php';

header('Content-Type: application/json; charset=utf-8');

/** @var mysqli $link */

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode([
        'ok'    => false,
        'error' => 'Method not allowed',
    ]);
    exit;
}

if (!isset($_GET['start'], $_GET['end'])) {
    http_response_code(400);
    echo json_encode([
        'ok'    => false,
        'error' => 'Missing start or end parameter',
    ]);
    exit;
}

$start = trim((string) ($_GET['start'] ?? ''));
$end   = trim((string) ($_GET['end'] ?? ''));

if (!isValidDateYmd($start) || !isValidDateYmd($end)) {
    http_response_code(400);
    echo json_encode([
        'ok'    => false,
        'error' => 'Invalid date format, expected YYYY-MM-DD',
    ]);
    exit;
}

$sql = <<<SQL
SELECT 
    click_id,
    SUM(clicks)       AS clicks,
    SUM(leads)        AS leads,
    SUM(payout)       AS payout,
    MAX(click_date)   AS last_click_date
FROM clickrecord
WHERE click_date BETWEEN ? AND ?
GROUP BY click_id
ORDER BY last_click_date DESC
SQL;

$stmt = mysqli_prepare($link, $sql);

if ($stmt === false) {
    http_response_code(500);
    echo json_encode([
        'ok'    => false,
        'error' => 'Database prepare error',
    ]);
    exit;
}

mysqli_stmt_bind_param($stmt, 'ss', $start, $end);

if (!mysqli_stmt_execute($stmt)) {
    mysqli_stmt_close($stmt);

    http_response_code(500);
    echo json_encode([
        'ok'    => false,
        'error' => 'Database execute error',
    ]);
    exit;
}

$result = mysqli_stmt_get_result($stmt);

$response = [
    'ok'   => true,
    'data' => [],
];

$index = 1;

while ($row = mysqli_fetch_assoc($result)) {
    $clicks = isset($row['clicks']) ? (int) $row['clicks'] : 0;
    $leads  = isset($row['leads']) ? (int) $row['leads'] : 0;
    $payout = isset($row['payout']) ? (float) $row['payout'] : 0.0;

    $cr = 0.0;
    if ($clicks > 0) {
        $cr = ($leads / $clicks) * 100.0;
    }

    $rawClickId = (string) ($row['click_id'] ?? '');
    $cleanClickId = strtoupper(preg_replace('/[^A-Za-z0-9_\-]/', '', $rawClickId));

    $response['data'][] = [
        'id'       => $index++,
        'click_id' => $cleanClickId,
        'clicks'   => $clicks,
        'leads'    => $leads,
        'payout'   => $payout,
        'cr'       => round($cr, 2), // contoh: 12.34 → UI bisa render "12.34%"
    ];
}

mysqli_free_result($result);
mysqli_stmt_close($stmt);

echo json_encode(
    $response,
    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
);
exit;

/**
 * Validasi format tanggal YYYY-MM-DD.
 */
function isValidDateYmd(string $date): bool
{
    if ($date === '') {
        return false;
    }

    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
        return false;
    }

    $parts = explode('-', $date);
    if (count($parts) !== 3) {
        return false;
    }

    [$year, $month, $day] = $parts;

    return checkdate((int) $month, (int) $day, (int) $year);
}
