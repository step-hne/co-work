<?php

declare(strict_types=1);

require_once __DIR__ . '/../redirect_payload.php';

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../connection.config.php';

$redirectPayload = srp_redirect_payload_decode($_GET['rk'] ?? null);

$clickId = meetup_sanitize_token($redirectPayload['click_id'] ?? ($_GET['click_id'] ?? null), 128);
$countryCode = meetup_sanitize_country_code($redirectPayload['country_code'] ?? ($_GET['country_code'] ?? null));
$userAgent = meetup_sanitize_token($redirectPayload['user_agent'] ?? ($_GET['user_agent'] ?? null), 32);
$ipAddress = meetup_sanitize_ip($redirectPayload['ip_address'] ?? ($_GET['ip_address'] ?? null));
$userLp = meetup_sanitize_token($redirectPayload['user_lp'] ?? ($_GET['user_lp'] ?? null), 64);

if ($clickId === null || $countryCode === null || $userAgent === null || $userLp === null) {
    meetup_fail(400);
}

$recordUrl = strtoupper($clickId);
$clickDate = date('Y-m-d');
$redirectToken = srp_redirect_payload_encode(
    $recordUrl,
    strtolower($countryCode),
    strtolower($userAgent),
    $ipAddress,
    strtolower($userLp)
);

try {
    meetup_ensure_clickrecord_table($pdo);

    $generateStatement = $pdo->prepare('SELECT 1 FROM generate WHERE sub_id = :sub_id LIMIT 1');
    $generateStatement->execute(['sub_id' => $recordUrl]);

    if ($generateStatement->fetchColumn() === false) {
        meetup_fail(404);
    }

    $updateStatement = $pdo->prepare(
        'UPDATE clickrecord SET clicks = clicks + 1 WHERE click_id = :click_id AND click_date = :click_date'
    );
    $updateStatement->execute([
        'click_id' => $recordUrl,
        'click_date' => $clickDate,
    ]);

    if ($updateStatement->rowCount() === 0) {
        $insertStatement = $pdo->prepare(
            'INSERT INTO clickrecord (click_id, clicks, leads, payout, click_date) '
            . 'VALUES (:click_id, 1, :leads, :payout, :click_date)'
        );
        $insertStatement->execute([
            'click_id' => $recordUrl,
            'leads' => '0',
            'payout' => '0',
            'click_date' => $clickDate,
        ]);
    }
} catch (Throwable $e) {
    error_log('Meetup click pipeline failed: ' . $e->getMessage());
    meetup_fail(500);
}

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Location: /_meetups/r.php?rk=' . rawurlencode($redirectToken), true, 302);
exit;

function meetup_sanitize_token(mixed $value, int $maxLength): ?string
{
    if (!is_scalar($value)) {
        return null;
    }

    $value = trim((string) $value);
    if ($value === '' || strlen($value) > $maxLength) {
        return null;
    }

    return preg_match('/^[A-Za-z0-9_-]+$/', $value) === 1 ? $value : null;
}

function meetup_sanitize_country_code(mixed $value): ?string
{
    if (!is_scalar($value)) {
        return null;
    }

    $value = strtolower(trim((string) $value));
    if ($value === '') {
        return null;
    }

    return preg_match('/^[a-z]{2}$/', $value) === 1 ? $value : null;
}

function meetup_sanitize_ip(mixed $value): string
{
    if (!is_scalar($value)) {
        return '';
    }

    $value = trim((string) $value);
    if ($value === '') {
        return '';
    }

    return filter_var($value, FILTER_VALIDATE_IP) !== false ? $value : '';
}

function meetup_ensure_clickrecord_table(PDO $pdo): void
{
    $statement = $pdo->prepare(
        'SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = :table_name LIMIT 1'
    );
    $statement->execute(['table_name' => 'clickrecord']);

    if ($statement->fetchColumn() !== false) {
        return;
    }

    throw new RuntimeException('Required table clickrecord is not installed.');
}

function meetup_fail(int $statusCode): never
{
    http_response_code($statusCode);
    header('Content-Type: text/plain; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    exit;
}
