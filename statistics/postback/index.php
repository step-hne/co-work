<?php

declare(strict_types=1);

// ?click_id={base64url_payload}&payout={decimal}&token={optional_hmac_secret}

require_once __DIR__ . '/../connection.config.php';
require_once __DIR__ . '/../../Base64URL.php';

if (!headers_sent()) {
    header('Content-Type: text/plain; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=()');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    header("Content-Security-Policy: default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
}

function pbEnv(string $key, ?string $default = null): ?string
{
    $value = getenv($key);

    if ($value !== false) {
        return trim((string) $value);
    }

    if (isset($_ENV[$key])) {
        return trim((string) $_ENV[$key]);
    }

    if (isset($_SERVER[$key])) {
        return trim((string) $_SERVER[$key]);
    }

    return $default;
}

function pbLog(string $message, array $context = []): void
{
    $safe = [];

    foreach ($context as $key => $value) {
        $key = (string) $key;

        if (
            stripos($key, 'pass') !== false
            || stripos($key, 'secret') !== false
            || stripos($key, 'token') !== false
        ) {
            continue;
        }

        if (is_scalar($value) || $value === null) {
            $safe[$key] = $value;
        }
    }

    $suffix = '';

    if ($safe !== []) {
        $json = json_encode(
            $safe,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR
        );

        if (is_string($json)) {
            $suffix = ' ' . $json;
        }
    }

    error_log('[postback] ' . $message . $suffix);
}

function pbRespond(int $statusCode, string $message): never
{
    http_response_code($statusCode);
    echo $message;
    exit;
}

function pbHasControlChars(string $value): bool
{
    return preg_match('/[\x00-\x1F\x7F]/', $value) === 1;
}

function pbRejectSuspiciousRequest(): void
{
    $queryString = (string) ($_SERVER['QUERY_STRING'] ?? '');

    if (strlen($queryString) > 4096) {
        pbLog('blocked_suspicious_request', ['reason' => 'query_too_long']);
        pbRespond(400, 'BAD_REQUEST');
    }

    foreach ($_GET as $key => $value) {
        if (!is_string($key) || pbHasControlChars($key)) {
            pbLog('blocked_suspicious_request', ['reason' => 'invalid_key']);
            pbRespond(400, 'BAD_REQUEST');
        }

        if (is_array($value)) {
            pbLog('blocked_suspicious_request', ['reason' => 'array_param', 'key' => $key]);
            pbRespond(400, 'BAD_REQUEST');
        }

        $stringValue = (string) $value;

        if (pbHasControlChars($stringValue)) {
            pbLog('blocked_suspicious_request', ['reason' => 'control_chars', 'key' => $key]);
            pbRespond(400, 'BAD_REQUEST');
        }
    }
}

function pbRequirePostbackSecret(): void
{
    $secret = pbEnv('POSTBACK_SECRET', '');

    if ($secret === null || $secret === '') {
        pbLog('postback_secret_not_configured');
        pbRespond(503, 'SERVICE_UNAVAILABLE');
    }

    $token = isset($_GET['token']) ? (string) $_GET['token'] : '';

    if ($token === '' || !hash_equals($secret, $token)) {
        pbLog('unauthorized_postback');
        pbRespond(403, 'FORBIDDEN');
    }
}

function pbNormalizePayout(string $raw): string
{
    $raw = trim($raw);

    if ($raw === '') {
        pbRespond(400, 'BAD_REQUEST');
    }

    if (strlen($raw) > 20) {
        pbLog('invalid_payout', ['reason' => 'too_long']);
        pbRespond(400, 'BAD_REQUEST');
    }

    if (preg_match('/^\d{1,12}(\.\d{1,4})?$/', $raw) !== 1) {
        pbLog('invalid_payout', ['reason' => 'format']);
        pbRespond(400, 'BAD_REQUEST');
    }

    $float = (float) $raw;

    if (!is_finite($float) || $float < 0) {
        pbLog('invalid_payout', ['reason' => 'range']);
        pbRespond(400, 'BAD_REQUEST');
    }

    return number_format($float, 2, '.', '');
}

function pbNormalizeClickId(string $raw): string
{
    $value = strtoupper(trim($raw));

    if ($value === '' || strlen($value) > 128) {
        pbLog('invalid_click_id', ['reason' => 'length']);
        pbRespond(400, 'BAD_REQUEST');
    }

    if (preg_match('/^[A-Z0-9._:-]+$/', $value) !== 1) {
        pbLog('invalid_click_id', ['reason' => 'chars']);
        pbRespond(400, 'BAD_REQUEST');
    }

    return $value;
}

function pbNormalizeCountry(string $raw): string
{
    $value = strtoupper(trim($raw));

    if (preg_match('/^[A-Z]{2,3}$/', $value) !== 1) {
        pbLog('invalid_country');
        pbRespond(400, 'BAD_REQUEST');
    }

    return $value;
}

function pbNormalizeIp(string $raw): string
{
    $value = trim($raw);

    if (filter_var($value, FILTER_VALIDATE_IP) === false) {
        pbLog('invalid_ip');
        pbRespond(400, 'BAD_REQUEST');
    }

    return $value;
}

function pbNormalizeTraffic(string $raw): string
{
    $value = strtoupper(trim($raw));

    if ($value === '' || strlen($value) > 255 || pbHasControlChars($value)) {
        pbLog('invalid_traffic');
        pbRespond(400, 'BAD_REQUEST');
    }

    return $value;
}

function pbNormalizeNetwork(string $raw): string
{
    $value = strtolower(trim($raw));

    if ($value === '' || strlen($value) > 64) {
        pbLog('invalid_network', ['reason' => 'length']);
        pbRespond(400, 'BAD_REQUEST');
    }

    if (preg_match('/^[a-z0-9._-]+$/', $value) !== 1) {
        pbLog('invalid_network', ['reason' => 'chars']);
        pbRespond(400, 'BAD_REQUEST');
    }

    return $value;
}

function pbDecodePayload(string $encoded): array
{
    $encoded = trim($encoded);

    if ($encoded === '' || strlen($encoded) > 2048) {
        pbLog('invalid_encoded_click_id', ['reason' => 'length']);
        pbRespond(400, 'BAD_REQUEST');
    }

    if (preg_match('/^[A-Za-z0-9_-]+={0,2}$/', $encoded) !== 1) {
        pbLog('invalid_encoded_click_id', ['reason' => 'chars']);
        pbRespond(400, 'BAD_REQUEST');
    }

    if (!function_exists('base64url_decode')) {
        pbLog('base64url_decode_missing');
        pbRespond(500, 'SERVER_ERROR');
    }

    $decoded = base64url_decode($encoded);

    if (!is_string($decoded) || $decoded === '') {
        pbLog('decode_failed');
        pbRespond(400, 'BAD_REQUEST');
    }

    if (strlen($decoded) > 2048 || pbHasControlChars($decoded)) {
        pbLog('invalid_decoded_payload');
        pbRespond(400, 'BAD_REQUEST');
    }

    $parts = explode(',', $decoded);

    if (count($parts) < 5) {
        pbLog('invalid_payload_parts', ['count' => count($parts)]);
        pbRespond(400, 'BAD_REQUEST');
    }

    return $parts;
}

function pbPrepare(mysqli $link, string $sql): mysqli_stmt
{
    $stmt = $link->prepare($sql);

    if (!$stmt instanceof mysqli_stmt) {
        pbLog('prepare_failed', [
            'errno' => $link->errno,
            'error' => $link->error,
        ]);

        pbRespond(500, 'SERVER_ERROR');
    }

    return $stmt;
}

function pbInsertLeadReport(
    mysqli $link,
    string $clickId,
    string $ipAddress,
    string $country,
    string $payout,
    string $conversionDate,
    string $currencySymbol,
    string $network,
    string $traffic
): void {
    $stmt = pbPrepare(
        $link,
        'INSERT INTO leadreport
            (click_id, ip_address, country, payout, conversion_date, currency_symbol, network, traffic)
         VALUES
            (?, ?, ?, ?, ?, ?, ?, ?)'
    );

    $stmt->bind_param(
        'ssssssss',
        $clickId,
        $ipAddress,
        $country,
        $payout,
        $conversionDate,
        $currencySymbol,
        $network,
        $traffic
    );

    if (!$stmt->execute()) {
        pbLog('insert_leadreport_failed', [
            'errno' => $stmt->errno,
            'error' => $stmt->error,
        ]);

        $stmt->close();
        pbRespond(500, 'SERVER_ERROR');
    }

    $stmt->close();
}

function pbUpsertClickRecord(mysqli $link, string $clickId, string $payout, string $conversionDate): void
{
    $stmt = pbPrepare(
        $link,
        'INSERT INTO clickrecord
            (click_id, clicks, leads, payout, click_date)
         VALUES
            (?, 1, 1, ?, ?)
         ON DUPLICATE KEY UPDATE
            clicks = clicks + 1,
            leads = CAST(leads AS UNSIGNED) + 1,
            payout = CAST(payout AS DECIMAL(18,2)) + CAST(VALUES(payout) AS DECIMAL(18,2))'
    );

    $stmt->bind_param('sss', $clickId, $payout, $conversionDate);

    if (!$stmt->execute()) {
        pbLog('upsert_clickrecord_failed', [
            'errno' => $stmt->errno,
            'error' => $stmt->error,
        ]);

        $stmt->close();
        pbRespond(500, 'SERVER_ERROR');
    }

    $stmt->close();
}

function pbEnsureClickRecordUniqueIndex(mysqli $link): void
{
    $database = $link->query('SELECT DATABASE() AS db_name');

    if (!$database instanceof mysqli_result) {
        pbLog('read_database_name_failed', ['errno' => $link->errno, 'error' => $link->error]);
        pbRespond(500, 'SERVER_ERROR');
    }

    $row = $database->fetch_assoc();
    $database->free();
    $dbName = isset($row['db_name']) ? (string) $row['db_name'] : '';

    if ($dbName === '') {
        pbLog('database_name_empty');
        pbRespond(500, 'SERVER_ERROR');
    }

    $indexName = 'ux_clickrecord_click_id_date';
    $tableName = 'clickrecord';

    $stmt = pbPrepare(
        $link,
        'SELECT COUNT(*) FROM information_schema.statistics
         WHERE table_schema = ? AND table_name = ? AND index_name = ?'
    );
    $stmt->bind_param('sss', $dbName, $tableName, $indexName);

    if (!$stmt->execute()) {
        pbLog('check_unique_index_failed', ['errno' => $stmt->errno, 'error' => $stmt->error]);
        $stmt->close();
        pbRespond(500, 'SERVER_ERROR');
    }

    $stmt->bind_result($count);
    $stmt->fetch();
    $stmt->close();

    if ((int) $count > 0) {
        return;
    }

    if (!$link->query('ALTER TABLE clickrecord ADD UNIQUE KEY ux_clickrecord_click_id_date (click_id, click_date)')) {
        pbLog('create_unique_index_failed', ['errno' => $link->errno, 'error' => $link->error]);
        pbRespond(500, 'SERVER_ERROR');
    }
}

pbRejectSuspiciousRequest();
pbRequirePostbackSecret();

if (!isset($_GET['click_id'], $_GET['payout'])) {
    pbRespond(400, 'BAD_REQUEST');
}

if (!$link instanceof mysqli) {
    pbLog('db_not_connected');
    pbRespond(500, 'SERVER_ERROR');
}

$payload = pbDecodePayload((string) $_GET['click_id']);

$clickId = pbNormalizeClickId((string) $payload[0]);
$country = pbNormalizeCountry((string) $payload[1]);
$ipAddress = pbNormalizeIp((string) $payload[2]);
$traffic = pbNormalizeTraffic((string) $payload[3]);
$network = pbNormalizeNetwork((string) $payload[4]);
$payout = pbNormalizePayout((string) $_GET['payout']);

$timezone = pbEnv('POSTBACK_TIMEZONE', 'UTC');

try {
    $dateTimeZone = new DateTimeZone((string) $timezone);
} catch (Throwable $e) {
    pbLog('invalid_timezone', ['timezone' => $timezone]);
    $dateTimeZone = new DateTimeZone('UTC');
}

$conversionDate = (new DateTimeImmutable('now', $dateTimeZone))->format('Y-m-d');
$currencySymbol = '$';

$transactionStarted = false;

try {
    $transactionStarted = $link->begin_transaction();

    if (!$transactionStarted) {
        pbLog('begin_transaction_failed', ['errno' => $link->errno, 'error' => $link->error]);
        pbRespond(500, 'SERVER_ERROR');
    }

    pbInsertLeadReport(
        $link,
        $clickId,
        $ipAddress,
        $country,
        $payout,
        $conversionDate,
        $currencySymbol,
        $network,
        $traffic
    );

    pbEnsureClickRecordUniqueIndex($link);
    pbUpsertClickRecord($link, $clickId, $payout, $conversionDate);

    if ($transactionStarted) {
        $link->commit();
    }

    $link->close();
    pbRespond(200, 'OK');
} catch (Throwable $e) {
    pbLog('postback_failed', [
        'error' => $e->getMessage(),
    ]);

    if ($transactionStarted) {
        @$link->rollback();
    }

    @$link->close();
    pbRespond(500, 'SERVER_ERROR');
}
