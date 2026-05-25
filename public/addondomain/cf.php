<?php

declare(strict_types=1);

include_once('../connection.php');
include_once('../session_guards.php');
include_once(dirname(__DIR__, 2) . '/env.php');
load_env_file(dirname(__DIR__) . '/.env');
include_once('../cf-lib.php');

header('Content-Type: application/json; charset=utf-8');

/**
 * Persist CF data back to the addondomain row.
 */
function cfSaveToDB(mysqli $conn, int $id, string $zoneId, string $status, string $ns): void
{
    $stmt = mysqli_prepare(
        $conn,
        'UPDATE addondomain SET cf_zone_id = ?, cf_status = ?, cf_ns = ? WHERE id = ?'
    );
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare CF update.');
    }
    bindStatementValues($stmt, 'sssi', [$zoneId, $status, $ns, $id]);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);
}


/**
 * Fetch the domain string for a given addondomain row.
 * Returns ['id'=>int, 'domain'=>string, 'cf_zone_id'=>string, 'cf_status'=>string, 'cf_ns'=>string]
 */
function cfGetRow(mysqli $conn, int $id): array
{
    $stmt = mysqli_prepare(
        $conn,
        'SELECT id, domain,
                COALESCE(cf_zone_id,\'\') AS cf_zone_id,
                COALESCE(cf_status,\'\')  AS cf_status,
                COALESCE(cf_ns,\'\')      AS cf_ns
         FROM addondomain WHERE id = ?'
    );
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare row query.');
    }
    bindStatementValues($stmt, 'i', [$id]);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $row    = $result ? mysqli_fetch_assoc($result) : null;
    mysqli_stmt_close($stmt);

    if (!$row) {
        jsonError(404, 'not-found');
    }

    return $row;
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/**
 * zone_add — add/verify domain in Cloudflare; fetch NS records; apply
 * all security + performance settings, provision DNS, add security headers.
 */
function cfActionZoneAdd(mysqli $conn, array $params): void
{
    $id = (int) ($params['id'] ?? 0);
    if ($id < 1) {
        jsonError(422, 'invalid-id');
    }

    $row    = cfGetRow($conn, $id);
    $domain = $row['domain'];

    // --- 1. Look up existing zone by domain name ---
    $listResp  = cfApi('GET', '/zones?name=' . urlencode($domain) . '&status=active,pending');
    $zoneId    = '';
    $cfStatus  = '';
    $cfNsJson  = '';

    if (!empty($listResp['result']) && is_array($listResp['result'])) {
        // Zone already exists
        $zone     = $listResp['result'][0];
        $zoneId   = $zone['id']     ?? '';
        $cfStatus = $zone['status'] ?? 'pending';
        $cfNsJson = json_encode($zone['name_servers'] ?? []);
    } else {
        // --- 2. Create the zone ---
        $accountId = app_env('CF_ACCOUNT_ID', '');
        $createBody = [
            'name'    => $domain,
            'jump_start' => true,
        ];
        if ($accountId !== '') {
            $createBody['account'] = ['id' => $accountId];
        }

        $createResp = cfApi('POST', '/zones', $createBody);
        if (empty($createResp['success'])) {
            $rawMsg = $createResp['errors'][0]['message'] ?? 'zone-create-failed';
            $msg = str_contains($rawMsg, 'zone.create')
                ? 'Token CF tidak punya izin buat zone. Buka CF Dashboard → My Profile → API Tokens → edit token → pastikan ada: Account > Zone (Edit), Zone > Zone (Edit), Zone > Zone Settings (Edit), Zone > DNS (Edit), Zone > Firewall Services (Edit), Zone > Transform Rules (Edit). Simpan token baru ke CF Config.'
                : $rawMsg;
            jsonError(200, $msg);
        }

        $zone     = $createResp['result'];
        $zoneId   = $zone['id']     ?? '';
        $cfStatus = $zone['status'] ?? 'pending';
        $cfNsJson = json_encode($zone['name_servers'] ?? []);
    }

    // --- 3. Apply all security + performance settings, header rules, and recommended features ---
    if ($zoneId !== '') {
        cfApplyAllRecommended($zoneId);
    }

    // --- 4. Auto-provision DNS records ---
    $dnsLog = [];
    $serverIp = app_env('CF_SERVER_IP', '');
    if ($zoneId !== '' && $serverIp !== '') {
        $dnsLog = cfProvisionDns($zoneId, $domain, $serverIp);
    }

    // --- 5. Persist ---
    cfSaveToDB($conn, $id, $zoneId, $cfStatus, $cfNsJson);

    echo json_encode([
        'ok'        => true,
        'zone_id'   => $zoneId,
        'cf_status' => $cfStatus,
        'cf_ns'     => json_decode($cfNsJson, true),
        'dns_log'   => $dnsLog,
    ]);
}

/**
 * refresh_status — re-fetch zone status and NS from CF.
 */
function cfActionRefreshStatus(mysqli $conn, array $params): void
{
    $id = (int) ($params['id'] ?? 0);
    if ($id < 1) {
        jsonError(422, 'invalid-id');
    }

    $row    = cfGetRow($conn, $id);
    $zoneId = $row['cf_zone_id'];

    if ($zoneId === '') {
        jsonError(409, 'no-zone-id');
    }

    $resp = cfApi('GET', '/zones/' . $zoneId);
    if (empty($resp['success'])) {
        $msg = $resp['errors'][0]['message'] ?? 'zone-fetch-failed';
        jsonError(200, $msg);
    }

    $zone     = $resp['result'];
    $cfStatus = $zone['status'] ?? 'unknown';
    $cfNsJson = json_encode($zone['name_servers'] ?? []);

    cfSaveToDB($conn, $id, $zoneId, $cfStatus, $cfNsJson);

    echo json_encode([
        'ok'        => true,
        'zone_id'   => $zoneId,
        'cf_status' => $cfStatus,
        'cf_ns'     => json_decode($cfNsJson, true),
    ]);
}

/**
 * purge_cache — purge everything for a zone.
 */
function cfActionPurgeCache(mysqli $conn, array $params): void
{
    $id = (int) ($params['id'] ?? 0);
    if ($id < 1) {
        jsonError(422, 'invalid-id');
    }

    $row    = cfGetRow($conn, $id);
    $zoneId = $row['cf_zone_id'];

    if ($zoneId === '') {
        jsonError(409, 'no-zone-id');
    }

    $resp = cfApi('POST', '/zones/' . $zoneId . '/purge_cache', ['purge_everything' => true]);
    if (empty($resp['success'])) {
        $msg = $resp['errors'][0]['message'] ?? 'purge-failed';
        jsonError(200, $msg);
    }

    echo json_encode(['ok' => true]);
}

/**
 * ssl_mode — set SSL mode to 'off'|'flexible'|'full'|'strict'.
 */
function cfActionSslMode(mysqli $conn, array $params): void
{
    $id   = (int) ($params['id'] ?? 0);
    $mode = (string) ($params['mode'] ?? 'full');
    if ($id < 1) {
        jsonError(422, 'invalid-id');
    }
    $allowed = ['off', 'flexible', 'full', 'strict'];
    if (!in_array($mode, $allowed, true)) {
        jsonError(422, 'invalid-mode');
    }

    $row    = cfGetRow($conn, $id);
    $zoneId = $row['cf_zone_id'];

    if ($zoneId === '') {
        jsonError(409, 'no-zone-id');
    }

    $resp = cfApi('PATCH', '/zones/' . $zoneId . '/settings/ssl', ['value' => $mode]);
    if (empty($resp['success'])) {
        $msg = $resp['errors'][0]['message'] ?? 'ssl-mode-failed';
        jsonError(200, $msg);
    }

    echo json_encode(['ok' => true, 'mode' => $mode]);
}

/**
 * always_https — toggle Always Use HTTPS on/off.
 */
function cfActionAlwaysHttps(mysqli $conn, array $params): void
{
    $id    = (int) ($params['id'] ?? 0);
    $value = ((string) ($params['value'] ?? 'on')) === 'on' ? 'on' : 'off';
    if ($id < 1) {
        jsonError(422, 'invalid-id');
    }

    $row    = cfGetRow($conn, $id);
    $zoneId = $row['cf_zone_id'];

    if ($zoneId === '') {
        jsonError(409, 'no-zone-id');
    }

    $resp = cfApi('PATCH', '/zones/' . $zoneId . '/settings/always_use_https', ['value' => $value]);
    if (empty($resp['success'])) {
        $msg = $resp['errors'][0]['message'] ?? 'always-https-failed';
        jsonError(200, $msg);
    }

    echo json_encode(['ok' => true, 'value' => $value]);
}

/**
 * zone_delete — permanently delete a zone from Cloudflare by zone_id.
 */
function cfActionZoneDelete(array $params): void
{
    $zoneId = trim((string) ($params['zone_id'] ?? ''));
    if ($zoneId === '') {
        jsonError(422, 'invalid-zone-id');
    }

    $resp = cfApi('DELETE', '/zones/' . $zoneId);
    if (empty($resp['success'])) {
        $msg = $resp['errors'][0]['message'] ?? 'zone-delete-failed';
        jsonError(200, $msg);
    }

    echo json_encode(['ok' => true, 'zone_id' => $zoneId]);
}

// ---------------------------------------------------------------------------
// .env read / write helpers
// ---------------------------------------------------------------------------

function envFilePath(): string
{
    return dirname(__DIR__) . '/.env';
}

function envReadAll(): array
{
    $path = envFilePath();
    if (!is_readable($path)) {
        return [];
    }
    $result = [];
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#' || !str_contains($line, '=')) {
            continue;
        }
        [$k, $v] = explode('=', $line, 2);
        $result[trim($k)] = trim($v);
    }
    return $result;
}

function envWriteKeys(array $updates): void
{
    $path  = envFilePath();
    $lines = is_readable($path) ? file($path, FILE_IGNORE_NEW_LINES) : [];

    $written = [];
    foreach ($lines as &$line) {
        $trimmed = trim($line);
        if ($trimmed === '' || $trimmed[0] === '#' || !str_contains($trimmed, '=')) {
            continue;
        }
        [$k] = explode('=', $trimmed, 2);
        $k = trim($k);
        if (array_key_exists($k, $updates)) {
            $line      = $k . '=' . $updates[$k];
            $written[$k] = true;
        }
    }
    unset($line);

    foreach ($updates as $k => $v) {
        if (!isset($written[$k])) {
            $lines[] = $k . '=' . $v;
        }
    }

    file_put_contents($path, implode("\n", $lines) . "\n", LOCK_EX);
}

// ---------------------------------------------------------------------------
// Config actions
// ---------------------------------------------------------------------------

function cfActionConfigGet(): void
{
    $keys = ['CF_API_TOKEN', 'CF_ACCOUNT_ID', 'CF_SERVER_IP', 'CF_NS1', 'CF_NS2'];
    $env  = envReadAll();
    $out  = [];
    foreach ($keys as $key) {
        $val = $env[$key] ?? '';
        if ($key === 'CF_API_TOKEN' && $val !== '') {
            $len = strlen($val);
            $val = $len > 8
                ? substr($val, 0, 4) . str_repeat('•', min($len - 8, 28)) . substr($val, -4)
                : str_repeat('•', $len);
        }
        $out[$key] = $val;
    }
    echo json_encode(['ok' => true, 'config' => $out]);
}

function cfActionConfigSave(array $params): void
{
    $allowed = ['CF_API_TOKEN', 'CF_ACCOUNT_ID', 'CF_SERVER_IP', 'CF_NS1', 'CF_NS2'];
    $updates = [];
    foreach ($allowed as $key) {
        if (!isset($params[$key])) {
            continue;
        }
        $val = trim((string) $params[$key]);
        if ($val === '' || str_contains($val, '•')) {
            continue;
        }
        $updates[$key] = $val;
    }
    if (!empty($updates)) {
        envWriteKeys($updates);
    }
    echo json_encode(['ok' => true, 'saved' => array_keys($updates)]);
}

function cfRequireAddonDomainSchema(mysqli $conn): void
{
    foreach (['cf_zone_id', 'cf_status', 'cf_ns'] as $column) {
        $stmt = mysqli_prepare(
            $conn,
            'SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? LIMIT 1'
        );
        if (!$stmt instanceof mysqli_stmt) {
            jsonError(500, 'schema-check-failed');
        }

        $table = 'addondomain';
        mysqli_stmt_bind_param($stmt, 'ss', $table, $column);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $exists = $result instanceof mysqli_result && mysqli_fetch_row($result) !== null;
        if ($result instanceof mysqli_result) {
            mysqli_free_result($result);
        }
        mysqli_stmt_close($stmt);

        if (!$exists) {
            jsonError(503, 'schema-not-installed');
        }
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

try {
    startAdminGuardSession();
    if (empty($_SESSION['admin_authenticated'])) {
        jsonError(403, 'unauthorized');
    }

    $params = $_SERVER['REQUEST_METHOD'] === 'POST' ? $_POST : $_GET;
    $action = (string) ($params['action'] ?? '');

    // config_get is read-only — no CSRF required
    if ($action !== 'config_get' && !hasValidSessionCsrf('admin_panel', requestCsrfToken())) {
        jsonError(419, 'invalid-csrf');
    }

    // Config actions don't need a DB connection
    if ($action === 'config_get') {
        cfActionConfigGet();
        exit;
    }
    if ($action === 'config_save') {
        cfActionConfigSave($params);
        exit;
    }

    $db   = new dbObj();
    $conn = $db->getConnstring();

    cfRequireAddonDomainSchema($conn);

    switch ($action) {
        case 'zone_add':
            cfActionZoneAdd($conn, $params);
            break;
        case 'refresh_status':
            cfActionRefreshStatus($conn, $params);
            break;
        case 'purge_cache':
            cfActionPurgeCache($conn, $params);
            break;
        case 'ssl_mode':
            cfActionSslMode($conn, $params);
            break;
        case 'always_https':
            cfActionAlwaysHttps($conn, $params);
            break;
        case 'zone_delete':
            cfActionZoneDelete($params);
            break;
        default:
            jsonError(400, 'unknown-action');
    }
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}
