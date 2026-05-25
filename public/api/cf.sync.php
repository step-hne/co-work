<?php

declare(strict_types=1);

include_once('../connection.config.php');
include_once('../session_guards.php');
include_once(dirname(__DIR__, 2) . '/env.php');
load_env_file(dirname(__DIR__) . '/.env');
include_once('../cf-lib.php');

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonError(405, 'method-not-allowed');
}

/**
 * Persist CF zone data for a user-owned domain (lookup by domain + sub_domain).
 */
function cfSyncSaveToDB(mysqli $db, string $domain, string $subDomain, string $zoneId, string $status, string $nsJson): void
{
    $stmt = mysqli_prepare(
        $db,
        'UPDATE addondomain SET cf_zone_id = ?, cf_status = ?, cf_ns = ? WHERE domain = ? AND sub_domain = ?'
    );
    if (!$stmt) {
        throw new RuntimeException('DB prepare failed.');
    }
    bindStatementValues($stmt, 'sssss', [$zoneId, $status, $nsJson, $domain, $subDomain]);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);
}

try {
    startUserGuardSession();
    $sessionSubId = authenticatedUserSubId();
    if ($sessionSubId === '') {
        jsonError(403, 'unauthorized');
    }
    if (!hasValidSessionCsrf('user_portal', requestCsrfToken())) {
        jsonError(419, 'invalid-csrf');
    }

    $domain    = trim((string) ($_POST['domain'] ?? ''));
    $subDomain = strtoupper(trim((string) ($_POST['sub_domain'] ?? '')));

    if ($domain === '' || $subDomain === '') {
        jsonError(422, 'missing-fields');
    }
    if ($subDomain !== $sessionSubId) {
        jsonError(403, 'forbidden');
    }

    // Confirm domain belongs to this user
    $stmt = mysqli_prepare($link, 'SELECT id FROM addondomain WHERE domain = ? AND sub_domain = ? LIMIT 1');
    if (!$stmt) {
        jsonError(500, 'db-error');
    }
    bindStatementValues($stmt, 'ss', [$domain, $subDomain]);
    mysqli_stmt_execute($stmt);
    $check = mysqli_stmt_get_result($stmt);
    if (!$check || !mysqli_fetch_assoc($check)) {
        jsonError(403, 'domain-not-found');
    }
    mysqli_stmt_close($stmt);

    // Prefer user-specific CF credentials, fall back to admin env
    $cfToken     = '';
    $cfAccountId = '';
    $uStmt = mysqli_prepare($link, 'SELECT cf_token, cf_account_id FROM `generate` WHERE sub_id = ? LIMIT 1');
    if ($uStmt) {
        bindStatementValues($uStmt, 's', [$sessionSubId]);
        mysqli_stmt_execute($uStmt);
        $uRow = mysqli_fetch_assoc(mysqli_stmt_get_result($uStmt));
        mysqli_stmt_close($uStmt);
        $cfToken     = trim((string) ($uRow['cf_token']      ?? ''));
        $cfAccountId = trim((string) ($uRow['cf_account_id'] ?? ''));
    }
    if ($cfToken === '') {
        $cfToken     = app_env('CF_API_TOKEN', '');
        $cfAccountId = app_env('CF_ACCOUNT_ID', '');
    }

    if ($cfToken === '') {
        jsonError(500, 'cf-not-configured');
    }
    if ($cfAccountId === '') {
        jsonError(500, 'cf-account-missing');
    }

    $zoneId        = '';
    $cfStatus      = '';
    $nameServers   = [];
    $alreadyExists = false;

    // Attempt to create zone
    $createBody = [
        'name'       => $domain,
        'account'    => ['id' => $cfAccountId],
        'jump_start' => true,
    ];
    $createResp = cfApi('POST', '/zones', $createBody, $cfToken);

    if ($createResp['success'] ?? false) {
        $zone        = $createResp['result'];
        $zoneId      = $zone['id']           ?? '';
        $cfStatus    = $zone['status']        ?? 'pending';
        $nameServers = $zone['name_servers']  ?? [];
    } else {
        // Check if zone already exists (CF error code 1061)
        foreach (($createResp['errors'] ?? []) as $cfErr) {
            if (($cfErr['code'] ?? 0) === 1061) {
                $alreadyExists = true;
                break;
            }
        }

        if ($alreadyExists) {
            $listResp = cfApi('GET', '/zones?name=' . rawurlencode($domain), null, $cfToken);
            if (($listResp['success'] ?? false) && !empty($listResp['result'][0])) {
                $zone        = $listResp['result'][0];
                $zoneId      = $zone['id']          ?? '';
                $cfStatus    = $zone['status']       ?? 'pending';
                $nameServers = $zone['name_servers'] ?? [];
            } else {
                jsonError(409, 'zone-exists');
            }
        } else {
            $firstMsg = $createResp['errors'][0]['message'] ?? 'cf-api-failed';
            jsonError(400, $firstMsg);
        }
    }

    // Apply all settings, header rules, DNS, and recommended features (same as admin flow)
    if ($zoneId !== '') {
        cfApplyAllRecommended($zoneId, $cfToken);

        $serverIp = app_env('CF_SERVER_IP', '');
        if ($serverIp !== '') {
            cfProvisionDns($zoneId, $domain, $serverIp, $cfToken);
        }
    }

    // Persist zone data to addondomain row
    cfSyncSaveToDB($link, $domain, $subDomain, $zoneId, $cfStatus, json_encode($nameServers));

    echo json_encode([
        'ok'             => true,
        'zone_id'        => $zoneId,
        'status'         => $cfStatus,
        'name_servers'   => $nameServers,
        'already_exists' => $alreadyExists,
    ]);
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}
