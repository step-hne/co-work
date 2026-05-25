<?php

declare(strict_types=1);

include_once __DIR__ . '/../xmlapi.php';
include_once __DIR__ . '/../session_guards.php';
include_once(dirname(__DIR__, 2) . '/env.php');
load_env_file(dirname(__DIR__) . '/.env');

if (ob_get_level() > 0) {
    ob_end_clean();
}
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
ignore_user_abort(true);

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    jsonError(405, 'method-not-allowed');
}

try {
    startUserGuardSession();

    if (authenticatedUserSubId() === '') {
        jsonError(403, 'unauthorized');
    }

    if (!hasValidSessionCsrf('user_portal', requestCsrfToken())) {
        jsonError(419, 'invalid-csrf');
    }

    $domain = normalizeCpanelDomain((string) ($_POST['domain'] ?? ''));
    if ($domain === null) {
        jsonError(422, 'invalid-domain');
    }

    if (!ajax_api($domain)) {
        jsonError(502, 'cpanel-operation-failed');
    }

    echo json_encode(['ok' => true]);
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}

function normalizeCpanelDomain(string $domain): ?string
{
    $domain = strtolower(rtrim(trim($domain), '.'));
    if ($domain === '' || strlen($domain) > 253) {
        return null;
    }

    if (filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
        return null;
    }

    return $domain;
}

function makeCpanelClient(): xmlapi
{
    $host = app_env('CPANEL_HOST', 'localhost');
    $port = (int) app_env('CPANEL_PORT', '2083');

    $client = new xmlapi($host);
    $client->set_port($port);
    $client->set_output('json');
    $client->set_debug(0);

    return $client;
}

function cpanelParkAndSubdomain(xmlapi $client, string $user, string $domain, string $dir): bool
{
    $result = $client->api2_query($user, 'Park', 'park', ['domain' => $domain]);
    if ($result === null) {
        return false;
    }

    $result = $client->api2_query($user, 'SubDomain', 'addsubdomain', [
        'domain'     => '*',
        'rootdomain' => $domain,
        'dir'        => $dir,
    ]);

    return $result !== null;
}

function ajax_api(string $domain): bool
{
    $user  = app_required_env('CPANEL_USER');
    $dir   = app_env('CPANEL_SUBDOMAIN_DIR', '/public_html');
    $token = app_env('CPANEL_API_TOKEN', '');

    // --- Try token auth first (if configured) ---
    if ($token !== '') {
        $client = makeCpanelClient();
        $client->token_auth($user, $token);

        if (cpanelParkAndSubdomain($client, $user, $domain, $dir)) {
            return true;
        }
        // Token failed — fall through to password auth
    }

    // --- Fallback: password auth ---
    $pass = app_required_env('CPANEL_PASSWORD');

    $client = makeCpanelClient();
    $client->password_auth($user, $pass);

    return cpanelParkAndSubdomain($client, $user, $domain, $dir);
}
