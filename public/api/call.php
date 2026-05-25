<?php

declare(strict_types=1);

error_reporting(0);

include_once('../session_guards.php');

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonError(405, 'method-not-allowed');
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

    $domain = trim((string) ($_POST['domain'] ?? ''));
    $userid = strtoupper(trim((string) ($_POST['sub_domain'] ?? '')));
    if ($domain === '' || $userid === '') {
        jsonError(422, 'missing-fields');
    }
    if ($userid !== $sessionSubId) {
        jsonError(403, 'forbidden');
    }

    $serverPort = (int) ($_SERVER['SERVER_PORT'] ?? 80);
    $loopbackScheme = ($serverPort === 443) ? 'https' : 'http';
    $url = $loopbackScheme . '://127.0.0.1:' . $serverPort . '/api/api.php';
    $curl = curl_init();
    $csrfToken = requestCsrfToken();
    $post = [
        'domain' => $domain,
        'csrf_token' => $csrfToken,
    ];
    $headers = [
        'Host: ' . $_SERVER['HTTP_HOST'],
        'X-CSRF-Token: ' . $csrfToken,
        'Cookie: ' . session_name() . '=' . session_id(),
    ];

    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_POST, true);
    curl_setopt($curl, CURLOPT_POSTFIELDS, $post);
    curl_setopt($curl, CURLOPT_TIMEOUT, 15);
    curl_setopt($curl, CURLOPT_HEADER, 0);
    curl_setopt($curl, CURLOPT_FORBID_REUSE, true);
    curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 5);
    curl_setopt($curl, CURLOPT_FRESH_CONNECT, true);
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, $loopbackScheme === 'https' ? 2 : 0);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, $loopbackScheme === 'https');
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
    $result = curl_exec($curl);

    if ($result === false) {
        jsonError(502, 'cpanel-request-failed');
    }

    echo json_encode([
        [
            'domain' => $domain,
            'userid' => $userid,
        ],
    ]);
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}
