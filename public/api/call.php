<?php

declare(strict_types=1);

error_reporting(0);

include_once('../session_guards.php');

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonError(405, 'method-not-allowed');
}

/**
 * @return array{scheme:string,host:string,port:int,hostHeader:string}
 */
function resolveLoopbackTarget(): array
{
    $isHttps = false;
    if (isset($_SERVER['HTTPS'])) {
        $httpsValue = strtolower(trim((string) $_SERVER['HTTPS']));
        $isHttps = $httpsValue !== '' && $httpsValue !== 'off' && $httpsValue !== '0';
    }

    if (!$isHttps) {
        $forwardedProto = strtolower(trim((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')));
        $isHttps = $forwardedProto === 'https';
    }

    $scheme = $isHttps ? 'https' : 'http';

    $requestHost = trim((string) ($_SERVER['HTTP_HOST'] ?? ''));
    $hostHeader = $requestHost !== '' ? $requestHost : '127.0.0.1';

    $serverPort = (int) ($_SERVER['SERVER_PORT'] ?? 0);
    if ($serverPort <= 0) {
        $serverPort = $isHttps ? 443 : 80;
    }

    $host = '127.0.0.1';
    $serverAddress = trim((string) ($_SERVER['SERVER_ADDR'] ?? ''));
    if ($serverAddress === '::1') {
        $host = '[::1]';
    }

    return [
        'scheme' => $scheme,
        'host' => $host,
        'port' => $serverPort,
        'hostHeader' => $hostHeader,
    ];
}

try {
    startUserGuardSession();
    $sessionSubId = authenticatedUserSubId();
    if ($sessionSubId === '') {
        jsonError(403, 'unauthorized');
    }

    $csrfToken = requestCsrfToken();
    if (!hasValidSessionCsrf('user_portal', $csrfToken)) {
        jsonError(419, 'invalid-csrf');
    }

    $domain = trim((string) ($_POST['domain'] ?? ''));
    $userid = strtoupper(trim((string) ($_POST['sub_domain'] ?? '')));
    if ($domain === '' || $userid === '') {
        jsonError(422, 'missing-fields');
    }

    if (str_contains($domain, "\r") || str_contains($domain, "\n")) {
        jsonError(422, 'invalid-domain');
    }

    if ($userid !== $sessionSubId) {
        jsonError(403, 'forbidden');
    }

    $loopbackTarget = resolveLoopbackTarget();
    $url = $loopbackTarget['scheme']
        . '://'
        . $loopbackTarget['host']
        . ':'
        . (string) $loopbackTarget['port']
        . '/api/api.php';

    $curl = curl_init();
    $post = [
        'domain' => $domain,
        'csrf_token' => $csrfToken,
    ];

    $headers = [
        'X-CSRF-Token: ' . $csrfToken,
        'Host: ' . $loopbackTarget['hostHeader'],
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
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, $loopbackTarget['scheme'] === 'https' ? 2 : 0);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, $loopbackTarget['scheme'] === 'https');
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);

    $result = curl_exec($curl);
    $httpStatus = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
    $curlError = curl_error($curl);
    curl_close($curl);

    if ($result === false) {
        jsonError(502, 'cpanel-request-failed:' . $curlError);
    }

    $decodedResult = json_decode((string) $result, true);
    if (!is_array($decodedResult)) {
        jsonError(502, 'cpanel-invalid-response');
    }

    if ($httpStatus >= 400) {
        jsonError(502, 'cpanel-error-status-' . (string) $httpStatus);
    }

    echo json_encode($decodedResult);
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}
