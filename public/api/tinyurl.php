<?php
declare(strict_types=1);

include_once dirname(__DIR__, 2) . '/env.php';
load_env_file(dirname(__DIR__) . '/.env');

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'err' => 'method-not-allowed', 'allow' => 'POST']);
    exit;
}

$longurl = trim((string) ($_POST['longurl'] ?? ''));
$prm     = (string) ($_POST['prm'] ?? '');

if ($longurl === '') {
    http_response_code(400);
    echo json_encode(['ok' => false, 'err' => 'missing longurl']);
    exit;
}

function is_http_url_tu(string $u): bool
{
    if (!filter_var($u, FILTER_VALIDATE_URL)) {
        return false;
    }
    $sch = strtolower((string) parse_url($u, PHP_URL_SCHEME));
    return $sch === 'http' || $sch === 'https';
}

if (!is_http_url_tu($longurl)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'err' => 'invalid longurl']);
    exit;
}

function shorten_tinyurl(string $url): array
{
    $apiKey = app_env('TINYURL_API_KEY', '');
    if ($apiKey === '') {
        return [null, 'missing TINYURL_API_KEY'];
    }
    $endpoint = 'https://api.tinyurl.com/create';

    $payload = json_encode([
        'url'    => $url,
        'domain' => 'tinyurl.com',
    ]);

    $ch = curl_init($endpoint);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_HTTPHEADER     => [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $apiKey,
        ],
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT        => 12,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);

    $resp  = curl_exec($ch);
    $cerr  = curl_error($ch);
    $http  = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($resp === false || $cerr !== '') {
        return [null, 'curl:' . $cerr];
    }

    $body = trim((string) $resp);
    if ($http < 200 || $http > 299) {
        return [null, 'http:' . $http . ' body:' . $body];
    }

    $decoded = json_decode($body, true);
    $short   = $decoded['data']['tiny_url'] ?? null;

    if (!is_string($short) || $short === '') {
        return [null, 'tinyurl:empty response'];
    }

    return [$short, null];
}

[$short, $err] = shorten_tinyurl($longurl);
if ($short === null) {
    http_response_code(502);
    echo json_encode(['ok' => false, 'err' => 'shorten_failed', 'msg' => $err]);
    exit;
}

function rand_token_tu(int $n): string
{
    $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $len = strlen($alphabet);
    $s = '';
    for ($i = 0; $i < $n; $i++) {
        $s .= $alphabet[random_int(0, $len - 1)];
    }
    return $s;
}

$shim = $short;
switch ($prm) {
    case 'b':
        $shim = 'https://l.facebook.com/l.php?u=' . rawurlencode($short) . '&h=' . rand_token_tu(7) . '&s=1';
        break;
    case 'f':
        $shim = 'https://l.wl.co/l?u=' . rawurlencode($short);
        break;
}

echo json_encode([['l' => $shim]], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
