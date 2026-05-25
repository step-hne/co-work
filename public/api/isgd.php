<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok'=>false,'err'=>'method-not-allowed','allow'=>'POST']);
    exit;
}

if (!isset($_POST['longurl']) || trim((string)$_POST['longurl']) === '') {
    http_response_code(400);
    echo json_encode(['ok'=>false,'err'=>'missing longurl']);
    exit;
}

$longurl = trim((string)$_POST['longurl']);
$prm     = isset($_POST['prm']) ? (string)$_POST['prm'] : '';

function is_http_url(string $u): bool {
    if (!filter_var($u, FILTER_VALIDATE_URL)) return false;
    $sch = strtolower((string)parse_url($u, PHP_URL_SCHEME));
    return $sch === 'http' || $sch === 'https';
}
if (!is_http_url($longurl)) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'err'=>'invalid longurl']);
    exit;
}

function shorten_isgd(string $url): array {
    $api = 'https://is.gd/create.php?format=simple&url=' . rawurlencode($url);
    $ch = curl_init($api);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => 0,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    $resp = curl_exec($ch);
    $cerr = curl_error($ch);
    $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);

    if ($resp === false) {
        return [null, 'curl:'.$cerr];
    }
    $s = trim((string)$resp);
    if ($http !== 200) {
        return [null, 'http:'.$http.' body:'.$s];
    }
    if ($s === '' || stripos($s, 'Error:') === 0) {
        return [null, 'isgd:'.$s];
    }
    return [$s, null];
}

[$short, $err] = shorten_isgd($longurl);
if ($short === null) {
    http_response_code(502);
    echo json_encode(['ok'=>false,'err'=>'shorten_failed','msg'=>$err]);
    exit;
}

function rand_token(int $n): string {
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
        $shim = 'https://l.facebook.com/l.php?u=' . rawurlencode($short) . '&h=' . rand_token(7) . '&s=1';
        break;
    case 'f':
        $shim = 'https://l.wl.co/l?u=' . rawurlencode($short);
        break;
}

echo json_encode([['l' => $shim]], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
