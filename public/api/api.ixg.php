<?php
declare(strict_types=1);

include_once dirname(__DIR__, 2) . '/env.php';
load_env_file(dirname(__DIR__) . '/.env');

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  http_response_code(405);
  echo json_encode(['ok'=>false,'err'=>'method-not-allowed','allow'=>'POST']);
  exit;
}

$longurl = isset($_POST['longurl']) ? trim((string)$_POST['longurl']) : '';
$prm     = isset($_POST['prm']) ? (string)$_POST['prm'] : '';

if ($longurl === '') {
  http_response_code(400);
  echo json_encode(['ok'=>false,'err'=>'missing longurl']);
  exit;
}

$AF_SECRET = app_env('AF_SECRET');
if (!$AF_SECRET || $AF_SECRET === '') {
  http_response_code(500);
  echo json_encode(['ok'=>false,'err'=>'missing AF_SECRET']);
  exit;
}

$ts = time();
$canon = [
  'code'  => '',
  'desc'  => '',
  'img'   => '',
  'title' => '',
  'ts'    => $ts,
  'url'   => $longurl,
];
ksort($canon);
$payload = json_encode($canon, JSON_UNESCAPED_SLASHES);
$sig = rtrim(strtr(base64_encode(hash_hmac('sha256', $payload, $AF_SECRET, true)), '+/', '-_'), '=');

$ch = curl_init('https://me.ixg.llc/api.php?op=create');
curl_setopt_array($ch, [
  CURLOPT_POST => true,
  CURLOPT_RETURNTRANSFER => true,
  CURLOPT_HTTPHEADER => [
    'X-Bypass-Key: ' . app_env('IXG_BYPASS_KEY'),
    'User-Agent: ssl-manager/1.0',
    'Accept: application/json',
  ],
  CURLOPT_POSTFIELDS => http_build_query([
    'url'   => $canon['url'],
    'title' => $canon['title'],
    'desc'  => $canon['desc'],
    'img'   => $canon['img'],
    'code'  => $canon['code'],
    'ts'    => $ts,
    'sig'   => $sig,
  ]),
  CURLOPT_CONNECTTIMEOUT => 5,
  CURLOPT_TIMEOUT => 12,
]);
$resp = curl_exec($ch);
$cerr = curl_error($ch);
$http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);

if ($resp === false) {
  http_response_code(502);
  echo json_encode(['ok'=>false,'err'=>'curl','msg'=>$cerr]);
  exit;
}

$j = json_decode($resp, true);
if (!is_array($j)) {
  $isCfChallenge = stripos($resp, 'challenge-platform') !== false
    || stripos($resp, 'Just a moment') !== false
    || stripos($resp, '__cf_chl_') !== false;
  http_response_code($http ?: 500);
  echo json_encode([
    'ok'   => false,
    'err'  => $isCfChallenge ? 'cf-challenge' : 'bad-json',
    'http' => $http,
    'hint' => $isCfChallenge ? 'Origin diblokir Cloudflare Managed Challenge — whitelist IP atau pasang WAF skip rule via header rahasia.' : null,
  ]);
  exit;
}
if (empty($j['ok'])) {
  http_response_code($http ?: 400);
  echo json_encode(['ok'=>false,'err'=>'api-failed','api'=>$j]);
  exit;
}

$short = (string)($j['short_url'] ?? '');
if ($short === '') {
  http_response_code(500);
  echo json_encode(['ok'=>false,'err'=>'no-short-url','api'=>$j]);
  exit;
}

function rand_token(int $n, string $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'): string {
  $len = strlen($alphabet);
  $s = '';
  for ($i = 0; $i < $n; $i++) {
    $s .= $alphabet[random_int(0, $len - 1)];
  }
  return $s;
}

$short = preg_replace(
  '#^https?://[a-z0-9-]+\.ixg\.llc/#i',
  'https://' . rand_token(8, 'abcdefghijklmnopqrstuvwxyz0123456789') . '.ixg.llc/',
  $short,
  1
);

switch ($prm) {
  case 'b':
    $_short = 'https://l.facebook.com/l.php?u=' . rawurlencode($short)
            . '&h=' . rand_token(7) . '&s=1';
    break;
  case 'f':
    $_short = 'https://l.wl.co/l?u=' . rawurlencode($short);
    break;
  default:
    $_short = $short;
}

echo json_encode([['l' => $_short]], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);