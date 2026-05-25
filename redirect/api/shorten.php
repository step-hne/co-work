<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/env.php';

load_env_file(dirname(__DIR__) . '/.env');

require_once dirname(__DIR__, 2) . '/Base64URL.php';
require_once __DIR__ . '/../public_link.php';

header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');

if (srp_api_is_https()) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// ── Shared: resolve API key ───────────────────────────────────────────────────
$apiKey = app_env('SRP_API_KEY', '') ?? '';

if ($apiKey === '') {
    error_log('SRP_API_KEY is not configured');
    srp_api_fail(503, 'Service Unavailable');
}

// ── Mode B: ?key=<api_key>&url=<target_url> — GET atau POST ──────────────────
// Auth via query-string key; sub_id extracted from URL path; base_url from URL host.
if (isset($_GET['key'], $_GET['url']) && is_string($_GET['key']) && is_string($_GET['url'])) {
    if (!in_array($_SERVER['REQUEST_METHOD'], ['GET', 'POST'], true)) {
        header('Allow: GET, POST');
        srp_api_fail(405, 'Method Not Allowed');
    }

    if (!hash_equals($apiKey, $_GET['key'])) {
        srp_api_fail(401, 'Unauthorized');
    }

    $rawInputUrl = trim($_GET['url']);

    if ($rawInputUrl === '' || strlen($rawInputUrl) > 2048) {
        srp_api_fail(422, 'Invalid url parameter');
    }

    $parsedInput = parse_url($rawInputUrl);

    if (
        !is_array($parsedInput)
        || !isset($parsedInput['scheme'], $parsedInput['host'])
        || strtolower((string) $parsedInput['scheme']) !== 'https'
    ) {
        srp_api_fail(422, 'url must be an absolute https:// URL');
    }

    $inputScheme = 'https';
    $inputHost   = preg_replace('/[^a-zA-Z0-9.\-:\[\]]/', '', (string) $parsedInput['host']);
    $inputBase   = $inputScheme . '://' . $inputHost;

    $inputPath = isset($parsedInput['path'])
        ? trim($parsedInput['path'], '/')
        : '';

    $subId = $inputPath !== '' ? basename($inputPath) : '';

    if ($subId === '' || strlen($subId) > 2048 || preg_match('/^[A-Za-z0-9_=+\/-]{1,2048}$/', $subId) !== 1) {
        srp_api_fail(422, 'Cannot extract valid sub_id from url path');
    }

    $payload = srp_public_link_decode_legacy_token($subId);

    if ($payload === null) {
        srp_api_fail(422, 'Invalid sub_id token in url path');
    }

    try {
        /** @var PDO $pdo */
        $pdo = require __DIR__ . '/../connection.config.php';

        srp_short_link_ensure_table($pdo);

        $code = srp_short_link_generate_unique_code($pdo);
        srp_short_link_create($pdo, $code, $payload);
    } catch (Throwable $e) {
        error_log('api/shorten (mode-b) failed: ' . $e->getMessage());
        srp_api_fail(500, 'Internal Server Error');
    }

    $shortToken = srp_short_link_build_token($code);
    $shortUrl   = $inputBase . '/' . $shortToken;

    http_response_code(201);
    echo json_encode(
        ['ok' => true, 'code' => $code, 'token' => $shortToken, 'url' => $shortUrl],
        JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );
    exit;
}

// ── Mode A: Authorization: Bearer <key> + JSON body ──────────────────────────
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: GET, POST');
    srp_api_fail(405, 'Method Not Allowed');
}

$authHeader = isset($_SERVER['HTTP_AUTHORIZATION']) && is_string($_SERVER['HTTP_AUTHORIZATION'])
    ? $_SERVER['HTTP_AUTHORIZATION']
    : '';

if (substr_compare($authHeader, 'Bearer ', 0, 7, false) !== 0) {
    header('WWW-Authenticate: Bearer realm="srp-api"');
    srp_api_fail(401, 'Unauthorized');
}

$providedKey = substr($authHeader, 7);

if (!hash_equals($apiKey, $providedKey)) {
    header('WWW-Authenticate: Bearer realm="srp-api"');
    srp_api_fail(401, 'Unauthorized');
}

// ── Parse JSON body ───────────────────────────────────────────────────────────
$rawBody = (string) file_get_contents('php://input');

if ($rawBody === '') {
    srp_api_fail(400, 'Empty request body');
}

if (strlen($rawBody) > 8192) {
    srp_api_fail(413, 'Request body too large');
}

try {
    $body = json_decode($rawBody, true, 8, JSON_THROW_ON_ERROR);
} catch (JsonException $e) {
    srp_api_fail(400, 'Invalid JSON');
}

if (!is_array($body)) {
    srp_api_fail(400, 'Expected a JSON object');
}

// ── Resolve payload ───────────────────────────────────────────────────────────
$payload = null;

if (isset($body['sub_id']) && is_string($body['sub_id'])) {
    $payload = srp_public_link_decode_legacy_token(trim($body['sub_id']));

    if ($payload === null) {
        srp_api_fail(422, 'Invalid sub_id token');
    }
} else {
    $clickId = srp_public_link_sanitize_token_part($body['click_id'] ?? null, 64);
    $userLp  = srp_public_link_sanitize_token_part($body['user_lp'] ?? null, 64);

    if ($clickId === null || $userLp === null) {
        srp_api_fail(422, 'Provide either sub_id or both click_id and user_lp');
    }

    $payload = [
        'click_id'     => $clickId,
        'user_lp'      => $userLp,
        'canonical_url' => srp_public_link_normalize_https_url($body['canonical_url'] ?? '') ?? '',
        'image_url'    => srp_public_link_normalize_https_url($body['image_url'] ?? '') ?? '',
        'title'        => srp_public_link_normalize_title($body['title'] ?? ''),
        'lg'           => srp_public_link_normalize_lg($body['lg'] ?? ''),
    ];
}

// ── Optional custom short code ────────────────────────────────────────────────
$requestedCode = null;

if (isset($body['code']) && is_string($body['code']) && $body['code'] !== '') {
    $requestedCode = srp_short_link_sanitize_code($body['code']);

    if ($requestedCode === null) {
        srp_api_fail(422, 'Invalid code — use 4–32 chars [A-Za-z0-9_-]');
    }
}

// ── Optional base_url override ────────────────────────────────────────────────
$baseUrl = null;

if (isset($body['base_url']) && is_string($body['base_url']) && $body['base_url'] !== '') {
    $baseUrl = srp_public_link_normalize_https_url(trim($body['base_url']));

    if ($baseUrl === null) {
        srp_api_fail(422, 'Invalid base_url — must be an absolute https:// URL');
    }

    $baseUrl = rtrim((string) $baseUrl, '/');
}

if ($baseUrl === null) {
    $scheme  = srp_api_is_https() ? 'https' : 'http';
    $rawHost = isset($_SERVER['HTTP_HOST']) && is_string($_SERVER['HTTP_HOST'])
        ? $_SERVER['HTTP_HOST']
        : 'localhost';
    $host = preg_replace('/[^a-zA-Z0-9.\-:\[\]]/', '', $rawHost);
    $baseUrl = $scheme . '://' . $host;
}

// ── Persist ───────────────────────────────────────────────────────────────────
try {
    /** @var PDO $pdo */
    $pdo = require __DIR__ . '/../connection.config.php';

    srp_short_link_ensure_table($pdo);

    if ($requestedCode !== null) {
        if (srp_short_link_exists($pdo, $requestedCode)) {
            srp_api_fail(409, 'Short code already taken');
        }

        $code = $requestedCode;
    } else {
        $code = srp_short_link_generate_unique_code($pdo);
    }

    srp_short_link_create($pdo, $code, $payload);
} catch (Throwable $e) {
    error_log('api/shorten failed: ' . $e->getMessage());
    srp_api_fail(500, 'Internal Server Error');
}

$shortToken = srp_short_link_build_token($code);
$shortUrl   = $baseUrl . '/' . $shortToken;

http_response_code(201);
echo json_encode(
    ['ok' => true, 'code' => $code, 'token' => $shortToken, 'url' => $shortUrl],
    JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
);

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * @return never
 */
function srp_api_fail(int $status, string $message): never
{
    http_response_code($status);
    echo json_encode(
        ['ok' => false, 'error' => $message],
        JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE
    );
    exit;
}

function srp_api_is_https(): bool
{
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        return true;
    }

    if (
        isset($_SERVER['HTTP_X_FORWARDED_PROTO'])
        && is_string($_SERVER['HTTP_X_FORWARDED_PROTO'])
        && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https'
    ) {
        return true;
    }

    return false;
}
