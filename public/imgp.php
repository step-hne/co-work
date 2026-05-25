<?php
declare(strict_types=1);

error_reporting(0);

/**
 * Image proxy — fetches a remote image and re-serves it on the same origin.
 * Allows Facebook's OG scraper (and other social bots) to read images
 * that would otherwise be blocked by CORS, geo-restrictions, or bot filters.
 *
 * Usage: /imgp?u=<base64url-encoded-image-url>
 * Resizes to max 1200×630 and re-encodes as JPEG (≤85 quality) if GD is available.
 */

function imgpIsPrivateIp(string $ip): bool
{
    $long = ip2long($ip);
    if ($long === false) {
        return true;
    }
    foreach ([
        ['10.0.0.0',      '10.255.255.255'],
        ['172.16.0.0',    '172.31.255.255'],
        ['192.168.0.0',   '192.168.255.255'],
        ['127.0.0.0',     '127.255.255.255'],
        ['169.254.0.0',   '169.254.255.255'],
        ['0.0.0.0',       '0.255.255.255'],
    ] as [$lo, $hi]) {
        if ($long >= ip2long($lo) && $long <= ip2long($hi)) {
            return true;
        }
    }
    return false;
}

// ── Decode the URL parameter ──────────────────────────────────────────────────
$encoded = trim((string) ($_GET['u'] ?? ''));
if ($encoded === '') {
    http_response_code(400);
    exit;
}

// base64url → base64 → string
$url = base64_decode(strtr($encoded, '-_', '+/'), true);
if ($url === false || $url === '') {
    http_response_code(400);
    exit;
}
$url = trim($url);

// ── Validate URL ──────────────────────────────────────────────────────────────
if (filter_var($url, FILTER_VALIDATE_URL) === false) {
    http_response_code(400);
    exit;
}

$scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
if ($scheme !== 'http' && $scheme !== 'https') {
    http_response_code(403);
    exit;
}

$host = (string) parse_url($url, PHP_URL_HOST);
if ($host === '') {
    http_response_code(400);
    exit;
}

// ── SSRF guard — block literal private/loopback IP hosts only ────────────────
// (DNS-resolution based check skipped: unreliable on shared hosting)
if (filter_var($host, FILTER_VALIDATE_IP) !== false && imgpIsPrivateIp($host)) {
    http_response_code(403);
    exit;
}

// ── Fetch image ───────────────────────────────────────────────────────────────
$ch = curl_init($url);
if ($ch === false) {
    http_response_code(502);
    exit;
}

curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS      => 3,
    CURLOPT_CONNECTTIMEOUT => 5,
    CURLOPT_TIMEOUT        => 15,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => 0,
    CURLOPT_USERAGENT      => 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
    CURLOPT_HTTPHEADER     => ['Accept: image/webp,image/apng,image/*,*/*;q=0.8'],
]);

$body     = curl_exec($ch);
$httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
$rawCt    = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
curl_close($ch);

if ($body === false || $httpCode < 200 || $httpCode >= 400) {
    http_response_code(502);
    exit;
}

// ── Validate content-type ─────────────────────────────────────────────────────
$ct = strtolower(trim(explode(';', $rawCt)[0]));
$allowed = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml'];
if (!in_array($ct, $allowed, true)) {
    http_response_code(415);
    exit;
}

// ── Optional GD compress / resize (max 1200×630 for OG) ──────────────────────
$rasterTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
if (function_exists('imagecreatefromstring') && in_array($ct, $rasterTypes, true)) {
    $img = @imagecreatefromstring((string) $body);
    if ($img !== false) {
        $origW = imagesx($img);
        $origH = imagesy($img);
        $maxW  = 1200;
        $maxH  = 630;

        if ($origW > $maxW || $origH > $maxH) {
            $ratio  = min($maxW / $origW, $maxH / $origH);
            $newW   = (int) round($origW * $ratio);
            $newH   = (int) round($origH * $ratio);
            $canvas = imagecreatetruecolor($newW, $newH);

            if ($canvas !== false) {
                if ($ct === 'image/png') {
                    imagealphablending($canvas, false);
                    imagesavealpha($canvas, true);
                }
                imagecopyresampled($canvas, $img, 0, 0, 0, 0, $newW, $newH, $origW, $origH);
                imagedestroy($img);

                ob_start();
                if ($ct === 'image/png') {
                    imagepng($canvas, null, 6);
                } else {
                    imagejpeg($canvas, null, 85);
                    $ct = 'image/jpeg';
                }
                $compressed = ob_get_clean();
                imagedestroy($canvas);

                if ($compressed !== false && $compressed !== '') {
                    $body = $compressed;
                }
            }
        } else {
            imagedestroy($img);
        }
    }
}

// ── Serve ─────────────────────────────────────────────────────────────────────
header('Content-Type: ' . $ct);
header('Content-Length: ' . strlen((string) $body));
header('Cache-Control: public, max-age=86400, immutable');
header('X-Content-Type-Options: nosniff');
echo $body;
exit;
