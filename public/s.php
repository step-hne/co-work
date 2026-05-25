<?php
declare(strict_types=1);

error_reporting(0);

include_once __DIR__ . '/connection.config.php';

$code = preg_replace('/[^A-Za-z0-9]/', '', (string) ($_GET['c'] ?? ''));

if ($code === '') {
    http_response_code(404);
    exit;
}

$stmt = mysqli_prepare($link, 'SELECT long_url, og_title, og_image FROM shortlinks WHERE code = ? LIMIT 1');
if (!$stmt) {
    http_response_code(500);
    exit;
}

mysqli_stmt_bind_param($stmt, 's', $code);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
$row    = $result ? mysqli_fetch_assoc($result) : null;
mysqli_stmt_close($stmt);

if (!is_array($row) || empty($row['long_url'])) {
    http_response_code(404);
    exit;
}

$target = filter_var($row['long_url'], FILTER_VALIDATE_URL) !== false ? $row['long_url'] : null;

if ($target === null) {
    http_response_code(404);
    exit;
}

$ogTitle = trim((string) ($row['og_title'] ?? ''));
$ogImage = trim((string) ($row['og_image'] ?? ''));

// ── Bot / OG-scraper detection ────────────────────────────────────────────────
$ua    = (string) ($_SERVER['HTTP_USER_AGENT'] ?? '');
$uaLow = strtolower($ua);

// Facebook/Meta bot family (excludes FBAN/FBAV in-app browser)
$isFbFamily = !preg_match('/\b(FBAN|FBAV)\b/', $ua)
    && (str_contains($uaLow, 'facebookexternalhit')
        || str_contains($uaLow, 'facebot')
        || str_contains($uaLow, 'meta-externalagent')
        || str_contains($uaLow, 'facebookcatalog'));

// Other social/OG scrapers
$isSocialBot = $isFbFamily
    || str_contains($uaLow, 'twitterbot')
    || str_contains($uaLow, 'linkedinbot')
    || str_contains($uaLow, 'whatsapp')
    || str_contains($uaLow, 'telegrambot')
    || str_contains($uaLow, 'slackbot')
    || str_contains($uaLow, 'discordbot')
    || str_contains($uaLow, 'applebot')
    || str_contains($uaLow, 'googlebot');

if ($isSocialBot) {
    $esc      = fn(string $s): string => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $shortUrl = 'https://' . $_SERVER['HTTP_HOST'] . '/s-' . $code;

    // Accept any valid image URL (HTTP or HTTPS) — proxy will fetch it
    $validImage   = ($ogImage !== '' && filter_var($ogImage, FILTER_VALIDATE_URL) !== false) ? $ogImage : '';
    $proxiedImage = '';
    if ($validImage !== '') {
        $proxiedImage = 'https://' . $_SERVER['HTTP_HOST'] . '/imgp?u='
            . rtrim(strtr(base64_encode($validImage), '+/', '-_'), '=');
    }

    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    echo '<!DOCTYPE html><html prefix="og: https://ogp.me/ns#"><head>';
    echo '<meta charset="utf-8">';
    echo '<title>' . $esc($ogTitle ?: 'Preview') . '</title>';
    echo '<meta property="og:type" content="website">';
    echo '<meta property="og:url" content="' . $esc($shortUrl) . '">';
    if ($ogTitle !== '') {
        echo '<meta property="og:title" content="' . $esc($ogTitle) . '">';
        echo '<meta property="og:description" content="' . $esc($ogTitle) . '">';
    }
    if ($proxiedImage !== '') {
        echo '<meta property="og:image" content="' . $esc($proxiedImage) . '">';
        echo '<meta property="og:image:secure_url" content="' . $esc($proxiedImage) . '">';
        echo '<meta property="og:image:width" content="1200">';
        echo '<meta property="og:image:height" content="630">';
        echo '<meta name="twitter:card" content="summary_large_image">';
        echo '<meta name="twitter:image" content="' . $esc($proxiedImage) . '">';
    }
    if ($ogTitle !== '') {
        echo '<meta name="twitter:title" content="' . $esc($ogTitle) . '">';
    }
    echo '<meta http-equiv="refresh" content="0;url=' . $esc($target) . '">';
    echo '</head><body></body></html>';
    exit;
}

header('Location: ' . $target, true, 302);
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
exit;
