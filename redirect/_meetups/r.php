<?php

declare(strict_types=1);

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../connection.config.php';
require_once dirname(__DIR__, 2) . '/Base64URL.php';
require_once __DIR__ . '/../redirect_payload.php';

$redirectPayload = srp_redirect_payload_decode($_GET['rk'] ?? null);

$click_id = meetup_sanitize_token($redirectPayload['click_id'] ?? ($_GET['click_id'] ?? null), 128);
$country_code = meetup_sanitize_country_code($redirectPayload['country_code'] ?? ($_GET['country_code'] ?? null));
$user_agent = meetup_sanitize_token($redirectPayload['user_agent'] ?? ($_GET['user_agent'] ?? null), 32);
$ip_address = meetup_sanitize_ip($redirectPayload['ip_address'] ?? ($_GET['ip_address'] ?? null));
$user_lp = meetup_sanitize_token($redirectPayload['user_lp'] ?? ($_GET['user_lp'] ?? null), 64);

if ($click_id === null || $country_code === null || $user_agent === null || $user_lp === null) {
    meetup_fail(400);
}

try {
    $offerRow = meetup_fetch_offer($pdo, 'country_code', $country_code);

    if ($offerRow === null) {
        $offerRow = meetup_fetch_offer($pdo, 'network', strtoupper($user_lp));
    }

    if ($offerRow === null) {
        meetup_fail(404);
    }

    $redirect = html_entity_decode($offerRow['offer'], ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $resolvedNetwork = meetup_sanitize_token($offerRow['network'], 64);

    if ($redirect === '' || $resolvedNetwork === null) {
        meetup_fail(500);
    }

    $placeholders = ['{sub_id}', '{click_id}'];
    $replacements = [
        strtoupper($click_id),
        base64url_encode(
            strtoupper($click_id)
            . ',' . strtoupper($country_code)
            . ',' . $ip_address
            . ',' . strtoupper($user_agent)
            . ',' . strtoupper($resolvedNetwork)
        ),
    ];
    $offer = str_replace($placeholders, $replacements, $redirect);

    $offerUrl = meetup_sanitize_offer_url($offer);
    if ($offerUrl === null) {
        meetup_fail(500);
    }

    if ($click_id !== '') {
        require __DIR__ . '/clicks.php';
    }

} catch (Throwable $e) {
    error_log('Meetup offer lookup failed: ' . $e->getMessage());
    meetup_fail(500);
}

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Content-Type: text/html; charset=UTF-8');

$safeUrl = htmlspecialchars($offerUrl, ENT_QUOTES | ENT_HTML5, 'UTF-8');
echo '<!DOCTYPE html><html><head>'
    . '<meta charset="UTF-8">'
    . '<meta name="referrer" content="no-referrer">'
    . '<meta http-equiv="refresh" content="0;url=' . $safeUrl . '">'
    . '</head><body><script>window.location.replace(' . json_encode($offerUrl, JSON_UNESCAPED_SLASHES) . ');</script></body></html>';
exit;

/**
 * @return array{offer: string, network: string}|null
 */
function meetup_fetch_offer(PDO $pdo, string $column, string $value): ?array
{
    $allowedColumns = ['country_code', 'network'];
    if (!in_array($column, $allowedColumns, true)) {
        throw new InvalidArgumentException('Unsupported offering column.');
    }

    $rangeStatement = $pdo->prepare(
        sprintf('SELECT MIN(id) AS min_id, MAX(id) AS max_id FROM offering WHERE %s = :value', $column)
    );
    $rangeStatement->execute(['value' => $value]);
    $range = $rangeStatement->fetch();

    if (!is_array($range) || $range['min_id'] === null || $range['max_id'] === null) {
        return null;
    }

    $minId = (int) $range['min_id'];
    $maxId = (int) $range['max_id'];
    if ($minId < 1 || $maxId < $minId) {
        return null;
    }

    $randomId = random_int($minId, $maxId);
    $row = meetup_fetch_offer_at_or_after_id($pdo, $column, $value, $randomId)
        ?? meetup_fetch_offer_at_or_after_id($pdo, $column, $value, $minId);

    if (!is_array($row)) {
        return null;
    }

    $offer = isset($row['offer']) && is_string($row['offer']) ? $row['offer'] : '';
    $network = isset($row['network']) && is_string($row['network']) ? $row['network'] : '';

    return [
        'offer' => $offer,
        'network' => $network,
    ];
}

/**
 * @return array{offer: string, network: string}|null
 */
function meetup_fetch_offer_at_or_after_id(PDO $pdo, string $column, string $value, int $minimumId): ?array
{
    $allowedColumns = ['country_code', 'network'];
    if (!in_array($column, $allowedColumns, true)) {
        throw new InvalidArgumentException('Unsupported offering column.');
    }

    $statement = $pdo->prepare(
        sprintf(
            'SELECT offer, network FROM offering WHERE %s = :value AND id >= :minimum_id ORDER BY id ASC LIMIT 1',
            $column
        )
    );
    $statement->execute([
        'value' => $value,
        'minimum_id' => $minimumId,
    ]);
    $row = $statement->fetch();

    return is_array($row) ? $row : null;
}

function meetup_sanitize_token(mixed $value, int $maxLength): ?string
{
    if (!is_scalar($value)) {
        return null;
    }

    $value = trim((string) $value);
    if ($value === '' || strlen($value) > $maxLength) {
        return null;
    }

    return preg_match('/^[A-Za-z0-9_-]+$/', $value) === 1 ? $value : null;
}

function meetup_sanitize_country_code(mixed $value): ?string
{
    if (!is_scalar($value)) {
        return null;
    }

    $value = strtolower(trim((string) $value));
    if ($value === '') {
        return null;
    }

    return preg_match('/^[a-z]{2}$/', $value) === 1 ? $value : null;
}

function meetup_sanitize_ip(mixed $value): string
{
    if (!is_scalar($value)) {
        return '';
    }

    $value = trim((string) $value);
    if ($value === '') {
        return '';
    }

    return filter_var($value, FILTER_VALIDATE_IP) !== false ? $value : '';
}

function meetup_sanitize_offer_url(string $value): ?string
{
    $value = trim($value);
    if ($value === '' || strlen($value) > 2048) {
        return null;
    }

    if (filter_var($value, FILTER_VALIDATE_URL) === false) {
        return null;
    }

    $scheme = strtolower((string) parse_url($value, PHP_URL_SCHEME));

    return $scheme === 'https' ? $value : null;
}

function meetup_fail(int $statusCode): never
{
    http_response_code($statusCode);
    header('Content-Type: text/plain; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    exit;
}
