<?php

declare(strict_types=1);

include_once __DIR__ . '/../login.php';

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

function cleanText(mixed $value, int $maxLength = 160): string
{
    if (!is_scalar($value)) {
        return '';
    }

    $text = trim((string) $value);
    $text = preg_replace('/[\x00-\x1F\x7F]/', '', $text) ?? '';
    $text = strip_tags($text);

    if (strlen($text) > $maxLength) {
        $text = substr($text, 0, $maxLength);
    }

    return $text;
}

function cleanCode(mixed $value, int $maxLength = 32): string
{
    $text = strtoupper(cleanText($value, $maxLength));
    $text = preg_replace('/[^A-Z0-9_-]/', '', $text) ?? '';

    return substr($text, 0, $maxLength);
}

function cleanKey(mixed $value, int $maxLength = 64): string
{
    $text = strtolower(cleanText($value, $maxLength));
    $text = preg_replace('/[^a-z0-9_-]/', '', $text) ?? '';

    return substr($text, 0, $maxLength);
}

function cleanIp(mixed $value): string
{
    $text = cleanText($value, 64);

    if (filter_var($text, FILTER_VALIDATE_IP)) {
        return $text;
    }

    return '';
}

function readJsonRows(string $filename): array
{
    if (!is_file($filename) || !is_readable($filename)) {
        return [];
    }

    $json = file_get_contents($filename);
    if (!is_string($json) || trim($json) === '') {
        return [];
    }

    $decoded = json_decode($json, true);
    if (!is_array($decoded)) {
        return [];
    }

    return $decoded;
}

function userAgentMeta(string $key): array
{
    $map = [
        'wap' => [
            'label' => 'WAP',
            'icon' => '/dist/wap.svg',
        ],
        'web' => [
            'label' => 'WEB',
            'icon' => '/dist/web.svg',
        ],
        'tablet' => [
            'label' => 'TABLET',
            'icon' => '/dist/tablet.svg',
        ],
    ];

    return $map[$key] ?? [
        'label' => strtoupper($key),
        'icon' => '',
    ];
}

function networkMeta(string $key): array
{
    $map = [
        'lospollos' => [
            'label' => 'LosPollos',
            'icon' => '/dist/lp.svg',
        ],
        'imonetizeit' => [
            'label' => 'iMonetizeIt',
            'icon' => '/dist/imo.svg',
        ],
        'imonetizeit-1' => [
            'label' => 'iMonetizeIt-1',
            'icon' => '/dist/imo.svg',
        ],
        'imonetizeit-2' => [
            'label' => 'iMonetizeIt-2',
            'icon' => '/dist/imo.svg',
        ],
        'trafee' => [
            'label' => 'Trafee',
            'icon' => '/dist/tf.svg',
        ],
        'torazzo' => [
            'label' => 'Torazzo',
            'icon' => '/dist/custom.svg',
        ],
        'custom' => [
            'label' => 'Custom',
            'icon' => '/dist/custom.svg',
        ],
    ];

    return $map[$key] ?? [
        'label' => $key,
        'icon' => '',
    ];
}

$lastId = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if (!is_int($lastId) || $lastId < 0) {
    $lastId = 0;
}

$filename = __DIR__ . '/../temp/' . date('Y-m-d') . '.json';
$result = readJsonRows($filename);

$page = [];

foreach ($result as $row) {
    if (!is_array($row)) {
        continue;
    }

    $rowId = isset($row['id']) ? (int) $row['id'] : 0;

    if ($rowId !== ($lastId + 1)) {
        continue;
    }

    $clickId = cleanCode($row['click_id'] ?? '', 80);
    $countryCode = cleanCode($row['country_code'] ?? '', 2);
    $countryFlagClass = $countryCode !== ''
        ? 'flag flag-' . strtolower($countryCode)
        : 'flag flag--';

    $userAgentKey = cleanKey($row['user_agent'] ?? '', 16);
    $userAgent = userAgentMeta($userAgentKey);

    $networkKey = cleanKey($row['info'] ?? '', 80);
    $network = networkMeta($networkKey);

    $ipAddress = cleanIp($row['ip_address'] ?? '');
    $rowTime = cleanText($row['time'] ?? '', 32);

    if ($rowId < 1 || $clickId === '') {
        continue;
    }

    $page[] = [
        'id' => $rowId,
        'click_id' => $clickId,

        'country_code' => $countryCode,
        'country_flag_class' => $countryFlagClass,

        'user_agent' => $userAgent['label'],
        'user_agent_icon' => $userAgent['icon'],

        'network' => $network['label'],
        'network_icon' => $network['icon'],

        'ip_address' => $ipAddress,
        'time' => $rowTime,
    ];
}

echo json_encode(
    $page,
    JSON_UNESCAPED_SLASHES
    | JSON_UNESCAPED_UNICODE
    | JSON_INVALID_UTF8_SUBSTITUTE
);