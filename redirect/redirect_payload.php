<?php

declare(strict_types=1);

/**
 * @return array{click_id: string, country_code: string, user_agent: string, ip_address: string, user_lp: string}|null
 */
function srp_redirect_payload_decode(mixed $value): ?array
{
    if (!is_scalar($value)) {
        return null;
    }

    $value = trim((string) $value);
    if ($value === '' || strlen($value) > 1024) {
        return null;
    }

    $decoded = srp_redirect_base64url_decode($value);

    if (!is_string($decoded) || $decoded === '') {
        return null;
    }

    $parts = str_getcsv($decoded);

    if (count($parts) !== 5) {
        return null;
    }

    return [
        'click_id' => is_string($parts[0]) ? $parts[0] : '',
        'country_code' => is_string($parts[1]) ? $parts[1] : '',
        'user_agent' => is_string($parts[2]) ? $parts[2] : '',
        'ip_address' => is_string($parts[3]) ? $parts[3] : '',
        'user_lp' => is_string($parts[4]) ? $parts[4] : '',
    ];
}

function srp_redirect_payload_encode(
    string $clickId,
    string $countryCode,
    string $userAgent,
    string $ipAddress,
    string $userLp
): string {
    return srp_redirect_base64url_encode(implode(',', [$clickId, $countryCode, $userAgent, $ipAddress, $userLp]));
}

function srp_redirect_base64url_encode(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function srp_redirect_base64url_decode(string $value): string|false
{
    if ($value === '' || preg_match('/^[A-Za-z0-9_-]+$/', $value) !== 1) {
        return false;
    }

    $padding = (4 - (strlen($value) % 4)) % 4;
    $decoded = base64_decode(
        strtr($value . str_repeat('=', $padding), '-_', '+/'),
        true
    );

    return $decoded === false ? false : $decoded;
}
