<?php

declare(strict_types=1);

if (!function_exists('getUserIP')) {
    function getUserIP(): string
    {
        $sources = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_TRUE_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR',
        ];

        foreach ($sources as $source) {
            if (!isset($_SERVER[$source]) || !is_string($_SERVER[$source])) {
                continue;
            }

            $value = trim($_SERVER[$source]);
            if ($value === '') {
                continue;
            }

            $candidates = $source === 'HTTP_X_FORWARDED_FOR'
                ? explode(',', $value)
                : [$value];

            foreach ($candidates as $candidate) {
                $candidate = trim($candidate);

                if ($candidate !== '' && filter_var($candidate, FILTER_VALIDATE_IP) !== false) {
                    return $candidate;
                }
            }
        }

        return '';
    }
}
