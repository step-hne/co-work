<?php

declare(strict_types=1);

if (!function_exists('load_env_file')) {
    function load_env_file(string $filePath): void
    {
        /** @var array<string, true> $loadedFiles */
        static $loadedFiles = [];

        $realPath = realpath($filePath);
        if ($realPath === false) {
            return;
        }

        if (isset($loadedFiles[$realPath])) {
            return;
        }

        if (!is_readable($realPath)) {
            return;
        }

        $lines = file($realPath, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            return;
        }

        foreach ($lines as $line) {
            load_env_line($line);
        }

        $loadedFiles[$realPath] = true;
    }
}

if (!function_exists('load_env_line')) {
    function load_env_line(string $line): void
    {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            return;
        }

        if (str_starts_with($line, 'export ')) {
            $line = ltrim(substr($line, 7));
        }

        $separatorPosition = strpos($line, '=');
        if ($separatorPosition === false) {
            return;
        }

        $name = trim(substr($line, 0, $separatorPosition));
        if ($name === '' || preg_match('/^[A-Z0-9_]+$/', $name) !== 1) {
            return;
        }

        if (getenv($name) !== false || isset($_ENV[$name]) || isset($_SERVER[$name])) {
            return;
        }

        $value = load_env_normalize_value(substr($line, $separatorPosition + 1));

        putenv($name . '=' . $value);
        $_ENV[$name] = $value;
        $_SERVER[$name] = $value;
    }
}

if (!function_exists('load_env_normalize_value')) {
    function load_env_normalize_value(string $value): string
    {
        $value = trim($value);
        $length = strlen($value);

        if ($length >= 2) {
            $firstCharacter = $value[0];
            $lastCharacter = $value[$length - 1];

            if (
                ($firstCharacter === '"' && $lastCharacter === '"')
                || ($firstCharacter === '\'' && $lastCharacter === '\'')
            ) {
                $value = substr($value, 1, -1);

                if ($firstCharacter === '"') {
                    $value = strtr(
                        $value,
                        [
                            '\\n' => "\n",
                            '\\r' => "\r",
                            '\\t' => "\t",
                            '\\\\' => '\\',
                            '\\"' => '"',
                        ]
                    );
                }

                return $value;
            }
        }

        $commentPosition = strpos($value, ' #');

        if ($commentPosition !== false) {
            $value = rtrim(substr($value, 0, $commentPosition));
        }

        return $value;
    }
}

if (!function_exists('app_env')) {
    function app_env(string $key, ?string $default = null): ?string
    {
        $value = $_ENV[$key] ?? $_SERVER[$key] ?? getenv($key);
        if ($value === false || $value === null || $value === '') {
            return $default;
        }

        return is_string($value) ? $value : (string) $value;
    }
}

if (!function_exists('app_required_env')) {
    function app_required_env(string $key): string
    {
        $value = app_env($key);
        if ($value === null || $value === '') {
            throw new RuntimeException('Missing required environment variable: ' . $key);
        }

        return $value;
    }
}
