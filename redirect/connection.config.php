<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/env.php';

load_env_file(__DIR__ . '/.env');

try {
    $databaseHost = connection_env('DB_HOST', 'localhost');
    $databaseUser = connection_required_env('DB_USER');
    $databasePass = connection_required_env('DB_PASS');
    $databaseName = connection_required_env('DB_NAME');

    $databasePort = (int) (connection_env('DB_PORT', '3306') ?? '3306');
    if ($databasePort < 1 || $databasePort > 65535) {
        $databasePort = 3306;
    }

    $dsn = sprintf(
        'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
        $databaseHost,
        $databasePort,
        $databaseName
    );

    $pdoOptions = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
        // Reuse MySQL connection across requests when running under PHP-FPM.
        // Silently ignored in CGI/suPHP mode (each request gets its own process).
        PDO::ATTR_PERSISTENT         => true,
    ];

    if (defined('PDO::MYSQL_ATTR_MULTI_STATEMENTS')) {
        $pdoOptions[PDO::MYSQL_ATTR_MULTI_STATEMENTS] = false;
    }

    return new PDO($dsn, $databaseUser, $databasePass, $pdoOptions);
} catch (Throwable $e) {
    error_log('Database bootstrap failed: ' . $e->getMessage());
    http_response_code(500);
    header('Content-Type: text/plain; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    exit('Internal Server Error');
}

function connection_required_env(string $name): string
{
    $value = connection_env($name);

    if ($value === null) {
        throw new RuntimeException('Missing required environment variable: ' . $name);
    }

    return $value;
}

function connection_env(string $name, ?string $default = null): ?string
{
    $candidates = [
        getenv($name),
        $_ENV[$name] ?? null,
        $_SERVER[$name] ?? null,
    ];

    foreach ($candidates as $candidate) {
        if (!is_string($candidate)) {
            continue;
        }

        $candidate = trim($candidate);
        if ($candidate !== '') {
            return $candidate;
        }
    }

    return $default;
}
