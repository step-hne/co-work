<?php

declare(strict_types=1);

include_once dirname(__DIR__) . '/env.php';
load_env_file(__DIR__ . '/.env');

try {
    $mysql_host = app_env('DB_HOST', 'localhost');
    $mysql_user = app_required_env('DB_USER');
    $mysql_pass = app_required_env('DB_PASSWORD');
    $mysql_database = app_required_env('DB_NAME');

    $link = mysqli_connect($mysql_host, $mysql_user, $mysql_pass, $mysql_database);
    if (!$link) {
        throw new RuntimeException('Database connection failed.');
    }

    mysqli_set_charset($link, 'utf8mb4');

    register_shutdown_function(static function () use (&$link): void {
        if ($link instanceof mysqli) {
            @mysqli_close($link);
            $link = null;
        }
    });
} catch (Throwable $e) {
    http_response_code(500);
    exit('Configuration error');
}
