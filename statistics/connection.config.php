<?php

declare(strict_types=1);

/**
 * Hardened mysqli connection bootstrap.
 *
 * Exposes:
 * - $link mysqli|null
 * - $mysql_host string
 * - $mysql_user string
 * - $mysql_database string
 *
 * Required config:
 * - DB_HOST
 * - DB_USER
 * - DB_PASSWORD
 * - DB_NAME
 *
 * Optional config:
 * - DB_PORT=3306
 * - DB_SOCKET=
 * - DB_CHARSET=utf8mb4
 * - DB_PERSISTENT=0
 */

require_once dirname(__DIR__) . '/env.php';

mysqli_report(MYSQLI_REPORT_OFF);

load_env_file(__DIR__ . '/.env');

if (!function_exists('appDbEnvBool')) {
    function appDbEnvBool(string $key, bool $default = false): bool
    {
        $value = app_env($key);

        if ($value === null || $value === '') {
            return $default;
        }

        $normalized = strtolower(trim($value));

        return in_array($normalized, ['1', 'true', 'yes', 'on'], true);
    }
}

if (!function_exists('appDbEnvInt')) {
    function appDbEnvInt(string $key, int $default): int
    {
        $value = app_env($key);

        if ($value === null || $value === '') {
            return $default;
        }

        if (preg_match('/^\d+$/', $value) !== 1) {
            return $default;
        }

        $intValue = (int) $value;

        if ($intValue < 1 || $intValue > 65535) {
            return $default;
        }

        return $intValue;
    }
}

if (!function_exists('appDbLog')) {
    function appDbLog(string $message, array $context = []): void
    {
        $safeContext = [];

        foreach ($context as $key => $value) {
            $key = (string) $key;

            if (stripos($key, 'pass') !== false || stripos($key, 'secret') !== false) {
                continue;
            }

            if (is_scalar($value) || $value === null) {
                $safeContext[$key] = $value;
            }
        }

        $suffix = '';

        if ($safeContext !== []) {
            $encoded = json_encode(
                $safeContext,
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR
            );

            if (is_string($encoded)) {
                $suffix = ' ' . $encoded;
            }
        }

        error_log('[db] ' . $message . $suffix);
    }
}

if (!function_exists('appDbNormalizeHost')) {
    function appDbNormalizeHost(string $host, bool $persistent): string
    {
        $host = trim($host);

        if ($host === '') {
            return '';
        }

        if (str_starts_with($host, 'p:')) {
            $host = substr($host, 2);
        }

        if ($persistent) {
            return 'p:' . $host;
        }

        return $host;
    }
}

if (!function_exists('appDbConnect')) {
    function appDbConnect(
        string $host,
        string $user,
        string $password,
        string $database,
        int $port,
        ?string $socket,
        string $charset
    ): ?mysqli {
        $mysqli = @mysqli_init();

        if (!$mysqli instanceof mysqli) {
            appDbLog('mysqli_init_failed');
            return null;
        }

        @$mysqli->options(MYSQLI_OPT_CONNECT_TIMEOUT, 5);

        $connected = false;

        if ($socket !== null && $socket !== '') {
            $connected = @$mysqli->real_connect($host, $user, $password, $database, $port, $socket);
        } else {
            $connected = @$mysqli->real_connect($host, $user, $password, $database, $port);
        }

        if ($connected !== true) {
            appDbLog('connect_failed', [
                'host' => $host,
                'user' => $user,
                'database' => $database,
                'port' => $port,
                'errno' => mysqli_connect_errno(),
                'error' => mysqli_connect_error(),
            ]);

            @$mysqli->close();
            return null;
        }

        if (@$mysqli->select_db($database) !== true) {
            appDbLog('select_db_failed', [
                'database' => $database,
                'errno' => $mysqli->errno,
                'error' => $mysqli->error,
            ]);

            @$mysqli->close();
            return null;
        }

        if (@$mysqli->set_charset($charset) !== true) {
            appDbLog('set_charset_failed', [
                'charset' => $charset,
                'errno' => $mysqli->errno,
                'error' => $mysqli->error,
            ]);

            @$mysqli->close();
            return null;
        }

        return $mysqli;
    }
}

$requiredKeys = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME'];
$missingKeys = [];

foreach ($requiredKeys as $requiredKey) {
    $requiredValue = app_env($requiredKey);

    if ($requiredValue === null || $requiredValue === '') {
        $missingKeys[] = $requiredKey;
    }
}

$link = null;

$mysql_host = '';
$mysql_user = '';
$mysql_database = '';

if ($missingKeys !== []) {
    appDbLog('missing_required_config', [
        'missing' => implode(',', $missingKeys),
    ]);
} else {
    $dbHostRaw = (string) app_env('DB_HOST');
    $dbPersistent = appDbEnvBool('DB_PERSISTENT', false);

    $mysql_host = appDbNormalizeHost($dbHostRaw, $dbPersistent);
    $mysql_user = (string) app_env('DB_USER');
    $mysqlPass = (string) app_env('DB_PASSWORD');
    $mysql_database = (string) app_env('DB_NAME');

    $dbPort = appDbEnvInt('DB_PORT', 3306);
    $dbSocket = app_env('DB_SOCKET', '');
    $dbCharset = app_env('DB_CHARSET', 'utf8mb4');

    if ($mysql_host === '' || $mysql_user === '' || $mysql_database === '') {
        appDbLog('invalid_required_config');
    } else {
        $link = appDbConnect(
            $mysql_host,
            $mysql_user,
            $mysqlPass,
            $mysql_database,
            $dbPort,
            $dbSocket,
            (string) $dbCharset
        );

        if ($link instanceof mysqli && @$link->ping() !== true) {
            appDbLog('stale_connection_detected_retry_once', [
                'host' => $mysql_host,
                'database' => $mysql_database,
            ]);

            @$link->close();

            $link = appDbConnect(
                $mysql_host,
                $mysql_user,
                $mysqlPass,
                $mysql_database,
                $dbPort,
                $dbSocket,
                (string) $dbCharset
            );
        }
    }

    unset($mysqlPass);
}
