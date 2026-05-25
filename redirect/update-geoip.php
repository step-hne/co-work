<?php

declare(strict_types=1);

/**
 * CLI-only updater for GeoLite2-Country.mmdb.
 *
 * Usage:
 *   php redirect/update-geoip.php
 *
 * Requires MAXMIND_LICENSE_KEY in redirect/.env
 * Get a free key at: https://www.maxmind.com/en/geolite2/signup
 *
 * Crontab (setiap Rabu 03:00 — MaxMind rilis Selasa pertama tiap bulan):
 *   0 3 * * 3 /usr/local/bin/php /home/<user>/redirect/update-geoip.php >> /home/<user>/redirect/logs/geoip-update.log 2>&1
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit(1);
}

require_once __DIR__ . '/../env.php';
load_env_file(__DIR__ . '/.env');

const GEOIP_EDITION          = 'GeoLite2-Country';
const GEOIP_MMDB_FILENAME    = 'GeoLite2-Country.mmdb';
const GEOIP_DOWNLOAD_BASE    = 'https://download.maxmind.com/app/geoip_download';
const GEOIP_CONNECT_TIMEOUT  = 10;
const GEOIP_READ_TIMEOUT      = 90;

function geoip_log(string $level, string $message): void
{
    $line = date('[Y-m-d H:i:s]') . " [{$level}] {$message}" . PHP_EOL;
    fwrite($level === 'ERROR' ? STDERR : STDOUT, $line);
}

function geoip_build_url(string $licenseKey, string $suffix): string
{
    return GEOIP_DOWNLOAD_BASE . '?' . http_build_query([
        'edition_id'  => GEOIP_EDITION,
        'license_key' => $licenseKey,
        'suffix'      => $suffix,
    ]);
}

function geoip_curl_to_file(string $url, string $destPath): void
{
    $ch = curl_init($url);
    if ($ch === false) {
        throw new RuntimeException('curl_init failed.');
    }

    $fp = fopen($destPath, 'wb');
    if ($fp === false) {
        curl_close($ch);
        throw new RuntimeException('Cannot open temp file: ' . $destPath);
    }

    curl_setopt_array($ch, [
        CURLOPT_FILE            => $fp,
        CURLOPT_CONNECTTIMEOUT  => GEOIP_CONNECT_TIMEOUT,
        CURLOPT_TIMEOUT         => GEOIP_READ_TIMEOUT,
        CURLOPT_FOLLOWLOCATION  => true,
        CURLOPT_MAXREDIRS       => 3,
        CURLOPT_SSL_VERIFYPEER  => true,
        CURLOPT_SSL_VERIFYHOST  => 2,
        CURLOPT_PROTOCOLS       => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_USERAGENT       => 'GeoIP-Updater/1.0',
        CURLOPT_FAILONERROR     => true,
    ]);

    $ok      = curl_exec($ch);
    $code    = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $errno   = curl_errno($ch);
    $errstr  = curl_error($ch);
    curl_close($ch);
    fclose($fp);

    if ($ok === false || $errno !== 0) {
        throw new RuntimeException("cURL error ({$errno}): {$errstr}");
    }

    if ($code !== 200) {
        throw new RuntimeException("HTTP {$code} downloading archive.");
    }
}

function geoip_curl_string(string $url): string
{
    $ch = curl_init($url);
    if ($ch === false) {
        throw new RuntimeException('curl_init failed.');
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER  => true,
        CURLOPT_CONNECTTIMEOUT  => GEOIP_CONNECT_TIMEOUT,
        CURLOPT_TIMEOUT         => 15,
        CURLOPT_FOLLOWLOCATION  => true,
        CURLOPT_MAXREDIRS       => 3,
        CURLOPT_SSL_VERIFYPEER  => true,
        CURLOPT_SSL_VERIFYHOST  => 2,
        CURLOPT_PROTOCOLS       => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_USERAGENT       => 'GeoIP-Updater/1.0',
        CURLOPT_FAILONERROR     => true,
    ]);

    $body   = curl_exec($ch);
    $code   = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $errno  = curl_errno($ch);
    $errstr = curl_error($ch);
    curl_close($ch);

    if ($body === false || $errno !== 0) {
        throw new RuntimeException("cURL error ({$errno}): {$errstr}");
    }

    if ($code !== 200 || !is_string($body)) {
        throw new RuntimeException("HTTP {$code} fetching checksum.");
    }

    return $body;
}

function geoip_find_mmdb(string $dir, string $filename): ?string
{
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
    );

    foreach ($it as $file) {
        if ($file instanceof SplFileInfo && $file->getFilename() === $filename) {
            return $file->getPathname();
        }
    }

    return null;
}

function geoip_rmdir_recursive(string $dir): void
{
    if (!is_dir($dir)) {
        return;
    }

    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($it as $item) {
        if (!($item instanceof SplFileInfo)) {
            continue;
        }

        if ($item->isDir()) {
            @rmdir($item->getPathname());
        } else {
            @unlink($item->getPathname());
        }
    }

    @rmdir($dir);
}

// ── Guard ─────────────────────────────────────────────────────────────────────

if (!function_exists('curl_init')) {
    geoip_log('ERROR', 'cURL extension tidak tersedia. Install php-curl lalu coba lagi.');
    exit(1);
}

$licenseKey = app_env('MAXMIND_LICENSE_KEY');
if ($licenseKey === null || $licenseKey === '') {
    geoip_log('ERROR', 'MAXMIND_LICENSE_KEY tidak dikonfigurasi di redirect/.env');
    exit(1);
}

// ── Paths ─────────────────────────────────────────────────────────────────────

$dbPath    = __DIR__ . '/databases/' . GEOIP_MMDB_FILENAME;
$dbDir     = dirname($dbPath);
$tmpTarGz  = tempnam(sys_get_temp_dir(), 'geoip_dl_') . '.tar.gz';
$tmpExtDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'geoip_ext_' . bin2hex(random_bytes(8));

// ── Main ──────────────────────────────────────────────────────────────────────

try {
    // Step 1 — Checksum dulu (kecil, cepat; jika gagal tidak buang bandwidth)
    geoip_log('INFO', 'Mengunduh checksum SHA-256…');
    $checksumRaw  = geoip_curl_string(geoip_build_url($licenseKey, 'tar.gz.sha256'));
    $expectedHash = strtolower(trim(explode(' ', trim($checksumRaw))[0]));

    if ($expectedHash === '' || strlen($expectedHash) !== 64 || preg_match('/^[0-9a-f]{64}$/', $expectedHash) !== 1) {
        throw new RuntimeException('Format checksum tidak terduga: ' . substr($checksumRaw, 0, 80));
    }

    // Step 2 — Download archive
    geoip_log('INFO', 'Mengunduh ' . GEOIP_EDITION . '.tar.gz…');
    geoip_curl_to_file(geoip_build_url($licenseKey, 'tar.gz'), $tmpTarGz);

    $downloadedBytes = filesize($tmpTarGz);
    geoip_log('INFO', sprintf('Unduhan selesai (%.1f MB).', ($downloadedBytes !== false ? $downloadedBytes : 0) / 1048576));

    // Step 3 — Verifikasi SHA-256
    $actualHash = strtolower((string) hash_file('sha256', $tmpTarGz));
    if (!hash_equals($expectedHash, $actualHash)) {
        throw new RuntimeException("SHA-256 mismatch. expected={$expectedHash} actual={$actualHash}");
    }
    geoip_log('INFO', 'Checksum OK.');

    // Step 4 — Ekstrak
    mkdir($tmpExtDir, 0700, true);
    $phar = new PharData($tmpTarGz);
    $phar->extractTo($tmpExtDir);
    unset($phar); // tutup handle sebelum cleanup

    $mmdbSrc = geoip_find_mmdb($tmpExtDir, GEOIP_MMDB_FILENAME);
    if ($mmdbSrc === null) {
        throw new RuntimeException(GEOIP_MMDB_FILENAME . ' tidak ditemukan di dalam archive.');
    }

    // Step 5 — Atomic replace (copy → chmod → rename)
    if (!is_dir($dbDir)) {
        mkdir($dbDir, 0700, true);
    }

    $tmpDest = $dbPath . '.tmp.' . bin2hex(random_bytes(4));

    if (!copy($mmdbSrc, $tmpDest)) {
        throw new RuntimeException("copy() gagal: {$mmdbSrc} → {$tmpDest}");
    }

    chmod($tmpDest, 0600);

    if (!rename($tmpDest, $dbPath)) {
        @unlink($tmpDest);
        throw new RuntimeException("rename() gagal saat mengganti {$dbPath}");
    }

    geoip_log('INFO', 'GeoLite2-Country.mmdb berhasil diperbarui → ' . $dbPath);
    exit(0);

} catch (Throwable $e) {
    geoip_log('ERROR', $e->getMessage());
    exit(1);

} finally {
    if (is_file($tmpTarGz)) {
        @unlink($tmpTarGz);
    }
    geoip_rmdir_recursive($tmpExtDir);
}
