<?php

declare(strict_types=1);

$reportDirRaw = function_exists('app_env') ? app_env('SRP_REPORT_DIR', '') : (getenv('SRP_REPORT_DIR') ?: '');
// Allow only safe directory name characters — no slashes, dots, or traversal sequences.
$reportDir = (is_string($reportDirRaw) && preg_match('/^[A-Za-z0-9._-]+$/', $reportDirRaw) === 1)
    ? $reportDirRaw
    : '';
$baseDir = dirname(__DIR__, 2) . ($reportDir !== '' ? '/' . $reportDir : '') . '/temp';
$today = date('Y-m-d');
$yesterday = date('Y-m-d', strtotime('-1 day'));
$filename = $baseDir . '/' . $today . '.json';
$yesterdayFile = $baseDir . '/' . $yesterday . '.json';

$clickId = isset($click_id) && is_scalar($click_id) ? strtolower(trim((string) $click_id)) : '';
$countryCode = isset($country_code) && is_scalar($country_code) ? strtolower(trim((string) $country_code)) : '';
$userAgent = isset($user_agent) && is_scalar($user_agent) ? strtolower(trim((string) $user_agent)) : '';
$ipAddress = isset($ip_address) && is_scalar($ip_address) ? trim((string) $ip_address) : '';
$userLp = isset($user_lp) && is_scalar($user_lp) ? trim((string) $user_lp) : '';

if (!is_dir($baseDir)) {
    mkdir($baseDir, 0700, true);
}

$fp = fopen($filename, 'c+');

if ($fp !== false) {
    try {
        if (flock($fp, LOCK_EX)) {
            rewind($fp);

            $contents = stream_get_contents($fp);
            if (!is_string($contents) || $contents === '') {
                $contents = '[]';
            }

            try {
                $decoded = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
            } catch (Throwable $e) {
                $decoded = [];
            }

            $data = is_array($decoded) ? $decoded : [];

            $lastId = 0;
            $lastItem = end($data);

            if (
                is_array($lastItem)
                && array_key_exists('id', $lastItem)
                && is_numeric($lastItem['id'])
            ) {
                $lastId = (int) $lastItem['id'];
            }

            $data[] = [
                'id' => $lastId + 1,
                'click_id' => $clickId,
                'country_code' => $countryCode,
                'user_agent' => $userAgent,
                'ip_address' => $ipAddress,
                'info' => $userLp,
                'time' => $today,
            ];

            $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if (!is_string($json)) {
                $json = '[]';
            }

            rewind($fp);
            ftruncate($fp, 0);
            fwrite($fp, $json);
            fflush($fp);

            flock($fp, LOCK_UN);
        }
    } catch (Throwable $e) {
        // silent fail-close for legacy include flow
    } finally {
        fclose($fp);
    }
} else {
    try {
        $existing = [];

        if (is_file($filename) && is_readable($filename)) {
            $raw = file_get_contents($filename);
            if (is_string($raw) && $raw !== '') {
                try {
                    $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
                    if (is_array($decoded)) {
                        $existing = $decoded;
                    }
                } catch (Throwable $e) {
                    $existing = [];
                }
            }
        }

        $lastId = 0;
        $lastItem = end($existing);

        if (
            is_array($lastItem)
            && array_key_exists('id', $lastItem)
            && is_numeric($lastItem['id'])
        ) {
            $lastId = (int) $lastItem['id'];
        }

        $existing[] = [
            'id' => $lastId + 1,
            'click_id' => $clickId,
            'country_code' => $countryCode,
            'user_agent' => $userAgent,
            'ip_address' => $ipAddress,
            'info' => $userLp,
            'time' => $today,
        ];

        $json = json_encode($existing, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (is_string($json)) {
            file_put_contents($filename, $json, LOCK_EX);
        }
    } catch (Throwable $e) {
        // silent fail-close for legacy include flow
    }
}

if (is_file($yesterdayFile)) {
    @unlink($yesterdayFile);
}
