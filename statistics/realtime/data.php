<?php

declare(strict_types=1);

include_once __DIR__ . '/../login.php';

function rtSendSecurityHeaders(): void
{
    if (headers_sent()) {
        return;
    }

    header('Content-Type: application/json; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
}

function rtOutputJson(array $payload): void
{
    $json = json_encode(
        $payload,
        JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
    );

    if ($json === false) {
        echo '{"data":[]}';
        return;
    }

    echo $json;
}

function rtNormalizeUtf8(string $value): string
{
    if ($value === '') {
        return '';
    }

    if (preg_match('//u', $value) === 1) {
        return $value;
    }

    if (function_exists('mb_convert_encoding')) {
        $converted = mb_convert_encoding($value, 'UTF-8', 'UTF-8, ISO-8859-1, Windows-1252');

        if (is_string($converted) && preg_match('//u', $converted) === 1) {
            return $converted;
        }
    }

    if (function_exists('iconv')) {
        $converted = iconv('Windows-1252', 'UTF-8//IGNORE', $value);

        if (is_string($converted) && preg_match('//u', $converted) === 1) {
            return $converted;
        }

        $converted = iconv('ISO-8859-1', 'UTF-8//IGNORE', $value);

        if (is_string($converted) && preg_match('//u', $converted) === 1) {
            return $converted;
        }
    }

    return '';
}

function rtEscapeHtml(string $value): string
{
    return htmlspecialchars(rtNormalizeUtf8($value), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function rtSvgImg(string $src, string $title = '', int $size = 14): string
{
    return '<img src="' . rtEscapeHtml($src) . '" width="' . $size . '" height="' . $size . '" class="rt-icon" alt="" title="' . rtEscapeHtml($title) . '">';
}

function rtStringLength(string $value): int
{
    $normalized = rtNormalizeUtf8($value);

    if (function_exists('mb_strlen')) {
        return mb_strlen($normalized, 'UTF-8');
    }

    return strlen($normalized);
}

rtSendSecurityHeaders();

try {
    include_once '../connection.config.php';

    if (!isset($link) || !($link instanceof mysqli)) {
        error_log('[realtime/data] Invalid mysqli connection.');
        rtOutputJson(['data' => []]);
        exit;
    }

    mysqli_set_charset($link, 'utf8mb4');

    if (!isset($_GET['date']) || !is_string($_GET['date'])) {
        rtOutputJson(['data' => []]);
        mysqli_close($link);
        exit;
    }

    $dateRaw = $_GET['date'];
    $dateParam = $dateRaw === '2' ? 'yesterday' : 'today';
    $conversionDate = date('Y-m-d', strtotime($dateParam));

    $topClickId = null;

    $sqlTop = '
        SELECT click_id, SUM(payout) AS total_payout
        FROM leadreport
        WHERE conversion_date = ?
        GROUP BY click_id
        ORDER BY total_payout DESC
        LIMIT 1
    ';

    $stmtTop = mysqli_prepare($link, $sqlTop);

    if ($stmtTop instanceof mysqli_stmt) {
        mysqli_stmt_bind_param($stmtTop, 's', $conversionDate);
        mysqli_stmt_execute($stmtTop);

        $resultTop = mysqli_stmt_get_result($stmtTop);

        if ($resultTop instanceof mysqli_result) {
            $rowTop = mysqli_fetch_assoc($resultTop);

            if ($rowTop !== null && $rowTop !== false) {
                $topClickId = (string) ($rowTop['click_id'] ?? '');
            }

            mysqli_free_result($resultTop);
        }

        mysqli_stmt_close($stmtTop);
    }

    $sql = '
        SELECT
            id,
            click_id,
            ip_address,
            country,
            traffic,
            currency_symbol,
            payout,
            conversion_date,
            network
        FROM leadreport
        WHERE conversion_date = ?
        ORDER BY id ASC
    ';

    $stmt = mysqli_prepare($link, $sql);

    if (!($stmt instanceof mysqli_stmt)) {
        rtOutputJson(['data' => []]);
        mysqli_close($link);
        exit;
    }

    mysqli_stmt_bind_param($stmt, 's', $conversionDate);
    mysqli_stmt_execute($stmt);

    $result = mysqli_stmt_get_result($stmt);

    $response = [
        'data' => [],
    ];

    if ($result instanceof mysqli_result && mysqli_num_rows($result) > 0) {
        $number = 1;

        while ($row = mysqli_fetch_assoc($result)) {
            $clickIdRaw = rtNormalizeUtf8((string) ($row['click_id'] ?? ''));
            $networkRaw = strtoupper(rtNormalizeUtf8((string) ($row['network'] ?? '')));
            $trafficRaw = strtoupper(rtNormalizeUtf8((string) ($row['traffic'] ?? '')));
            $countryRaw = strtoupper(rtNormalizeUtf8((string) ($row['country'] ?? '')));

            $idClickDisplay = rtSvgImg('/dist/user.svg', 'User') . ' ' . rtEscapeHtml($clickIdRaw);

            if ($topClickId !== null && $clickIdRaw === $topClickId) {
                $idClickDisplay = rtSvgImg('/dist/top.svg', 'Top Earner') . ' ' . rtEscapeHtml($clickIdRaw);
            }

            if ($clickIdRaw === 'SCATTER') {
                $idClickDisplay = rtSvgImg('/dist/scatter.svg', 'Scatter')
                    . ' <span class="neons"><em>-' . rtEscapeHtml($clickIdRaw) . '-</em></span>';
            }

            if ($clickIdRaw === '') {
                $idClickDisplay = rtSvgImg('/dist/ngix.svg', 'NGIX') . ' NGIX';
            }

            if (rtStringLength($clickIdRaw) > 20) {
                $idClickDisplay = rtSvgImg('/dist/user.svg', 'User') . ' YELLOW';
            }

            $trafficSvg = [
                'WAP' => '/dist/wap.svg',
                'WEB' => '/dist/web.svg',
                'TABLET' => '/dist/tablet.svg',
            ];

            if (isset($trafficSvg[$trafficRaw])) {
                $trafficDisplay = rtSvgImg($trafficSvg[$trafficRaw], $trafficRaw);
            } else {
                $trafficDisplay = '<code class="rt-code">' . rtEscapeHtml($trafficRaw) . '</code>';
            }

            $networkSvg = [
                'LOSPOLLOS' => '/dist/lp.svg',
                'IMONETIZEIT' => '/dist/imo.svg',
                'IMONETIZEIT-1' => '/dist/imo.svg',
                'IMONETIZEIT-2' => '/dist/imo.svg',
                'IMONETIZEIT2' => '/dist/imo.svg',
                'TRAFEE' => '/dist/tf.svg',
                'TORAZZO' => '/dist/custom.svg',
                'CUSTOM' => '/dist/custom.svg',
                'OFFER' => '/dist/custom.svg',
            ];

            if (isset($networkSvg[$networkRaw])) {
                $networkDisplay = rtSvgImg($networkSvg[$networkRaw], $networkRaw, 16);
            } elseif ($networkRaw === '') {
                $networkDisplay = rtSvgImg('/dist/imo.svg', 'iMonetizeIt', 16);
            } elseif ($networkRaw === 'ADVERTEN') {
                $networkDisplay = '<span class="label rt-label-adverten">ADVERTEN</span>';
            } else {
                $networkDisplay = rtEscapeHtml($networkRaw);
            }

            $ipAddress = rtNormalizeUtf8((string) ($row['ip_address'] ?? ''));
            $countryClass = strtolower($countryRaw);

            if (preg_match('/^[a-z]{2}$/', $countryClass) !== 1) {
                $countryClass = 'xx';
            }

            $ipDisplay = '<a href="#" class="js-ip rt-ip" id="' . rtEscapeHtml($ipAddress) . '" data-ip="'
                . rtEscapeHtml($ipAddress) . '"><span> ' . rtEscapeHtml($ipAddress) . '</span></a>';

            $countryDisplay = '<span class="flag flag-' . rtEscapeHtml($countryClass) . '"></span> '
                . rtEscapeHtml($countryRaw);

            $currencySymbol = rtNormalizeUtf8((string) ($row['currency_symbol'] ?? '$'));
            $payoutValue = (float) ($row['payout'] ?? 0.0);
            $payoutDisplay = rtEscapeHtml($currencySymbol) . number_format($payoutValue, 2);

            $conversionDateValue = rtNormalizeUtf8((string) ($row['conversion_date'] ?? ''));
            $conversionDateDisplay = '<span class="text-muted">' . rtEscapeHtml($conversionDateValue) . '</span>';

            $response['data'][] = [
                'id' => $number++,
                'click_id' => $idClickDisplay,
                'ip_address' => $ipDisplay,
                'country' => $countryDisplay,
                'traffic' => $trafficDisplay,
                'payout' => $payoutDisplay,
                'conversion_date' => $conversionDateDisplay,
                'network' => $networkDisplay,
            ];
        }

        mysqli_free_result($result);
    }

    mysqli_stmt_close($stmt);
    mysqli_close($link);

    rtOutputJson($response);
} catch (Throwable $e) {
    error_log('[realtime/data] ' . $e->getMessage());
    rtOutputJson(['data' => []]);
}