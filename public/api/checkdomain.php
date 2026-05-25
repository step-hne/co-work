<?php

declare(strict_types=1);

include_once __DIR__ . '/../connection.config.php';

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

/**
 * @return list<array{id: int, info: string, domain: string}>
 */
function fetchDomainCheckRows(mysqli $link, string $accessToken): array
{
    $stmt = mysqli_prepare($link, 'SELECT domain FROM addondomain WHERE sub_domain = ? ORDER BY domain ASC');
    if (!$stmt instanceof mysqli_stmt) {
        return [];
    }

    $scope = 'GLOBAL';
    mysqli_stmt_bind_param($stmt, 's', $scope);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    $rows = [];
    $counter = 1;

    if ($result instanceof mysqli_result) {
        while ($row = mysqli_fetch_assoc($result)) {
            $domain = isset($row['domain']) && is_string($row['domain']) ? trim($row['domain']) : '';
            if ($domain === '') {
                continue;
            }

            $rows[] = [
                'id' => $counter++,
                'info' => graphDomainStatusHtml($domain, $accessToken),
                'domain' => '<footer class="text-muted" style="text-decoration:none;">' . escapeHtml($domain) . '</footer>',
            ];
        }
        mysqli_free_result($result);
    }

    mysqli_stmt_close($stmt);

    return $rows;
}

function graphDomainStatusHtml(string $domain, string $accessToken): string
{
    $response = requestGraphScrapeStatus($domain, $accessToken);
    $safeDomain = escapeHtml($domain);

    if (isset($response['url']) && is_string($response['url']) && $response['url'] !== '') {
        return $safeDomain . '<footer class="text-muted" style="text-decoration:none;color:#3AAF85"><i class="fa fa-check" aria-hidden="true"> Domain Aman!</i></footer>';
    }

    $message = '';
    if (isset($response['error']['message']) && is_string($response['error']['message'])) {
        $message = $response['error']['message'];
    }

    if ($message === '(#368) The action attempted has been deemed abusive or is otherwise disallowed') {
        return $safeDomain . '<footer class="text-muted" style="text-decoration:none;color:#DA552F"><i class="fa fa-times" aria-hidden="true"> Domain Fraud!</i></footer>';
    }

    return escapeHtml($message !== '' ? $message : 'Unknown response');
}

/**
 * @return array<string, mixed>
 */
function requestGraphScrapeStatus(string $domain, string $accessToken): array
{
    $curl = curl_init('https://graph.facebook.com/');
    if ($curl === false) {
        return [];
    }

    curl_setopt_array($curl, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query([
            'id' => 'http://' . $domain,
            'scrape' => 'true',
            'access_token' => $accessToken,
        ], '', '&', PHP_QUERY_RFC3986),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_HEADER => false,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 12,
    ]);

    $data = curl_exec($curl);
    curl_close($curl);

    if (!is_string($data) || trim($data) === '') {
        return [];
    }

    try {
        $decoded = json_decode($data, true, 32, JSON_THROW_ON_ERROR);
    } catch (Throwable $e) {
        return [];
    }

    return is_array($decoded) ? $decoded : [];
}

function escapeHtml(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$accessToken = isset($_GET['accessToken']) && is_scalar($_GET['accessToken'])
    ? trim((string) $_GET['accessToken'])
    : '';

if ($accessToken === '') {
    http_response_code(400);
    echo json_encode([]);
    exit;
}

echo json_encode(fetchDomainCheckRows($link, $accessToken), JSON_UNESCAPED_SLASHES);
