<?php

declare(strict_types=1);

include_once('../connection.config.php');
include_once('../session_guards.php');

header('Content-Type: application/json; charset=utf-8');

function userDomainRows(mysqli $link, string $subDomain): array
{
    $stmt = mysqli_prepare($link, 'SELECT sub_domain, domain FROM addondomain WHERE sub_domain = ? ORDER BY domain ASC');
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare user domain list query.');
    }

    bindStatementValues($stmt, 's', [$subDomain]);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    $rows = [];
    $counter = 1;
    if ($result) {
        while ($row = mysqli_fetch_assoc($result)) {
            $rows[] = [
                'id' => $counter++,
                'sub_domain' => (string) ($row['sub_domain'] ?? ''),
                'domain' => (string) ($row['domain'] ?? ''),
            ];
        }
    }

    mysqli_stmt_close($stmt);

    return $rows;
}

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonError(405, 'method-not-allowed');
    }

    startUserGuardSession();
    $sessionSubId = authenticatedUserSubId();
    if ($sessionSubId === '') {
        jsonError(403, 'unauthorized');
    }
    if (!hasValidSessionCsrf('user_portal', requestCsrfToken())) {
        jsonError(419, 'invalid-csrf');
    }

    $subDomain = strtoupper(trim((string) ($_POST['sub_domain'] ?? '')));
    $domain = trim((string) ($_POST['domain'] ?? ''));
    if ($subDomain === '' || $domain === '') {
        jsonError(422, 'missing-fields');
    }
    if ($subDomain !== $sessionSubId) {
        jsonError(403, 'forbidden');
    }

    $stmt = mysqli_prepare($link, 'INSERT INTO addondomain (sub_domain, domain) VALUES (?, ?)');
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare insert query.');
    }

    bindStatementValues($stmt, 'ss', [$subDomain, $domain]);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);

    echo json_encode(userDomainRows($link, $subDomain));
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}