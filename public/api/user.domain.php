<?php

declare(strict_types=1);

include_once('../connection.config.php');
include_once('../session_guards.php');

header('Content-Type: application/json; charset=utf-8');

try {
    startUserGuardSession();
    $sessionSubId = authenticatedUserSubId();
    if ($sessionSubId === '') {
        jsonError(403, 'unauthorized');
    }

    $subDomain = strtoupper(trim((string) ($_GET['sub_domain'] ?? '')));
    if ($subDomain === '' || $subDomain !== $sessionSubId) {
        jsonError(403, 'forbidden');
    }

    $stmt = mysqli_prepare($link, 'SELECT sub_domain, domain FROM addondomain WHERE sub_domain = ? ORDER BY domain ASC');
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare user domain query.');
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

    echo json_encode($rows);
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}