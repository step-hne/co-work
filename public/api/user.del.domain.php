<?php

declare(strict_types=1);

include_once('../connection.config.php');
include_once('../session_guards.php');

header('Content-Type: application/json; charset=utf-8');

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

    $domain = trim((string) ($_POST['domain'] ?? ''));
    if ($domain === '') {
        jsonError(422, 'missing-domain');
    }

    $stmt = mysqli_prepare($link, 'DELETE FROM addondomain WHERE domain = ? AND sub_domain = ?');
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare delete query.');
    }

    bindStatementValues($stmt, 'ss', [$domain, $sessionSubId]);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);

    echo json_encode(['ok' => true]);
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}