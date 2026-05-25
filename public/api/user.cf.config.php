<?php

declare(strict_types=1);

include_once('../connection.config.php');
include_once('../session_guards.php');

header('Content-Type: application/json; charset=utf-8');

function requireGenerateCfSchema(mysqli $link): void
{
    foreach (['cf_token', 'cf_account_id'] as $column) {
        $stmt = mysqli_prepare(
            $link,
            'SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? LIMIT 1'
        );
        if (!$stmt instanceof mysqli_stmt) {
            jsonError(500, 'schema-check-failed');
        }

        $table = 'generate';
        mysqli_stmt_bind_param($stmt, 'ss', $table, $column);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $exists = $result instanceof mysqli_result && mysqli_fetch_row($result) !== null;
        if ($result instanceof mysqli_result) {
            mysqli_free_result($result);
        }
        mysqli_stmt_close($stmt);

        if (!$exists) {
            jsonError(503, 'schema-not-installed');
        }
    }
}

try {
    startUserGuardSession();
    $sessionSubId = authenticatedUserSubId();
    if ($sessionSubId === '') {
        jsonError(403, 'unauthorized');
    }
    requireGenerateCfSchema($link);

    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

    if ($method === 'GET') {
        $stmt = mysqli_prepare($link, 'SELECT cf_token, cf_account_id FROM `generate` WHERE sub_id = ? LIMIT 1');
        if (!$stmt) { jsonError(500, 'db-error'); }
        bindStatementValues($stmt, 's', [$sessionSubId]);
        mysqli_stmt_execute($stmt);
        $row = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));
        mysqli_stmt_close($stmt);

        $hasToken = !empty($row['cf_token']);
        echo json_encode([
            'ok'             => true,
            'has_token'      => $hasToken,
            'token_masked'   => $hasToken ? substr((string)$row['cf_token'], 0, 6) . str_repeat('•', 20) : '',
            'account_id'     => (string)($row['cf_account_id'] ?? ''),
        ]);
        exit;
    }

    if ($method === 'POST') {
        if (!hasValidSessionCsrf('user_portal', requestCsrfToken())) {
            jsonError(419, 'invalid-csrf');
        }

        $action    = trim((string)($_POST['action'] ?? 'save'));
        $token     = trim((string)($_POST['cf_token'] ?? ''));
        $accountId = trim((string)($_POST['cf_account_id'] ?? ''));

        if ($action === 'clear') {
            $stmt = mysqli_prepare($link, 'UPDATE `generate` SET cf_token = NULL, cf_account_id = NULL WHERE sub_id = ?');
            if (!$stmt) { jsonError(500, 'db-error'); }
            bindStatementValues($stmt, 's', [$sessionSubId]);
            mysqli_stmt_execute($stmt);
            mysqli_stmt_close($stmt);
            echo json_encode(['ok' => true, 'cleared' => true]);
            exit;
        }

        // action=save
        if ($token === '') { jsonError(422, 'token-required'); }

        $stmt = mysqli_prepare($link, 'UPDATE `generate` SET cf_token = ?, cf_account_id = ? WHERE sub_id = ?');
        if (!$stmt) { jsonError(500, 'db-error'); }
        bindStatementValues($stmt, 'sss', [$token, $accountId, $sessionSubId]);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_close($stmt);
        echo json_encode(['ok' => true, 'saved' => true]);
        exit;
    }

    jsonError(405, 'method-not-allowed');
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}
