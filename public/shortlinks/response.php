<?php

declare(strict_types=1);

include_once('../connection.php');
include_once('../session_guards.php');

header('Content-Type: application/json; charset=utf-8');

function slEnsureTable(mysqli $conn): void
{
    static $done = false;
    if ($done) { return; }
    $done = true;

    foreach (['code', 'long_url', 'og_title', 'og_image', 'created_at'] as $column) {
        $stmt = mysqli_prepare(
            $conn,
            'SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? LIMIT 1'
        );
        if (!$stmt instanceof mysqli_stmt) {
            jsonError(500, 'schema-check-failed');
        }

        $table = 'shortlinks';
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
    startAdminGuardSession();
    if (empty($_SESSION['admin_authenticated'])) {
        jsonError(403, 'unauthorized');
    }

    $params = $_SERVER['REQUEST_METHOD'] === 'POST' ? $_POST : $_GET;
    $action = trim((string) ($params['action'] ?? ''));

    if ($action !== '' && !hasValidSessionCsrf('admin_panel', requestCsrfToken())) {
        jsonError(419, 'invalid-csrf');
    }

    $db   = new dbObj();
    $conn = $db->getConnstring();
    slEnsureTable($conn);

    if ($action === 'delete') {
        $code = trim((string) ($params['code'] ?? ''));
        if ($code === '' || preg_match('/^[A-Za-z0-9_-]{1,14}$/', $code) !== 1) {
            jsonError(422, 'invalid-code');
        }
        $stmt = mysqli_prepare($conn, 'DELETE FROM shortlinks WHERE code = ?');
        if (!$stmt) { jsonError(500, 'db-error'); }
        bindStatementValues($stmt, 's', [$code]);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_close($stmt);
        echo json_encode(['ok' => true]);
        exit;
    }

    // List (paginated)
    $rowCount = isset($params['rowCount']) ? (int) $params['rowCount'] : 25;
    if ($rowCount === 0 || $rowCount < -1) { $rowCount = 25; }
    $page    = max(1, (int) ($params['current'] ?? 1));
    $offset  = $rowCount === -1 ? 0 : (($page - 1) * $rowCount);
    $search  = trim((string) ($params['searchPhrase'] ?? ''));

    $where    = '';
    $types    = '';
    $bindings = [];
    if ($search !== '') {
        $like     = '%' . $search . '%';
        $where    = ' WHERE (code LIKE ? OR og_title LIKE ? OR long_url LIKE ?)';
        $types    = 'sss';
        $bindings = [$like, $like, $like];
    }

    $cStmt = mysqli_prepare($conn, 'SELECT COUNT(*) AS total FROM shortlinks' . $where);
    if (!$cStmt) { jsonError(500, 'db-error'); }
    bindStatementValues($cStmt, $types, $bindings);
    mysqli_stmt_execute($cStmt);
    $cRow  = mysqli_fetch_assoc(mysqli_stmt_get_result($cStmt));
    $total = (int) ($cRow['total'] ?? 0);
    mysqli_stmt_close($cStmt);

    $sql   = 'SELECT code, long_url, og_title, created_at FROM shortlinks' . $where . ' ORDER BY created_at DESC';
    $dTypes    = $types;
    $dBindings = $bindings;
    if ($rowCount !== -1) {
        $sql       .= ' LIMIT ? OFFSET ?';
        $dTypes    .= 'ii';
        $dBindings[] = $rowCount;
        $dBindings[] = $offset;
    }

    $dStmt = mysqli_prepare($conn, $sql);
    if (!$dStmt) { jsonError(500, 'db-error'); }
    bindStatementValues($dStmt, $dTypes, $dBindings);
    mysqli_stmt_execute($dStmt);
    $result = mysqli_stmt_get_result($dStmt);

    $rows = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $host      = (string) parse_url((string) $row['long_url'], PHP_URL_HOST);
        $shortUrl  = $host !== '' ? 'https://' . $host . '/s-' . $row['code'] : '';
        $ts        = (int) $row['created_at'];
        $rows[] = [
            'code'       => $row['code'],
            'short_url'  => $shortUrl,
            'og_title'   => $row['og_title'],
            'long_url'   => $row['long_url'],
            'created_at' => $ts > 0 ? date('Y-m-d H:i', $ts) : '',
        ];
    }
    mysqli_stmt_close($dStmt);

    echo json_encode(['rows' => $rows, 'total' => $total, 'current' => $page]);
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}
