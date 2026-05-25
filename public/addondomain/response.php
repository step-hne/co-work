<?php

declare(strict_types=1);

include_once('../connection.php');
include_once('../session_guards.php');

header('Content-Type: application/json; charset=utf-8');

function adminDomainParams(): array
{
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        return $_POST;
    }

    return $_GET;
}

function ensureCfColumns(mysqli $conn): void
{
    static $done = false;
    if ($done) {
        return;
    }
    $done = true;

    foreach (['cf_zone_id', 'cf_status', 'cf_ns'] as $column) {
        $stmt = mysqli_prepare(
            $conn,
            'SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? LIMIT 1'
        );
        if (!$stmt instanceof mysqli_stmt) {
            jsonError(500, 'schema-check-failed');
        }

        $table = 'addondomain';
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

function adminDomainList(mysqli $conn, array $params): array
{
    ensureCfColumns($conn);

    $rowCount = isset($params['rowCount']) ? (int) $params['rowCount'] : 100;
    if ($rowCount === 0 || $rowCount < -1) {
        $rowCount = 100;
    }

    $page = max(1, (int) ($params['current'] ?? 1));
    $offset = $rowCount === -1 ? 0 : (($page - 1) * $rowCount);
    $search = trim((string) ($params['searchPhrase'] ?? ''));

    $whereSql = '';
    $types = '';
    $bindings = [];
    if ($search !== '') {
        $like = $search . '%';
        $whereSql = ' WHERE (sub_domain LIKE ? OR domain LIKE ?)';
        $types = 'ss';
        $bindings = [$like, $like];
    }

    $orderSql = ' ORDER BY id DESC';
    if (!empty($params['sort']) && is_array($params['sort'])) {
        $sortColumn = (string) key($params['sort']);
        $sortDirection = strtoupper((string) current($params['sort'])) === 'DESC' ? 'DESC' : 'ASC';
        if (in_array($sortColumn, ['id', 'sub_domain', 'domain'], true)) {
            $orderSql = ' ORDER BY ' . $sortColumn . ' ' . $sortDirection;
        }
    }

    $countStmt = mysqli_prepare($conn, 'SELECT COUNT(*) AS total FROM addondomain' . $whereSql);
    if (!$countStmt) {
        throw new RuntimeException('Failed to prepare count query.');
    }
    bindStatementValues($countStmt, $types, $bindings);
    mysqli_stmt_execute($countStmt);
    $countResult = mysqli_stmt_get_result($countStmt);
    $countRow = $countResult ? mysqli_fetch_assoc($countResult) : ['total' => 0];
    mysqli_stmt_close($countStmt);

    $dataSql = 'SELECT id, sub_domain, domain, COALESCE(cf_zone_id,\'\') AS cf_zone_id, COALESCE(cf_status,\'\') AS cf_status, COALESCE(cf_ns,\'\') AS cf_ns FROM addondomain' . $whereSql . $orderSql;
    $dataTypes = $types;
    $dataBindings = $bindings;
    if ($rowCount !== -1) {
        $dataSql .= ' LIMIT ? OFFSET ?';
        $dataTypes .= 'ii';
        $dataBindings[] = $rowCount;
        $dataBindings[] = $offset;
    }

    $dataStmt = mysqli_prepare($conn, $dataSql);
    if (!$dataStmt) {
        throw new RuntimeException('Failed to prepare list query.');
    }
    bindStatementValues($dataStmt, $dataTypes, $dataBindings);
    mysqli_stmt_execute($dataStmt);
    $dataResult = mysqli_stmt_get_result($dataStmt);

    $rows = [];
    if ($dataResult) {
        while ($row = mysqli_fetch_assoc($dataResult)) {
            $rows[] = $row;
        }
    }
    mysqli_stmt_close($dataStmt);

    return [
        'current' => $page,
        'rowCount' => $rowCount,
        'total' => (int) ($countRow['total'] ?? 0),
        'rows' => $rows,
    ];
}

function adminDomainInsert(mysqli $conn, array $params): void
{
    $subDomain = strtoupper(trim((string) ($params['sub_domain'] ?? '')));
    $domain = trim((string) ($params['domain'] ?? ''));

    if ($subDomain === '' || $domain === '') {
        jsonError(422, 'missing-fields');
    }

    $stmt = mysqli_prepare($conn, 'INSERT INTO addondomain (sub_domain, domain) VALUES (?, ?)');
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare insert query.');
    }
    bindStatementValues($stmt, 'ss', [$subDomain, $domain]);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);

    echo json_encode(['ok' => true]);
}

function adminDomainUpdate(mysqli $conn, array $params): void
{
    $id = (int) ($params['edit_id'] ?? 0);
    $subDomain = strtoupper(trim((string) ($params['edit_sub_domain'] ?? '')));
    $domain = trim((string) ($params['edit_domain'] ?? ''));

    if ($id < 1 || $subDomain === '' || $domain === '') {
        jsonError(422, 'missing-fields');
    }

    $stmt = mysqli_prepare($conn, 'UPDATE addondomain SET sub_domain = ?, domain = ? WHERE id = ?');
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare update query.');
    }
    bindStatementValues($stmt, 'ssi', [$subDomain, $domain, $id]);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);

    echo json_encode(['ok' => true]);
}

function adminDomainDelete(mysqli $conn, array $params): void
{
    $id = (int) ($params['id'] ?? 0);
    if ($id < 1) {
        jsonError(422, 'invalid-id');
    }

    $stmt = mysqli_prepare($conn, 'DELETE FROM addondomain WHERE id = ?');
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare delete query.');
    }
    bindStatementValues($stmt, 'i', [$id]);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);

    echo json_encode(['ok' => true]);
}

try {
    startAdminGuardSession();
    if (empty($_SESSION['admin_authenticated'])) {
        jsonError(403, 'unauthorized');
    }

    $db = new dbObj();
    $conn = $db->getConnstring();
    $params = adminDomainParams();
    $action = (string) ($params['action'] ?? '');

    if (in_array($action, ['add', 'edit', 'delete'], true) && !hasValidSessionCsrf('admin_panel', requestCsrfToken())) {
        jsonError(419, 'invalid-csrf');
    }

    switch ($action) {
        case 'add':
            adminDomainInsert($conn, $params);
            break;
        case 'edit':
            adminDomainUpdate($conn, $params);
            break;
        case 'delete':
            adminDomainDelete($conn, $params);
            break;
        default:
            echo json_encode(adminDomainList($conn, $params));
            break;
    }
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}
