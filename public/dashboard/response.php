<?php

declare(strict_types=1);

include_once('../connection.php');
include_once('../session_guards.php');

header('Content-Type: application/json; charset=utf-8');

function adminPanelParams(): array
{
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        return $_POST;
    }

    return $_GET;
}

function adminPanelList(mysqli $conn, array $params): array
{
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
        $whereSql = ' WHERE (sub_id LIKE ? OR password LIKE ? OR gen_url LIKE ? OR sm_url LIKE ?)';
        $types = 'ssss';
        $bindings = [$like, $like, $like, $like];
    }

    $orderSql = ' ORDER BY id DESC';
    if (!empty($params['sort']) && is_array($params['sort'])) {
        $sortColumn = (string) key($params['sort']);
        $sortDirection = strtoupper((string) current($params['sort'])) === 'DESC' ? 'DESC' : 'ASC';
        if (in_array($sortColumn, ['id', 'sub_id', 'password', 'gen_url', 'sm_url'], true)) {
            $orderSql = ' ORDER BY ' . $sortColumn . ' ' . $sortDirection;
        }
    }

    $countStmt = mysqli_prepare($conn, 'SELECT COUNT(*) AS total FROM generate' . $whereSql);
    if (!$countStmt) {
        throw new RuntimeException('Failed to prepare count query.');
    }
    bindStatementValues($countStmt, $types, $bindings);
    mysqli_stmt_execute($countStmt);
    $countResult = mysqli_stmt_get_result($countStmt);
    $countRow = $countResult ? mysqli_fetch_assoc($countResult) : ['total' => 0];
    mysqli_stmt_close($countStmt);

    $dataSql = 'SELECT id, sub_id, password, gen_url, sm_url FROM generate' . $whereSql . $orderSql;
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

function adminPanelInsert(mysqli $conn, array $params): void
{
    $subId = strtoupper(trim((string) ($params['sub_id'] ?? '')));
    $password = trim((string) ($params['password'] ?? ''));
    $genUrl = trim((string) ($params['gen_url'] ?? ''));
    $smUrl = strtoupper(trim((string) ($params['sm_url'] ?? '')));

    if ($subId === '' || $password === '' || $genUrl === '' || $smUrl === '') {
        jsonError(422, 'missing-fields');
    }

    $stmt = mysqli_prepare($conn, 'INSERT INTO generate (sub_id, password, gen_url, sm_url) VALUES (?, ?, ?, ?)');
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare insert query.');
    }
    bindStatementValues($stmt, 'ssss', [$subId, $password, $genUrl, $smUrl]);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);

    echo json_encode(['ok' => true]);
}

function adminPanelUpdate(mysqli $conn, array $params): void
{
    $id = (int) ($params['edit_id'] ?? 0);
    $subId = strtoupper(trim((string) ($params['edit_sub_id'] ?? '')));
    $password = trim((string) ($params['edit_password'] ?? ''));
    $genUrl = trim((string) ($params['edit_gen_url'] ?? ''));
    $smUrl = strtoupper(trim((string) ($params['edit_sm_url'] ?? '')));

    if ($id < 1 || $subId === '' || $password === '' || $genUrl === '' || $smUrl === '') {
        jsonError(422, 'missing-fields');
    }

    $stmt = mysqli_prepare($conn, 'UPDATE generate SET sub_id = ?, password = ?, gen_url = ?, sm_url = ? WHERE id = ?');
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare update query.');
    }
    bindStatementValues($stmt, 'ssssi', [$subId, $password, $genUrl, $smUrl, $id]);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);

    echo json_encode(['ok' => true]);
}

function adminPanelDelete(mysqli $conn, array $params): void
{
    $id = (int) ($params['id'] ?? 0);
    if ($id < 1) {
        jsonError(422, 'invalid-id');
    }

    $stmt = mysqli_prepare($conn, 'DELETE FROM generate WHERE id = ?');
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
    $params = adminPanelParams();
    $action = (string) ($params['action'] ?? '');

    if (in_array($action, ['add', 'edit', 'delete'], true) && !hasValidSessionCsrf('admin_panel', requestCsrfToken())) {
        jsonError(419, 'invalid-csrf');
    }

    switch ($action) {
        case 'add':
            adminPanelInsert($conn, $params);
            break;
        case 'edit':
            adminPanelUpdate($conn, $params);
            break;
        case 'delete':
            adminPanelDelete($conn, $params);
            break;
        default:
            echo json_encode(adminPanelList($conn, $params));
            break;
    }
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}