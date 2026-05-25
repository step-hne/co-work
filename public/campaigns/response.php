<?php

declare(strict_types=1);

include_once('../connection.php');
include_once('../session_guards.php');

header('Content-Type: application/json; charset=utf-8');

function adminCampaignParams(): array
{
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        return $_POST;
    }

    return $_GET;
}

function adminCampaignList(mysqli $conn, array $params): array
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
        $whereSql = ' WHERE (country_code LIKE ? OR ua LIKE ? OR offer LIKE ? OR network LIKE ?)';
        $types = 'ssss';
        $bindings = [$like, $like, $like, $like];
    }

    $orderSql = ' ORDER BY id DESC';
    if (!empty($params['sort']) && is_array($params['sort'])) {
        $sortColumn = (string) key($params['sort']);
        $sortDirection = strtoupper((string) current($params['sort'])) === 'DESC' ? 'DESC' : 'ASC';
        if (in_array($sortColumn, ['id', 'country_code', 'ua', 'offer', 'network'], true)) {
            $orderSql = ' ORDER BY ' . $sortColumn . ' ' . $sortDirection;
        }
    }

    $countStmt = mysqli_prepare($conn, 'SELECT COUNT(*) AS total FROM offering' . $whereSql);
    if (!$countStmt) {
        throw new RuntimeException('Failed to prepare count query.');
    }
    bindStatementValues($countStmt, $types, $bindings);
    mysqli_stmt_execute($countStmt);
    $countResult = mysqli_stmt_get_result($countStmt);
    $countRow = $countResult ? mysqli_fetch_assoc($countResult) : ['total' => 0];
    mysqli_stmt_close($countStmt);

    $dataSql = 'SELECT id, country_code, ua, offer, network FROM offering' . $whereSql . $orderSql;
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

function adminCampaignInsert(mysqli $conn, array $params): void
{
    $countryCode = strtoupper(trim((string) ($params['country_code'] ?? '')));
    $ua = strtoupper(trim((string) ($params['ua'] ?? '')));
    $offer = trim((string) ($params['offer'] ?? ''));
    $network = trim((string) ($params['network'] ?? ''));

    if ($countryCode === '' || $ua === '' || $offer === '' || $network === '') {
        jsonError(422, 'missing-fields');
    }

    $stmt = mysqli_prepare($conn, 'INSERT INTO offering (country_code, offer, ua, network) VALUES (?, ?, ?, ?)');
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare insert query.');
    }
    bindStatementValues($stmt, 'ssss', [$countryCode, $offer, $ua, $network]);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);

    echo json_encode(['ok' => true]);
}

function adminCampaignUpdate(mysqli $conn, array $params): void
{
    $id = (int) ($params['edit_id'] ?? 0);
    $countryCode = strtoupper(trim((string) ($params['edit_country_code'] ?? '')));
    $ua = strtoupper(trim((string) ($params['edit_ua'] ?? '')));
    $offer = trim((string) ($params['edit_offer'] ?? ''));
    $network = trim((string) ($params['edit_network'] ?? ''));

    if ($id < 1 || $countryCode === '' || $ua === '' || $offer === '' || $network === '') {
        jsonError(422, 'missing-fields');
    }

    $stmt = mysqli_prepare($conn, 'UPDATE offering SET country_code = ?, ua = ?, offer = ?, network = ? WHERE id = ?');
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare update query.');
    }
    bindStatementValues($stmt, 'ssssi', [$countryCode, $ua, $offer, $network, $id]);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);

    echo json_encode(['ok' => true]);
}

function adminCampaignDelete(mysqli $conn, array $params): void
{
    $id = (int) ($params['id'] ?? 0);
    if ($id < 1) {
        jsonError(422, 'invalid-id');
    }

    $stmt = mysqli_prepare($conn, 'DELETE FROM offering WHERE id = ?');
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
    $params = adminCampaignParams();
    $action = (string) ($params['action'] ?? '');

    if (in_array($action, ['add', 'edit', 'delete'], true) && !hasValidSessionCsrf('admin_panel', requestCsrfToken())) {
        jsonError(419, 'invalid-csrf');
    }

    switch ($action) {
        case 'add':
            adminCampaignInsert($conn, $params);
            break;
        case 'edit':
            adminCampaignUpdate($conn, $params);
            break;
        case 'delete':
            adminCampaignDelete($conn, $params);
            break;
        default:
            echo json_encode(adminCampaignList($conn, $params));
            break;
    }
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}