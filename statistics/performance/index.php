<?php

declare(strict_types=1);

include_once '../login.php';
include_once '../connection.config.php';

function pnSendSecurityHeaders(): void
{
    if (headers_sent()) {
        return;
    }

    header_remove('Content-Security-Policy');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('Referrer-Policy: same-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=()');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');

    $csp = implode('; ', [
        "default-src 'self'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'self'",
        "object-src 'none'",
        "img-src 'self' data: https:",
        "font-src 'self' data: https:",
        "media-src 'self' data: https:",
        "style-src 'self' 'unsafe-inline' https:",
        "style-src-elem 'self' 'unsafe-inline' https:",
        "style-src-attr 'unsafe-inline'",
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https:",
        "script-src-elem 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https:",
        "connect-src 'self' https:",
    ]);

    header('Content-Security-Policy: ' . $csp);
}

function pnEnsureSession(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
}

function pnH(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function pnCsrfToken(): string
{
    pnEnsureSession();

    if (
        !isset($_SESSION['pn_csrf_token'])
        || !is_string($_SESSION['pn_csrf_token'])
        || $_SESSION['pn_csrf_token'] === ''
    ) {
        $_SESSION['pn_csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['pn_csrf_token'];
}

function pnVerifyCsrf(?string $token): bool
{
    pnEnsureSession();

    if (!is_string($token) || $token === '') {
        return false;
    }

    if (!isset($_SESSION['pn_csrf_token']) || !is_string($_SESSION['pn_csrf_token'])) {
        return false;
    }

    return hash_equals($_SESSION['pn_csrf_token'], $token);
}

function pnHandleLogout(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return;
    }

    $action = isset($_POST['action']) && is_string($_POST['action']) ? $_POST['action'] : '';
    if ($action !== 'logout') {
        return;
    }

    if (!pnVerifyCsrf($_POST['csrf_token'] ?? null)) {
        http_response_code(403);
        echo 'Invalid CSRF token.';
        exit;
    }

    pnEnsureSession();
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();

        setcookie(
            session_name(),
            '',
            [
                'expires' => time() - 42000,
                'path' => isset($params['path']) ? (string) $params['path'] : '/',
                'domain' => isset($params['domain']) ? (string) $params['domain'] : '',
                'secure' => isset($params['secure']) ? (bool) $params['secure'] : false,
                'httponly' => true,
                'samesite' => 'Strict',
            ]
        );
    }

    session_destroy();
    header('Location: /performance/');
    exit;
}

function normalizeDate(string $input): ?string
{
    $input = trim($input);

    if ($input === '') {
        return null;
    }

    $dateTime = DateTime::createFromFormat('Y-m-d', $input);
    if (!$dateTime instanceof DateTime) {
        return null;
    }

    $errors = DateTime::getLastErrors();
    if ($errors !== false && ($errors['warning_count'] > 0 || $errors['error_count'] > 0)) {
        return null;
    }

    return $dateTime->format('Y-m-d');
}

function pnSafeFileNameDate(string $value): string
{
    return preg_replace('/[^0-9\-]/', '', $value) ?? '';
}

pnSendSecurityHeaders();
pnHandleLogout();

$today = date('Y-m-d');
$start = $today;
$end = $today;
$data = ['data' => []];
$statusMessage = '';
$statusType = '';

if (isset($_POST['click'], $_POST['start'], $_POST['end'])) {
    try {
        if (!pnVerifyCsrf($_POST['csrf_token'] ?? null)) {
            throw new RuntimeException('Invalid CSRF token.');
        }

        $start = normalizeDate((string) $_POST['start']) ?? $today;
        $end = normalizeDate((string) $_POST['end']) ?? $today;

        if ($start > $end) {
            throw new InvalidArgumentException('Invalid date range.');
        }

        $sql = '
            SELECT
                click_id,
                SUM(clicks) AS clicks,
                SUM(leads) AS leads,
                SUM(payout) AS payout,
                MAX(click_date) AS last_click_date
            FROM clickrecord
            WHERE click_date BETWEEN ? AND ?
            GROUP BY click_id
            ORDER BY payout DESC, last_click_date DESC, click_id ASC
        ';

        $stmt = mysqli_prepare($link, $sql);
        if (!$stmt instanceof mysqli_stmt) {
            throw new RuntimeException('Failed preparing report query.');
        }

        mysqli_stmt_bind_param($stmt, 'ss', $start, $end);

        if (!mysqli_stmt_execute($stmt)) {
            mysqli_stmt_close($stmt);
            throw new RuntimeException('Failed executing report query.');
        }

        $result = mysqli_stmt_get_result($stmt);
        if (!$result instanceof mysqli_result) {
            mysqli_stmt_close($stmt);
            throw new RuntimeException('Failed reading report result.');
        }

        $index = 1;
        while ($row = mysqli_fetch_assoc($result)) {
            $clicks = (int) ($row['clicks'] ?? 0);
            $leads = (int) ($row['leads'] ?? 0);
            $payout = (float) ($row['payout'] ?? 0.0);
            $cr = $clicks > 0 ? round(($leads / $clicks) * 100, 2) : 0.0;
            $clickId = strtoupper(preg_replace('/[^A-Za-z0-9_\-]/', '', (string) ($row['click_id'] ?? '')) ?? '');

            $data['data'][] = [
                'id' => $index,
                'click_id' => $clickId,
                'clicks' => $clicks,
                'leads' => $leads,
                'payout' => number_format($payout, 2, '.', ''),
                'cr' => number_format($cr, 2, '.', ''),
            ];

            $index++;
        }

        mysqli_free_result($result);
        mysqli_stmt_close($stmt);
    } catch (Throwable $e) {
        $statusType = 'error';
        $statusMessage = $e->getMessage();
    }
}

if (isset($link) && $link instanceof mysqli) {
    mysqli_close($link);
}

include_once '../header.php';
?>
<style>
:root{color-scheme:light;--bg:#f7f7f7;--panel:#fff;--panel-soft:#f7f7f7;--panel-fade:rgba(255,255,255,.66);--line:rgba(41,43,44,.18);--line-soft:rgba(41,43,44,.1);--text:#292b2c;--text-strong:#111;--accent:#292b2c;--accent-hover:#3a3d3f;--accent-soft:rgba(41,43,44,.06);--on-accent:#f7f7f7;--danger:#9f3138;--danger-soft:rgba(159,49,56,.08);--success:#2563eb;--success-soft:rgba(37,99,235,.08);--blue-soft:rgba(37,99,235,.08);--blue-line:rgba(37,99,235,.28);--radius:.3rem;--shadow:0 1px 4px rgba(41,43,44,.08);--shadow-modal:0 8px 24px rgba(41,43,44,.16)}@media (prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#292b2c;--panel:#303334;--panel-soft:#35393a;--panel-fade:rgba(247,247,247,.045);--line:rgba(247,247,247,.18);--line-soft:rgba(247,247,247,.1);--text:#f7f7f7;--text-strong:#fff;--accent:#f7f7f7;--accent-hover:#e7e7e7;--accent-soft:rgba(247,247,247,.08);--on-accent:#292b2c;--danger:#ef9a9a;--danger-soft:rgba(239,154,154,.11);--success:#93c5fd;--success-soft:rgba(147,197,253,.1);--blue-soft:rgba(147,197,253,.1);--blue-line:rgba(147,197,253,.34);--shadow:0 1px 5px rgba(0,0,0,.28);--shadow-modal:0 10px 28px rgba(0,0,0,.42)}}*{box-sizing:border-box}html{min-height:100%;background:var(--bg)}body{min-height:100vh;margin:0;padding:58px 8px 18px!important;background:linear-gradient(180deg,var(--panel-soft) 0%,var(--bg) 100%)!important;color:var(--text)!important;font-family:monospace!important;font-size:13px;line-height:1.45;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility}a{color:inherit;text-decoration:none}.container{width:100%;max-width:1180px;margin:0 auto}code{font-family:Consolas,Monaco,'Courier New',monospace;font-size:11.5px;color:var(--text);background:var(--panel-soft);border:1px solid var(--line-soft);border-radius:var(--radius);padding:1px 4px}.navbar.navbar-default{min-height:44px;border:0!important;border-bottom:0!important;background:color-mix(in srgb,var(--panel) 94%,transparent)!important;box-shadow:var(--shadow)!important}.navbar .container{max-width:1180px}.navbar-brand{height:44px!important;padding:12px 10px!important;color:var(--text-strong)!important;font-size:13px;line-height:20px}.navbar-nav>li>a{padding-top:12px!important;padding-bottom:12px!important;color:var(--text)!important;font-size:12px}.navbar-nav>li>a:hover,.navbar-default .navbar-nav>.active>a,.navbar-default .navbar-nav>.active>a:focus,.navbar-default .navbar-nav>.active>a:hover{background:var(--accent)!important;color:var(--on-accent)!important}.navbar-toggle{margin-top:5px!important;margin-bottom:5px!important;border-color:var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important}.navbar-toggle .icon-bar{background:var(--text)!important}.panel,.panel-default,.well,.modal-content{border:0!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;box-shadow:var(--shadow)!important;overflow:hidden}.panel-heading,.panel-footer,.modal-header,.modal-footer{padding:8px 10px!important;background:linear-gradient(180deg,var(--panel) 0%,var(--panel-soft) 100%)!important;border:0!important;color:var(--text-strong)!important}.panel-body,.modal-body{padding:10px!important;background:transparent!important;color:var(--text)!important}.pull-right{display:flex;align-items:center;gap:6px}.modal-content{box-shadow:var(--shadow-modal)!important}.modal-title{font-size:14px;font-weight:700;color:var(--text-strong)}.close{color:var(--text)!important;opacity:.78;text-shadow:none}.form-group{margin-bottom:8px}.control-label,label{margin-bottom:4px;color:var(--text-strong);font-size:12px}.form-control,input[type=text],input[type=number],input[type=password],input[type=search],select,textarea{height:31px;min-height:31px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-family:Consolas,Monaco,'Courier New',monospace!important;font-size:12px!important;line-height:1.4!important;box-shadow:none!important; }.form-control:focus,input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent)!important;box-shadow:0 0 0 2px color-mix(in srgb,var(--accent) 18%,transparent)!important}.form-control::placeholder,textarea::placeholder{color:color-mix(in srgb,var(--text) 54%,transparent)}.form-control[readonly],input[readonly],textarea[readonly]{background:var(--panel-soft)!important;color:var(--text)!important}textarea.form-control{height:auto;min-height:114px;resize:none}.input-group-addon{height:31px;padding:5px 8px;background:var(--panel-soft)!important;border-color:var(--line)!important;color:var(--text)!important;border-radius:var(--radius)!important;font-size:11.5px}.btn,button,.btn-sm,.btn-xs{display:inline-flex;align-items:center;justify-content:center;gap:5px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-size:11.5px;font-weight:700;line-height:1.2;box-shadow:none!important;outline:none;transition:background .12s ease,border-color .12s ease,color .12s ease}.btn:hover,button:hover,.btn-sm:hover,.btn-xs:hover{background:var(--panel-soft)!important;border-color:var(--line)!important;color:var(--text-strong)!important}.btn-primary,.btn-primary:focus,.btn-primary:active,.btn.active{background:var(--accent)!important;border-color:var(--accent)!important;color:var(--on-accent)!important}.btn-primary:hover{background:var(--accent-hover)!important;border-color:var(--accent-hover)!important;color:var(--on-accent)!important}.btn-danger,.btn-danger:focus{background:var(--danger-soft)!important;border-color:rgba(159,49,56,.34)!important;color:var(--danger)!important}.btn-danger:hover{background:rgba(159,49,56,.16)!important;color:var(--danger)!important}.glyphicon{top:1px;color:currentColor}.action-ico{display:inline-flex;align-items:center;justify-content:center;flex-shrink:0}.action-ico svg{display:block}.table-responsive{border:0!important}.table{width:100%;margin:4px 0 0;border-collapse:separate;border-spacing:0;border:0;border-radius:var(--radius);overflow:hidden;background:var(--panel)!important}.table>thead>tr>th{position:sticky;top:0;z-index:20;padding:7px 8px!important;border-bottom:1px solid var(--line)!important;background:var(--panel-soft)!important;color:var(--text-strong)!important;font-size:10.5px!important;line-height:1.2;text-transform:uppercase;letter-spacing:.035em;white-space:nowrap}.table>tbody>tr>td{padding:6px 8px!important;border-top:1px solid var(--line-soft)!important;color:var(--text);font-size:11.5px;vertical-align:middle;word-break:break-word;background:var(--panel)!important}.table-hover>tbody>tr:hover>td{background:var(--panel-soft)!important}.bootgrid-table th>.column-header-anchor{color:var(--text-strong)!important}.bootgrid-header,.bootgrid-footer{margin:6px 0!important;color:var(--text)!important}.bootgrid-header .search .form-control{height:31px}.bootgrid-header .actionBar{text-align:right}.pagination>li>a,.pagination>li>span{border-color:var(--line)!important;background:var(--panel)!important;color:var(--text)!important}.pagination>.active>a,.pagination>.active>span{background:var(--accent)!important;border-color:var(--accent)!important;color:var(--on-accent)!important}.dropdown-menu{border:0!important;border-radius:var(--radius)!important;background:var(--panel)!important;box-shadow:var(--shadow-modal)!important}.dropdown-menu>li>a{color:var(--text)!important;font-size:12px}.dropdown-menu>li>a:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}.alert{border-radius:var(--radius)!important}.alert-danger,.error{background:var(--danger-soft)!important;border-color:rgba(159,49,56,.28)!important;color:var(--danger)!important}.alert-success,.success{background:var(--blue-soft)!important;border-color:var(--blue-line)!important;color:var(--text)!important}.label{border-radius:var(--radius)!important}.label-default{background:var(--panel-soft)!important;color:var(--text)!important;border:1px solid var(--line)}blockquote{margin:0 0 10px;padding:7px 10px;border-left:2px solid var(--line)!important;background:var(--panel-fade);border-radius:var(--radius);font-size:12px}.text-warning{margin:0 0 2px;color:var(--text-strong)!important;font-weight:700}.text-muted{color:var(--text)!important}.flag{border-radius:var(--radius)}.admin-toast-root{position:fixed;right:12px;bottom:12px;z-index:10050;display:flex;flex-direction:column;gap:6px;align-items:flex-end}.admin-toast{max-width:340px;padding:8px 10px;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:12px;line-height:1.35}.admin-toast strong{display:block;margin-bottom:2px;color:var(--text-strong)}.admin-toast--error{border-color:rgba(159,49,56,.34);background:var(--danger-soft);color:var(--danger)}.admin-toast--success{border-color:var(--blue-line);background:var(--blue-soft);color:var(--text)}.admin-fallback-backdrop{position:fixed;inset:0;z-index:10040;display:flex;align-items:center;justify-content:center;padding:12px;background:rgba(0,0,0,.36)}.admin-fallback-dialog{width:min(420px,100%);border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);overflow:hidden}.admin-fallback-head{padding:10px;border-bottom:1px solid var(--line-soft);font-weight:800;color:var(--text-strong)}.admin-fallback-body{padding:10px;font-size:12px}.admin-fallback-actions{display:flex;gap:6px;justify-content:flex-end;padding:10px;border-top:1px solid var(--line-soft);background:var(--panel-soft)}@media screen and (max-width:768px){body{padding:58px 6px 12px!important;font-size:12.5px}.container{width:100%!important;max-width:100%!important;padding-left:6px!important;padding-right:6px!important}.panel-heading,.panel-body,.panel-footer{padding:7px!important}.navbar .container{padding-left:8px!important;padding-right:8px!important}.navbar-collapse{border-color:var(--line)!important;background:var(--panel)!important}.pull-right{float:none!important;justify-content:flex-end}.input-group{display:block}.input-group>.form-control,.input-group>.input-group-addon,.input-group>.input-group-btn,.input-group-btn>.btn{display:block;width:100%!important}.input-group-addon{border-bottom:0!important;border-radius:var(--radius) var(--radius) 0 0!important}.input-group>.form-control{border-radius:0 0 var(--radius) var(--radius)!important}.input-group-btn>.btn{margin-top:5px}.table{display:block;overflow-x:auto;white-space:nowrap}.modal-dialog{width:auto!important;margin:8px}}#tbl_trackers{table-layout:fixed;width:100%;min-width:800px}#tbl_trackers th:nth-child(1),#tbl_trackers td:nth-child(1){width:50px;text-align:center;padding-left:4px!important;padding-right:4px!important}#tbl_trackers th:nth-child(2),#tbl_trackers td:nth-child(2){width:120px}#tbl_trackers th:nth-child(3),#tbl_trackers td:nth-child(3){width:120px}#tbl_trackers th:nth-child(5),#tbl_trackers td:nth-child(5){width:120px}.td-num{display:block;font-size:11.5px;font-weight:600;font-family:Consolas,Monaco,monospace;color:color-mix(in srgb,var(--text) 44%,transparent);text-align:center}.td-tracker{display:inline-block;width:100%;padding:2px 8px;border-radius:.3rem;border:1px solid var(--line);background:var(--panel-soft);font-family:Consolas,Monaco,monospace;font-size:11.5px;font-weight:700;letter-spacing:.03em;white-space:nowrap}.td-subdomain{display:inline-block;padding:2px 8px;border-radius:.3rem!important;width:100%;border:1px solid var(--line);background:var(--panel-soft);font-family:Consolas,Monaco,monospace;font-size:11.5px;font-weight:700;letter-spacing:.03em;white-space:nowrap}.td-url{display:block;max-width:100%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:Consolas,Monaco,monospace;font-size:11.5px}.td-pass{font-family:Consolas,Monaco,monospace;font-size:11.5px;color:color-mix(in srgb,var(--text) 60%,transparent)}
/* bootgrid toolbar search/select fix */.navbar-default .navbar-nav>li>a:hover,.navbar-default .navbar-nav>li>a:focus{background:color-mix(in srgb,var(--accent) 5%,transparent)!important;color:var(--text-strong)!important;box-shadow:inset 0 -1px 0 var(--line-soft)!important}.navbar-default .navbar-nav>.active>a,.navbar-default .navbar-nav>.active>a:hover,.navbar-default .navbar-nav>.active>a:focus{background:transparent!important;color:var(--text-strong)!important;box-shadow:inset 0 -1px 0 var(--accent)!important}.panel,.panel-default{overflow:visible!important}.panel-body{overflow:visible!important}.table-responsive{overflow-x:auto!important;overflow-y:visible!important}.bootgrid-header{position:relative!important;z-index:80!important;display:block!important;margin:8px 0 7px!important;color:var(--text)!important}.bootgrid-header .actionBar{display:flex!important;align-items:center!important;justify-content:flex-end!important;gap:8px!important;float:none!important;width:100%!important;margin:0!important;text-align:right!important;white-space:nowrap!important}.bootgrid-header .search{position:relative!important;display:inline-flex!important;align-items:center!important;float:none!important;width:220px!important;min-width:220px!important;max-width:260px!important;margin:0!important;vertical-align:middle!important}.bootgrid-header .search .input-group{display:flex!important;align-items:stretch!important;width:100%!important;border-collapse:separate!important}.bootgrid-header .search .input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;min-width:34px!important;height:32px!important;padding:0!important;border:1px solid var(--line)!important;border-right:0!important;border-radius:var(--radius) 0 0 var(--radius)!important;background:var(--panel-soft)!important;color:var(--text)!important;line-height:1!important}.bootgrid-header .search .input-group-addon .glyphicon{top:0!important;font-size:12px!important}.bootgrid-header .search .search-field,.bootgrid-header .search .form-control{display:block!important;flex:1 1 auto!important;width:100%!important;height:32px!important;min-height:32px!important;padding:5px 9px!important;border:1px solid var(--line)!important;border-left:0!important;border-radius:0 var(--radius) var(--radius) 0!important;background:var(--panel)!important;color:var(--text)!important;font-size:12px!important;line-height:1.4!important;box-shadow:none!important}.bootgrid-header .search .search-field:focus,.bootgrid-header .search .form-control:focus{border-color:var(--accent)!important;border-left:0!important;box-shadow:0 0 0 2px color-mix(in srgb,var(--accent) 13%,transparent)!important}.bootgrid-header .actions{position:relative!important;display:inline-flex!important;align-items:center!important;gap:6px!important;float:none!important;margin:0!important;vertical-align:middle!important}.bootgrid-header .actions>.btn-group{position:relative!important;display:inline-flex!important;float:none!important;margin:0!important;vertical-align:middle!important}.bootgrid-header .actions .btn,.bootgrid-header .actions .dropdown-toggle{display:inline-flex!important;align-items:center!important;justify-content:center!important;gap:6px!important;height:32px!important;min-width:38px!important;padding:5px 10px!important;line-height:1.2!important;border-radius:var(--radius)!important}.bootgrid-header .actions .dropdown-toggle{min-width:64px!important}.bootgrid-header .actions .dropdown-toggle .caret{margin-left:2px!important}.bootgrid-header .actions .dropdown-menu{position:absolute!important;top:calc(100% + 4px)!important;right:0!important;left:auto!important;z-index:3000!important;display:none;min-width:112px!important;width:112px!important;margin:0!important;padding:4px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;box-shadow:var(--shadow-modal)!important;list-style:none!important}.bootgrid-header .actions .open>.dropdown-menu{display:block!important}.bootgrid-header .actions .dropdown-menu>li{display:block!important;float:none!important;width:100%!important;margin:0!important;padding:0!important;text-align:left!important}.bootgrid-header .actions .dropdown-menu>li>a{display:block!important;width:100%!important;min-width:0!important;padding:6px 9px!important;border-radius:var(--radius)!important;background:transparent!important;color:var(--text)!important;font-size:12px!important;line-height:1.25!important;text-align:left!important;white-space:nowrap!important}.bootgrid-header .actions .dropdown-menu>li>a:hover,.bootgrid-header .actions .dropdown-menu>li>a:focus{background:var(--panel-soft)!important;color:var(--text-strong)!important}.bootgrid-header .actions .dropdown-menu>.active>a,.bootgrid-header .actions .dropdown-menu>.active>a:hover,.bootgrid-header .actions .dropdown-menu>.active>a:focus{background:var(--accent-soft)!important;color:var(--text-strong)!important;box-shadow:inset 2px 0 0 var(--accent)!important}.bootgrid-footer{position:relative!important;z-index:20!important}.bootgrid-footer .pagination{margin:0!important}@media screen and (max-width:768px){.bootgrid-header .actionBar{align-items:stretch!important;justify-content:stretch!important;flex-wrap:wrap!important;gap:6px!important}.bootgrid-header .search{width:100%!important;min-width:0!important;max-width:none!important;flex:1 0 100%!important}.bootgrid-header .actions{margin-left:auto!important}.bootgrid-header .actions .dropdown-menu{right:0!important;left:auto!important}}
input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}
/* final action icon render fix */#tbl_trackers th:last-child,#tbl_trackers td:last-child{text-align:center!important;white-space:nowrap!important;width:108px!important;min-width:108px!important;max-width:108px!important}.bootgrid-table td:last-child{overflow:visible!important}.action-btn,.bootgrid-table .command-edit,.bootgrid-table .command-delete{display:inline-flex!important;align-items:center!important;justify-content:center!important;width:32px!important;height:26px!important;min-width:32px!important;min-height:26px!important;padding:0!important;margin:0 2px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-size:0!important;line-height:1!important;text-indent:0!important;vertical-align:middle!important;opacity:1!important;visibility:visible!important;box-shadow:none!important;overflow:visible!important}.action-btn:hover,.bootgrid-table .command-edit:hover{background:var(--accent-soft)!important;border-color:var(--line)!important;color:var(--text-strong)!important}.bootgrid-table .command-delete{color:var(--danger)!important}.bootgrid-table .command-delete:hover{background:var(--danger-soft)!important;border-color:color-mix(in srgb,var(--danger) 34%,var(--line))!important;color:var(--danger)!important}.bootgrid-table .command-edit[disabled],.bootgrid-table .command-delete[disabled]{opacity:.58!important;cursor:not-allowed!important}.action-btn .action-ico,.bootgrid-table .command-edit .action-ico,.bootgrid-table .command-delete .action-ico{display:inline-flex!important;align-items:center!important;justify-content:center!important;width:16px!important;height:16px!important;min-width:16px!important;min-height:16px!important;color:currentColor!important;opacity:1!important;visibility:visible!important;overflow:visible!important;pointer-events:none!important}.action-btn svg,.bootgrid-table .command-edit svg,.bootgrid-table .command-delete svg{display:block!important;width:16px!important;height:16px!important;min-width:16px!important;min-height:16px!important;overflow:visible!important;color:currentColor!important;opacity:1!important;visibility:visible!important;pointer-events:none!important}.action-btn svg *,.bootgrid-table .command-edit svg *,.bootgrid-table .command-delete svg *{vector-effect:non-scaling-stroke!important;stroke:currentColor!important;stroke-width:2!important;stroke-linecap:round!important;stroke-linejoin:round!important;fill:none!important;opacity:1!important;visibility:visible!important}.btn-icon svg,.btn-primary svg{display:block!important;width:13px!important;height:13px!important;fill:currentColor!important;color:currentColor!important;opacity:1!important;visibility:visible!important}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}
body,.table,input,select,textarea{font-family:monospace!important}
.table{width:100%;border-collapse:collapse;font-size:12.5px;margin:0!important;border:0!important;border-radius:0!important;background:transparent!important}
.table>thead>tr>th{height:34px;padding:0 12px!important;text-align:left;font-size:11px;font-weight:600;color:var(--text-strong);text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--line)!important;border-top:0!important;background:var(--panel-soft)!important;white-space:nowrap;position:static}
.table>tbody>tr>td{padding:6px 12px!important;vertical-align:middle;border-bottom:1px solid var(--line-soft)!important;border-top:0!important;font-size:12.5px;font-weight:400;color:var(--text)!important;word-break:break-word;background:transparent!important}
.table>tbody>tr:last-child>td{border-bottom:0!important}
.table-hover>tbody>tr:hover>td{background:var(--panel-soft)!important}
.table-striped>tbody>tr:nth-of-type(odd)>td{background:transparent!important}
.tbl-toolbar{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 12px;flex-wrap:wrap;border-bottom:1px solid var(--line)}
.tbl-toolbar-left{display:flex;align-items:center;gap:6px}
.tbl-footer{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 12px;border-top:1px solid var(--line);font-size:12px;color:var(--text);flex-wrap:wrap}
#tbl_trackers td.url-cell{max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.form-control:focus,input:focus,select:focus,textarea:focus{outline:none;color:var(--text-strong)!important}
.panel,.panel-default{box-shadow:0 1px 2px rgba(41,43,44,.04),0 4px 16px rgba(41,43,44,.06)!important}
.modal-content{box-shadow:0 8px 32px rgba(41,43,44,.12),0 2px 8px rgba(41,43,44,.05)!important}
.navbar-default .navbar-nav>li>a{ }
.navbar-default .navbar-nav>li>a:hover,.navbar-default .navbar-nav>li>a:focus{box-shadow:inset 0 -1px 0 var(--line)!important;background:transparent!important;color:var(--text-strong)!important}
.navbar-default .navbar-nav>.active>a,.navbar-default .navbar-nav>.active>a:hover,.navbar-default .navbar-nav>.active>a:focus{background:transparent!important;color:var(--text-strong)!important;box-shadow:inset 0 -2px 0 var(--accent)!important}
input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}
.form-control:focus,input:focus,select:focus,textarea:focus{box-shadow:none!important}.bootgrid-header .search .search-field:focus,.bootgrid-header .search .form-control:focus{box-shadow:none!important}*:focus,*:focus-visible{outline:none!important;box-shadow:none!important}
/* realtime page local fixes */
.panel_m{margin-top:4px}.panel-heading .panel-title{gap:10px}.panel-heading .searchbox{display:flex!important;align-items:stretch!important;flex:1 1 auto!important;max-width:520px!important;width:100%!important}.panel-heading .searchbox>.input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;min-width:34px!important;height:31px!important;padding:0!important;border-right:0!important;border-radius:var(--radius) 0 0 var(--radius)!important}.panel-heading .searchbox>.form-control{display:block!important;flex:1 1 auto!important;width:auto!important;min-width:0!important;border-left:0!important;border-right:0!important;border-radius:0!important}.panel-heading .searchbox>.input-group-btn{display:flex!important;flex:0 0 auto!important;width:auto!important}.panel-heading .searchbox>.input-group-btn>.btn{height:31px!important;margin:0!important;border-radius:0 var(--radius) var(--radius) 0!important;white-space:nowrap!important}.rg-source{margin:8px 0 0;padding:7px 10px;border:1px solid var(--line-soft);border-radius:var(--radius);background:var(--panel);box-shadow:var(--shadow);font-size:11.5px}.pre-colon{font-weight:700;color:var(--text-strong)}.post-colon{font-family:Consolas,Monaco,'Courier New',monospace;color:var(--text)}#notifications{position:fixed;right:12px;bottom:12px;z-index:10060;display:flex;flex-direction:column;gap:6px;align-items:flex-end}.notice{max-width:420px;padding:8px 10px;border:1px solid var(--blue-line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:12px;line-height:1.35}.notice .close{float:right;margin-left:8px;width:14px;height:14px;border:0!important;border-radius:var(--radius)!important;background:var(--panel-soft)!important}#logout-toast{position:fixed;right:12px;bottom:12px;z-index:10070;display:none;padding:8px 10px;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:12px}#logout-toast.show{display:block}.navbar-btn.btn-link{margin:0!important;border:0!important;background:transparent!important;box-shadow:none!important}@media screen and (max-width:768px){.panel-heading .panel-title{display:block!important}.panel-heading .searchbox{max-width:none!important}.panel-heading .searchbox>.input-group-addon,.panel-heading .searchbox>.form-control,.panel-heading .searchbox>.input-group-btn,.panel-heading .searchbox>.input-group-btn>.btn{display:flex!important;width:auto!important}.panel-heading .searchbox>.form-control{flex:1 1 auto!important}.panel-heading .searchbox>.input-group-btn>.btn{margin-top:0!important}.navbar-btn.btn-link{padding:12px 10px!important}.table{width:100%!important;min-width:860px!important}}
/* performance-network local alignment */.pn-filter-form{display:flex;align-items:stretch;gap:8px;margin:0 0 8px;flex-wrap:wrap}.pn-filter-form .pn-date-field{flex:1 1 220px;min-width:180px;padding:0}.pn-filter-form .input-group{width:100%;display:flex!important;align-items:stretch!important}.pn-filter-form .form-control{border-radius:var(--radius) 0 0 var(--radius)!important}.pn-filter-form .input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;border-left:0!important;border-radius:0 var(--radius) var(--radius) 0!important}.pn-filter-form .btn{height:31px;align-self:stretch}.pn-toolbar{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}.pn-toolbar .searchbox{flex:1 1 280px;margin:0!important}.pn-toolbar .input-group{display:flex!important;width:100%!important}.pn-toolbar .input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;border-right:0!important;border-radius:var(--radius) 0 0 var(--radius)!important}.pn-toolbar .form-control{flex:1 1 auto!important;width:auto!important;border-left:0!important;border-right:0!important;border-radius:0!important}.pn-toolbar .input-group-btn{display:flex!important;flex:0 0 auto!important}.pn-toolbar .input-group-btn>.btn{height:31px!important;border-radius:0 var(--radius) var(--radius) 0!important;margin:0!important}.pn-export{display:flex;align-items:center;justify-content:flex-end;gap:6px;flex:0 0 auto}.pn-empty{padding:12px!important;text-align:center!important;color:var(--text)!important;background:var(--panel)!important}.rg-source{margin:8px 0 0;padding:7px 10px;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);box-shadow:var(--shadow);font-size:11.5px}.rg-source .pre-colon{font-weight:800;color:var(--text-strong)}.rg-source .post-colon{font-family:Consolas,Monaco,'Courier New',monospace;color:var(--text)}#logout-toast{position:fixed;right:12px;bottom:12px;z-index:10060;display:none;padding:8px 10px;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:12px}#logout-toast.show{display:block}.navbar-btn.btn-link{height:44px!important;margin:0!important;padding:12px 10px!important;border:0!important;background:transparent!important;color:var(--text)!important;text-decoration:none!important}.navbar-btn.btn-link:hover{background:transparent!important;color:var(--text-strong)!important}.table>tfoot>tr>th{padding:7px 8px!important;border-top:1px solid var(--line)!important;background:var(--panel-soft)!important;color:var(--text-strong)!important;font-size:11.5px}@media screen and (max-width:768px){.pn-filter-form{display:flex!important;gap:6px}.pn-filter-form .pn-date-field{flex:1 1 100%;width:100%;min-width:0}.pn-filter-form .input-group{display:flex!important}.pn-filter-form .input-group>.form-control{width:auto!important;border-radius:var(--radius) 0 0 var(--radius)!important}.pn-filter-form .input-group>.input-group-addon{width:34px!important;border-bottom:1px solid var(--line)!important;border-radius:0 var(--radius) var(--radius) 0!important}.pn-filter-form .btn{width:100%!important}.pn-toolbar{align-items:stretch}.pn-toolbar .searchbox{flex:1 1 100%}.pn-toolbar .input-group{display:flex!important}.pn-toolbar .input-group>.form-control{width:auto!important;border-radius:0!important}.pn-toolbar .input-group>.input-group-addon{width:34px!important;border-bottom:1px solid var(--line)!important;border-radius:var(--radius) 0 0 var(--radius)!important}.pn-toolbar .input-group-btn{width:auto!important}.pn-toolbar .input-group-btn>.btn{width:auto!important;margin-top:0!important;border-radius:0 var(--radius) var(--radius) 0!important}.pn-export{width:100%;justify-content:flex-end}.table{display:block;overflow-x:auto;white-space:nowrap}}
/* refresh/search input-group hard fix */.pn-toolbar{align-items:flex-start!important}.pn-toolbar .searchbox{display:block!important;flex:1 1 540px!important;max-width:540px!important;min-width:280px!important}.pn-toolbar .searchbox .input-group{display:flex!important;align-items:stretch!important;width:100%!important;border-collapse:separate!important}.pn-toolbar .searchbox .input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;height:31px!important;padding:0!important;border:1px solid var(--line)!important;border-right:0!important;border-radius:var(--radius) 0 0 var(--radius)!important;background:var(--panel-soft)!important}.pn-toolbar .searchbox .form-control{display:block!important;flex:1 1 auto!important;width:auto!important;min-width:0!important;height:31px!important;border:1px solid var(--line)!important;border-left:0!important;border-right:0!important;border-radius:0!important}.pn-toolbar .searchbox .input-group-btn{display:flex!important;align-items:stretch!important;flex:0 0 auto!important;width:auto!important;min-width:0!important;white-space:nowrap!important}.pn-toolbar .searchbox .input-group-btn>.pn-refresh-btn{display:inline-flex!important;align-items:center!important;justify-content:center!important;gap:5px!important;width:auto!important;min-width:84px!important;height:31px!important;margin:0!important;padding:0 10px!important;border:1px solid var(--line)!important;border-left:0!important;border-radius:0 var(--radius) var(--radius) 0!important;background:var(--panel)!important;color:var(--text)!important;white-space:nowrap!important;overflow:hidden!important}.pn-toolbar .searchbox .input-group-btn>.pn-refresh-btn:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}.pn-toolbar .searchbox .input-group-btn>.pn-refresh-btn img{flex:0 0 auto!important}.pn-toolbar .searchbox .input-group-btn>.pn-refresh-btn strong{display:inline!important;line-height:1!important}.pn-export{padding-top:0!important}@media screen and (max-width:768px){.pn-toolbar .searchbox{flex:1 1 100%!important;max-width:none!important;min-width:0!important}.pn-toolbar .searchbox .input-group{display:flex!important;flex-wrap:nowrap!important}.pn-toolbar .searchbox .input-group-addon{flex:0 0 32px!important;width:32px!important}.pn-toolbar .searchbox .input-group-btn{flex:0 0 auto!important;width:auto!important}.pn-toolbar .searchbox .input-group-btn>.pn-refresh-btn{width:auto!important;min-width:76px!important;margin:0!important}}
:root{--font-mono-old:"Lucida Console","Courier New",Consolas,Monaco,monospace}body,.navbar,.panel,.table,.form-control,input,select,textarea,button,.btn,.dropdown-menu,.notice,.rt-notice-line,.rg-source,code,pre,kbd,samp{font-family:var(--font-mono-old)!important;font-size-adjust:none}.table>thead>tr>th{font-family:var(--font-mono-old)!important;font-size:10.5px!important}.table>tbody>tr>td{font-family:var(--font-mono-old)!important;font-size:12px!important}.form-control,input,select,textarea,.btn,button{font-family:var(--font-mono-old)!important;font-size:11.5px!important}

/* performance network earning sort + numeric alignment */
#userlead th:nth-child(1),
#userlead td:nth-child(1){
  text-align:left!important;
  font-variant-numeric:tabular-nums;
}

#userlead th:nth-child(3),
#userlead td:nth-child(3),
#userlead th:nth-child(4),
#userlead td:nth-child(4),
#userlead th:nth-child(5),
#userlead td:nth-child(5),
#userlead th:nth-child(6),
#userlead td:nth-child(6){
  text-align:right!important;
  font-variant-numeric:tabular-nums;
  white-space:nowrap!important;
}

#userlead th:nth-child(6),
#userlead td:nth-child(6){
  min-width:110px!important;
}

</style>
<!-- Fixed navbar -->
<nav class="navbar navbar-default navbar-fixed-top">
    <div class="container">
        <div class="navbar-header">
            <button
                type="button"
                class="navbar-toggle collapsed"
                data-toggle="collapse"
                data-target="#navbar"
                aria-expanded="false"
                aria-controls="navbar"
            >
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
            </button>
            <a class="navbar-brand" href="#">
                <strong>
                    <img src="/dist/info.svg" alt="" style="width:13px;height:13px;vertical-align:middle;">
                    PERFOMANCE NETWORK
                </strong>
            </a>
        </div>
        <div id="navbar" class="navbar-collapse collapse">
            <ul class="nav navbar-nav navbar-right">
                <li>
                    <a href="/realtime/?date=rt_1">
                        <strong>
                            REALTIME CONVERSION
                            <img src="/dist/info.svg" alt="" style="width:13px;height:13px;vertical-align:middle;">
                        </strong>
                    </a>
                </li>
                <li>
                    <a>
                        <strong>
                            <img src="/dist/menu.svg" alt="" style="width:13px;height:13px;vertical-align:middle;">
                        </strong>
                    </a>
                </li>
                <li class="active">
                    <a href="#">
                        <strong>PERFORMANCE NETWORK</strong>
                        <img src="/dist/menu.svg" alt="" style="width:13px;height:13px;vertical-align:middle;">
                    </a>
                </li>
                <li>
                    <form method="post" action="/performance/" id="logout-form" style="margin:0;">
                        <input type="hidden" name="csrf_token" value="<?= pnH(pnCsrfToken()) ?>">
                        <input type="hidden" name="action" value="logout">
                        <button type="submit" id="btn-logout" class="btn btn-link navbar-btn">
                            <strong>LOGOUT</strong>
                        </button>
                    </form>
                </li>
            </ul>
        </div>
    </div>
</nav>

<hr style="margin:3px;padding:3px 3px;border:0;border-bottom:0 dashed #ccc">

<div class="container">
    <?php if ($statusMessage !== ''): ?>
        <div class="alert <?= $statusType === 'error' ? 'alert-danger' : 'alert-success' ?>">
            <?= pnH($statusMessage) ?>
        </div>
    <?php endif; ?>

    <form method="post" id="pn-filter-form" class="pn-filter-form" autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?= pnH(pnCsrfToken()) ?>">
        <div class="pn-date-field">
            <div class="input-group date" data-date-format="yyyy-mm-dd">
                <input
                    type="text"
                    class="form-control input-sm"
                    name="start"
                    id="start"
                    placeholder="{start date}"
                    autocomplete="off"
                    value="<?= pnH($start) ?>"
                >
                <div class="input-group-addon input-sm">
                    <img src="/dist/calendar.svg" alt="" style="width:13px;height:13px;vertical-align:middle;">
                </div>
            </div>
        </div>

        <div class="pn-date-field">
            <div class="input-group date" data-date-format="yyyy-mm-dd">
                <input
                    type="text"
                    class="form-control input-sm"
                    name="end"
                    id="end"
                    placeholder="{end date}"
                    autocomplete="off"
                    value="<?= pnH($end) ?>"
                >
                <div class="input-group-addon input-sm">
                    <img src="/dist/calendar.svg" alt="" style="width:13px;height:13px;vertical-align:middle;">
                </div>
            </div>
        </div>

        <button name="click" class="btn btn-default btn-sm" value="1" type="submit">
            <strong>Load Conversions</strong>
        </button>
    </form>

    <div class="panel_m panel panel-default">
        <div class="panel-heading">
            <div class="pn-toolbar">
                <div class="form-group search searchbox">
                    <div class="input-group">
                        <span class="input-group-addon">
                            <img src="/dist/search.svg" alt="" style="width:13px;height:13px;vertical-align:middle;">
                        </span>
                        <input
                            type="text"
                            class="form-control input-sm"
                            id="search"
                            placeholder="Search..."
                        >
                        <span class="input-group-btn">
                            <button
                                class="btn btn-default btn-sm pn-refresh-btn"
                                id="refresh"
                                type="button"
                            >
                                <img src="/dist/refresh.svg" alt="" style="width:13px;height:13px;vertical-align:middle;">
                                <strong>Refresh</strong>
                            </button>
                        </span>
                    </div>
                </div>
                <div id="export" class="pn-export"></div>
            </div>
        </div>
        <div class="panel-body">
            <table
                id="userlead"
                class="table table-condensed table-hover table-striped"
                cellspacing="0"
                data-toggle="bootgrid"
                style="table-layout:auto;"
            >
                <thead>
                <tr>
                    <th data-column-id="id" data-type="numeric" data-identifier="true" data-resizable-column-id="id" data-noresize>#</th>
                    <th data-column-id="click_id">ID</th>
                    <th data-column-id="clicks">ALL CLICKS</th>
                    <th data-column-id="leads">LEADS</th>
                    <th data-column-id="cr">CR</th>
                    <th data-column-id="payout">EARNING</th>
                </tr>
                </thead>
                <tbody>
                <?php $rows = $data['data'] ?? []; ?>
                <?php if (is_array($rows) && count($rows) > 0): ?>
                    <?php foreach ($rows as $row): ?>
                        <tr>
                            <td class="no"><?= pnH((string) ($row['id'] ?? '')) ?></td>
                            <td><?= pnH((string) ($row['click_id'] ?? '')) ?></td>
                            <td><?= pnH((string) ($row['clicks'] ?? '')) ?></td>
                            <td><?= pnH((string) ($row['leads'] ?? '')) ?></td>
                            <td><?= pnH((string) ($row['cr'] ?? '')) ?></td>
                            <td><?= pnH((string) ($row['payout'] ?? '')) ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
                <tfoot>
                <tr>
                    <th colspan="6" id="sum"></th>
                </tr>
                </tfoot>
            </table>
        </div>
    </div>

    <div class="rg-source">
        <span class="pre-colon">SOURCE</span>:
        <span class="post-colon">NGIX!</span>
    </div>
</div>

<script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-datepicker/1.4.1/js/bootstrap-datepicker.min.js"></script>
<script type="text/javascript">
$(document).ready(function () {
    'use strict';

    $.fn.dataTable.ext.errMode = 'throw';

    $('.input-group.date').datepicker({
        format: 'yyyy-mm-dd'
    });

    var table = $('#userlead').DataTable({
        processing: true,
        language: {
            search: '',
            searchPlaceholder: 'Search...'
        },
        paging: false,
        ordering: true,
        order: [[5, 'desc'], [0, 'asc']],
        columnDefs: [
            {targets: [0, 2, 3, 4, 5], type: 'num'}
        ],
        info: false,
        searching: true,
        dom: "<'top'>l<'searchbox' t>ip",
        footerCallback: function () {
            var api = this.api();

            var intVal = function (i) {
                var parsed;

                if (typeof i === 'string') {
                    i = i.replace(/[^0-9.\-]/g, '');
                    parsed = parseFloat(i);
                    return isNaN(parsed) ? 0 : parsed;
                }

                if (typeof i === 'number') {
                    return i;
                }

                return 0;
            };

            var pageTotal = api
                .column(5, {page: 'current'})
                .data()
                .reduce(function (a, b) {
                    return intVal(a) + intVal(b);
                }, 0);

            $('#sum').html('<i>Total Earning: $' + pageTotal.toFixed(2) + '</i>');
        }
    });

    $('.dataTables_empty').text('No data available in table {select date range for load conversions}');

    $('#search').on('keyup', function () {
        table.search($(this).val()).draw();
    });

    $('#refresh').on('click', function () {
        var form = document.getElementById('pn-filter-form');

        if (form) {
            form.submit();
            return;
        }

        table.order([[5, 'desc'], [0, 'asc']]).draw(false);
        window.scrollTo(0, document.body.scrollHeight);
    });

    if ($.fn.tableExport) {
        var $myTable = $('#userlead');

        $myTable.tableExport({
            headers: true,
            footers: true,
            formats: ['xlsx'],
            fileName: <?= json_encode('conversion-' . pnSafeFileNameDate($start) . '-' . pnSafeFileNameDate($end), JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT) ?>,
            bootstrap: false,
            exportButtons: true,
            position: 'bottom',
            ignoreRows: null,
            ignoreCols: null,
            trimWhitespace: false,
            RTL: false,
            sheetname: 'id'
        });

        var $buttons = $myTable.find('caption').children().detach();
        $buttons.appendTo('#export');
    }

    $('#logout-form').on('submit', function (e) {
        e.preventDefault();

        var form = this;
        var toast = document.getElementById('logout-toast');

        if (toast) {
            toast.classList.add('show');
        }

        setTimeout(function () {
            form.submit();
        }, 900);
    });
});
</script>
<div id="logout-toast">Logging out…</div>
</body>
</html>
