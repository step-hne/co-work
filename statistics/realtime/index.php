<?php

declare(strict_types=1);

include_once('../login.php');
include_once('../connection.config.php');

$rtNonce = bin2hex(random_bytes(16));

function rtSendSecurityHeaders(string $nonce): void
{
    if (headers_sent()) {
        return;
    }

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
        "script-src 'self' 'unsafe-inline' 'nonce-" . $nonce . "' https://www.gstatic.com https:",
        "connect-src 'self' https:",
    ]);

    header('Content-Security-Policy: ' . $csp);
}

function rtEnsureSession(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
}

function rtH(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function rtCsrfToken(): string
{
    rtEnsureSession();

    if (
        !isset($_SESSION['rt_csrf_token'])
        || !is_string($_SESSION['rt_csrf_token'])
        || $_SESSION['rt_csrf_token'] === ''
    ) {
        $_SESSION['rt_csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['rt_csrf_token'];
}

function rtVerifyCsrf(?string $token): bool
{
    rtEnsureSession();

    if (!is_string($token) || $token === '') {
        return false;
    }

    if (!isset($_SESSION['rt_csrf_token']) || !is_string($_SESSION['rt_csrf_token'])) {
        return false;
    }

    return hash_equals($_SESSION['rt_csrf_token'], $token);
}

function rtReadJsonArray(string $filename): array
{
    if (!is_file($filename) || !is_readable($filename)) {
        return [];
    }

    $json = file_get_contents($filename);
    if (!is_string($json) || trim($json) === '') {
        return [];
    }

    $decoded = json_decode($json, true);
    if (!is_array($decoded)) {
        return [];
    }

    return $decoded;
}

function rtHandlePostLogout(string $date): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return;
    }

    $action = isset($_POST['action']) && is_string($_POST['action']) ? $_POST['action'] : '';
    if ($action !== 'logout') {
        return;
    }

    if (!rtVerifyCsrf($_POST['csrf_token'] ?? null)) {
        http_response_code(403);
        echo 'Invalid CSRF token.';
        exit;
    }

    rtEnsureSession();
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

    header('Location: /realtime/?date=' . rawurlencode($date));
    exit;
}

rtSendSecurityHeaders($rtNonce);

$date = isset($_GET['date']) && is_string($_GET['date']) ? $_GET['date'] : 'rt_1';

if ($date !== 'rt_1' && $date !== 'rt_2') {
    header('Location: ?date=rt_1', true, 302);
    exit;
}

rtHandlePostLogout($date);

$conversion = $date === 'rt_1' ? 1 : 2;
$time = date('Y-m-d', strtotime('today'));
$filename = '../temp/' . $time . '.json';
$result = rtReadJsonArray($filename);

include_once('../header.php');
?>
<style nonce="<?= rtH($rtNonce) ?>">
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
.rt-notice-line{display:inline-flex;align-items:center;gap:5px;flex-wrap:wrap}.rt-inline-icon{display:inline-block!important;width:14px!important;height:14px!important;vertical-align:middle!important;object-fit:contain}.rt-network-icon{width:16px!important;height:16px!important}.rt-click-id{color:#0275d8}.rt-country-code{color:#d9534f}.notice .close{padding-left:10px!important}
:root{--font-mono-old:"Lucida Console","Courier New",Consolas,Monaco,monospace}body,.navbar,.panel,.table,.form-control,input,select,textarea,button,.btn,.dropdown-menu,.notice,.rt-notice-line,.rg-source,code,pre,kbd,samp{font-family:var(--font-mono-old)!important;font-size-adjust:none}.table>thead>tr>th{font-family:var(--font-mono-old)!important;font-size:10.5px!important}.table>tbody>tr>td{font-family:var(--font-mono-old)!important;font-size:12px!important}.form-control,input,select,textarea,.btn,button{font-family:var(--font-mono-old)!important;font-size:11.5px!important}
#userlead th:nth-child(1),
#userlead td:nth-child(1),
#userlead th:nth-child(6),
#userlead td:nth-child(6),
#userlead th:nth-child(7),
#userlead td:nth-child(7){
  text-align:right!important;
}

#userlead th:nth-child(1),
#userlead td:nth-child(1){
  width:44px!important;
  min-width:44px!important;
  max-width:44px!important;
  padding-right:12px!important;
}

#userlead th:nth-child(6),
#userlead td:nth-child(6){
  width:110px!important;
  min-width:110px!important;
  max-width:110px!important;
  white-space:nowrap!important;
  font-variant-numeric:tabular-nums;
}

#userlead th:nth-child(7),
#userlead td:nth-child(7){
  width:210px!important;
  min-width:210px!important;
  max-width:260px!important;
  white-space:nowrap!important;
  font-variant-numeric:tabular-nums;
}

#userlead td:nth-child(7){
  overflow:hidden!important;
  text-overflow:ellipsis!important;
}

#userlead tfoot th#sum{
  text-align:left!important;
  font-variant-numeric:tabular-nums;
}

/* final applied patch: numeric alignment + flat non-bold realtime notification */
#userlead th:nth-child(1),#userlead td:nth-child(1){width:44px!important;min-width:44px!important;max-width:44px!important;text-align:left!important;padding-left:12px!important;padding-right:8px!important;font-variant-numeric:tabular-nums}
#userlead th:nth-child(6),#userlead td:nth-child(6){width:110px!important;min-width:110px!important;max-width:110px!important;text-align:right!important;white-space:nowrap!important;font-variant-numeric:tabular-nums}
#userlead th:nth-child(7),#userlead td:nth-child(7){width:210px!important;min-width:210px!important;max-width:260px!important;text-align:right!important;white-space:nowrap!important;font-variant-numeric:tabular-nums}
#userlead td:nth-child(7){overflow:hidden!important;text-overflow:ellipsis!important}
#userlead tfoot th#sum{text-align:left!important;font-variant-numeric:tabular-nums}
#notifications{position:fixed!important;right:12px!important;bottom:12px!important;z-index:10060!important;display:flex!important;flex-direction:column!important;gap:6px!important;align-items:flex-end!important}
.notice{max-width:420px!important;padding:7px 10px!important;border:0!important;box-shadow:none!important;background:var(--panel)!important;color:var(--text)!important;border-radius:var(--radius)!important;font-family:var(--font-mono-old,"Lucida Console","Courier New",Consolas,Monaco,monospace)!important;font-size:11.5px!important;line-height:1.35!important;font-weight:400!important}
.notice .close{float:right!important;margin-left:8px!important;width:14px!important;height:14px!important;padding:0!important;border:0!important;box-shadow:none!important;background:transparent!important;color:var(--text)!important;opacity:.65!important;text-decoration:none!important}
.notice .close:hover,.notice .close:focus{background:transparent!important;opacity:1!important;outline:none!important;box-shadow:none!important}
.rt-notice-line{display:inline-flex!important;align-items:center!important;gap:5px!important;flex-wrap:wrap!important;font-family:var(--font-mono-old,"Lucida Console","Courier New",Consolas,Monaco,monospace)!important;font-size:11.5px!important;line-height:1.35!important;font-weight:400!important}
.notice strong,.notice b,.notice span,.notice code,.rt-notice-line,.rt-notice-line strong,.rt-notice-line b,.rt-notice-line span,.rt-click-id,.rt-country-code{font-weight:400!important}
.rt-click-id{color:#0275d8!important}.rt-country-code{color:#d9534f!important}
.rt-inline-icon{display:inline-block!important;width:14px!important;height:14px!important;min-width:14px!important;min-height:14px!important;vertical-align:middle!important;object-fit:contain!important;filter:none!important;box-shadow:none!important}
.rt-network-icon{width:16px!important;height:16px!important;min-width:16px!important;min-height:16px!important}.rt-info-icon{opacity:.78!important}.notice .flag{display:inline-block!important;vertical-align:middle!important;border-radius:var(--radius)!important;box-shadow:none!important}
.panel-heading .searchbox>.input-group-btn>.pn-refresh-btn{height:31px!important;margin:0!important;border-radius:0 var(--radius) var(--radius) 0!important;white-space:nowrap!important;width:auto!important;min-width:82px!important}


/* final search input-group match + relative realtime assets */
.panel-heading .panel-title{display:flex!important;align-items:center!important;justify-content:space-between!important;gap:10px!important}
.panel-heading .input-group.search.searchbox{display:flex!important;align-items:stretch!important;flex:0 1 540px!important;width:100%!important;max-width:540px!important;height:31px!important;margin:0!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;overflow:hidden!important;box-shadow:none!important;border-collapse:separate!important}
.panel-heading .input-group.search.searchbox>.input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;min-width:34px!important;height:29px!important;min-height:29px!important;padding:0!important;border:0!important;border-right:1px solid var(--line-soft)!important;border-radius:0!important;background:var(--panel-soft)!important;color:var(--text)!important;line-height:1!important;box-shadow:none!important}
.panel-heading .input-group.search.searchbox>.form-control{display:block!important;flex:1 1 auto!important;width:auto!important;min-width:0!important;height:29px!important;min-height:29px!important;padding:5px 9px!important;border:0!important;border-radius:0!important;background:var(--panel)!important;color:var(--text)!important;font-family:var(--font-mono-old,"Lucida Console","Courier New",Consolas,Monaco,monospace)!important;font-size:11.5px!important;line-height:1.4!important;box-shadow:none!important;outline:none!important}
.panel-heading .input-group.search.searchbox>.form-control:focus{border:0!important;box-shadow:none!important;outline:none!important;color:var(--text-strong)!important}
.panel-heading .input-group.search.searchbox>.input-group-btn{display:flex!important;align-items:stretch!important;flex:0 0 auto!important;width:auto!important;min-width:0!important;height:29px!important;white-space:nowrap!important}
.panel-heading .input-group.search.searchbox>.input-group-btn>.btn,.panel-heading .input-group.search.searchbox>.input-group-btn>.pn-refresh-btn{display:inline-flex!important;align-items:center!important;justify-content:center!important;gap:5px!important;width:auto!important;min-width:88px!important;height:29px!important;min-height:29px!important;margin:0!important;padding:0 10px!important;border:0!important;border-left:1px solid var(--line-soft)!important;border-radius:0!important;background:var(--panel)!important;color:var(--text-strong)!important;font-family:var(--font-mono-old,"Lucida Console","Courier New",Consolas,Monaco,monospace)!important;font-size:11.5px!important;font-weight:700!important;line-height:1.2!important;box-shadow:none!important;outline:none!important;white-space:nowrap!important}
.panel-heading .input-group.search.searchbox>.input-group-btn>.btn:hover,.panel-heading .input-group.search.searchbox>.input-group-btn>.pn-refresh-btn:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}
.panel-heading .input-group.search.searchbox img{display:block!important;width:13px!important;height:13px!important;vertical-align:middle!important;object-fit:contain!important}
@media screen and (max-width:768px){.panel-heading .panel-title{display:block!important}.panel-heading .input-group.search.searchbox{max-width:none!important;flex:1 1 auto!important}.panel-heading .input-group.search.searchbox>.input-group-addon{display:flex!important;width:34px!important;min-width:34px!important}.panel-heading .input-group.search.searchbox>.form-control{display:block!important;width:auto!important;min-width:0!important;flex:1 1 auto!important}.panel-heading .input-group.search.searchbox>.input-group-btn{display:flex!important;width:auto!important;flex:0 0 auto!important}.panel-heading .input-group.search.searchbox>.input-group-btn>.btn,.panel-heading .input-group.search.searchbox>.input-group-btn>.pn-refresh-btn{display:inline-flex!important;width:auto!important;margin-top:0!important}}

/* final search border seam fix */
.panel-heading .input-group.search.searchbox{display:flex!important;align-items:stretch!important;width:100%!important;max-width:540px!important;height:31px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;overflow:hidden!important;box-shadow:none!important}
.panel-heading .input-group.search.searchbox>.input-group-addon,.panel-heading .input-group.search.searchbox>.form-control,.panel-heading .input-group.search.searchbox>.input-group-btn,.panel-heading .input-group.search.searchbox>.input-group-btn>.btn,.panel-heading .input-group.search.searchbox>.input-group-btn>.pn-refresh-btn{border:0!important;box-shadow:none!important;outline:none!important}
.panel-heading .input-group.search.searchbox>.input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;min-width:34px!important;height:29px!important;min-height:29px!important;padding:0!important;border-radius:0!important;background:var(--panel-soft)!important;color:var(--text)!important;line-height:1!important}
.panel-heading .input-group.search.searchbox>.form-control{display:block!important;flex:1 1 auto!important;width:auto!important;min-width:0!important;height:29px!important;min-height:29px!important;padding:5px 9px!important;border-radius:0!important;background:var(--panel)!important;color:var(--text)!important;line-height:1.4!important}
.panel-heading .input-group.search.searchbox>.input-group-btn{display:flex!important;align-items:stretch!important;flex:0 0 auto!important;width:auto!important;height:29px!important;min-height:29px!important;background:var(--panel)!important}
.panel-heading .input-group.search.searchbox>.input-group-btn>.btn,.panel-heading .input-group.search.searchbox>.input-group-btn>.pn-refresh-btn{display:inline-flex!important;align-items:center!important;justify-content:center!important;gap:5px!important;width:auto!important;min-width:88px!important;height:29px!important;min-height:29px!important;margin:0!important;padding:0 10px!important;border-radius:0!important;background:var(--panel)!important;color:var(--text-strong)!important;white-space:nowrap!important;font-weight:700!important}
.panel-heading .input-group.search.searchbox>.input-group-btn>.btn:hover,.panel-heading .input-group.search.searchbox>.input-group-btn>.pn-refresh-btn:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}
.panel-heading .input-group.search.searchbox img{display:block!important;width:13px!important;height:13px!important;box-shadow:none!important;filter:none!important}
@media screen and (max-width:768px){.panel-heading .input-group.search.searchbox{max-width:none!important;flex-wrap:nowrap!important}.panel-heading .input-group.search.searchbox>.input-group-addon{display:flex!important;width:34px!important;min-width:34px!important}.panel-heading .input-group.search.searchbox>.form-control{display:block!important;width:auto!important;min-width:0!important;flex:1 1 auto!important}.panel-heading .input-group.search.searchbox>.input-group-btn{display:flex!important;width:auto!important;flex:0 0 auto!important}.panel-heading .input-group.search.searchbox>.input-group-btn>.btn,.panel-heading .input-group.search.searchbox>.input-group-btn>.pn-refresh-btn{display:inline-flex!important;width:auto!important;margin-top:0!important}}

/* sweetalert2 monospace light final */
:root{--font-mono-light:"Lucida Console","Courier New",Consolas,Monaco,monospace}.swal2-container,.swal2-container *{box-sizing:border-box!important;font-family:var(--font-mono-light)!important;font-weight:400!important;letter-spacing:.01em!important}.swal2-container{z-index:10090!important}.swal2-modal,.swal2-popup{width:320px!important;max-width:calc(100vw - 24px)!important;padding:14px!important;border:0!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;box-shadow:0 6px 22px rgba(0,0,0,.14)!important;overflow:visible!important}.swal2-title{margin:0 0 8px!important;padding:0!important;color:var(--text-strong)!important;font-size:18px!important;font-weight:400!important;line-height:1.25!important;text-align:center!important}.swal2-content,.swal2-html-container{margin:0!important;padding:0!important;color:var(--text)!important;font-size:11.5px!important;font-weight:400!important;line-height:1.45!important;text-align:left!important;overflow:visible!important}.rt-swal-text{display:block!important;margin:0!important;padding:0!important;color:var(--text)!important;font-size:11.5px!important;font-weight:400!important;line-height:1.45!important;text-align:left!important}.swal2-actions,.swal2-buttonswrapper{display:flex!important;align-items:center!important;justify-content:center!important;gap:8px!important;margin:12px 0 0!important;padding:0!important;min-height:31px!important;overflow:visible!important}.swal2-confirm,.swal2-cancel,.swal2-styled{display:inline-flex!important;align-items:center!important;justify-content:center!important;position:static!important;width:auto!important;min-width:88px!important;height:31px!important;min-height:31px!important;margin:0!important;padding:0 12px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;box-shadow:none!important;outline:none!important;transform:none!important;writing-mode:horizontal-tb!important;white-space:nowrap!important;text-indent:0!important;text-transform:none!important;font-size:11.5px!important;font-weight:400!important;line-height:1.2!important;vertical-align:middle!important;overflow:hidden!important}.swal2-confirm,.swal2-confirm:focus,.swal2-confirm:hover{background:var(--accent)!important;border-color:var(--accent)!important;color:var(--on-accent)!important}.swal2-cancel,.swal2-cancel:focus,.swal2-cancel:hover{background:var(--panel)!important;border-color:var(--line)!important;color:var(--text)!important}.swal2-loader{display:inline-block!important;width:22px!important;height:22px!important;min-width:22px!important;min-height:22px!important;margin:0 8px!important;padding:0!important;border-width:3px!important;border-style:solid!important;border-radius:50%!important;box-shadow:none!important;outline:none!important;transform:none!important;vertical-align:middle!important}.swal2-loading .swal2-confirm{display:none!important}.swal2-container pre{width:100%!important;max-width:100%!important;margin:8px 0 0!important;padding:8px!important;border:1px solid var(--line-soft)!important;border-radius:var(--radius)!important;background:var(--panel-soft)!important;color:var(--text)!important;font-size:11.5px!important;font-weight:400!important;line-height:1.45!important;white-space:pre-wrap!important;word-break:break-word!important;overflow:auto!important;text-align:left!important}.swal2-container strong,.swal2-container b,.swal2-container footer,.swal2-container .text-muted{font-weight:400!important}

/* final realtime notice: transparent background + relaxed spacing */
#notifications{position:fixed!important;right:12px!important;bottom:12px!important;z-index:10060!important;display:flex!important;flex-direction:column!important;gap:10px!important;align-items:flex-end!important;pointer-events:none!important}.notice{display:block!important;width:auto!important;max-width:none!important;padding:0!important;margin:0!important;border:0!important;border-radius:0!important;background:transparent!important;box-shadow:none!important;color:var(--text)!important;font-family:var(--font-mono-old,"Lucida Console","Courier New",Consolas,Monaco,monospace)!important;font-size:11.5px!important;font-weight:400!important;line-height:1.55!important;pointer-events:auto!important}.notice .close{display:none!important}.rt-notice-line{display:inline-flex!important;align-items:center!important;justify-content:flex-start!important;gap:8px!important;flex-wrap:wrap!important;padding:0!important;margin:0!important;background:transparent!important;border:0!important;box-shadow:none!important;color:var(--text)!important;font-family:var(--font-mono-old,"Lucida Console","Courier New",Consolas,Monaco,monospace)!important;font-size:11.5px!important;font-weight:400!important;line-height:1.6!important;white-space:normal!important}.rt-click-id,.rt-country-code,.rt-notice-line span,.rt-notice-line code,.rt-notice-line strong,.rt-notice-line b{font-weight:400!important}.rt-click-id{color:#0275d8!important}.rt-country-code{color:#d9534f!important}.rt-inline-icon{display:inline-block!important;width:14px!important;height:14px!important;min-width:14px!important;min-height:14px!important;vertical-align:middle!important;object-fit:contain!important;margin:0!important;padding:0!important;background:transparent!important;box-shadow:none!important;border:0!important}.rt-network-icon{width:16px!important;height:16px!important;min-width:16px!important;min-height:16px!important}.notice .flag,.rt-notice-line .flag{display:inline-block!important;vertical-align:middle!important;margin:0 1px 0 0!important;border-radius:.15rem!important;box-shadow:none!important}@media screen and (max-width:768px){#notifications{right:8px!important;left:8px!important;bottom:8px!important;align-items:flex-start!important;gap:8px!important}.notice{width:auto!important;max-width:100%!important}.rt-notice-line{gap:7px!important;line-height:1.55!important}}
</style>
    <!-- Fixed navbar -->
    <nav class="navbar navbar-default navbar-fixed-top">
      <div class="container">
        <div class="navbar-header">
          <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
            <span class="sr-only">Toggle navigation</span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
          </button>
          <a class="navbar-brand" href="#">
            <strong class="text-muted">
              <img src="/dist/info.svg" alt="" style="width:13px;height:13px;vertical-align:middle;">
              REALTIME CONVERSION <?= $date === 'rt_1' ? 'TODAY' : 'YESTERDAY' ?>
            </strong>
          </a>
        </div>

        <div id="navbar" class="navbar-collapse collapse">
          <ul class="nav navbar-nav navbar-right">
            <li class="dropdown active">
              <a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-haspopup="true" aria-expanded="false">
                <strong>
                  REALTIME CONVERSION
                  <img src="/dist/info.svg" alt="" style="width:13px;height:13px;vertical-align:middle;">
                </strong>
                <span class="caret"></span>
              </a>

              <ul class="dropdown-menu">
                <li class="dropdown-header">REALTIME CONVERSION</li>
                <li role="separator" class="divider"></li>

                <?php if ($date === 'rt_1'): ?>
                  <li class="active"><a href="#"><strong>TODAY</strong></a></li>
                  <li role="separator" class="divider"></li>
                  <li><a href="/realtime/?date=rt_2"><strong>YESTERDAY</strong></a></li>
                  <li role="separator" class="divider"></li>
                  <li>
                    <a href="/click/">
                      <strong>
                        PERFOMANCE CLICK
                        <img src="/dist/chart.svg" alt="" style="width:13px;height:13px;vertical-align:middle;">
                      </strong>
                    </a>
                  </li>
                <?php else: ?>
                  <li><a href="/realtime/?date=rt_1"><strong>TODAY</strong></a></li>
                  <li role="separator" class="divider"></li>
                  <li class="active"><a href="#"><strong>YESTERDAY</strong></a></li>
                  <li role="separator" class="divider"></li>
                  <li>
                    <a href="/click/">
                      <strong>
                        PERFOMANCE CLICK
                        <img src="/dist/chart.svg" alt="" style="width:13px;height:13px;vertical-align:middle;">
                      </strong>
                    </a>
                  </li>
                <?php endif; ?>
              </ul>
            </li>

            <li>
              <a>
                <strong>
                  <img src="/dist/menu.svg" alt="" style="width:13px;height:13px;vertical-align:middle;">
                </strong>
              </a>
            </li>

            <li>
              <a href="/performance/">
                <strong>PERFORMANCE NETWORK</strong>
                <img src="/dist/menu.svg" alt="" style="width:13px;height:13px;vertical-align:middle;">
              </a>
            </li>

            <li>
              <form method="post" action="/realtime/?date=<?= rtH(rawurlencode($date)) ?>" id="logout-form" style="margin:0;">
                <input type="hidden" name="csrf_token" value="<?= rtH(rtCsrfToken()) ?>">
                <input type="hidden" name="action" value="logout">
                <button type="submit" id="btn-logout" class="btn btn-link navbar-btn" style="padding:15px;color:inherit;text-decoration:none;">
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
        <div class="panel_m panel panel-default">
            <div id="notifications" style="height:auto;"></div>

            <div class="panel-heading">
                <h1 class="panel-title" style="font-size:18px;display:flex;justify-content:space-between;align-items:center;">
                    <div class="input-group search searchbox">
                        <span class="input-group-addon">
                          <img src="/dist/search.svg" alt="" style="width:13px;height:13px;vertical-align:middle;">
                        </span>
                        <input type="text" class="form-control input-sm" id="search" placeholder="Search...">
                        <span class="input-group-btn">
                            <button class="btn btn-default btn-sm pn-refresh-btn" id="refresh" type="button">
                              <img src="/dist/refresh.svg" alt="" style="width:13px;height:13px;vertical-align:middle;">
                              <strong>Refresh</strong>
                            </button>
                        </span>
                    </div>

                    <span data-toggle="tooltip" data-placement="right" data-original-title="more">
                        <span id="marquee" style="font-family:'Courier New',monospace;font-size:32px;display:flex;justify-content:space-between;color:rgb(128,128,128);opacity:.8;"></span>
                    </span>
                </h1>
            </div>

            <div class="panel-body">
                <table id="userlead" class="table table-condensed table-hover table-striped" cellspacing="0" data-toggle="bootgrid" style="table-layout:auto;">
                    <thead>
                        <tr>
                            <th data-column-id="id" data-type="numeric" data-identifier="true" data-resizable-column-id="id" data-noresize>#</th>
                            <th data-column-id="click_id">ID</th>
                            <th data-column-id="network">NETWORK</th>
                            <th data-column-id="country">COUNTRY</th>
                            <th data-column-id="traffic">TRAFFIC</th>
                            <th data-column-id="payout">EARNING</th>
                            <th data-column-id="ip_address">IPADDRESS</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                    <tfoot>
                        <tr>
                            <th colspan="7" id="sum"></th>
                        </tr>
                    </tfoot>
                </table>
            </div>
        </div>

        <hr style="margin:-7px;padding:-7px -7px;border:0;box-sizing:border-box;border-bottom:0">

        <div class="rg-source">
            <span class="pre-colon">SOURCE</span>: <span class="post-colon">NGIX!</span>
        </div>
    </div>
<?php
$conversionDate = date('Y-m-d', strtotime('today'));
$last = 0;

if (isset($link) && $link instanceof mysqli) {
    $stmt = mysqli_prepare($link, 'SELECT id FROM leadreport WHERE conversion_date = ? ORDER BY id DESC LIMIT 1');

    if ($stmt instanceof mysqli_stmt) {
        mysqli_stmt_bind_param($stmt, 's', $conversionDate);

        if (mysqli_stmt_execute($stmt)) {
            mysqli_stmt_bind_result($stmt, $dbLastId);

            if (mysqli_stmt_fetch($stmt)) {
                $last = (int) $dbLastId;
            }
        }

        mysqli_stmt_close($stmt);
    }
}

$lastIdFromJson = 0;

foreach ($result as $rowId) {
    if (is_array($rowId) && isset($rowId['id'])) {
        $lastIdFromJson = (int) $rowId['id'];
    }
}

if (isset($link) && $link instanceof mysqli) {
    mysqli_close($link);
}
?>
<script nonce="<?= rtH($rtNonce) ?>">
var lastId = <?= (int) $last ?>;
var last_id = <?= (int) $lastIdFromJson ?>;
var rtConversion = <?= (int) $conversion ?>;
</script>

<script src="https://www.gstatic.com/firebasejs/4.1.2/firebase-app.js" type="text/javascript" nonce="<?= rtH($rtNonce) ?>"></script>
<script src="https://www.gstatic.com/firebasejs/4.1.2/firebase-messaging.js" type="text/javascript" nonce="<?= rtH($rtNonce) ?>"></script>
<script src="../dist/push.js" nonce="<?= rtH($rtNonce) ?>"></script>

<script type="text/javascript" nonce="<?= rtH($rtNonce) ?>">
$(document).ready(function () {
    'use strict';

    function asText(value) {
        if (value === null || typeof value === 'undefined') {
            return '';
        }

        return String(value);
    }

    function escapeHtml(value) {
        return $('<div>').text(asText(value)).html();
    }

    function safeFlagCode(value) {
        return asText(value).toLowerCase().replace(/[^a-z]/g, '').substring(0, 3);
    }

    function safeAssetUrl(value) {
        var raw = asText(value);

        if (raw === '') {
            return '';
        }

        try {
            var parsed = new URL(raw, window.location.href);

            if (parsed.protocol !== 'https:' && parsed.origin !== window.location.origin) {
                return '';
            }

            return parsed.href;
        } catch (e) {
            return '';
        }
    }

    $('img').on('contextmenu', function () {
        return false;
    });

    window.Notify = function (text, callback, closeCallback, style) {
        var time = 25000;
        var $container = $('#notifications');
        var safeStyle = typeof style === 'undefined' ? 'warning' : asText(style).replace(/[^a-z0-9_-]/gi, '');
        var $html = $('<div>', {'class': 'notice notice-' + safeStyle});
        var $icon = $('<img>', {
            src: '/dist/info.svg',
            alt: '',
            css: {
                width: '14px',
                height: '14px',
                verticalAlign: 'middle'
            }
        });

        $('<a>', {
            text: '',
            class: 'button close',
            style: 'padding-left:10px;',
            href: '#',
            click: function (e) {
                e.preventDefault();

                if (typeof closeCallback === 'function') {
                    closeCallback();
                }

                removeNotice();
            }
        }).prependTo($html);

        $html.append($icon);
        $html.append(document.createTextNode(' ' + asText(text)));

        $container.prepend($html);
        $html.removeClass('hide').hide().fadeIn('slow');

        function removeNotice() {
            $html.stop().fadeOut('slow', function () {
                $html.remove();
            });
        }

        var timer = setInterval(removeNotice, time);

        $html.hover(function () {
            clearInterval(timer);
        }, function () {
            timer = setInterval(removeNotice, time);
        });

        $html.on('click', function () {
            clearInterval(timer);

            if (typeof callback === 'function') {
                callback();
            }

            removeNotice();
        });
    };

    function safeIconUrl(value) {
    var raw = asText(value);

    if (raw === '') {
        return '';
    }

    if (!/^\/dist\/[a-z0-9_.-]+\.svg$/i.test(raw)) {
        return '';
    }

    return raw;
}

function safeFlagClass(value) {
    var raw = asText(value);

    if (!/^flag flag-[a-z]{2}$/.test(raw) && raw !== 'flag flag--') {
        return 'flag flag--';
    }

    return raw;
}

function renderRealtimeNotice(userRow) {
    var $wrap = $('<span>', {'class': 'rt-notice-line'});
    var userAgentIcon = safeIconUrl(userRow.user_agent_icon);
    var networkIcon = safeIconUrl(userRow.network_icon);

    $('<span>', {'class': 'rt-click-id'})
        .text(asText(userRow.click_id))
        .appendTo($wrap);

    $wrap.append(document.createTextNode(' : '));

    $('<span>', {'class': safeFlagClass(userRow.country_flag_class)})
        .appendTo($wrap);

    $wrap.append(document.createTextNode(' '));

    $('<span>', {'class': 'rt-country-code'})
        .text(asText(userRow.country_code))
        .appendTo($wrap);

    $wrap.append(document.createTextNode(' : '));

    if (userAgentIcon !== '') {
        $('<img>', {
            src: userAgentIcon,
            alt: asText(userRow.user_agent),
            title: asText(userRow.user_agent),
            class: 'rt-inline-icon'
        }).appendTo($wrap);
    } else {
        $('<code>').text(asText(userRow.user_agent)).appendTo($wrap);
    }

    $wrap.append(document.createTextNode(' : '));

    if (networkIcon !== '') {
        $('<img>', {
            src: networkIcon,
            alt: asText(userRow.network),
            title: asText(userRow.network),
            class: 'rt-inline-icon rt-network-icon'
        }).appendTo($wrap);
    } else {
        $('<span>').text(asText(userRow.network)).appendTo($wrap);
    }

    return $wrap;
}

window.NotifyNode = function ($node, callback, closeCallback, style) {
    var time = 25000;
    var $container = $('#notifications');
    var safeStyle = typeof style === 'undefined' ? 'warning' : asText(style).replace(/[^a-z0-9_-]/gi, '');
    var $html = $('<div>', {'class': 'notice notice-' + safeStyle});
    var $icon = $('<img>', {
        src: '/dist/info.svg',
        alt: '',
        class: 'rt-inline-icon'
    });

    $('<a>', {
        text: '',
        class: 'button close',
        href: '#',
        click: function (e) {
            e.preventDefault();

            if (typeof closeCallback === 'function') {
                closeCallback();
            }

            removeNotice();
        }
    }).prependTo($html);

    $html.append($icon);
    $html.append(document.createTextNode(' '));
    $html.append($node);

    $container.prepend($html);
    $html.removeClass('hide').hide().fadeIn('slow');

    function removeNotice() {
        $html.stop().fadeOut('slow', function () {
            $html.remove();
        });
    }

    var timer = setInterval(removeNotice, time);

    $html.hover(function () {
        clearInterval(timer);
    }, function () {
        timer = setInterval(removeNotice, time);
    });

    $html.on('click', function () {
        clearInterval(timer);

        if (typeof callback === 'function') {
            callback();
        }

        removeNotice();
    });
};

setInterval(function () {
    var delay = 10000;

    $.ajax({
        url: 'json.parse.php?id=' + encodeURIComponent(String(last_id)),
        dataType: 'json',
        cache: false,
        success: function (json) {
            if (!Array.isArray(json) || json.length < 1) {
                return;
            }

            $.each(json, function (keyId, userRow) {
                if (!userRow || typeof userRow !== 'object') {
                    return;
                }

                if (
                    asText(userRow.country_code) === '-' ||
                    asText(userRow.country_code) === 'ID'
                ) {
                    last_id = parseInt(userRow.id, 10) || last_id;
                    return;
                }

                setTimeout(function () {
                    window.NotifyNode(renderRealtimeNotice(userRow));
                }, Number(keyId) * delay);

                last_id = parseInt(userRow.id, 10) || last_id;
            });
        }
    });
}, 10000);

    $.fn.dataTable.ext.errMode = 'throw';

    var table = $('#userlead').DataTable({
        ajax: 'data.php?date=' + encodeURIComponent(String(rtConversion)),
        columns: [
            {data: 'id'},
            {data: 'click_id'},
            {data: 'network'},
            {data: 'country'},
            {data: 'traffic'},
            {data: 'payout'},
            {data: 'ip_address'}
        ],
        oLanguage: {
            sSearch: '',
            sSearchPlaceholder: 'Search...'
        },
        sPaginationType: 'bootstrap',
        paging: false,
        responsive: true,
        ordering: false,
        order: [],
        info: false,
        bFilter: true,
        sDom: "<'top'>l<'searchbox' t>ip",
        footerCallback: function () {
            var api = this.api();

            var intVal = function (i) {
                if (typeof i === 'string') {
                    return i.replace(/[\$,]/g, '') * 1;
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

    $('.dataTables_empty').text('There are currently no leads available for this.');

    $('#search').on('keyup', function () {
        table.search($(this).val()).draw();
    });

    $('#refresh').on('click', function () {
        $('#userlead').fadeOut(100).fadeIn(100);
        table.ajax.reload(null, false);
        window.scrollTo(0, document.body.scrollHeight);
    });

    setInterval(function () {
        var delay = 5000;

        $.ajax({
            url: 'lead.php?id=' + encodeURIComponent(String(lastId)),
            dataType: 'json',
            cache: false,
            success: function (json) {
                if (!Array.isArray(json) || json.length < 1) {
                    return;
                }

                $.each(json, function (key, user) {
                    if (!user || typeof user !== 'object') {
                        return;
                    }

                    setTimeout(function () {
                        var audioUrl = safeAssetUrl(user.audio);
                        var iconUrl = safeAssetUrl(user.img);

                        table.ajax.reload(null, false);

                        if (audioUrl !== '') {
                            try {
                                var audio = new Audio(audioUrl);
                                var playResult = audio.play();

                                if (playResult && typeof playResult.catch === 'function') {
                                    playResult.catch(function () {});
                                }
                            } catch (e) {}
                        }

                        if (typeof Push !== 'undefined' && Push && Push.Permission && Push.create) {
                            Push.Permission.request(function () {
                                Push.create(asText(user.click_id), {
                                    body: '{' + asText(user.network) + '} ' +
                                        asText(user.country) + ' -' +
                                        asText(user.traffic) + ' -' +
                                        asText(user.payout),
                                    icon: iconUrl,
                                    timeout: 4000,
                                    onClick: function () {
                                        window.focus();
                                        this.close();
                                    }
                                });
                            });
                        }

                        window.scrollTo(0, document.body.scrollHeight);
                    }, Number(key) * delay);

                    lastId = parseInt(user.id, 10) || lastId;
                });
            }
        });
    }, 10000);

    window.scrollTo(0, document.body.scrollHeight);

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

    window.ip = function (ele) {
        var id = '';

        if (ele) {
            if (typeof ele.getAttribute === 'function') {
                id = ele.getAttribute('data-ip') || ele.id || '';
            } else if (ele.id) {
                id = ele.id;
            }
        }

        id = String(id);

        if (id === '') {
            return;
        }

        var ipAPI = 'checkIP.php?IP2Location=' + encodeURIComponent(id);

        if (typeof Swal === 'undefined' || !Swal || !Swal.queue) {
            return;
        }

        Swal.queue([{
            title: 'IP Address Lookup!',
            confirmButtonText: 'IP Checker',
            showCancelButton: true,
            allowOutsideClick: false,
            html: '<span class="rt-swal-text">Get IP Address location information:</span>',
            showLoaderOnConfirm: true,
            preConfirm: function () {
                return fetch(ipAPI, {
                    credentials: 'same-origin',
                    headers: {
                        Accept: 'application/json'
                    }
                })
                    .then(function (response) {
                        if (!response.ok) {
                            throw new Error('Invalid response.');
                        }

                        return response.json();
                    })
                    .then(function (data) {
                        var code = safeFlagCode(data.code);
                        var html = '<pre>' +
                            '<footer class="text-muted">IP Address Identify Geolocation:</footer>' +
                            'ip_address: ' + escapeHtml(data.ip_address) +
                            '\ncountry_code: <span class="flag flag-' + code + '"></span> ' + escapeHtml(data.code) +
                            '\ncountry_name: ' + escapeHtml(data.name) +
                            '\nregion: ' + escapeHtml(data.region) +
                            '\ncity: ' + escapeHtml(data.city) +
                            '</pre>';

                        Swal.insertQueueStep({
                            title: 'IP Address Result',
                            html: html,
                            confirmButtonText: 'Close'
                        });
                    })
                    .catch(function () {
                        Swal.insertQueueStep({
                            type: 'error',
                            title: 'Lookup Failed',
                            text: 'Unable to get IP address location information.',
                            confirmButtonText: 'Close'
                        });
                    });
            }
        }]);
    };

    $(document).on('click', '.js-ip', function (e) {
        e.preventDefault();

        if (typeof window.ip === 'function') {
            window.ip(this);
        }
    });
});
</script>

<div id="logout-toast">Logging out…</div>
</body>
</html>
