<?php

declare(strict_types=1);

error_reporting(0);

include_once __DIR__ . '/../password.login.php';
include_once __DIR__ . '/../xmlapi.php';
include_once __DIR__ . '/../connection.config.php';
include_once dirname(__DIR__, 2) . '/env.php';
load_env_file(dirname(__DIR__) . '/.env');

const ADMIN_CSRF_NAMESPACE = 'admin_panel';

function adminIsHttpsRequest(): bool
{
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        return true;
    }

    return (int) ($_SERVER['SERVER_PORT'] ?? 0) === 443;
}

function startAdminSession(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    session_name('sslmgr_admin');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => adminIsHttpsRequest(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}

function adminEsc(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function adminCsrfToken(): string
{
    if (!isset($_SESSION['csrf'][ADMIN_CSRF_NAMESPACE]) || !is_string($_SESSION['csrf'][ADMIN_CSRF_NAMESPACE])) {
        $_SESSION['csrf'][ADMIN_CSRF_NAMESPACE] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf'][ADMIN_CSRF_NAMESPACE];
}

function adminHasValidCsrf(?string $token): bool
{
    $storedToken = $_SESSION['csrf'][ADMIN_CSRF_NAMESPACE] ?? null;

    return is_string($token) && is_string($storedToken) && hash_equals($storedToken, $token);
}

function adminRequestCsrfToken(): ?string
{
    $headerToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
    if (is_string($headerToken) && $headerToken !== '') {
        return $headerToken;
    }

    $postedToken = $_POST['csrf_token'] ?? null;

    return is_string($postedToken) ? $postedToken : null;
}

function normalizeAddonDomain(string $value): string
{
    $domain = strtolower(trim($value));
    $domain = preg_replace('/^https?:\/\//i', '', $domain) ?? '';
    $domain = trim($domain, " \t\n\r\0\x0B./");

    if ($domain === '' || strlen($domain) > 253) {
        return '';
    }

    if (preg_match('/[\/\\\\:@?#\[\]]/', $domain) === 1) {
        return '';
    }

    if (preg_match('/^(localhost|localdomain)$/i', $domain) === 1) {
        return '';
    }

    if (filter_var($domain, FILTER_VALIDATE_IP) !== false) {
        return '';
    }

    if (preg_match('/^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $domain) !== 1) {
        return '';
    }

    return $domain;
}

function addondom(string $domain): array
{
    $cpanelUser        = app_required_env('CPANEL_USER');
    $cpanelHost        = app_env('CPANEL_HOST', 'localhost');
    $cpanelPort        = (int) app_env('CPANEL_PORT', '2083');
    $cpanelSubdomainDir = app_env('CPANEL_SUBDOMAIN_DIR', '/public_html');
    $token             = app_env('CPANEL_API_TOKEN', '');

    $xmlApi = new xmlapi($cpanelHost);
    $xmlApi->set_port($cpanelPort);
    $xmlApi->set_output('json');
    $xmlApi->set_debug(0);

    if ($token !== '') {
        $xmlApi->token_auth($cpanelUser, $token);
    } else {
        $xmlApi->password_auth($cpanelUser, app_required_env('CPANEL_PASSWORD'));
    }

    $parkResult = $xmlApi->api2_query($cpanelUser, 'Park', 'park', [
        'domain' => $domain,
    ]);

    // Always attempt wildcard — even if park was already done previously
    $wildcardResult = $xmlApi->api2_query($cpanelUser, 'SubDomain', 'addsubdomain', [
        'domain'     => '*',
        'rootdomain' => $domain,
        'dir'        => $cpanelSubdomainDir,
    ]);

    // If wildcard failed (e.g. subdomain already exists), try removing then re-adding
    $wildcardOk = is_array($wildcardResult)
        && isset($wildcardResult['cpanelresult']['data'][0]['result'])
        && (int) $wildcardResult['cpanelresult']['data'][0]['result'] === 1;

    if (!$wildcardOk) {
        $xmlApi->api2_query($cpanelUser, 'SubDomain', 'delsubdomain', [
            'domain' => '*.' . $domain,
        ]);
        $wildcardResult = $xmlApi->api2_query($cpanelUser, 'SubDomain', 'addsubdomain', [
            'domain'     => '*',
            'rootdomain' => $domain,
            'dir'        => $cpanelSubdomainDir,
        ]);
    }

    return [
        'park'     => $parkResult,
        'wildcard' => $wildcardResult,
    ];
}

function showLoginPasswordProtect(string $errorMsg, string $nonce, string $csrfToken): never
{
    header('Location: /login.php');
    exit;
}

startAdminSession();

$nonce = base64_encode(random_bytes(18));
$csrfToken = adminCsrfToken();

header('Content-Type: text/html; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('X-Frame-Options: SAMEORIGIN');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header(
    "Content-Security-Policy: default-src 'self'; "
    . "base-uri 'self'; "
    . "form-action 'self'; "
    . "frame-ancestors 'self'; "
    . "img-src 'self' data: https:; "
    . "font-src 'self' data: https:; "
    . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://use.fontawesome.com https://cdnjs.cloudflare.com; "
    . "script-src 'self' 'nonce-{$nonce}'; "
    . "connect-src 'self';"
);

if (isset($_GET['help'])) {
    $self = str_replace('\\', '\\\\', __FILE__);
    exit('Include following code into every page you would like to protect, at the very beginning (first line):<br>&lt;?php include("' . $self . '"); ?&gt;');
}

if (isset($_GET['logout'])) {
    unset($_SESSION['admin_authenticated']);
    session_regenerate_id(true);
    header('Location: /login.php');
    exit;
}


if (empty($_SESSION['admin_authenticated'])) {
    showLoginPasswordProtect('', $nonce, $csrfToken);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'cpanel_delete') {
    header('Content-Type: application/json; charset=utf-8');

    if (!adminHasValidCsrf(adminRequestCsrfToken())) {
        http_response_code(419);
        echo json_encode(['ok' => false, 'err' => 'invalid-csrf']);
        exit;
    }

    $domain = normalizeAddonDomain((string) ($_POST['domain'] ?? ''));
    if ($domain === '') {
        http_response_code(422);
        echo json_encode(['ok' => false, 'err' => 'invalid-domain']);
        exit;
    }

    try {
        $cpanelUser        = app_required_env('CPANEL_USER');
        $cpanelHost        = app_env('CPANEL_HOST', 'localhost');
        $cpanelPort        = (int) app_env('CPANEL_PORT', '2083');
        $token             = app_env('CPANEL_API_TOKEN', '');

        $xmlApi = new xmlapi($cpanelHost);
        $xmlApi->set_port($cpanelPort);
        $xmlApi->set_output('json');
        $xmlApi->set_debug(0);

        if ($token !== '') {
            $xmlApi->token_auth($cpanelUser, $token);
        } else {
            $xmlApi->password_auth($cpanelUser, app_required_env('CPANEL_PASSWORD'));
        }

        $delWildcard = $xmlApi->api2_query($cpanelUser, 'SubDomain', 'delsubdomain', [
            'domain' => '*.' . $domain,
        ]);
        $unpark = $xmlApi->api2_query($cpanelUser, 'Park', 'unpark', [
            'domain' => $domain,
        ]);

        echo json_encode(['ok' => true, 'domain' => $domain, 'del_wildcard' => $delWildcard, 'unpark' => $unpark]);
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['ok' => false, 'err' => 'cpanel-request-failed']);
    }
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['url'])) {
    header('Content-Type: application/json; charset=utf-8');

    if (!adminHasValidCsrf(adminRequestCsrfToken())) {
        http_response_code(419);
        echo json_encode(['ok' => false, 'err' => 'invalid-csrf']);
        exit;
    }

    $domain = normalizeAddonDomain((string) ($_POST['url'] ?? ''));
    if ($domain === '') {
        http_response_code(422);
        echo json_encode(['ok' => false, 'err' => 'invalid-domain']);
        exit;
    }

    try {
        echo json_encode([
            'ok' => true,
            'domain' => $domain,
            'addondom' => addondom($domain),
        ]);
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['ok' => false, 'err' => 'cpanel-request-failed']);
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>ADMIN PANEL</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="<?= adminEsc($csrfToken); ?>">
    <link href="/favicon.ico" rel="icon" type="image/x-icon">
    <link rel="stylesheet" href="../dist/bootstrap.min.css" type="text/css" media="all">
    <link href="../dist/flags.css" rel="stylesheet">
    <link href="//fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
    <style nonce="<?= adminEsc($nonce); ?>">:root{--font-mono-old:"Lucida Console","Courier New",Consolas,Monaco,monospace}body,input,textarea,button,select,pre,code,kbd,samp{font-family:var(--font-mono-old)}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}</style>

    <style nonce="<?= adminEsc($nonce); ?>">:root{color-scheme:light;--bg:#f7f7f7;--panel:#fff;--panel-soft:#f7f7f7;--panel-fade:rgba(255,255,255,.66);--line:rgba(41,43,44,.18);--line-soft:rgba(41,43,44,.1);--text:#292b2c;--text-strong:#111;--accent:#292b2c;--accent-hover:#3a3d3f;--on-accent:#f7f7f7;--danger:#9f3138;--danger-soft:rgba(159,49,56,.08);--success:#2563eb;--success-soft:rgba(37,99,235,.08);--blue-soft:rgba(37,99,235,.08);--blue-line:rgba(37,99,235,.28);--radius:.3rem;--shadow:0 1px 4px rgba(41,43,44,.08);--shadow-modal:0 8px 24px rgba(41,43,44,.16)}@media (prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#292b2c;--panel:#303334;--panel-soft:#35393a;--panel-fade:rgba(247,247,247,.045);--line:rgba(247,247,247,.18);--line-soft:rgba(247,247,247,.1);--text:#f7f7f7;--text-strong:#fff;--accent:#f7f7f7;--accent-hover:#e7e7e7;--on-accent:#292b2c;--danger:#ef9a9a;--danger-soft:rgba(239,154,154,.11);--success:#93c5fd;--success-soft:rgba(147,197,253,.1);--blue-soft:rgba(147,197,253,.1);--blue-line:rgba(147,197,253,.34);--shadow:0 1px 5px rgba(0,0,0,.28);--shadow-modal:0 10px 28px rgba(0,0,0,.42)}}*{box-sizing:border-box}html{min-height:100%;background:var(--bg)}body{min-height:100vh;margin:0;padding:58px 8px 18px!important;background:linear-gradient(180deg,var(--panel-soft) 0%,var(--bg) 100%)!important;color:var(--text)!important;font-family:monospace!important;font-size:13px;line-height:1.45;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility}a{color:inherit;text-decoration:none}.container{width:100%;max-width:1180px;margin:0 auto}code{font-family:Consolas,Monaco,'Courier New',monospace;font-size:11.5px;color:var(--text);background:var(--panel-soft);border:1px solid var(--line-soft);border-radius:var(--radius);padding:1px 4px}.navbar.navbar-default{min-height:44px;border:0!important;border-bottom:0!important;background:color-mix(in srgb,var(--panel) 94%,transparent)!important;box-shadow:var(--shadow)!important}.navbar .container{max-width:1180px}.navbar-brand{height:44px!important;padding:12px 10px!important;color:var(--text-strong)!important;font-size:13px;line-height:20px}.navbar-nav>li>a{padding-top:12px!important;padding-bottom:12px!important;color:var(--text)!important;font-size:12px}.navbar-nav>li>a:hover,.navbar-default .navbar-nav>.active>a,.navbar-default .navbar-nav>.active>a:focus,.navbar-default .navbar-nav>.active>a:hover{background:var(--accent)!important;color:var(--on-accent)!important}.navbar-toggle{margin-top:5px!important;margin-bottom:5px!important;border-color:var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important}.navbar-toggle .icon-bar{background:var(--text)!important}.panel,.panel-default,.well,.modal-content{border:0!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;box-shadow:var(--shadow)!important;overflow:hidden}.panel-heading,.panel-footer,.modal-header,.modal-footer{padding:8px 10px!important;background:linear-gradient(180deg,var(--panel) 0%,var(--panel-soft) 100%)!important;border:0!important;color:var(--text-strong)!important}.panel-body,.modal-body{padding:10px!important;background:transparent!important;color:var(--text)!important}.pull-right{display:flex;align-items:center;gap:6px}.modal-content{box-shadow:var(--shadow-modal)!important}.modal-title{font-size:14px;font-weight:700;color:var(--text-strong)}.close{color:var(--text)!important;opacity:.78;text-shadow:none}.form-group{margin-bottom:8px}.control-label,label{margin-bottom:4px;color:var(--text-strong);font-size:12px}.form-control,input[type=text],input[type=number],input[type=password],input[type=search],select,textarea{height:31px;min-height:31px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-family:monospace!important;font-size:13px!important;line-height:1.4!important;box-shadow:none!important; }.form-control:focus,input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent)!important;box-shadow:0 0 0 2px color-mix(in srgb,var(--accent) 18%,transparent)!important}.form-control::placeholder,textarea::placeholder{color:color-mix(in srgb,var(--text) 54%,transparent)}.form-control[readonly],input[readonly],textarea[readonly]{background:var(--panel-soft)!important;color:var(--text)!important}textarea.form-control{height:auto;min-height:114px;resize:none}.input-group-addon{height:31px;padding:5px 8px;background:var(--panel-soft)!important;border-color:var(--line)!important;color:var(--text)!important;border-radius:var(--radius)!important;font-size:11.5px}.btn,button,.btn-sm,.btn-xs{display:inline-flex;align-items:center;justify-content:center;gap:5px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-size:11.5px;font-weight:700;line-height:1.2;box-shadow:none!important;outline:none;transition:background .12s ease,border-color .12s ease,color .12s ease}.btn:hover,button:hover,.btn-sm:hover,.btn-xs:hover{background:var(--panel-soft)!important;border-color:var(--line)!important;color:var(--text-strong)!important}.btn-primary,.btn-primary:focus,.btn-primary:active,.btn.active{background:var(--accent)!important;border-color:var(--accent)!important;color:var(--on-accent)!important}.btn-primary:hover{background:var(--accent-hover)!important;border-color:var(--accent-hover)!important;color:var(--on-accent)!important}.btn-danger,.btn-danger:focus{background:var(--danger-soft)!important;border-color:rgba(159,49,56,.34)!important;color:var(--danger)!important}.btn-danger:hover{background:rgba(159,49,56,.16)!important;color:var(--danger)!important}.glyphicon{top:1px;color:currentColor}.action-ico{display:inline-flex;align-items:center;justify-content:center;flex-shrink:0}.action-ico svg{display:block}.table-responsive{border:0!important}.table{width:100%;margin:4px 0 0;border-collapse:separate;border-spacing:0;border:0;border-radius:var(--radius);overflow:hidden;background:var(--panel)!important}.table>thead>tr>th{position:sticky;top:0;z-index:20;padding:7px 8px!important;border-bottom:1px solid var(--line)!important;background:var(--panel-soft)!important;color:var(--text-strong)!important;font-size:10.5px!important;line-height:1.2;text-transform:uppercase;letter-spacing:.035em;white-space:nowrap}.table>tbody>tr>td{padding:6px 8px!important;border-top:1px solid var(--line-soft)!important;color:var(--text);font-size:11.5px;vertical-align:middle;word-break:break-word;background:var(--panel)!important}.table-hover>tbody>tr:hover>td{background:var(--panel-soft)!important}.bootgrid-table th>.column-header-anchor{color:var(--text-strong)!important}.bootgrid-header,.bootgrid-footer{margin:6px 0!important;color:var(--text)!important}.bootgrid-header .search .form-control{height:31px}.bootgrid-header .actionBar{text-align:right}.pagination>li>a,.pagination>li>span{border-color:var(--line)!important;background:var(--panel)!important;color:var(--text)!important}.pagination>.active>a,.pagination>.active>span{background:var(--accent)!important;border-color:var(--accent)!important;color:var(--on-accent)!important}.dropdown-menu{border:0!important;border-radius:var(--radius)!important;background:var(--panel)!important;box-shadow:var(--shadow-modal)!important}.dropdown-menu>li>a{color:var(--text)!important;font-size:12px}.dropdown-menu>li>a:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}.alert{border-radius:var(--radius)!important}.alert-danger,.error{background:var(--danger-soft)!important;border-color:rgba(159,49,56,.28)!important;color:var(--danger)!important}.alert-success,.success{background:var(--blue-soft)!important;border-color:var(--blue-line)!important;color:var(--text)!important}.label{border-radius:var(--radius)!important}.label-default{background:var(--panel-soft)!important;color:var(--text)!important;border:1px solid var(--line)}blockquote{margin:0 0 10px;padding:7px 10px;border-left:2px solid var(--line)!important;background:var(--panel-fade);border-radius:var(--radius);font-size:12px}.text-warning{margin:0 0 2px;color:var(--text-strong)!important;font-weight:700}.text-muted{color:var(--text)!important}.flag{border-radius:var(--radius)}.admin-toast-root{position:fixed;right:12px;bottom:12px;z-index:10050;display:flex;flex-direction:column;gap:6px;align-items:flex-end}.admin-toast{max-width:340px;padding:8px 10px;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:12px;line-height:1.35}.admin-toast strong{display:block;margin-bottom:2px;color:var(--text-strong)}.admin-toast--error{border-color:rgba(159,49,56,.34);background:var(--danger-soft);color:var(--danger)}.admin-toast--success{border-color:var(--blue-line);background:var(--blue-soft);color:var(--text)}.admin-fallback-backdrop{position:fixed;inset:0;z-index:10040;display:flex;align-items:center;justify-content:center;padding:12px;background:rgba(0,0,0,.36)}.admin-fallback-dialog{width:min(420px,100%);border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);overflow:hidden}.admin-fallback-head{padding:10px;border-bottom:1px solid var(--line-soft);font-weight:800;color:var(--text-strong)}.admin-fallback-body{padding:10px;font-size:12px}.admin-fallback-actions{display:flex;gap:6px;justify-content:flex-end;padding:10px;border-top:1px solid var(--line-soft);background:var(--panel-soft)}@media screen and (max-width:768px){body{padding:58px 6px 12px!important;font-size:12.5px}.container{width:100%!important;max-width:100%!important;padding-left:6px!important;padding-right:6px!important}.panel-heading,.panel-body,.panel-footer{padding:7px!important}.navbar .container{padding-left:8px!important;padding-right:8px!important}.navbar-collapse{border-color:var(--line)!important;background:var(--panel)!important}.pull-right{float:none!important;justify-content:flex-end}.input-group{display:block}.input-group>.form-control,.input-group>.input-group-addon,.input-group>.input-group-btn,.input-group-btn>.btn{display:block;width:100%!important}.input-group-addon{border-bottom:0!important;border-radius:var(--radius) var(--radius) 0 0!important}.input-group>.form-control{border-radius:0 0 var(--radius) var(--radius)!important}.input-group-btn>.btn{margin-top:5px}.table{display:block;overflow-x:auto;white-space:nowrap}.modal-dialog{width:auto!important;margin:8px}}#tbl_domains{table-layout:fixed;width:100%;min-width:820px}#tbl_domains th:nth-child(1),#tbl_domains td:nth-child(1){width:50px;text-align:center;padding-left:4px!important;padding-right:4px!important}#tbl_domains th:nth-child(2),#tbl_domains td:nth-child(2){width:130px}#tbl_domains th:nth-child(4),#tbl_domains td:nth-child(4){width:140px}.td-num{display:block;font-size:11.5px;font-weight:600;font-family:Consolas,Monaco,monospace;color:color-mix(in srgb,var(--text) 44%,transparent);text-align:center}.td-subdomain{display:inline-block;padding:2px 8px;border-radius:.3rem!important;width:100%;border:1px solid var(--line);background:var(--panel-soft);font-family:Consolas,Monaco,monospace;font-size:11.5px;font-weight:700;letter-spacing:.03em;white-space:nowrap}.td-domain{display:block;max-width:100%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:Consolas,Monaco,monospace;font-size:11.5px;font-weight:600}.mono-input{font-family:Consolas,Monaco,'Courier New',monospace!important;font-size:12px!important}.ns-card footer{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.ns-card code{background:transparent;border:0;padding:0;color:var(--text-strong)}.cf-badge{display:inline-flex;align-items:center;gap:4px;padding:2px 7px;border-radius:20px;font-size:10.5px;font-weight:600;letter-spacing:.02em;border:1px solid var(--line);background:var(--panel-soft);color:var(--text)}.cf-badge::before{content:'';display:inline-block;width:7px;height:7px;border-radius:50%;background:currentColor;opacity:.5}.cf-badge--active{border-radius:.3rem!important;width:100%;border-color:rgba(22,163,74,.3);color:#16a34a}.cf-badge--active::before{opacity:1}.cf-badge--pending{border-radius:.3rem!important;width:100%;border-color:rgba(217,119,6,.3);color:#d97706}.cf-badge--pending::before{opacity:1}.cf-badge--moved{border-radius:.3rem!important;width:100%;border-color:rgba(37,99,235,.3);color:#2563eb}.cf-badge--moved::before{opacity:1}.cf-badge--none{border-radius:.3rem!important;width:100%;opacity:.62}.btn-cf{display:inline-flex!important;align-items:center!important;justify-content:center!important;width:28px!important;height:26px!important;padding:0!important;margin:0 1px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-size:0!important;line-height:1!important;vertical-align:middle!important;cursor:pointer!important}.btn-cf:hover{background:rgba(37,99,235,.1)!important;border-color:rgba(37,99,235,.3)!important;color:#2563eb!important}.btn-cf svg{display:block!important;width:14px!important;height:14px!important;pointer-events:none!important}@media (prefers-color-scheme:dark){.cf-badge--active{color:#4ade80}.cf-badge--pending{color:#fbbf24}.cf-badge--moved{color:#93c5fd}}@keyframes cf-spin{to{transform:rotate(360deg)}}.btn-cf--loading{opacity:.7!important;cursor:default!important}.btn-cf--loading svg{animation:cf-spin .7s linear infinite}.btn-syncall--loading svg{animation:cf-spin .7s linear infinite}
/* bootgrid toolbar search/select fix */.navbar-default .navbar-nav>li>a:hover,.navbar-default .navbar-nav>li>a:focus{background:color-mix(in srgb,var(--accent) 5%,transparent)!important;color:var(--text-strong)!important;box-shadow:inset 0 -1px 0 var(--line-soft)!important}.navbar-default .navbar-nav>.active>a,.navbar-default .navbar-nav>.active>a:hover,.navbar-default .navbar-nav>.active>a:focus{background:transparent!important;color:var(--text-strong)!important;box-shadow:inset 0 -2px 0 var(--accent)!important}.panel,.panel-default{overflow:visible!important}.panel-body{overflow:visible!important}.table-responsive{overflow-x:auto!important;overflow-y:visible!important}.bootgrid-header{position:relative!important;z-index:80!important;display:block!important;margin:8px 0 7px!important;color:var(--text)!important}.bootgrid-header .actionBar{display:flex!important;align-items:center!important;justify-content:flex-end!important;gap:8px!important;float:none!important;width:100%!important;margin:0!important;text-align:right!important;white-space:nowrap!important}.bootgrid-header .search{position:relative!important;display:inline-flex!important;align-items:center!important;float:none!important;width:220px!important;min-width:220px!important;max-width:260px!important;margin:0!important;vertical-align:middle!important}.bootgrid-header .search .input-group{display:flex!important;align-items:stretch!important;width:100%!important;border-collapse:separate!important}.bootgrid-header .search .input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;min-width:34px!important;height:32px!important;padding:0!important;border:1px solid var(--line)!important;border-right:0!important;border-radius:var(--radius) 0 0 var(--radius)!important;background:var(--panel-soft)!important;color:var(--text)!important;line-height:1!important}.bootgrid-header .search .input-group-addon .glyphicon{top:0!important;font-size:12px!important}.bootgrid-header .search .search-field,.bootgrid-header .search .form-control{display:block!important;flex:1 1 auto!important;width:100%!important;height:32px!important;min-height:32px!important;padding:5px 9px!important;border:1px solid var(--line)!important;border-left:0!important;border-radius:0 var(--radius) var(--radius) 0!important;background:var(--panel)!important;color:var(--text)!important;font-size:12px!important;line-height:1.4!important;box-shadow:none!important}.bootgrid-header .search .search-field:focus,.bootgrid-header .search .form-control:focus{border-color:var(--accent)!important;border-left:0!important;box-shadow:0 0 0 2px color-mix(in srgb,var(--accent) 13%,transparent)!important}.bootgrid-header .actions{position:relative!important;display:inline-flex!important;align-items:center!important;gap:6px!important;float:none!important;margin:0!important;vertical-align:middle!important}.bootgrid-header .actions>.btn-group{position:relative!important;display:inline-flex!important;float:none!important;margin:0!important;vertical-align:middle!important}.bootgrid-header .actions .btn,.bootgrid-header .actions .dropdown-toggle{display:inline-flex!important;align-items:center!important;justify-content:center!important;gap:6px!important;height:32px!important;min-width:38px!important;padding:5px 10px!important;line-height:1.2!important;border-radius:var(--radius)!important}.bootgrid-header .actions .dropdown-toggle{min-width:64px!important}.bootgrid-header .actions .dropdown-toggle .caret{margin-left:2px!important}.bootgrid-header .actions .dropdown-menu{position:absolute!important;top:calc(100% + 4px)!important;right:0!important;left:auto!important;z-index:3000!important;display:none;min-width:112px!important;width:112px!important;margin:0!important;padding:4px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;box-shadow:var(--shadow-modal)!important;list-style:none!important}.bootgrid-header .actions .open>.dropdown-menu{display:block!important}.bootgrid-header .actions .dropdown-menu>li{display:block!important;float:none!important;width:100%!important;margin:0!important;padding:0!important;text-align:left!important}.bootgrid-header .actions .dropdown-menu>li>a{display:block!important;width:100%!important;min-width:0!important;padding:6px 9px!important;border-radius:var(--radius)!important;background:transparent!important;color:var(--text)!important;font-size:12px!important;line-height:1.25!important;text-align:left!important;white-space:nowrap!important}.bootgrid-header .actions .dropdown-menu>li>a:hover,.bootgrid-header .actions .dropdown-menu>li>a:focus{background:var(--panel-soft)!important;color:var(--text-strong)!important}.bootgrid-header .actions .dropdown-menu>.active>a,.bootgrid-header .actions .dropdown-menu>.active>a:hover,.bootgrid-header .actions .dropdown-menu>.active>a:focus{background:var(--accent-soft)!important;color:var(--text-strong)!important;box-shadow:inset 2px 0 0 var(--accent)!important}.bootgrid-footer{position:relative!important;z-index:20!important}.bootgrid-footer .pagination{margin:0!important}@media screen and (max-width:768px){.bootgrid-header .actionBar{align-items:stretch!important;justify-content:stretch!important;flex-wrap:wrap!important;gap:6px!important}.bootgrid-header .search{width:100%!important;min-width:0!important;max-width:none!important;flex:1 0 100%!important}.bootgrid-header .actions{margin-left:auto!important}.bootgrid-header .actions .dropdown-menu{right:0!important;left:auto!important}}
input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}</style>
<style nonce="<?= adminEsc($nonce); ?>">/* final action icon render fix */#tbl_domains th:last-child,#tbl_domains td:last-child{text-align:right!important;white-space:nowrap!important;width:184px!important;min-width:184px!important}.bootgrid-table td:last-child{overflow:visible!important}.action-btn,.bootgrid-table .command-edit,.bootgrid-table .command-delete{display:inline-flex!important;align-items:center!important;justify-content:center!important;width:32px!important;height:26px!important;min-width:32px!important;min-height:26px!important;padding:0!important;margin:0 2px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-size:0!important;line-height:1!important;text-indent:0!important;vertical-align:middle!important;opacity:1!important;visibility:visible!important;box-shadow:none!important;overflow:visible!important}.action-btn:hover,.bootgrid-table .command-edit:hover{background:var(--accent-soft)!important;border-color:var(--line)!important;color:var(--text-strong)!important}.bootgrid-table .command-delete{color:var(--danger)!important}.bootgrid-table .command-delete:hover{background:var(--danger-soft)!important;border-color:color-mix(in srgb,var(--danger) 34%,var(--line))!important;color:var(--danger)!important}.bootgrid-table .command-edit[disabled],.bootgrid-table .command-delete[disabled]{opacity:.58!important;cursor:not-allowed!important}.action-btn .action-ico,.bootgrid-table .command-edit .action-ico,.bootgrid-table .command-delete .action-ico{display:inline-flex!important;align-items:center!important;justify-content:center!important;width:16px!important;height:16px!important;min-width:16px!important;min-height:16px!important;color:currentColor!important;opacity:1!important;visibility:visible!important;overflow:visible!important;pointer-events:none!important}.action-btn svg,.bootgrid-table .command-edit svg,.bootgrid-table .command-delete svg{display:block!important;width:16px!important;height:16px!important;min-width:16px!important;min-height:16px!important;overflow:visible!important;color:currentColor!important;opacity:1!important;visibility:visible!important;pointer-events:none!important}.action-btn svg *,.bootgrid-table .command-edit svg *,.bootgrid-table .command-delete svg *{vector-effect:non-scaling-stroke!important;stroke:currentColor!important;stroke-width:2!important;stroke-linecap:round!important;stroke-linejoin:round!important;fill:none!important;opacity:1!important;visibility:visible!important}.btn-icon svg,.btn-primary svg{display:block!important;width:13px!important;height:13px!important;fill:currentColor!important;color:currentColor!important;opacity:1!important;visibility:visible!important}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}</style>
<style nonce="<?= adminEsc($nonce); ?>">
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
.form-control:focus,input:focus,select:focus,textarea:focus{outline:none;color:var(--text-strong)!important}
.panel,.panel-default{box-shadow:0 1px 2px rgba(41,43,44,.04),0 4px 16px rgba(41,43,44,.06)!important}
.modal-content{box-shadow:0 8px 32px rgba(41,43,44,.12),0 2px 8px rgba(41,43,44,.05)!important}
input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}
.form-control:focus,input:focus,select:focus,textarea:focus{box-shadow:none!important}.bootgrid-header .search .search-field:focus,.bootgrid-header .search .form-control:focus{box-shadow:none!important}*:focus,*:focus-visible{outline:none!important;box-shadow:none!important}</style>
</head>
<body>
<script nonce="<?= adminEsc($nonce); ?>" src="../dist/jquery-1.11.1.min.js"></script>
<script nonce="<?= adminEsc($nonce); ?>" src="../dist/bootstrap.min.js"></script>
<script nonce="<?= adminEsc($nonce); ?>">
(function ($) {
    'use strict';

    $.ajaxSetup({
        headers: {
            'X-CSRF-Token': <?= json_encode($csrfToken, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>
        }
    });
}(jQuery));
</script>
<script nonce="<?= adminEsc($nonce); ?>">
(function (window, document) {
    'use strict';

    function ensureToastRoot() {
        var root = document.querySelector('.admin-toast-root');
        if (root) {
            return root;
        }
        root = document.createElement('div');
        root.className = 'admin-toast-root';
        root.setAttribute('aria-live', 'polite');
        document.body.appendChild(root);
        return root;
    }

    function showToast(type, title, text) {
        var root = ensureToastRoot();
        var item = document.createElement('div');
        var normalizedType = type === 'error' ? 'error' : (type === 'success' ? 'success' : 'info');
        item.className = 'admin-toast admin-toast--' + normalizedType;
        if (title) {
            var strong = document.createElement('strong');
            strong.textContent = title;
            item.appendChild(strong);
        }
        if (text) {
            var span = document.createElement('span');
            span.textContent = text;
            item.appendChild(span);
        }
        root.appendChild(item);
        window.setTimeout(function () {
            if (item.parentNode) {
                item.parentNode.removeChild(item);
            }
        }, 2400);
    }

    function confirmDialog(options) {
        return new Promise(function (resolve) {
            var backdrop = document.createElement('div');
            backdrop.className = 'admin-fallback-backdrop';

            var dialog = document.createElement('div');
            dialog.className = 'admin-fallback-dialog';

            var head = document.createElement('div');
            head.className = 'admin-fallback-head';
            head.textContent = options.title || 'Confirm action';

            var body = document.createElement('div');
            body.className = 'admin-fallback-body';
            body.textContent = options.text || 'Continue?';

            var actions = document.createElement('div');
            actions.className = 'admin-fallback-actions';

            var cancel = document.createElement('button');
            cancel.type = 'button';
            cancel.className = 'btn btn-default btn-sm';
            cancel.textContent = options.cancelButtonText || 'Cancel';

            var ok = document.createElement('button');
            ok.type = 'button';
            ok.className = 'btn btn-primary btn-sm';
            ok.textContent = options.confirmButtonText || 'OK';

            function close(value) {
                if (backdrop.parentNode) {
                    backdrop.parentNode.removeChild(backdrop);
                }
                resolve({ value: value, isConfirmed: value });
            }

            cancel.addEventListener('click', function () {
                close(false);
            });
            ok.addEventListener('click', function () {
                close(true);
            });

            actions.appendChild(cancel);
            actions.appendChild(ok);
            dialog.appendChild(head);
            dialog.appendChild(body);
            dialog.appendChild(actions);
            backdrop.appendChild(dialog);
            document.body.appendChild(backdrop);
            ok.focus();
        });
    }

    window.showToast = showToast;

    if (!window.Swal || typeof window.Swal.fire !== 'function') {
        window.Swal = {
            fire: function (argOne, argTwo, argThree) {
                var options = typeof argOne === 'object' ? argOne : {
                    title: String(argOne || ''),
                    text: String(argTwo || ''),
                    type: String(argThree || 'info')
                };

                if (options.showCancelButton) {
                    return confirmDialog(options);
                }

                showToast(options.type || options.icon || 'info', options.title || '', options.text || '');
                return {
                    then: function (callback) {
                        if (typeof callback === 'function') {
                            window.setTimeout(function () {
                                callback({ value: true, isConfirmed: true });
                            }, 0);
                        }
                        return this;
                    }
                };
            }
        };
    }
}(window, document));
</script>

<div role="navigation" class="navbar navbar-default navbar-fixed-top">
        <div class="container">
            <div class="navbar-header">
                <button data-target=".navbar-collapse" data-toggle="collapse" class="navbar-toggle" type="button">
                    <span class="sr-only">Toggle navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a href="#" class="navbar-brand"><strong>Admin Panel</strong></a>
            </div>
            <div class="navbar-collapse collapse navbar-right">
                <ul class="nav navbar-nav">
                    <li><a href="/dashboard/"><strong>Dashboard</strong></a></li>
                    <li><a href="/campaigns/"><strong>Campaigns</strong></a></li>
                    <li class="active"><a href="#"><strong>Addon Domain</strong></a></li>
                    <li><a href="?logout" id="btn-logout" class="btn-danger"><strong>Logout</strong></a></li>
                </ul>
            </div>
            <!--/.nav-collapse -->
        </div>
    </div>

        <div class="container">
            <div class="panel panel-default">
                <div class="tbl-toolbar">
                    <div class="tbl-toolbar-left">
                        <div class="input-group" style="width:200px;">
                            <span class="input-group-addon"><svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span>
                            <input type="text" class="form-control" id="tbl-search" placeholder="Search...">
                        </div>
                        <select id="tbl-rowcount" class="form-control" style="width:70px;height:31px;display:inline-block;">
                            <option value="25">25</option>
                            <option value="50">50</option>
                            <option value="-1">All</option>
                        </select>
                    </div>
                    <div style="display:inline-flex;gap:6px;align-items:center;">
                    <button type="button" class="btn btn-xs btn-default btn-icon" id="command-cf-config" title="Cloudflare Configuration">
                        <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07M8.46 8.46a5 5 0 0 0 0 7.07"/></svg> CF Config</button>
                    <button type="button" class="btn btn-xs btn-default btn-icon" id="command-sync-all" title="Sync all domains to Cloudflare">
                        <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M21.5 2v6h-6"/><path d="M2.5 12A10 10 0 0 1 20 6.3"/><path d="M2.5 22v-6h6"/><path d="M21.5 12A10 10 0 0 1 4 17.7"/></svg> Sync All CF</button>
                    <button type="button" class="btn btn-xs btn-primary btn-icon" id="command-add" data-row-id="0">
                        <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 5v14"/><path d="M5 12h14"/></svg> Addon Domain</button>
                    </div>
                </div>
                <div style="overflow-x:auto;">
                    <table id="tbl_domains" class="table table-hover">
                        <thead>
                            <tr>
                                <th>Empid</th>
                                <th>Domain Title</th>
                                <th>Domain Name</th>
                                <th>CF Status</th>
                                <th style="text-align:right;">Action</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
                <div class="tbl-footer">
                    <span id="tbl-info"></span>
                    <ul class="pagination" id="tbl-pagination" style="margin:0;"></ul>
                </div>
            </div>
        </div>
        <div id="add_model" class="modal fade" data-keyboard="false" data-backdrop="static">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                        <h4 class="modal-title">Addon Domain</h4>
                    </div>
                    
                    <div class="modal-body">
                        <blockquote class="ns-card">
                            <p class="text-warning">Nameserver:</p>
                            <div class="text-muted" id="ns-info-list">
                                <span style="opacity:.6;">Memuat…</span>
                            </div>
                        </blockquote>  
                        <form method="post" id="frm_add">
                            <input type="hidden" value="add" name="action" id="action">
                            <div class="form-group">
                                <label for="salary" class="control-label">Domain Title: use [GLOBAL DOMAIN] for submit into global domain</label>
                                <hr style="margin:1px;padding:1px;border:0;border-bottom:0px">
                                    <select id="adddomain" class="form-control input-sm" type="button">
                                    <optgroup label="ADDON DOMAIN">
                                    <option value="0" disabled="" class="bold-option">---ADDON DOMAIN---</option>
                                    <option value="global" selected="selected" class="bold-option">[GLOBAL DOMAIN]</option>
                                    <?php $result = mysqli_query($link, "SELECT * FROM generate");
                                    while($row = mysqli_fetch_array($result)) {
                                        echo '<option value="'.$row['sub_id'].'">'.$row['sub_id'].'</option>';
                                        }?>
                                </optgroup></select>
                                <input readonly="readonly" type="hidden" class="form-control" id="sub_domain" name="sub_domain" required="true" />
                            </div>
                            <div class="form-group">
                                <label for="salary" class="control-label">Domain Name:</label>
                                <input type="text" placeholder="{example.com}" class="form-control" id="domain" name="domain" required="true" autofocus/>
                            </div>
                            <div class="form-group">
                                <label for="auto_cloudflare" class="control-label">Cloudflare Provisioning:</label>
                                <select id="auto_cloudflare" name="auto_cloudflare" class="form-control">
                                    <option value="1" selected="selected">Auto cPanel + Cloudflare</option>
                                    <option value="0">cPanel only</option>
                                </select>
                            </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
                        <button type="button" id="btn_add" class="btn btn-primary">Save</button>
                    </div>
                    </form>
                </div>
            </div>
        </div>
        <div id="edit_model" class="modal fade" data-keyboard="false" data-backdrop="static">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                        <h4 class="modal-title">Edit Domain</h4>
                    </div>
                    <div class="modal-body">
                        <form method="post" id="frm_edit">
                            <input type="hidden" value="edit" name="action" id="action">
                            <input type="hidden" value="0" name="edit_id" id="edit_id">

                            <div class="form-group">
                                <label for="salary" class="control-label">Domain Title:</label>
                                <input readonly="readonly" type="text" class="form-control" id="edit_sub_domain" name="edit_sub_domain" />
                            </div>
                            <div class="form-group">
                                <label for="salary" class="control-label">Domain Name:</label>
                                <input type="text" class="form-control" id="edit_domain" name="edit_domain" required="true" autofocus/>
                            </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
                        <button type="button" id="btn_edit" class="btn btn-primary">Save</button>
                    </div>
                    </form>
                </div>
            </div>
        </div>
        <div id="cf_config_modal" class="modal fade" data-keyboard="true" data-backdrop="static">
            <div class="modal-dialog" style="max-width:440px;">
                <div class="modal-content">
                    <div class="modal-header">
                        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                        <h4 class="modal-title">
                            <svg viewBox="0 0 24 24" width="15" height="15" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;vertical-align:-2px;" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07M8.46 8.46a5 5 0 0 0 0 7.07"/></svg>
                            Cloudflare Configuration
                        </h4>
                    </div>
                    <div class="modal-body">
                        <p style="margin:0 0 12px;font-size:11.5px;color:var(--text);opacity:.8;">Perubahan langsung disimpan ke <code>.env</code>. Refresh halaman setelah simpan agar efektif.</p>
                        <div class="form-group">
                            <label class="control-label">CF API Token</label>
                            <div style="display:flex;gap:6px;align-items:center;">
                                <input type="password" class="form-control" id="cfg_cf_token" placeholder="Kosongkan = tidak diubah" autocomplete="new-password">
                                <button type="button" class="btn btn-xs btn-default" id="cfg_cf_token_toggle" title="Tampilkan/sembunyikan" style="flex-shrink:0;width:32px;height:31px;padding:0;">
                                    <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                                </button>
                            </div>
                            <small style="font-size:11px;color:var(--text);opacity:.68;">Buat token di <strong>CF Dashboard → My Profile → API Tokens → Create Token</strong>.</small>
                        </div>
                        <div style="margin:-4px 0 12px;padding:9px 10px;border:1px solid var(--line-soft);border-radius:var(--radius);background:var(--panel-soft);font-size:11px;line-height:1.6;">
                            <div style="font-weight:700;margin-bottom:5px;color:var(--text-strong);">Permission yang dibutuhkan (Custom Token):</div>
                            <table style="width:100%;border-collapse:collapse;">
                                <tr><td style="padding:1px 6px 1px 0;color:var(--text);opacity:.75;white-space:nowrap;">Account → Account Settings</td><td style="padding:1px 0;font-weight:600;">Read</td><td style="padding:1px 0 1px 8px;color:var(--text);opacity:.6;font-size:10.5px;">— baca info akun</td></tr>
                                <tr style="background:color-mix(in srgb,var(--danger,#e53) 8%,transparent);outline:1px solid color-mix(in srgb,var(--danger,#e53) 30%,transparent);outline-offset:-1px;"><td style="padding:3px 6px 3px 0;white-space:nowrap;"><strong style="color:var(--danger,#e53);">Zone → Zone</strong></td><td style="padding:3px 0;font-weight:700;color:var(--danger,#e53);">Edit</td><td style="padding:3px 0 3px 8px;color:var(--danger,#e53);font-size:10.5px;"><strong>← WAJIB · banyak yang lupa ini</strong></td></tr>
                                <tr><td style="padding:1px 6px 1px 0;color:var(--text);opacity:.75;white-space:nowrap;">Zone → Zone Settings</td><td style="padding:1px 0;font-weight:600;">Edit</td><td style="padding:1px 0 1px 8px;color:var(--text);opacity:.6;font-size:10.5px;">— SSL, HTTPS, cache TTL, dll</td></tr>
                                <tr><td style="padding:1px 6px 1px 0;color:var(--text);opacity:.75;white-space:nowrap;">Zone → Zone</td><td style="padding:1px 0;font-weight:600;">Read</td><td style="padding:1px 0 1px 8px;color:var(--text);opacity:.6;font-size:10.5px;">— baca info &amp; status zone</td></tr>
                                <tr><td style="padding:1px 6px 1px 0;color:var(--text);opacity:.75;white-space:nowrap;">Zone → DNS</td><td style="padding:1px 0;font-weight:600;">Edit</td><td style="padding:1px 0 1px 8px;color:var(--text);opacity:.6;font-size:10.5px;">— auto-provision A, CNAME, TXT</td></tr>
                                <tr><td style="padding:1px 6px 1px 0;color:var(--text);opacity:.75;white-space:nowrap;">Zone → Cache Purge</td><td style="padding:1px 0;font-weight:600;">Purge</td><td style="padding:1px 0 1px 8px;color:var(--text);opacity:.6;font-size:10.5px;">— tombol Purge Cache</td></tr>
                                <tr><td style="padding:1px 6px 1px 0;color:var(--text);opacity:.75;white-space:nowrap;">Zone → Transform Rules</td><td style="padding:1px 0;font-weight:600;">Edit</td><td style="padding:1px 0 1px 8px;color:var(--text);opacity:.6;font-size:10.5px;">— inject security response headers</td></tr>
                                <tr><td style="padding:1px 6px 1px 0;color:var(--text);opacity:.75;white-space:nowrap;">Zone → Firewall Services</td><td style="padding:1px 0;font-weight:600;">Edit</td><td style="padding:1px 0 1px 8px;color:var(--text);opacity:.6;font-size:10.5px;">— custom WAF skip rules (Facebook ASN)</td></tr>
                            </table>
                        </div>
                        <div class="form-group">
                            <label class="control-label">CF Account ID</label>
                            <input type="text" class="form-control" id="cfg_cf_account" placeholder="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx">
                        </div>
                        <div class="form-group">
                            <label class="control-label">Server IP <small style="font-weight:400;opacity:.7;">(untuk auto DNS A record)</small></label>
                            <input type="text" class="form-control" id="cfg_cf_ip" placeholder="1.2.3.4">
                        </div>
                        <div class="form-group" style="margin-bottom:4px;">
                            <label class="control-label">Default Nameservers <small style="font-weight:400;opacity:.7;">(default fallback jika domain belum sync)</small></label>
                            <input type="text" class="form-control mono-input" id="cfg_cf_ns1" placeholder="ns1.example.com" style="margin-bottom:5px;">
                            <input type="text" class="form-control mono-input" id="cfg_cf_ns2" placeholder="ns2.example.com">
                        </div>
                        <div id="cfg_status" style="display:none;margin-top:8px;padding:7px 10px;border-radius:var(--radius);font-size:12px;"></div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-default btn-sm" data-dismiss="modal">Batal</button>
                        <button type="button" class="btn btn-primary btn-sm" id="cfg_save_btn">
                            <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                            Simpan
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <div id="cf_ns_modal" class="modal fade" data-keyboard="false" data-backdrop="static">
            <div class="modal-dialog" style="max-width:480px;">
                <div class="modal-content">
                    <div class="modal-header">
                        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                        <h4 class="modal-title">Cloudflare Nameservers</h4>
                    </div>
                    <div class="modal-body">
                        <p style="margin:0 0 8px;font-size:12px;color:var(--text);">
                            Point your domain <strong class="cf-ns-domain"></strong> to these nameservers at your domain registrar:
                        </p>
                        <ul class="cf-ns-list" style="margin:0;padding-left:18px;list-style:disc;"></ul>
                        <p style="margin:10px 0 0;font-size:11.5px;color:var(--text);opacity:.72;">
                            DNS propagation may take up to 24 hours. Run <em>Sync</em> again after pointing NS to refresh status.
                        </p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>
    <script nonce="<?= adminEsc($nonce); ?>">
    $(document).ready(function() {
        function svgIcon(type) {
            var a = ' width="14" height="14" viewBox="0 0 24 24" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"';
            if (type === 'delete') {
                return '<span class="action-ico" aria-hidden="true"><svg' + a + '><path d="M4 7h16"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M6 7l1 13h10l1-13"/><path d="M9 7V4h6v3"/></svg></span>';
            }
            return '<span class="action-ico" aria-hidden="true"><svg' + a + '><path d="M4 20h4l11-11-4-4L4 16v4z"/><path d="M14 6l4 4"/></svg></span>';
        }
        function escHtml(v) {
            return String(v === null || v === undefined ? '' : v)
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        var state = { current: 1, rowCount: 25, search: '' };

        $("#adddomain").on('change', function() { $("#sub_domain").val(this.value); });
        $("#sub_domain").val('global');

        function cfStatusBadge(row) {
            var status = (row.cf_zone_id && row.cf_zone_id !== '') ? (row.cf_status || 'unknown') : '';
            if (status === '') {
                return '<span class="cf-badge cf-badge--none" title="Not synced">— none</span>';
            }
            var cls = 'cf-badge';
            var label = status;
            if (status === 'active') { cls += ' cf-badge--active'; label = '<svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg> active'; }
            else if (status === 'pending') { cls += ' cf-badge--pending'; label = '<svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px" aria-hidden="true"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> pending'; }
            else if (status === 'moved') { cls += ' cf-badge--moved'; label = '<svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px" aria-hidden="true"><line x1="7" y1="17" x2="17" y2="7"/><polyline points="7 7 17 7 17 17"/></svg> moved'; }
            return '<span class="' + cls + '" title="Zone: ' + escHtml(row.cf_zone_id || '') + '">' + label + '</span>';
        }

        function cfSvg(type) {
            var a = ' width="14" height="14" viewBox="0 0 24 24" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"';
            if (type === 'sync') return '<svg' + a + '><path d="M21.5 2v6h-6"/><path d="M2.5 12A10 10 0 0 1 20 6.3"/><path d="M2.5 22v-6h6"/><path d="M21.5 12A10 10 0 0 1 4 17.7"/></svg>';
            if (type === 'purge') return '<svg' + a + '><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>';
            if (type === 'ns') return '<svg' + a + '><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
            return '';
        }

        function renderRow(row, idx) {
            var hasZone = row.cf_zone_id && row.cf_zone_id !== '';
            return '<tr data-row-id="' + escHtml(row.id) + '">' +
                '<td><span class="td-num">' + (idx + 1) + '</span></td>' +
                '<td><span class="td-subdomain">' + escHtml(row.sub_domain) + '</span></td>' +
                '<td><span class="td-domain" title="' + escHtml(row.domain) + '">' + escHtml(row.domain) + '</span></td>' +
                '<td>' + cfStatusBadge(row) + '</td>' +
                '<td style="text-align:right;white-space:nowrap;">' +
                    '<button type="button" class="btn-cf command-cpanel-sync" data-domain="' + escHtml(row.domain) + '" title="Sync to cPanel (Park + Wildcard)"><svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg></button>' +
                    '<button type="button" class="btn-cf command-cf-sync" data-row-id="' + escHtml(row.id) + '" data-domain="' + escHtml(row.domain) + '" title="Sync to Cloudflare">' + cfSvg('sync') + '</button>' +
                    (hasZone ? '<button type="button" class="btn-cf command-cf-purge" data-row-id="' + escHtml(row.id) + '" data-domain="' + escHtml(row.domain) + '" title="Purge CF Cache">' + cfSvg('purge') + '</button>' : '<button type="button" class="btn-cf" disabled style="opacity:.3;cursor:default;" title="No zone yet">' + cfSvg('purge') + '</button>') +
                    (hasZone ? '<button type="button" class="btn-cf command-cf-ns" data-row-id="' + escHtml(row.id) + '" data-domain="' + escHtml(row.domain) + '" data-ns="' + escHtml(row.cf_ns || '[]') + '" title="View NS records">' + cfSvg('ns') + '</button>' : '') +
                    ' <button type="button" class="btn btn-xs btn-default action-btn command-delete" data-row-id="' + escHtml(row.id) + '" data-domain="' + escHtml(row.domain) + '" data-zone-id="' + escHtml(row.cf_zone_id || '') + '" title="Delete" aria-label="Delete">' + svgIcon('delete') + '</button>' +
                '</td></tr>';
        }

        function renderPagination(total, current, rowCount) {
            if (rowCount === -1 || total === 0) { $('#tbl-pagination').empty(); return; }
            var pages = Math.ceil(total / rowCount);
            if (pages <= 1) { $('#tbl-pagination').empty(); return; }
            var html = '';
            html += '<li class="' + (current <= 1 ? 'disabled' : '') + '"><a href="#" data-page="' + (current - 1) + '">&laquo;</a></li>';
            var start = Math.max(1, current - 2), end = Math.min(pages, current + 2);
            if (start > 1) { html += '<li><a href="#" data-page="1">1</a></li>' + (start > 2 ? '<li class="disabled"><span>…</span></li>' : ''); }
            for (var p = start; p <= end; p++) {
                html += '<li class="' + (p === current ? 'active' : '') + '"><a href="#" data-page="' + p + '">' + p + '</a></li>';
            }
            if (end < pages) { html += (end < pages - 1 ? '<li class="disabled"><span>…</span></li>' : '') + '<li><a href="#" data-page="' + pages + '">' + pages + '</a></li>'; }
            html += '<li class="' + (current >= pages ? 'disabled' : '') + '"><a href="#" data-page="' + (current + 1) + '">&raquo;</a></li>';
            $('#tbl-pagination').html(html);
            $('#tbl-pagination').off('click', 'a').on('click', 'a', function(e) {
                e.preventDefault();
                var pg = parseInt($(this).data('page'));
                if (!isNaN(pg) && pg >= 1 && pg <= pages && pg !== state.current) {
                    state.current = pg; loadData();
                }
            });
        }

        function cfRequest(action, rowId, extra, btn) {
            if (btn) { $(btn).prop('disabled', true).addClass('btn-cf--loading'); }
            var data = $.extend({ action: action, id: rowId }, extra || {});
            return $.ajax({ type: 'POST', url: 'cf.php', data: data, dataType: 'json' })
                .always(function() { if (btn) { $(btn).prop('disabled', false).removeClass('btn-cf--loading'); } });
        }

        function cfUpdateRowBadge(rowId, cfStatus, zoneId, cfNs) {
            var tr = $('#tbl_domains tbody tr[data-row-id="' + rowId + '"]');
            if (!tr.length) { return; }
            var fakeRow = { cf_zone_id: zoneId, cf_status: cfStatus, cf_ns: cfNs };
            tr.find('td:nth-child(4)').html(cfStatusBadge(fakeRow));
        }

        function cfSync(rowId, domain, btn) {
            showToast('info', 'Syncing…', domain);
            cfRequest('zone_add', rowId, {}, btn)
                .done(function(data) {
                    if (data && data.ok) {
                        var dnsInfo = '';
                        if (data.dns_log && data.dns_log.length) {
                            var errs = data.dns_log.filter(function(l){ return l.indexOf('error:') === 0; }).length;
                            dnsInfo = ' · DNS: ' + (data.dns_log.length - errs) + ' ok' + (errs ? ', ' + errs + ' err' : '');
                        }
                        showToast('success', 'CF Zone OK', (data.cf_status || '') + ' — ' + domain + dnsInfo);
                        cfUpdateRowBadge(rowId, data.cf_status, data.zone_id, JSON.stringify(data.cf_ns || []));
                        cfShowNs(rowId, domain, JSON.stringify(data.cf_ns || []));
                    } else {
                        showToast('error', 'CF Error', (data && data.err) || 'zone_add failed');
                    }
                })
                .fail(function() { showToast('error', 'CF Sync Failed', domain); });
        }

        function cfPurge(rowId, domain, btn) {
            cfRequest('purge_cache', rowId, {}, btn)
                .done(function(data) {
                    if (data && data.ok) { showToast('success', 'Cache Purged', domain); }
                    else { showToast('error', 'Purge Failed', (data && data.err) || ''); }
                })
                .fail(function() { showToast('error', 'Purge Failed', domain); });
        }

        function cfShowNs(rowId, domain, nsJson) {
            var ns = [];
            try { ns = JSON.parse(nsJson || '[]'); } catch(e) {}
            var isFallback = false;
            if (!ns.length && cfDefaultNs.length) {
                ns = cfDefaultNs;
                isFallback = true;
            }
            var nsHtml = ns.length
                ? ns.map(function(n) { return '<li style="font-family:Consolas,Monaco,\'Courier New\',monospace;font-size:12px;padding:2px 0;">' + escHtml(n) + '</li>'; }).join('')
                : '<li style="color:var(--text);opacity:.6;">No NS records stored — run sync first.</li>';
            if (isFallback) {
                nsHtml += '<li style="margin-top:6px;font-size:11px;color:var(--text);opacity:.6;list-style:none;">⚠ Fallback dari env — jalankan Sync untuk NS spesifik domain ini.</li>';
            }
            $('#cf_ns_modal .cf-ns-domain').text(domain);
            $('#cf_ns_modal .cf-ns-list').html(nsHtml);
            $('#cf_ns_modal').modal('show');
        }

        function bindRowActions() {
            $('#tbl_domains').find('.command-delete').off('click').on('click', function() {
                var rowId = $(this).data('row-id');
                var domain = $(this).data('domain') || '';
                var zoneId = $(this).data('zone-id') || '';
                Swal.fire({
                    title: 'Are you sure?',
                    text: "You won't be able to revert this!",
                    type: 'warning',
                    showCancelButton: true,
                    allowOutsideClick: false,
                    confirmButtonColor: '#3085d6',
                    cancelButtonColor: '#d33',
                    confirmButtonText: 'Yes, delete it!'
                }).then(function(result) {
                    if (result.value) {
                        $.ajax({
                            type: 'POST', url: 'response.php',
                            data: { id: rowId, action: 'delete' },
                            dataType: 'json',
                            success: function() {
                                loadData();
                                if (domain !== '') {
                                    showToast('info', 'Removing from cPanel…', domain);
                                    $.ajax({
                                        type: 'POST', url: '',
                                        data: { action: 'cpanel_delete', domain: domain },
                                        dataType: 'json'
                                    }).done(function(res) {
                                        if (res && res.ok) {
                                            showToast('success', 'cPanel Removed', domain);
                                        } else {
                                            showToast('error', 'cPanel Remove Failed', (res && res.err) || domain);
                                        }
                                    }).fail(function() {
                                        showToast('error', 'cPanel Remove Error', domain);
                                    });
                                    if (zoneId !== '') {
                                        showToast('info', 'Removing CF Zone…', domain);
                                        $.ajax({
                                            type: 'POST', url: 'cf.php',
                                            data: { action: 'zone_delete', zone_id: zoneId },
                                            dataType: 'json'
                                        }).done(function(res) {
                                            if (res && res.ok) {
                                                showToast('success', 'CF Zone Removed', domain);
                                            } else {
                                                showToast('error', 'CF Zone Remove Failed', (res && res.err) || domain);
                                            }
                                        }).fail(function() {
                                            showToast('error', 'CF Zone Remove Error', domain);
                                        });
                                    }
                                } else {
                                    showToast('success', 'Deleted', 'Domain removed.');
                                }
                            }
                        });
                    }
                });
            });

            $('#tbl_domains').find('.command-cpanel-sync').off('click').on('click', function() {
                var btn = this;
                var domain = $(btn).data('domain');
                if (!domain) { return; }
                showToast('info', 'cPanel Sync…', domain);
                cpanelSync(domain, btn)
                    .done(function(res) {
                        if (res && res.ok) {
                            showToast('success', 'cPanel Synced', domain);
                        } else {
                            showToast('error', 'cPanel Sync Failed', (res && res.err) || domain);
                        }
                    })
                    .fail(function() { showToast('error', 'cPanel Sync Error', domain); });
            });

            $('#tbl_domains').find('.command-cf-sync').off('click').on('click', function() {
                var btn = this;
                var rowId = $(btn).data('row-id');
                var domain = $(btn).data('domain');
                cfSync(rowId, domain, btn);
            });

            $('#tbl_domains').find('.command-cf-purge').off('click').on('click', function() {
                var btn = this;
                var rowId = $(btn).data('row-id');
                var domain = $(btn).data('domain');
                cfPurge(rowId, domain, btn);
            });

            $('#tbl_domains').find('.command-cf-ns').off('click').on('click', function() {
                var rowId = $(this).data('row-id');
                var domain = $(this).data('domain');
                var nsJson = $(this).data('ns') || '[]';
                cfShowNs(rowId, domain, nsJson);
            });
        }

        function loadData() {
            $.ajax({
                type: 'POST', url: 'response.php',
                data: { current: state.current, rowCount: state.rowCount, searchPhrase: state.search },
                dataType: 'json',
                success: function(data) {
                    var rows = data.rows || [], total = data.total || 0;
                    var html = '';
                    for (var i = 0; i < rows.length; i++) { html += renderRow(rows[i], i); }
                    $('#tbl_domains tbody').html(html || '<tr><td colspan="5" style="text-align:center;padding:18px;color:var(--text);">No data</td></tr>');
                    var from = total === 0 ? 0 : ((state.current - 1) * (state.rowCount === -1 ? total : state.rowCount)) + 1;
                    var to = state.rowCount === -1 ? total : Math.min(state.current * state.rowCount, total);
                    $('#tbl-info').text('Showing ' + from + ' to ' + to + ' of ' + total + ' entries');
                    renderPagination(total, state.current, state.rowCount);
                    bindRowActions();
                }
            });
        }

        var searchTimer;
        $('#tbl-search').on('input', function() {
            clearTimeout(searchTimer);
            var val = $(this).val();
            searchTimer = setTimeout(function() { state.search = val; state.current = 1; loadData(); }, 300);
        });
        $('#tbl-rowcount').on('change', function() {
            state.rowCount = parseInt(this.value); state.current = 1; loadData();
        });

        function cpanelSync(domain, btn) {
            if (btn) { $(btn).prop('disabled', true).addClass('btn-cf--loading'); }
            return $.ajax({ type: 'POST', url: '', dataType: 'json', data: { url: domain } })
                .always(function() { if (btn) { $(btn).prop('disabled', false).removeClass('btn-cf--loading'); } });
        }

        function ajaxAction(action) {
            var addon = $('#domain').val().trim();
            var autoCloudflare = $('#auto_cloudflare').val() === '1';
            var data = $("#frm_" + action).serializeArray();
            $.ajax({
                type: 'POST', url: 'response.php',
                data: data, dataType: 'json',
                success: function(resp) {
                    $('#' + action + '_model').modal('hide');
                    loadData();
                    if (action === 'add' && addon !== '') {
                        showToast('info', 'cPanel Sync…', addon);
                        cpanelSync(addon)
                            .done(function(res) {
                                if (res && res.ok) {
                                    showToast('success', 'cPanel Synced', addon);
                                    if (autoCloudflare && resp && resp.id) {
                                        showToast('info', 'Cloudflare Sync…', addon);
                                        cfSync(resp.id, addon);
                                    }
                                } else {
                                    showToast('error', 'cPanel Sync Failed', (res && res.err) || addon);
                                }
                            })
                            .fail(function() { showToast('error', 'cPanel Sync Error', addon); });
                    }
                }
            });
        }

        $('#command-sync-all').on('click', function() {
            var btn = this;
            var syncSvg = '<svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6"/><path d="M2.5 12A10 10 0 0 1 20 6.3"/><path d="M2.5 22v-6h6"/><path d="M21.5 12A10 10 0 0 1 4 17.7"/></svg>';
            $(btn).prop('disabled', true).addClass('btn-syncall--loading').html(syncSvg + ' Syncing…');
            var rows = [];
            $('#tbl_domains tbody tr[data-row-id]').each(function() {
                var rowId = $(this).data('row-id');
                var domain = $(this).find('.command-cf-sync').data('domain') || '';
                if (rowId && domain) { rows.push({ id: rowId, domain: domain }); }
            });
            if (rows.length === 0) {
                showToast('info', 'No rows', 'Load data first.');
                $(btn).prop('disabled', false).removeClass('btn-syncall--loading').html('<svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6"/><path d="M2.5 12A10 10 0 0 1 20 6.3"/><path d="M2.5 22v-6h6"/><path d="M21.5 12A10 10 0 0 1 4 17.7"/></svg> Sync All CF');
                return;
            }
            var done = 0;
            function syncNext() {
                if (done >= rows.length) {
                    showToast('success', 'Sync All Done', done + ' domain(s) processed.');
                    $(btn).prop('disabled', false).removeClass('btn-syncall--loading').html('<svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6"/><path d="M2.5 12A10 10 0 0 1 20 6.3"/><path d="M2.5 22v-6h6"/><path d="M21.5 12A10 10 0 0 1 4 17.7"/></svg> Sync All CF');
                    loadData();
                    return;
                }
                var r = rows[done];
                done++;
                $(btn).html(syncSvg + ' Syncing ' + done + '/' + rows.length + '…');
                cfRequest('zone_add', r.id, {})
                    .done(function(data) {
                        if (data && data.ok) {
                            cfUpdateRowBadge(r.id, data.cf_status, data.zone_id, JSON.stringify(data.cf_ns || []));
                        }
                    })
                    .always(function() { syncNext(); });
            }
            syncNext();
        });

        var cpanelNsCache = null;
        var cpanelNsLoading = false;

        function loadCpanelNs() {
            if (cpanelNsCache !== null) {
                renderCpanelNs(cpanelNsCache);
                return;
            }
            $('#ns-info-list').html('<span style="opacity:.6;">Memuat…</span>');
            $.ajax({ type: 'GET', url: 'cpanel-ns.php', dataType: 'json' })
                .done(function(data) {
                    cpanelNsCache = (data && data.ok && data.ns && data.ns.length) ? data.ns : [];
                    renderCpanelNs(cpanelNsCache);
                })
                .fail(function() {
                    $('#ns-info-list').html('<span style="opacity:.6;">Gagal memuat nameserver.</span>');
                });
        }

        function renderCpanelNs(nsList) {
            if (!nsList || !nsList.length) {
                $('#ns-info-list').html('<span style="opacity:.6;">Nameserver tidak ditemukan.</span>');
                return;
            }
            var html = nsList.map(function(ns, i) {
                return 'Nameserver ' + (i + 1) + ': <code>' + escHtml(ns) + '</code>';
            }).join('<hr style="margin:1px;padding:0;border:0;">');
            $('#ns-info-list').html(html);
        }

        $("#command-add").on('click', function() {
            $("#domain").val('');
            $("#auto_cloudflare").val('1');
            loadCpanelNs();
            $('#add_model').modal('show');
        });
        $("#btn_add").on('click', function() {
            if ($.trim($("#domain").val()) === "") {
                Swal.fire({ allowOutsideClick: false, type: 'error', title: 'Oops...', text: 'Something went wrong! {Required all fields}' });
                return false;
            }
            ajaxAction('add');
        });
        $("#btn_edit").on('click', function() { ajaxAction('edit'); });

        loadData();

        // ── CF Config modal ──────────────────────────────────────────────
        var cfDefaultNs = [];

        $('#command-cf-config').on('click', function() {
            $('#cfg_status').hide().text('');
            $('#cfg_cf_token').val('').attr('type', 'password').attr('placeholder', 'Token baru…').removeAttr('data-masked');
            $('#cfg_cf_account').val('');
            $('#cfg_cf_ip').val('');
            $('#cfg_cf_ns1').val('');
            $('#cfg_cf_ns2').val('');
            $.ajax({ type: 'GET', url: 'cf.php', data: { action: 'config_get' }, dataType: 'json' })
                .done(function(data) {
                    if (data && data.ok && data.config) {
                        var masked = data.config.CF_API_TOKEN || '';
                        if (masked !== '') {
                            $('#cfg_cf_token').val(masked).attr('data-masked', '1').attr('placeholder', '');
                        } else {
                            $('#cfg_cf_token').attr('placeholder', 'Belum diset');
                        }
                        $('#cfg_cf_account').val(data.config.CF_ACCOUNT_ID || '');
                        $('#cfg_cf_ip').val(data.config.CF_SERVER_IP || '');
                        $('#cfg_cf_ns1').val(data.config.CF_NS1 || '');
                        $('#cfg_cf_ns2').val(data.config.CF_NS2 || '');
                        cfDefaultNs = [data.config.CF_NS1, data.config.CF_NS2].filter(function(n) { return n && n !== ''; });
                    }
                });
            $('#cf_config_modal').modal('show');
        });

        $('#cfg_cf_token_toggle').on('click', function() {
            var inp = $('#cfg_cf_token');
            inp.attr('type', inp.attr('type') === 'password' ? 'text' : 'password');
        });

        $('#cfg_cf_token').on('input', function() {
            $(this).removeAttr('data-masked');
        });

        $('#cfg_save_btn').on('click', function() {
            var btn = $(this).prop('disabled', true);
            var payload = {
                action:         'config_save',
                CF_API_TOKEN:   $('#cfg_cf_token').val().trim(),
                CF_ACCOUNT_ID:  $('#cfg_cf_account').val().trim(),
                CF_SERVER_IP:   $('#cfg_cf_ip').val().trim(),
                CF_NS1:         $('#cfg_cf_ns1').val().trim(),
                CF_NS2:         $('#cfg_cf_ns2').val().trim()
            };
            $.ajax({ type: 'POST', url: 'cf.php', data: payload, dataType: 'json' })
                .done(function(data) {
                    var st = $('#cfg_status').show();
                    if (data && data.ok) {
                        var saved = data.saved && data.saved.length ? data.saved.join(', ') : 'Tidak ada perubahan';
                        st.css({ background: 'var(--blue-soft)', border: '1px solid var(--blue-line)', color: 'var(--text)' }).html('<strong>Tersimpan:</strong> ' + escHtml(saved));
                        if (data.saved && data.saved.length) {
                            showToast('success', 'CF Config Saved', saved);
                        }
                    } else {
                        st.css({ background: 'var(--danger-soft)', border: '1px solid rgba(159,49,56,.28)', color: 'var(--danger)' }).text((data && data.err) || 'Gagal menyimpan');
                    }
                })
                .fail(function() {
                    $('#cfg_status').show().css({ background: 'var(--danger-soft)', color: 'var(--danger)' }).text('Request gagal');
                })
                .always(function() { btn.prop('disabled', false); });
        });
    });
    document.getElementById('btn-logout').addEventListener('click', function(e) {
        e.preventDefault();
        var href = this.getAttribute('href');
        document.getElementById('logout-toast').classList.add('show');
        setTimeout(function(){ window.location.href = href; }, 900);
    });
    </script>
<style nonce="<?= adminEsc($nonce); ?>">#logout-toast{position:fixed;bottom:20px;right:20px;background:rgba(41,43,44,.88);color:#fff;padding:7px 15px;border-radius:6px;font-size:12px;font-weight:600;z-index:99999;opacity:0;pointer-events:none;transition:opacity .2s;box-shadow:0 2px 8px rgba(0,0,0,.22)}#logout-toast.show{opacity:1}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}</style>
<div id="logout-toast">Logging out…</div>
</body></html>
