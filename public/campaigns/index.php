<?php

declare(strict_types=1);

error_reporting(0);

include_once __DIR__ . '/../password.login.php';

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
    <style nonce="<?= adminEsc($nonce); ?>">:root{color-scheme:light;--bg:#f7f7f7;--panel:#fff;--panel-soft:#f7f7f7;--panel-fade:rgba(255,255,255,.66);--line:rgba(41,43,44,.18);--line-soft:rgba(41,43,44,.1);--text:#292b2c;--text-strong:#111;--accent:#292b2c;--accent-hover:#3a3d3f;--on-accent:#f7f7f7;--danger:#9f3138;--danger-soft:rgba(159,49,56,.08);--success:#2563eb;--success-soft:rgba(37,99,235,.08);--blue-soft:rgba(37,99,235,.08);--blue-line:rgba(37,99,235,.28);--radius:.3rem;--shadow:0 1px 4px rgba(41,43,44,.08);--shadow-modal:0 8px 24px rgba(41,43,44,.16)}@media (prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#292b2c;--panel:#303334;--panel-soft:#35393a;--panel-fade:rgba(247,247,247,.045);--line:rgba(247,247,247,.18);--line-soft:rgba(247,247,247,.1);--text:#f7f7f7;--text-strong:#fff;--accent:#f7f7f7;--accent-hover:#e7e7e7;--on-accent:#292b2c;--danger:#ef9a9a;--danger-soft:rgba(239,154,154,.11);--success:#93c5fd;--success-soft:rgba(147,197,253,.1);--blue-soft:rgba(147,197,253,.1);--blue-line:rgba(147,197,253,.34);--shadow:0 1px 5px rgba(0,0,0,.28);--shadow-modal:0 10px 28px rgba(0,0,0,.42)}}*{box-sizing:border-box}html{min-height:100%;background:var(--bg)}body{min-height:100vh;margin:0;padding:58px 8px 18px!important;background:linear-gradient(180deg,var(--panel-soft) 0%,var(--bg) 100%)!important;color:var(--text)!important;font-family:monospace!important;font-size:13px;line-height:1.45;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility}a{color:inherit;text-decoration:none}.container{width:100%;max-width:1180px;margin:0 auto}code{font-family:Consolas,Monaco,'Courier New',monospace;font-size:11.5px;color:var(--text);background:var(--panel-soft);border:1px solid var(--line-soft);border-radius:var(--radius);padding:1px 4px}.navbar.navbar-default{min-height:44px;border:0!important;border-bottom:0!important;background:color-mix(in srgb,var(--panel) 94%,transparent)!important;box-shadow:var(--shadow)!important}.navbar .container{max-width:1180px}.navbar-brand{height:44px!important;padding:12px 10px!important;color:var(--text-strong)!important;font-size:13px;line-height:20px}.navbar-nav>li>a{padding-top:12px!important;padding-bottom:12px!important;color:var(--text)!important;font-size:12px}.navbar-nav>li>a:hover,.navbar-default .navbar-nav>.active>a,.navbar-default .navbar-nav>.active>a:focus,.navbar-default .navbar-nav>.active>a:hover{background:var(--accent)!important;color:var(--on-accent)!important}.navbar-toggle{margin-top:5px!important;margin-bottom:5px!important;border-color:var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important}.navbar-toggle .icon-bar{background:var(--text)!important}.panel,.panel-default,.well,.modal-content{border:0!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;box-shadow:var(--shadow)!important;overflow:hidden}.panel-heading,.panel-footer,.modal-header,.modal-footer{padding:8px 10px!important;background:linear-gradient(180deg,var(--panel) 0%,var(--panel-soft) 100%)!important;border:0!important;color:var(--text-strong)!important}.panel-body,.modal-body{padding:10px!important;background:transparent!important;color:var(--text)!important}.pull-right{display:flex;align-items:center;gap:6px}.modal-content{box-shadow:var(--shadow-modal)!important}.modal-title{font-size:14px;font-weight:700;color:var(--text-strong)}.close{color:var(--text)!important;opacity:.78;text-shadow:none}.form-group{margin-bottom:8px}.control-label,label{margin-bottom:4px;color:var(--text-strong);font-size:12px}.form-control,input[type=text],input[type=number],input[type=password],input[type=search],select,textarea{height:31px;min-height:31px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-family:monospace!important;font-size:13px!important;line-height:1.4!important;box-shadow:none!important; }.form-control:focus,input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent)!important;box-shadow:0 0 0 2px color-mix(in srgb,var(--accent) 18%,transparent)!important}.form-control::placeholder,textarea::placeholder{color:color-mix(in srgb,var(--text) 54%,transparent)}.form-control[readonly],input[readonly],textarea[readonly]{background:var(--panel-soft)!important;color:var(--text)!important}textarea.form-control{height:auto;min-height:114px;resize:none}.input-group-addon{height:31px;padding:5px 8px;background:var(--panel-soft)!important;border-color:var(--line)!important;color:var(--text)!important;border-radius:var(--radius)!important;font-size:11.5px}.btn,button,.btn-sm,.btn-xs{display:inline-flex;align-items:center;justify-content:center;gap:5px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-size:11.5px;font-weight:700;line-height:1.2;box-shadow:none!important;outline:none;transition:background .12s ease,border-color .12s ease,color .12s ease}.btn:hover,button:hover,.btn-sm:hover,.btn-xs:hover{background:var(--panel-soft)!important;border-color:var(--line)!important;color:var(--text-strong)!important}.btn-primary,.btn-primary:focus,.btn-primary:active,.btn.active{background:var(--accent)!important;border-color:var(--accent)!important;color:var(--on-accent)!important}.btn-primary:hover{background:var(--accent-hover)!important;border-color:var(--accent-hover)!important;color:var(--on-accent)!important}.btn-danger,.btn-danger:focus{background:var(--danger-soft)!important;border-color:rgba(159,49,56,.34)!important;color:var(--danger)!important}.btn-danger:hover{background:rgba(159,49,56,.16)!important;color:var(--danger)!important}.glyphicon{top:1px;color:currentColor}.action-ico{display:inline-flex;align-items:center;justify-content:center;flex-shrink:0}.action-ico svg{display:block}.table-responsive{border:0!important}.table{width:100%;margin:4px 0 0;border-collapse:separate;border-spacing:0;border:0;border-radius:var(--radius);overflow:hidden;background:var(--panel)!important}.table>thead>tr>th{position:sticky;top:0;z-index:20;padding:7px 8px!important;border-bottom:1px solid var(--line)!important;background:var(--panel-soft)!important;color:var(--text-strong)!important;font-size:10.5px!important;line-height:1.2;text-transform:uppercase;letter-spacing:.035em;white-space:nowrap}.table>tbody>tr>td{padding:6px 8px!important;border-top:1px solid var(--line-soft)!important;color:var(--text);font-size:11.5px;vertical-align:middle;word-break:break-word;background:var(--panel)!important}.table-hover>tbody>tr:hover>td{background:var(--panel-soft)!important}.bootgrid-table th>.column-header-anchor{color:var(--text-strong)!important}.bootgrid-header,.bootgrid-footer{margin:6px 0!important;color:var(--text)!important}.bootgrid-header .search .form-control{height:31px}.bootgrid-header .actionBar{text-align:right}.pagination>li>a,.pagination>li>span{border-color:var(--line)!important;background:var(--panel)!important;color:var(--text)!important}.pagination>.active>a,.pagination>.active>span{background:var(--accent)!important;border-color:var(--accent)!important;color:var(--on-accent)!important}.dropdown-menu{border:0!important;border-radius:var(--radius)!important;background:var(--panel)!important;box-shadow:var(--shadow-modal)!important}.dropdown-menu>li>a{color:var(--text)!important;font-size:12px}.dropdown-menu>li>a:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}.alert{border-radius:var(--radius)!important}.alert-danger,.error{background:var(--danger-soft)!important;border-color:rgba(159,49,56,.28)!important;color:var(--danger)!important}.alert-success,.success{background:var(--blue-soft)!important;border-color:var(--blue-line)!important;color:var(--text)!important}.label{border-radius:var(--radius)!important}.label-default{background:var(--panel-soft)!important;color:var(--text)!important;border:1px solid var(--line)}blockquote{margin:0 0 10px;padding:7px 10px;border-left:2px solid var(--line)!important;background:var(--panel-fade);border-radius:var(--radius);font-size:12px}.text-warning{margin:0 0 2px;color:var(--text-strong)!important;font-weight:700}.text-muted{color:var(--text)!important}.flag{border-radius:var(--radius)}.admin-toast-root{position:fixed;right:12px;bottom:12px;z-index:10050;display:flex;flex-direction:column;gap:6px;align-items:flex-end}.admin-toast{max-width:340px;padding:8px 10px;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:12px;line-height:1.35}.admin-toast strong{display:block;margin-bottom:2px;color:var(--text-strong)}.admin-toast--error{border-color:rgba(159,49,56,.34);background:var(--danger-soft);color:var(--danger)}.admin-toast--success{border-color:var(--blue-line);background:var(--blue-soft);color:var(--text)}.admin-fallback-backdrop{position:fixed;inset:0;z-index:10040;display:flex;align-items:center;justify-content:center;padding:12px;background:rgba(0,0,0,.36)}.admin-fallback-dialog{width:min(420px,100%);border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);overflow:hidden}.admin-fallback-head{padding:10px;border-bottom:1px solid var(--line-soft);font-weight:800;color:var(--text-strong)}.admin-fallback-body{padding:10px;font-size:12px}.admin-fallback-actions{display:flex;gap:6px;justify-content:flex-end;padding:10px;border-top:1px solid var(--line-soft);background:var(--panel-soft)}@media screen and (max-width:768px){body{padding:58px 6px 12px!important;font-size:12.5px}.container{width:100%!important;max-width:100%!important;padding-left:6px!important;padding-right:6px!important}.panel-heading,.panel-body,.panel-footer{padding:7px!important}.navbar .container{padding-left:8px!important;padding-right:8px!important}.navbar-collapse{border-color:var(--line)!important;background:var(--panel)!important}.pull-right{float:none!important;justify-content:flex-end}.input-group{display:block}.input-group>.form-control,.input-group>.input-group-addon,.input-group>.input-group-btn,.input-group-btn>.btn{display:block;width:100%!important}.input-group-addon{border-bottom:0!important;border-radius:var(--radius) var(--radius) 0 0!important}.input-group>.form-control{border-radius:0 0 var(--radius) var(--radius)!important}.input-group-btn>.btn{margin-top:5px}.table{display:block;overflow-x:auto;white-space:nowrap}.modal-dialog{width:auto!important;margin:8px}}.campaign-table-wrap{overflow-x:auto}#tbl_campaigns{table-layout:fixed;width:100%;min-width:900px}#tbl_campaigns th:nth-child(1),#tbl_campaigns td:nth-child(1){width:50px;text-align:center;padding-left:4px!important;padding-right:4px!important}#tbl_campaigns th:nth-child(2),#tbl_campaigns td:nth-child(2){width:118px}#tbl_campaigns th:nth-child(3),#tbl_campaigns td:nth-child(3){width:96px}#tbl_campaigns th:nth-child(5),#tbl_campaigns td:nth-child(5){width:140px}#tbl_campaigns th:nth-child(6),#tbl_campaigns td:nth-child(6){width:82px;text-align:right}.td-num{display:block;font-size:11.5px;font-weight:600;font-family:Consolas,Monaco,monospace;color:color-mix(in srgb,var(--text) 44%,transparent);text-align:center}.td-cc{display:flex;align-items:center;gap:5px;white-space:nowrap}.td-cc .cc-label{font-family:Consolas,Monaco,monospace;font-size:11.5px;font-weight:700;letter-spacing:.03em}.badge-device{display:inline-block;width:100%;padding:2px 7px;border-radius:.3rem;border:1px solid var(--line);background:var(--panel-soft);font-size:10.5px;font-weight:700;white-space:nowrap}.badge-device--mobile{border-color:var(--blue-line);background:var(--blue-soft);color:var(--success)}.badge-device--tablet{border-color:rgba(124,58,237,.3);background:rgba(124,58,237,.08);color:#7c3aed}.badge-net{display:inline-block;width:100%;padding:2px 9px;border-radius:.3rem;border:1px solid;font-size:10.5px;font-weight:700;white-space:nowrap;letter-spacing:.02em}.badge-net--imonetizeit{background:rgba(22,163,74,.08);border-color:rgba(22,163,74,.28);color:#16a34a}.badge-net--lospollos{background:var(--blue-soft);border-color:var(--blue-line);color:var(--success)}.badge-net--trafee{background:rgba(234,88,12,.07);border-color:rgba(234,88,12,.28);color:#ea580c}.badge-net--custom,.badge-net--other{background:var(--panel-soft);border-color:var(--line);color:var(--text)}.td-smartlink{display:block;max-width:100%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:Consolas,Monaco,monospace;font-size:11.5px}.param-note{display:block;color:var(--text)!important;font-size:11.5px;line-height:1.45}.param-token{color:var(--success)!important;font-weight:700}
/* bootgrid toolbar search/select fix */.navbar-default .navbar-nav>li>a:hover,.navbar-default .navbar-nav>li>a:focus{background:color-mix(in srgb,var(--accent) 5%,transparent)!important;color:var(--text-strong)!important;box-shadow:inset 0 -1px 0 var(--line-soft)!important}.navbar-default .navbar-nav>.active>a,.navbar-default .navbar-nav>.active>a:hover,.navbar-default .navbar-nav>.active>a:focus{background:transparent!important;color:var(--text-strong)!important;box-shadow:inset 0 -2px 0 var(--accent)!important}.panel,.panel-default{overflow:visible!important}.panel-body{overflow:visible!important}.table-responsive{overflow-x:auto!important;overflow-y:visible!important}.bootgrid-header{position:relative!important;z-index:80!important;display:block!important;margin:8px 0 7px!important;color:var(--text)!important}.bootgrid-header .actionBar{display:flex!important;align-items:center!important;justify-content:flex-end!important;gap:8px!important;float:none!important;width:100%!important;margin:0!important;text-align:right!important;white-space:nowrap!important}.bootgrid-header .search{position:relative!important;display:inline-flex!important;align-items:center!important;float:none!important;width:220px!important;min-width:220px!important;max-width:260px!important;margin:0!important;vertical-align:middle!important}.bootgrid-header .search .input-group{display:flex!important;align-items:stretch!important;width:100%!important;border-collapse:separate!important}.bootgrid-header .search .input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;min-width:34px!important;height:32px!important;padding:0!important;border:1px solid var(--line)!important;border-right:0!important;border-radius:var(--radius) 0 0 var(--radius)!important;background:var(--panel-soft)!important;color:var(--text)!important;line-height:1!important}.bootgrid-header .search .input-group-addon .glyphicon{top:0!important;font-size:12px!important}.bootgrid-header .search .search-field,.bootgrid-header .search .form-control{display:block!important;flex:1 1 auto!important;width:100%!important;height:32px!important;min-height:32px!important;padding:5px 9px!important;border:1px solid var(--line)!important;border-left:0!important;border-radius:0 var(--radius) var(--radius) 0!important;background:var(--panel)!important;color:var(--text)!important;font-size:12px!important;line-height:1.4!important;box-shadow:none!important}.bootgrid-header .search .search-field:focus,.bootgrid-header .search .form-control:focus{border-color:var(--accent)!important;border-left:0!important;box-shadow:0 0 0 2px color-mix(in srgb,var(--accent) 13%,transparent)!important}.bootgrid-header .actions{position:relative!important;display:inline-flex!important;align-items:center!important;gap:6px!important;float:none!important;margin:0!important;vertical-align:middle!important}.bootgrid-header .actions>.btn-group{position:relative!important;display:inline-flex!important;float:none!important;margin:0!important;vertical-align:middle!important}.bootgrid-header .actions .btn,.bootgrid-header .actions .dropdown-toggle{display:inline-flex!important;align-items:center!important;justify-content:center!important;gap:6px!important;height:32px!important;min-width:38px!important;padding:5px 10px!important;line-height:1.2!important;border-radius:var(--radius)!important}.bootgrid-header .actions .dropdown-toggle{min-width:64px!important}.bootgrid-header .actions .dropdown-toggle .caret{margin-left:2px!important}.bootgrid-header .actions .dropdown-menu{position:absolute!important;top:calc(100% + 4px)!important;right:0!important;left:auto!important;z-index:3000!important;display:none;min-width:112px!important;width:112px!important;margin:0!important;padding:4px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;box-shadow:var(--shadow-modal)!important;list-style:none!important}.bootgrid-header .actions .open>.dropdown-menu{display:block!important}.bootgrid-header .actions .dropdown-menu>li{display:block!important;float:none!important;width:100%!important;margin:0!important;padding:0!important;text-align:left!important}.bootgrid-header .actions .dropdown-menu>li>a{display:block!important;width:100%!important;min-width:0!important;padding:6px 9px!important;border-radius:var(--radius)!important;background:transparent!important;color:var(--text)!important;font-size:12px!important;line-height:1.25!important;text-align:left!important;white-space:nowrap!important}.bootgrid-header .actions .dropdown-menu>li>a:hover,.bootgrid-header .actions .dropdown-menu>li>a:focus{background:var(--panel-soft)!important;color:var(--text-strong)!important}.bootgrid-header .actions .dropdown-menu>.active>a,.bootgrid-header .actions .dropdown-menu>.active>a:hover,.bootgrid-header .actions .dropdown-menu>.active>a:focus{background:var(--accent-soft)!important;color:var(--text-strong)!important;box-shadow:inset 2px 0 0 var(--accent)!important}.bootgrid-footer{position:relative!important;z-index:20!important}.bootgrid-footer .pagination{margin:0!important}@media screen and (max-width:768px){.bootgrid-header .actionBar{align-items:stretch!important;justify-content:stretch!important;flex-wrap:wrap!important;gap:6px!important}.bootgrid-header .search{width:100%!important;min-width:0!important;max-width:none!important;flex:1 0 100%!important}.bootgrid-header .actions{margin-left:auto!important}.bootgrid-header .actions .dropdown-menu{right:0!important;left:auto!important}}
input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}</style>
<style nonce="<?= adminEsc($nonce); ?>">:root{--font-mono-old:"Lucida Console","Courier New",Consolas,Monaco,monospace}body,input,textarea,button,select,pre,code,kbd,samp{font-family:var(--font-mono-old)}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}</style>
<style nonce="<?= adminEsc($nonce); ?>">/* final action icon render fix */#tbl_campaigns th:last-child,#tbl_campaigns td:last-child{text-align:center!important;white-space:nowrap!important;width:108px!important;min-width:108px!important;max-width:108px!important}.bootgrid-table td:last-child{overflow:visible!important}.action-btn,.bootgrid-table .command-edit,.bootgrid-table .command-delete{display:inline-flex!important;align-items:center!important;justify-content:center!important;width:32px!important;height:26px!important;min-width:32px!important;min-height:26px!important;padding:0!important;margin:0 2px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-size:0!important;line-height:1!important;text-indent:0!important;vertical-align:middle!important;opacity:1!important;visibility:visible!important;box-shadow:none!important;overflow:visible!important}.action-btn:hover,.bootgrid-table .command-edit:hover{background:var(--accent-soft)!important;border-color:var(--line)!important;color:var(--text-strong)!important}.bootgrid-table .command-delete{color:var(--danger)!important}.bootgrid-table .command-delete:hover{background:var(--danger-soft)!important;border-color:color-mix(in srgb,var(--danger) 34%,var(--line))!important;color:var(--danger)!important}.bootgrid-table .command-edit[disabled],.bootgrid-table .command-delete[disabled]{opacity:.58!important;cursor:not-allowed!important}.action-btn .action-ico,.bootgrid-table .command-edit .action-ico,.bootgrid-table .command-delete .action-ico{display:inline-flex!important;align-items:center!important;justify-content:center!important;width:16px!important;height:16px!important;min-width:16px!important;min-height:16px!important;color:currentColor!important;opacity:1!important;visibility:visible!important;overflow:visible!important;pointer-events:none!important}.action-btn svg,.bootgrid-table .command-edit svg,.bootgrid-table .command-delete svg{display:block!important;width:16px!important;height:16px!important;min-width:16px!important;min-height:16px!important;overflow:visible!important;color:currentColor!important;opacity:1!important;visibility:visible!important;pointer-events:none!important}.action-btn svg *,.bootgrid-table .command-edit svg *,.bootgrid-table .command-delete svg *{vector-effect:non-scaling-stroke!important;stroke:currentColor!important;stroke-width:2!important;stroke-linecap:round!important;stroke-linejoin:round!important;fill:none!important;opacity:1!important;visibility:visible!important}.btn-icon svg,.btn-primary svg{display:block!important;width:13px!important;height:13px!important;fill:currentColor!important;color:currentColor!important;opacity:1!important;visibility:visible!important}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}</style>
<style nonce="<?= adminEsc($nonce); ?>">
body,.table,input,select,textarea{font-family:monospace!important}
.table{width:100%;border-collapse:collapse;font-size:12.5px;margin:0!important;border:0!important;background:transparent!important}
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
                    <li class="active"><a href="#"><strong>Campaigns</strong></a></li>
                    <li><a href="/addondomain/"><strong>Addon Domain</strong></a></li>
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
                    <span class="input-group-addon"><span class="glyphicon glyphicon-search"></span></span>
                    <input type="text" class="form-control" id="tbl-search" placeholder="Search...">
                </div>
                <select id="tbl-rowcount" class="form-control" style="width:70px;height:31px;display:inline-block;">
                    <option value="25">25</option>
                    <option value="50">50</option>
                    <option value="-1">All</option>
                </select>
            </div>
            <button type="button" class="btn btn-xs btn-primary btn-icon" id="command-add" data-row-id="0">
                <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 5v14"/><path d="M5 12h14"/></svg>
                <span>Create Campaigns</span>
            </button>
        </div>
        <div style="overflow-x:auto;">
            <table id="tbl_campaigns" class="table table-hover">
                <thead>
                    <tr>
                        <th>Empid</th>
                        <th>Country Code</th>
                        <th>Device</th>
                        <th class="offer-cell">Smartlink</th>
                        <th>Network</th>
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
    <div class="modal-dialog modal-wide">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                <h4 class="modal-title">Create Campaigns</h4>
            </div>
            <div class="modal-body">
                <?php
                $reportHost = adminEsc((string) app_env('REPORT_HOST', ''));
                ?>
                <div id="hint-smartlink" style="display:none;">
                    <blockquote>
                        <p class="hint-title">Contoh Smartlink:</p>
                        <span class="hint-line" id="hint-sl-line"></span>
                    </blockquote>
                    <blockquote>
                        <p class="hint-title">Contoh Postback URL:</p>
                        <span class="hint-line" id="hint-pb-line"></span>
                    </blockquote>
                    <blockquote>
                        <p class="hint-title">Parameter tersedia:</p>
                        <span class="param-note"><code>{sub_id}</code> &mdash; Tracker ID (sub_id user)</span>
                        <span class="param-note"><code>{click_id}</code> &mdash; Click ID unik yang di-generate sistem</span>
                    </blockquote>
                </div>
                <form method="post" id="frm_add">
                    <input type="hidden" value="add" name="action" id="action">
                    <input readonly="readonly" type="hidden" class="form-control" id="country_code" name="country_code" required="true">
                    <input readonly="readonly" type="hidden" class="form-control" id="ua" name="ua" required="true">
                    <div class="form-group">
                        <label for="offer" class="control-label">Smartlink:</label>
                        <input type="text" class="form-control" id="offer" name="offer" placeholder="https://domain.com/..." required>
                    </div>
                    <div class="form-group">
                        <label for="c_net" class="control-label">Select Network:</label>
                        <select id="c_net" class="form-control">
                            <option value="" disabled selected>* Select Network</option>
                            <option value="IMONETIZEIT">iMonetizeit</option>
                            <option value="LOSPOLLOS">LosPollos</option>
                            <option value="TRAFEE">Trafee</option>
                            <option value="CUSTOM">Custom</option>
                        </select>
                        <input type="text" class="form-control" id="custom_network" placeholder="Nama network..." style="display:none;margin-top:6px;" autocomplete="off">
                        <input readonly type="hidden" class="form-control" id="network" name="network" required>
                    </div>
                </form>
                <script nonce="<?= adminEsc($nonce); ?>">
                var _reportHost = <?= json_encode($reportHost, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT) ?>;
                var _networkHints = {
                    IMONETIZEIT: {
                        sl: 'https://domain.com/c/xx?s1=xx&amp;s2=xx&amp;s3=<b>{sub_id}</b>&amp;click_id=<b>{click_id}</b>',
                        pb: 'https://' + _reportHost + '/postback/?click_id=<b>&lt;click_id&gt;</b>&amp;payout=<b>&lt;payout&gt;</b>'
                    },
                    LOSPOLLOS: {
                        sl: 'https://domain.com/go?s1=<b>{sub_id}</b>&amp;s2=<b>{click_id}</b>',
                        pb: 'https://' + _reportHost + '/postback/?click_id=<b>{clickid}</b>&amp;payout=<b>{payout}</b>'
                    },
                    TRAFEE: {
                        sl: 'https://domain.com/?utm_source=xxx&amp;track=<b>{sub_id}</b>&amp;subsource=<b>{sub_id}</b>&amp;ext_click_id=<b>{click_id}</b>',
                        pb: 'https://' + _reportHost + '/postback/?click_id=<b>{ext_click_id}</b>&amp;payout=<b>{sum}</b>'
                    },
                    CUSTOM: {
                        sl: 'Sesuaikan parameter tracking network Anda.',
                        pb: 'https://' + _reportHost + '/postback/?click_id=<b>{click_id}</b>&amp;payout=<b>{payout}</b>'
                    }
                };

                </script>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
                <button type="button" id="btn_add" class="btn btn-primary">Save</button>
            </div>
        </div>
    </div>
</div>

<div id="edit_model" class="modal fade" data-keyboard="false" data-backdrop="static">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                <h4 class="modal-title">Edit Campaign</h4>
            </div>
            <div class="modal-body">
                <form method="post" id="frm_edit">
                    <input type="hidden" value="edit" name="action" id="action">
                    <input type="hidden" value="0" name="edit_id" id="edit_id">
                    <div class="form-group">
                        <input type="hidden" class="form-control" id="edit_country_code" name="edit_country_code" required="true" readonly="readonly">
                    </div>
                    <div class="form-group">
                        <input type="hidden" class="form-control" id="edit_ua" name="edit_ua" required="true" readonly="readonly">
                    </div>
                    <div class="form-group">
                        <label for="edit_offer" class="control-label">Smartlink:</label>
                        <input type="text" class="form-control" id="edit_offer" name="edit_offer" required>
                    </div>
                    <div class="form-group">
                        <label for="edit_network" class="control-label">Network:</label>
                        <select id="edit_network_sel" class="form-control">
                            <option value="IMONETIZEIT">iMonetizeit</option>
                            <option value="LOSPOLLOS">LosPollos</option>
                            <option value="TRAFEE">Trafee</option>
                            <option value="CUSTOM">Custom</option>
                        </select>
                        <input type="text" class="form-control" id="edit_custom_network" placeholder="Nama network..." style="display:none;margin-top:6px;" autocomplete="off">
                        <input type="hidden" class="form-control" id="edit_network" name="edit_network" required>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
                <button type="button" id="btn_edit" class="btn btn-primary">Save</button>
            </div>
        </div>
    </div>
</div>

<script nonce="<?= adminEsc($nonce); ?>">
    $(document).ready(function() {
        var state = { current: 1, rowCount: 25, search: '', rows: [] };

        function escHtml(v) {
            return String(v === null || v === undefined ? '' : v)
                .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
        }

        function svgIcon(type) {
            var a = ' width="14" height="14" viewBox="0 0 24 24" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"';
            if (type === 'delete') {
                return '<span class="action-ico" aria-hidden="true"><svg' + a + '><path d="M4 7h16"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M6 7l1 13h10l1-13"/><path d="M9 7V4h6v3"/></svg></span>';
            }
            if (type === 'plus') {
                return '<span class="action-ico" aria-hidden="true"><svg' + a + '><path d="M12 5v14"/><path d="M5 12h14"/></svg></span>';
            }
            return '<span class="action-ico" aria-hidden="true"><svg' + a + '><path d="M4 20h4l11-11-4-4L4 16v4z"/><path d="M14 6l4 4"/></svg></span>';
        }

        function renderRow(row, idx) {
            var offer = row.offer === null || row.offer === undefined ? '' : String(row.offer);
            var ccLower = escHtml((row.country_code || '').toLowerCase());
            var ccUpper = escHtml((row.country_code || '').toUpperCase());
            var uaRaw   = String(row.ua || '');
            var uaLower = uaRaw.toLowerCase();
            var deviceCls = uaLower.indexOf('mobile') !== -1 ? ' badge-device--mobile'
                          : uaLower.indexOf('tablet') !== -1 ? ' badge-device--tablet'
                          : '';
            var net    = String(row.network || '');
            var netKey = net.toLowerCase().replace(/[^a-z0-9]/g, '');
            var netCls = 'badge-net badge-net--' + (netKey || 'other');
            return '<tr>' +
                '<td><span class="td-num">' + (idx + 1) + '</span></td>' +
                '<td><span class="td-cc"><span class="flag flag-' + ccLower + '"></span><span class="cc-label">' + ccUpper + '</span></span></td>' +
                '<td><span class="badge-device' + deviceCls + '">' + escHtml(uaRaw) + '</span></td>' +
                '<td><span class="td-smartlink" title="' + escHtml(offer) + '">' + escHtml(offer) + '</span></td>' +
                '<td><span class="' + netCls + '">' + escHtml(net) + '</span></td>' +
                '<td style="text-align:right;white-space:nowrap;">' +
                    '<button type="button" class="btn btn-xs btn-default action-btn command-edit" data-row-id="' + escHtml(row.id) + '" title="Edit" aria-label="Edit">' + svgIcon('edit') + '</button> ' +
                    '<button type="button" class="btn btn-xs btn-default action-btn command-delete" data-row-id="' + escHtml(row.id) + '" title="Delete" aria-label="Delete">' + svgIcon('delete') + '</button>' +
                '</td>' +
            '</tr>';
        }

        function bindRowActions() {
            var tbody = document.querySelector('#tbl_campaigns tbody');
            $(tbody).find('.command-edit').off('click').on('click', function() {
                var rowId = String($(this).data('row-id'));
                var row = state.rows.filter(function(r) { return String(r.id) === rowId; })[0];
                if (!row) return;
                $('#edit_id').val(row.id);
                $('#edit_country_code').val(row.country_code);
                $('#edit_ua').val(row.ua);
                $('#edit_offer').val(row.offer);
                var knownNets = ['IMONETIZEIT','LOSPOLLOS','TRAFEE','CUSTOM'];
                var rowNet = (row.network || '').toUpperCase();
                if (knownNets.indexOf(rowNet) !== -1) {
                    $('#edit_network_sel').val(rowNet);
                    $('#edit_custom_network').hide().val('');
                    $('#edit_network').val(rowNet);
                } else {
                    $('#edit_network_sel').val('CUSTOM');
                    $('#edit_custom_network').show().val(row.network || '');
                    $('#edit_network').val((row.network || '').toUpperCase());
                }
                $('#edit_model').modal('show');
            });
            $(tbody).find('.command-delete').off('click').on('click', function() {
                var rowId = $(this).data('row-id');
                Swal.fire({
                    title: 'Are you sure?',
                    text: "You won't be able to revert this!",
                    type: 'warning',
                    showCancelButton: true,
                    allowOutsideClick: false,
                    confirmButtonColor: '#292b2c',
                    cancelButtonColor: '#9f3138',
                    confirmButtonText: 'Yes, delete it!'
                }).then(function(result) {
                    if (result.value) {
                        $.ajax({
                            type: 'POST', url: 'response.php',
                            data: { id: rowId, action: 'delete' },
                            dataType: 'json',
                            success: function() { loadData(); Swal.fire('Deleted!', 'Your file has been deleted.', 'success'); }
                        });
                    }
                });
            });
        }

        function renderPagination(total, current, rowCount) {
            var info = document.getElementById('tbl-info');
            var pg = document.getElementById('tbl-pagination');
            if (rowCount === -1 || total === 0) {
                info.textContent = total === 0 ? 'No entries' : 'Showing all ' + total + ' entries';
                pg.innerHTML = '';
                return;
            }
            var totalPages = Math.ceil(total / rowCount);
            var start = (current - 1) * rowCount + 1;
            var end = Math.min(current * rowCount, total);
            info.textContent = 'Showing ' + start + '–' + end + ' of ' + total;
            var pages = '<li class="' + (current <= 1 ? 'disabled' : '') + '"><a href="#" data-page="' + (current - 1) + '">&laquo;</a></li>';
            var s = Math.max(1, current - 2), e = Math.min(totalPages, current + 2);
            for (var i = s; i <= e; i++) {
                pages += '<li class="' + (i === current ? 'active' : '') + '"><a href="#" data-page="' + i + '">' + i + '</a></li>';
            }
            pages += '<li class="' + (current >= totalPages ? 'disabled' : '') + '"><a href="#" data-page="' + (current + 1) + '">&raquo;</a></li>';
            pg.innerHTML = pages;
            $(pg).find('a[data-page]').on('click', function(e) {
                e.preventDefault();
                var page = parseInt($(this).data('page'));
                if (page < 1 || page > totalPages) return;
                state.current = page;
                loadData();
            });
        }

        function loadData() {
            var tbody = document.querySelector('#tbl_campaigns tbody');
            tbody.innerHTML = '<tr><td colspan="6" style="padding:24px;text-align:center;color:var(--text)">Loading…</td></tr>';
            $.ajax({
                type: 'POST', url: 'response.php',
                data: { current: state.current, rowCount: state.rowCount, searchPhrase: state.search },
                dataType: 'json',
                success: function(data) {
                    if (!data || !data.rows) {
                        tbody.innerHTML = '<tr><td colspan="6" style="padding:24px;text-align:center;">Error loading data.</td></tr>';
                        return;
                    }
                    state.rows = data.rows;
                    if (data.rows.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="6" style="padding:24px;text-align:center;color:var(--text)">No data available.</td></tr>';
                        document.getElementById('tbl-info').textContent = 'No entries';
                        document.getElementById('tbl-pagination').innerHTML = '';
                    } else {
                        tbody.innerHTML = data.rows.map(function(r, i) { return renderRow(r, i); }).join('');
                        bindRowActions();
                        renderPagination(data.total, data.current, data.rowCount);
                    }
                },
                error: function() {
                    tbody.innerHTML = '<tr><td colspan="6" style="padding:24px;text-align:center;color:var(--danger)">Failed to load data.</td></tr>';
                }
            });
        }

        var searchTimer;
        $('#tbl-search').on('input', function() {
            clearTimeout(searchTimer);
            var val = this.value;
            searchTimer = setTimeout(function() { state.search = val; state.current = 1; loadData(); }, 300);
        });

        $('#tbl-rowcount').on('change', function() {
            state.rowCount = parseInt(this.value); state.current = 1; loadData();
        });

        function ajaxAction(action) {
            $.ajax({
                type: 'POST', url: 'response.php',
                data: $('#frm_' + action).serializeArray(),
                dataType: 'json',
                success: function() { $('#' + action + '_model').modal('hide'); loadData(); }
            });
        }

        function showNetworkHint(net) {
            var h = (typeof _networkHints !== 'undefined') ? _networkHints[net] : null;
            if (!h) { $('#hint-smartlink').hide(); return; }
            $('#hint-sl-line').html(h.sl);
            $('#hint-pb-line').html(h.pb);
            $('#hint-smartlink').show();
        }

        $('#c_net').on('change', function() {
            var val = this.value;
            if (val === 'CUSTOM') {
                $('#custom_network').show().focus();
                $('#network').val('');
            } else {
                $('#custom_network').hide().val('');
                $('#network').val(val);
            }
            showNetworkHint(val);
        });

        $('#custom_network').on('input', function() {
            var v = $.trim($(this).val()).toUpperCase();
            $('#network').val(v);
        });

        $('#command-add').on('click', function() {
            $('#c_net')[0].selectedIndex = 0;
            $('#custom_network').hide().val('');
            $('#country_code').val('global');
            $('#ua').val('global');
            $('#offer').val('');
            $('#network').val('');
            $('#hint-smartlink').hide();
            $('#add_model').modal('show');
        });

        $('#btn_add').on('click', function() {
            if (!$.trim($('#network').val()) || !$.trim($('#offer').val())) {
                Swal.fire({ allowOutsideClick: false, type: 'error', title: 'Oops...', text: 'Something went wrong! {Required all fields}' });
                return false;
            }
            ajaxAction('add');
            return true;
        });

        $('#edit_network_sel').on('change', function() {
            var val = this.value;
            if (val === 'CUSTOM') {
                $('#edit_custom_network').show().focus();
                $('#edit_network').val('');
            } else {
                $('#edit_custom_network').hide().val('');
                $('#edit_network').val(val);
            }
        });

        $('#edit_custom_network').on('input', function() {
            $('#edit_network').val($.trim($(this).val()).toUpperCase());
        });

        $('#btn_edit').on('click', function() { ajaxAction('edit'); });

        loadData();
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
</body>
</html>
