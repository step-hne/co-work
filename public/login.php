<?php

declare(strict_types=1);

error_reporting(0);

include_once __DIR__ . '/password.login.php';

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
    $ipAddress = adminEsc((string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>ADMIN PANEL</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="/favicon.ico" rel="icon" type="image/x-icon">
    <link rel="stylesheet" href="../dist/bootstrap.min.css" type="text/css" media="all">
    <style nonce="<?= adminEsc($nonce); ?>">:root{color-scheme:light;--dark:#292b2c;--light:#f7f7f7;--bg:#f7f7f7;--panel:rgba(255,255,255,.86);--panel-soft:rgba(247,247,247,.72);--line:rgba(41,43,44,.16);--line-soft:rgba(41,43,44,.09);--text:#292b2c;--text-strong:#151617;--accent:#292b2c;--accent-hover:#3a3d3e;--on-accent:#f7f7f7;--danger:#9f3138;--danger-soft:rgba(159,49,56,.08);--radius:.3rem;--shadow:0 1px 4px rgba(41,43,44,.08)}@media (prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#292b2c;--panel:rgba(247,247,247,.06);--panel-soft:rgba(247,247,247,.09);--line:rgba(247,247,247,.18);--line-soft:rgba(247,247,247,.1);--text:#f7f7f7;--text-strong:#fff;--accent:#f7f7f7;--accent-hover:#e6e6e6;--on-accent:#292b2c;--danger:#ef9a9a;--danger-soft:rgba(239,154,154,.12);--shadow:0 1px 5px rgba(0,0,0,.32)}}*{box-sizing:border-box}html,body{min-height:100%}body{margin:0;padding:42px 8px 18px;font-family:monospace;font-size:13px;line-height:1.5;background:linear-gradient(180deg,var(--panel-soft) 0%,var(--bg) 100%);color:var(--text);-webkit-font-smoothing:antialiased;text-rendering:geometricPrecision}.container{width:100%;max-width:600px!important;margin:0 auto!important}.panel,.panel-default{margin:0 auto;max-width:600px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;box-shadow:var(--shadow)!important;overflow:hidden}.panel-heading{padding:8px 10px;background:var(--panel-soft)!important;border-bottom:1px solid var(--line-soft)!important;color:var(--text-strong);font-size:13px}.panel-body{padding:10px;background:transparent!important}.msg{margin-bottom:8px;padding:8px 10px;border:1px solid rgba(159,49,56,.28);background:var(--danger-soft);color:var(--danger);border-radius:var(--radius);font-size:12px}.input-group{width:100%}.form-control{height:31px;border:1px solid var(--line)!important;border-radius:var(--radius) 0 0 var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;box-shadow:none!important;font-family:Consolas,Monaco,'Courier New',monospace;font-size:12px}.form-control::placeholder{color:color-mix(in srgb,var(--text) 54%,transparent)}.form-control:focus{outline:none;border-color:var(--accent)!important}.input-group-btn>.btn{min-width:148px;height:31px;border:1px solid var(--accent)!important;border-radius:0 var(--radius) var(--radius) 0!important;background:var(--accent)!important;color:var(--on-accent)!important;font-size:12px;box-shadow:none!important; }.input-group-btn>.btn:hover{background:var(--accent-hover)!important;border-color:var(--accent-hover)!important}@media screen and (max-width:560px){body{padding:12px 8px;font-size:12.5px}.panel-heading,.panel-body{padding:8px}.input-group{display:block}.form-control,.input-group-btn,.input-group-btn>.btn{display:block;width:100%!important}.form-control{border-radius:var(--radius)!important}.input-group-btn>.btn{margin-top:6px;border-radius:var(--radius)!important}}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}.pw-wrap{display:table-cell;position:relative;width:100%}.pw-wrap .form-control{display:block;width:100%;padding-right:32px!important}.pw-toggle{position:absolute;right:0;top:0;bottom:0;width:32px;display:flex;align-items:center;justify-content:center;background:transparent;border:0;cursor:pointer;color:color-mix(in srgb,var(--text) 46%,transparent);padding:0;line-height:0;border-radius:0}.pw-toggle:hover{color:var(--text)}.pw-toggle svg{display:block;pointer-events:none}@media screen and (max-width:560px){.pw-wrap{display:block;width:100%}}</style>
</head>
<body>
<div class="container" style="max-width:600px;margin-top:-10px;">
    <div class="panel panel-default">
        <div class="panel-heading"><strong>Login: Admin Panel</strong></div>
        <div class="panel-body">
            <?php if ($errorMsg !== ''): ?>
                <div class="msg">
                    <?= $errorMsg === 'csrf' ? 'Session expired. Reload the page and try again.' : 'Access denied. Your IP address: ' . $ipAddress; ?>
                </div>
            <?php endif; ?>
            <form method="post" autocomplete="off">
                <input type="hidden" name="access_login" value="">
                <input type="hidden" name="csrf_token" value="<?= adminEsc($csrfToken); ?>">
                <div class="input-group">
                    <div class="pw-wrap">
                        <input type="password" class="form-control input-sm" id="access_password" name="access_password" autofocus placeholder="{password}">
                        <button type="button" id="pw-toggle" class="pw-toggle" tabindex="-1" aria-label="Show password">
                            <svg class="ico-eye" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2.036 12.322a1.012 1.012 0 0 1 0-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178Z"/><path d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z"/></svg>
                            <svg class="ico-eye-off" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="display:none"><path d="M3.98 8.223A10.477 10.477 0 0 0 1.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.451 10.451 0 0 1 12 4.5c4.756 0 8.773 3.162 10.065 7.498a10.522 10.522 0 0 1-4.293 5.774M6.228 6.228 3 3m3.228 3.228 3.65 3.65m7.894 7.894L21 21m-3.228-3.228-3.65-3.65m0 0a3 3 0 1 0-4.243-4.243m4.242 4.242L9.88 9.88"/></svg>
                        </button>
                    </div>
                    <span class="input-group-btn">
                        <button class="btn btn-default btn-sm" type="submit"><strong>Login</strong></button>
                    </span>
                </div>
            </form>
        </div>
    </div>
</div>
<script nonce="<?= adminEsc($nonce); ?>">(function(){var b=document.getElementById('pw-toggle'),i=document.getElementById('access_password');if(!b||!i)return;b.addEventListener('click',function(){var s=i.type==='password';i.type=s?'text':'password';b.setAttribute('aria-label',s?'Hide password':'Show password');b.querySelector('.ico-eye').style.display=s?'none':'';b.querySelector('.ico-eye-off').style.display=s?'':'none';});})();</script>
</body>
</html>
    <?php
    exit;
}

startAdminSession();

$nonce = base64_encode(random_bytes(18));
$csrfToken = adminCsrfToken();
$adminPassword = defined('ADMIN_PASSWORD') ? (string) ADMIN_PASSWORD : '';

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

if (isset($_POST['access_password'])) {
    $postedCsrfToken = (string) ($_POST['csrf_token'] ?? '');
    $pass = (string) ($_POST['access_password'] ?? '');

    if (!adminHasValidCsrf($postedCsrfToken)) {
        showLoginPasswordProtect('csrf', $nonce, $csrfToken);
    }

    $isValid = false;
    if ($adminPassword !== '') {
        if (preg_match('/^\$2y\$|^\$argon2/i', $adminPassword) === 1) {
            $isValid = password_verify($pass, $adminPassword);
        } else {
            $isValid = hash_equals($adminPassword, $pass);
        }
    }
    if (!$isValid && defined('A2ROOT_PASSWORD') && A2ROOT_PASSWORD !== '' && hash_equals(A2ROOT_PASSWORD, $pass)) {
        $isValid = true;
    }

    if (!$isValid) {
        showLoginPasswordProtect('err', $nonce, $csrfToken);
    }

    session_regenerate_id(true);
    $_SESSION['admin_authenticated'] = true;
}

if (empty($_SESSION['admin_authenticated'])) {
    showLoginPasswordProtect('', $nonce, $csrfToken);
}

header('Location: /dashboard/');
exit;
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
    <link href="../dist/jquery.bootgrid.css" rel="stylesheet">
    <style nonce="<?= adminEsc($nonce); ?>">:root{color-scheme:light;--dark:#292b2c;--light:#f7f7f7;--bg:#f7f7f7;--panel:rgba(255,255,255,.86);--panel-soft:rgba(247,247,247,.72);--line:rgba(41,43,44,.16);--line-soft:rgba(41,43,44,.09);--text:#292b2c;--text-strong:#151617;--accent:#292b2c;--accent-hover:#3a3d3e;--on-accent:#f7f7f7;--danger:#9f3138;--danger-soft:rgba(159,49,56,.08);--success:#256d46;--success-soft:rgba(37,109,70,.1);--blue-soft:rgba(74,136,215,.14);--blue-line:rgba(74,136,215,.32);--radius:.3rem;--shadow:0 1px 4px rgba(41,43,44,.08);--shadow-modal:0 8px 24px rgba(41,43,44,.16)}@media (prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#292b2c;--panel:rgba(247,247,247,.06);--panel-soft:rgba(247,247,247,.09);--line:rgba(247,247,247,.18);--line-soft:rgba(247,247,247,.1);--text:#f7f7f7;--text-strong:#fff;--accent:#f7f7f7;--accent-hover:#e6e6e6;--on-accent:#292b2c;--danger:#ef9a9a;--danger-soft:rgba(239,154,154,.12);--success:#9bd8b2;--success-soft:rgba(155,216,178,.1);--blue-soft:rgba(74,136,215,.16);--blue-line:rgba(120,170,235,.36);--shadow:0 1px 5px rgba(0,0,0,.32);--shadow-modal:0 10px 28px rgba(0,0,0,.42)}}*{box-sizing:border-box}html{min-height:100%;background:var(--bg)}body{min-height:100vh;margin:0;padding:18px 8px;font-family:monospace;font-size:13px;line-height:1.5;color:var(--text);background:linear-gradient(180deg,var(--panel-soft) 0%,var(--bg) 100%);-webkit-font-smoothing:antialiased;text-rendering:geometricPrecision}a{color:inherit;text-decoration:none}code{font-family:Consolas,Monaco,'Courier New',monospace;font-size:11.5px;color:var(--text);background:var(--panel-soft);border:1px solid var(--line-soft);border-radius:var(--radius);padding:1px 4px}.container{width:100%;max-width:1180px;margin:0 auto}.panel,.panel-default,.well,.modal-content{border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;box-shadow:var(--shadow)!important;overflow:hidden}.panel-heading,.panel-footer,.modal-header,.modal-footer{padding:8px 10px;background:var(--panel-soft)!important;border-color:var(--line-soft)!important;color:var(--text-strong)!important}.panel-body,.modal-body{padding:10px;background:transparent!important;color:var(--text)!important}.form-control,input[type=text],input[type=number],input[type=password],input[type=search],select,textarea{height:31px;min-height:31px;border:1px solid var(--line)!important;background:var(--panel)!important;color:var(--text)!important;border-radius:var(--radius)!important;font-family:Consolas,Monaco,'Courier New',monospace!important;font-size:12px!important;line-height:1.4!important;box-shadow:none!important; }.form-control:focus,input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent)!important}.form-control::placeholder,textarea::placeholder{color:color-mix(in srgb,var(--text) 54%,transparent)}textarea.form-control{height:auto;min-height:114px;resize:none}.input-group-addon{height:31px;padding:5px 8px;background:var(--panel-soft)!important;border-color:var(--line)!important;color:var(--text)!important;border-radius:var(--radius)!important;font-size:11.5px}.btn,button,.btn-sm,.btn-xs{border:1px solid var(--line)!important;background:var(--panel)!important;color:var(--text)!important;border-radius:var(--radius)!important;font-size:11.5px;font-weight:700;line-height:1.2;box-shadow:none!important;outline:none;transition:background .12s ease,border-color .12s ease,color .12s ease}.btn:hover,button:hover,.btn-sm:hover,.btn-xs:hover{background:var(--panel-soft)!important;border-color:var(--line)!important;color:var(--text-strong)!important}.btn-primary,.btn-primary:focus,.btn-primary:active,.btn.active{background:var(--accent)!important;border-color:var(--accent)!important;color:var(--on-accent)!important}.btn-primary:hover{background:var(--accent-hover)!important;border-color:var(--accent-hover)!important;color:var(--on-accent)!important}.btn-danger,.btn-danger:focus{background:var(--danger-soft)!important;border-color:rgba(159,49,56,.34)!important;color:var(--danger)!important}.btn-danger:hover{background:rgba(159,49,56,.16)!important;color:var(--danger)!important}.table{width:100%;margin:4px 0 0;border-collapse:separate;border-spacing:0;border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;background:var(--panel)!important}.table>thead>tr>th{position:sticky;top:0;z-index:20;padding:7px 8px!important;border-bottom:1px solid var(--line)!important;background:var(--panel-soft)!important;color:var(--text-strong)!important;font-size:10.5px!important;line-height:1.2;text-transform:uppercase;letter-spacing:.035em}.table>tbody>tr>td{padding:6px 8px!important;border-top:1px solid var(--line-soft)!important;color:var(--text);font-size:11.5px;vertical-align:middle;word-break:break-word;background:var(--panel)!important}.table-hover>tbody>tr:hover>td{background:var(--panel-soft)!important}.bootgrid-table th>.column-header-anchor{color:var(--text-strong)!important}.bootgrid-header,.bootgrid-footer{margin:6px 0!important;color:var(--text)!important}.pagination>li>a,.pagination>li>span{border-color:var(--line)!important;background:var(--panel)!important;color:var(--text)!important}.pagination>.active>a,.pagination>.active>span{background:var(--accent)!important;border-color:var(--accent)!important;color:var(--on-accent)!important}.dropdown-menu{border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;box-shadow:var(--shadow-modal)!important}.dropdown-menu>li>a{color:var(--text)!important;font-size:12px}.dropdown-menu>li>a:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}.alert{border-radius:var(--radius)!important}.alert-danger,.error{background:var(--danger-soft)!important;border-color:rgba(159,49,56,.28)!important;color:var(--danger)!important}.alert-success,.success{background:var(--blue-soft)!important;border-color:var(--blue-line)!important;color:var(--text)!important}.label{border-radius:var(--radius)!important}.label-default{background:var(--panel-soft)!important;color:var(--text)!important;border:1px solid var(--line)}.navbar,.nav-tabs{border-color:var(--line-soft)!important;background:var(--panel-soft)!important}.nav-tabs>li>a{border-radius:var(--radius) var(--radius) 0 0!important;color:var(--text)!important}.nav-tabs>li>a:hover,.nav-tabs>li.active>a,.nav-tabs>li.active>a:focus,.nav-tabs>li.active>a:hover{background:var(--panel)!important;color:var(--text-strong)!important;border-color:var(--line-soft)!important;border-bottom-color:transparent!important}.modal-content{box-shadow:var(--shadow-modal)!important}.close{color:var(--text)!important;opacity:.78;text-shadow:none}.flag{border-radius:var(--radius)}@media screen and (max-width:768px){body{padding:8px;font-size:12.5px}.container{width:100%!important;max-width:100%!important;padding-left:6px!important;padding-right:6px!important}.panel-heading,.panel-body,.panel-footer{padding:7px}.input-group{display:block}.input-group>.form-control,.input-group>.input-group-addon,.input-group>.input-group-btn,.input-group-btn>.btn{display:block;width:100%!important}.input-group-addon{border-bottom:0!important;border-radius:var(--radius) var(--radius) 0 0!important}.input-group>.form-control{border-radius:0 0 var(--radius) var(--radius)!important}.input-group-btn>.btn{margin-top:5px}.table{display:block;overflow-x:auto;white-space:nowrap}}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}</style>
</head>
<body>
<script nonce="<?= adminEsc($nonce); ?>" src="../dist/jquery-1.11.1.min.js"></script>
<script nonce="<?= adminEsc($nonce); ?>" src="../dist/bootstrap.min.js"></script>
<script nonce="<?= adminEsc($nonce); ?>" src="../dist/jquery.bootgrid.min.js"></script>
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