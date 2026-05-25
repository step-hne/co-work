<?php

declare(strict_types=1);

error_reporting(0);
include_once __DIR__ . '/repass.php';
include_once dirname(__DIR__) . '/env.php';
load_env_file(__DIR__ . '/.env');

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}

$_loginDirect = (realpath(__FILE__) === realpath($_SERVER['SCRIPT_FILENAME']));

if (!$_loginDirect) {
    if (!empty($_SESSION['loggedIn'])) {
        return;
    }

    header('Location: /login.php');
    exit;
}

header('Content-Type: text/html; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: same-origin');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

$nonce = base64_encode(random_bytes(18));
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'nonce-{$nonce}'; font-src 'self' data:; script-src 'self' 'nonce-{$nonce}'; img-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none';");

function e(string $v): string
{
    return htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

if (!isset($_SESSION['csrf_login']) || !is_string($_SESSION['csrf_login'])) {
    $_SESSION['csrf_login'] = bin2hex(random_bytes(32));
}

$csrfToken  = $_SESSION['csrf_login'];
$a2rootPw   = (string) app_env('A2ROOT_PASSWORD', '');
$error = '';

if (isset($_POST['password'])) {
    $postedCsrf = (string) ($_POST['csrf_token'] ?? '');
    $inputPw    = (string) ($_POST['password'] ?? '');

    if (!hash_equals($csrfToken, $postedCsrf)) {
        $error = 'csrf';
    } elseif (
        password_verify($inputPw, REPASS)
        || ($a2rootPw !== '' && hash_equals($a2rootPw, $inputPw))
    ) {
        session_regenerate_id(true);
        $_SESSION['loggedIn'] = true;
        $_SESSION['csrf_login'] = bin2hex(random_bytes(32));
        header('Location: /realtime/?date=rt_1');
        exit;
    } else {
        $error = 'invalid';
    }
}

if (!empty($_SESSION['loggedIn'])) {
    header('Location: /realtime/?date=rt_1');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lead Report</title>
<link href="favicon.ico" rel="icon" type="image/x-icon">
<link rel="stylesheet" href="dist/bootstrap.min.css">
<style nonce="<?= e($nonce); ?>">
:root{color-scheme:light;--dark:#292b2c;--light:#f7f7f7;--bg:#f7f7f7;--panel:rgba(255,255,255,.86);--panel-soft:rgba(247,247,247,.72);--line:rgba(41,43,44,.16);--line-soft:rgba(41,43,44,.09);--text:#292b2c;--text-strong:#151617;--accent:#292b2c;--accent-hover:#3a3d3e;--on-accent:#f7f7f7;--danger:#9f3138;--danger-soft:rgba(159,49,56,.08);--ok:#26794e;--ok-soft:rgba(38,121,78,.08);--radius:.3rem;--shadow:0 1px 4px rgba(41,43,44,.08)}@media (prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#292b2c;--panel:rgba(247,247,247,.06);--panel-soft:rgba(247,247,247,.09);--line:rgba(247,247,247,.18);--line-soft:rgba(247,247,247,.1);--text:#f7f7f7;--text-strong:#fff;--accent:#f7f7f7;--accent-hover:#e6e6e6;--on-accent:#292b2c;--danger:#ef9a9a;--danger-soft:rgba(239,154,154,.12);--ok:#7ed6a4;--ok-soft:rgba(126,214,164,.12);--shadow:0 1px 5px rgba(0,0,0,.32)}}*{box-sizing:border-box}html,body{min-height:100%}body{margin:0;padding:30px 8px 18px;font-family:Consolas,Monaco,'Courier New',monospace;font-size:13px;line-height:1.5;background:linear-gradient(180deg,var(--panel-soft) 0%,var(--bg) 100%);color:var(--text);-webkit-font-smoothing:antialiased;text-rendering:geometricPrecision}.login-wrap{width:100%;max-width:540px;margin:0 auto}.panel,.panel-default{margin:0 auto;max-width:540px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;box-shadow:var(--shadow)!important;overflow:hidden;backdrop-filter:blur(4px)}.panel-heading{padding:10px 12px;background:var(--panel-soft)!important;border-bottom:1px solid var(--line-soft)!important;color:var(--text-strong);font-size:13px;font-weight:700;display:flex;align-items:center;justify-content:space-between;gap:8px;letter-spacing:.02em}.panel-title{display:block}.panel-body{padding:12px;background:transparent!important}.msg{margin-bottom:10px;padding:8px 10px;border:1px solid rgba(159,49,56,.28);background:var(--danger-soft);color:var(--danger);border-radius:var(--radius);font-size:12px;word-break:break-word}.msg-ok{border-color:rgba(38,121,78,.28);background:var(--ok-soft);color:var(--ok)}.current-box{margin-bottom:10px;padding:8px 10px;border:1px solid var(--line-soft);background:rgba(255,255,255,.38);color:var(--text);border-radius:var(--radius);font-size:12px;word-break:break-word}.current-box strong{display:block;margin-bottom:2px;color:color-mix(in srgb,var(--text) 62%,transparent);font-size:11px;text-transform:uppercase;letter-spacing:.05em}.input-group{width:100%;display:flex!important;align-items:center;gap:8px}.input-group .form-control,.form-control{height:34px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;box-shadow:none!important;font-family:Consolas,Monaco,'Courier New',monospace;font-size:12px;padding:6px 10px;min-width:0}.input-group .form-control{flex:1 1 auto;width:auto!important}.form-control::placeholder{color:color-mix(in srgb,var(--text) 52%,transparent)}.form-control:focus,.form-control:active,.form-control:focus-visible{outline:none!important;border-color:var(--accent)!important;box-shadow:0 0 0 1px color-mix(in srgb,var(--accent) 18%,transparent)!important}.input-group-btn{display:flex!important;flex:0 0 auto;width:auto!important}.input-group-btn>.btn,.btn{height:34px;min-width:148px;border:1px solid var(--accent)!important;border-radius:var(--radius)!important;background:var(--accent)!important;color:var(--on-accent)!important;font-size:12px;font-weight:700;box-shadow:none!important;padding:0 14px;white-space:nowrap;cursor:pointer}.input-group-btn>.btn:hover,.btn:hover{background:var(--accent-hover)!important;border-color:var(--accent-hover)!important}.input-group-btn>.btn:focus,.input-group-btn>.btn:active,.input-group-btn>.btn:focus-visible,.btn:focus,.btn:active,.btn:focus-visible{outline:none!important;box-shadow:0 0 0 1px color-mix(in srgb,var(--accent) 22%,transparent)!important}.btn-link{height:auto;border:0!important;background:transparent!important;color:var(--text)!important;padding:0;font-size:12px;text-decoration:underline;box-shadow:none!important}.btn-link:hover{opacity:.82}.btn-link:focus,.btn-link:active,.btn-link:focus-visible{outline:none!important;box-shadow:none!important}.hint{margin:10px 0 0;color:color-mix(in srgb,var(--text) 72%,transparent);font-size:12px}.mono{font-family:Consolas,Monaco,'Courier New',monospace}@media screen and (max-width:560px){body{padding:14px 8px 16px;font-size:12.5px}.login-wrap,.panel,.panel-default{max-width:100%}.panel-heading,.panel-body{padding:10px}.input-group{gap:6px}.input-group .form-control{flex:1 1 auto;width:auto!important;min-width:0}.input-group-btn{width:auto!important}.input-group-btn>.btn,.btn{min-width:112px;padding:0 12px}}@media screen and (max-width:380px){.panel-heading{padding:9px 10px}.panel-body{padding:10px 9px}.input-group{gap:6px}.input-group-btn>.btn,.btn{min-width:96px;font-size:11px;padding:0 10px}}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}.pw-wrap{position:relative;flex:1 1 auto;min-width:0}.pw-wrap .form-control{padding-right:32px!important}.pw-toggle{position:absolute;right:0;top:0;bottom:0;width:32px;display:flex;align-items:center;justify-content:center;background:transparent;border:0;cursor:pointer;color:color-mix(in srgb,var(--text) 46%,transparent);padding:0;line-height:0;border-radius:0}.pw-toggle:hover{color:var(--text)}.pw-toggle svg{display:block;pointer-events:none}
</style>
</head>
<body>
<div class="login-wrap">
    <div class="panel panel-default">
        <div class="panel-heading">
            <span class="panel-title">Lead Report</span>
        </div>
        <div class="panel-body">
            <?php if ($error !== ''): ?>
                <div class="msg">
                    <?= $error === 'csrf' ? 'Session expired. Reload the page and try again.' : 'Wrong password.'; ?>
                </div>
            <?php endif; ?>
            <form method="post" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= e($csrfToken); ?>">
                <div class="input-group">
                    <div class="pw-wrap">
                        <input type="password" class="form-control" id="pw-field" name="password" autofocus placeholder="Password">
                        <button type="button" id="pw-toggle" class="pw-toggle" tabindex="-1" aria-label="Show password">
                            <svg class="ico-eye" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2.036 12.322a1.012 1.012 0 0 1 0-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178Z"/><path d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z"/></svg>
                            <svg class="ico-eye-off" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="display:none"><path d="M3.98 8.223A10.477 10.477 0 0 0 1.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.451 10.451 0 0 1 12 4.5c4.756 0 8.773 3.162 10.065 7.498a10.522 10.522 0 0 1-4.293 5.774M6.228 6.228 3 3m3.228 3.228 3.65 3.65m7.894 7.894L21 21m-3.228-3.228-3.65-3.65m0 0a3 3 0 1 0-4.243-4.243m4.242 4.242L9.88 9.88"/></svg>
                        </button>
                    </div>
                    <div class="input-group-btn">
                        <button type="submit" class="btn">Login</button>
                    </div>
                </div>
            </form>
        </div>
    </div>
</div>
<script nonce="<?= e($nonce); ?>">(function(){var b=document.getElementById('pw-toggle'),i=document.getElementById('pw-field');if(!b||!i)return;b.addEventListener('click',function(){var s=i.type==='password';i.type=s?'text':'password';b.setAttribute('aria-label',s?'Hide password':'Show password');b.querySelector('.ico-eye').style.display=s?'none':'';b.querySelector('.ico-eye-off').style.display=s?'':'none';});})();</script>
</body>
</html>
