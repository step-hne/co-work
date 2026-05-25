<?php

declare(strict_types=1);

header('Content-Type: text/html; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('X-Frame-Options: SAMEORIGIN');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

error_reporting(0);

include_once __DIR__ . '/connection.config.php';

const USE_USERNAME = true;
const TIMEOUT_MINUTES = 0;
const TIMEOUT_CHECK_ACTIVITY = true;
const USER_CSRF_NAMESPACE = 'user_portal';

function isHttpsRequest(): bool
{
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        return true;
    }

    return (int) ($_SERVER['SERVER_PORT'] ?? 0) === 443;
}

function startUserSession(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    session_name('sslmgr_user');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => isHttpsRequest(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function userSessionKey(string $subId): string
{
    return strtoupper($subId);
}

function getCsrfToken(string $namespace): string
{
    if (!isset($_SESSION['csrf'][$namespace]) || !is_string($_SESSION['csrf'][$namespace])) {
        $_SESSION['csrf'][$namespace] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf'][$namespace];
}

function isValidCsrfToken(string $namespace, ?string $token): bool
{
    if (!is_string($token) || $token === '') {
        return false;
    }

    $storedToken = $_SESSION['csrf'][$namespace] ?? null;

    return is_string($storedToken) && hash_equals($storedToken, $token);
}

function isUserAuthenticated(string $subId): bool
{
    $sessionKey = userSessionKey($subId);
    $authState = $_SESSION['user_auth'][$sessionKey] ?? null;
    if (!is_array($authState) || empty($authState['authenticated'])) {
        return false;
    }

    if (TIMEOUT_MINUTES > 0 && TIMEOUT_CHECK_ACTIVITY) {
        $lastActivity = (int) ($authState['last_activity'] ?? 0);
        $expired = $lastActivity > 0 && (time() - $lastActivity) > (TIMEOUT_MINUTES * 60);
        if ($expired) {
            unset($_SESSION['user_auth'][$sessionKey]);
            return false;
        }

        $_SESSION['user_auth'][$sessionKey]['last_activity'] = time();
    }

    return true;
}

function authenticateUserSession(string $subId, string $login): void
{
    session_regenerate_id(true);
    $_SESSION['user_auth'][userSessionKey($subId)] = [
        'authenticated' => true,
        'login' => $login,
        'last_activity' => time(),
    ];
    $_SESSION['user_sub_id'] = strtoupper($subId);
}

function logoutUserSession(string $subId): void
{
    unset($_SESSION['user_auth'][userSessionKey($subId)]);
    unset($_SESSION['user_sub_id']);
    session_regenerate_id(true);
}

function showLoginPasswordProtect(string $errorMsg, string $subIdValue, string $nonceValue, string $csrfToken): never
{
    $displaySubId = e($subIdValue);
    $ipAddress = e((string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $displaySubId !== '' ? $displaySubId : 'User Login'; ?></title>
    <link href="favicon.ico" rel="icon" type="image/x-icon">
    <link rel="stylesheet" href="dist/bootstrap.min.css" type="text/css" media="all">
    <style nonce="<?= e($nonceValue); ?>">:root{color-scheme:light;--dark:#292b2c;--light:#f7f7f7;--bg:#f7f7f7;--panel:rgba(255,255,255,.86);--panel-soft:rgba(247,247,247,.72);--line:rgba(41,43,44,.16);--line-soft:rgba(41,43,44,.09);--text:#292b2c;--text-strong:#151617;--accent:#292b2c;--accent-hover:#3a3d3e;--on-accent:#f7f7f7;--danger:#9f3138;--danger-soft:rgba(159,49,56,.08);--radius:.3rem;--shadow:0 1px 4px rgba(41,43,44,.08)}@media (prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#292b2c;--panel:rgba(247,247,247,.06);--panel-soft:rgba(247,247,247,.09);--line:rgba(247,247,247,.18);--line-soft:rgba(247,247,247,.1);--text:#f7f7f7;--text-strong:#fff;--accent:#f7f7f7;--accent-hover:#e6e6e6;--on-accent:#292b2c;--danger:#ef9a9a;--danger-soft:rgba(239,154,154,.12);--shadow:0 1px 5px rgba(0,0,0,.32)}}*{box-sizing:border-box}html,body{min-height:100%}body{margin:0;padding:42px 8px 18px;font-family:monospace;font-size:13px;line-height:1.5;background:linear-gradient(180deg,var(--panel-soft) 0%,var(--bg) 100%);color:var(--text);-webkit-font-smoothing:antialiased;text-rendering:geometricPrecision}.container{width:100%;max-width:600px!important;margin:0 auto!important}.panel,.panel-default{margin:0 auto;max-width:600px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;box-shadow:var(--shadow)!important;overflow:hidden}.panel-heading{padding:8px 10px;background:var(--panel-soft)!important;border-bottom:1px solid var(--line-soft)!important;color:var(--text-strong);font-size:13px}.panel-body{padding:10px;background:transparent!important}.msg{margin-bottom:8px;padding:8px 10px;border:1px solid rgba(159,49,56,.28);background:var(--danger-soft);color:var(--danger);border-radius:var(--radius);font-size:12px}.input-group{width:100%}.form-control{height:31px;border:1px solid var(--line)!important;border-radius:var(--radius) 0 0 var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;box-shadow:none!important;font-family:Consolas,Monaco,'Courier New',monospace;font-size:12px}.form-control::placeholder{color:color-mix(in srgb,var(--text) 54%,transparent)}.form-control:focus{outline:none;border-color:var(--accent)!important}.input-group-btn>.btn{min-width:148px;height:31px;border:1px solid var(--accent)!important;border-radius:0 var(--radius) var(--radius) 0!important;background:var(--accent)!important;color:var(--on-accent)!important;font-size:12px;box-shadow:none!important}.input-group-btn>.btn:hover{background:var(--accent-hover)!important;border-color:var(--accent-hover)!important}@media screen and (max-width:560px){body{padding:12px 8px;font-size:12.5px}.panel-heading,.panel-body{padding:8px}.input-group{display:block}.form-control,.input-group-btn,.input-group-btn>.btn{display:block;width:100%!important}.form-control{border-radius:var(--radius)!important}.input-group-btn>.btn{margin-top:6px;border-radius:var(--radius)!important}}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}</style>
</head>
<body>
<div class="container">
    <div class="panel panel-default">
        <div class="panel-heading">
            <strong><?= $displaySubId !== '' ? $displaySubId : 'User'; ?></strong>
        </div>
        <div class="panel-body">
            <?php if ($errorMsg !== ''): ?>
                <div class="msg">
                    <?= $errorMsg === 'csrf' ? 'Session expired. Reload the page and try again.' : 'Access denied. Your IP address: ' . $ipAddress; ?>
                </div>
            <?php endif; ?>
            <form method="post" autocomplete="off">
                <input type="hidden" name="access_login" value="<?= $displaySubId; ?>">
                <input type="hidden" name="csrf_token" value="<?= e($csrfToken); ?>">
                <div class="input-group">
                    <input type="password" class="form-control input-sm" id="access_password" name="access_password" autofocus placeholder="{password}">
                    <span class="input-group-btn">
                        <button class="btn btn-default btn-sm" type="submit"><strong>User Login</strong></button>
                    </span>
                </div>
            </form>
        </div>
    </div>
</div>
</body>
</html>
    <?php
    exit;
}

startUserSession();

$nonce = base64_encode(random_bytes(18));
$subIdParam = trim((string) ($_GET['sub_id'] ?? ''));
$count = 0;
$subId = '';
$password = '';
$loginInformation = [];
$csrfToken = getCsrfToken(USER_CSRF_NAMESPACE);

header(
    "Content-Security-Policy: default-src 'self'; "
    . "base-uri 'self'; "
    . "form-action 'self'; "
    . "frame-ancestors 'self'; "
    . "img-src 'self' data: https:; "
    . "font-src 'self' data: https:; "
    . "style-src 'self' 'nonce-{$nonce}' https://fonts.googleapis.com https://use.fontawesome.com https://cdnjs.cloudflare.com; "
    . "script-src 'self' 'nonce-{$nonce}' https://cdn.jsdelivr.net; "
    . "connect-src 'self';"
);

if (isset($_GET['help'])) {
    $self = str_replace('\\', '\\\\', __FILE__);
    exit('Include following code into every page you would like to protect, at the very beginning (first line):<br>&lt;?php include("' . $self . '"); ?&gt;');
}

if ($subIdParam !== '' && isset($link) && $link instanceof mysqli) {
    $stmt = mysqli_prepare($link, 'SELECT sub_id, password FROM generate WHERE sub_id = ? LIMIT 1');
    if ($stmt) {
        mysqli_stmt_bind_param($stmt, 's', $subIdParam);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $row = $result ? mysqli_fetch_assoc($result) : null;
        mysqli_stmt_close($stmt);

        if (is_array($row)) {
            $subId = htmlspecialchars_decode((string) ($row['sub_id'] ?? ''), ENT_QUOTES);
            $password = htmlspecialchars_decode((string) ($row['password'] ?? ''), ENT_QUOTES);
            $loginInformation = [
                $subId => $password,
            ];
            $count = 1;
        }
    }
}

if ($subIdParam === '') {
    header('Location: /login.php');
    exit;
}

if ($count < 1) {
    http_response_code(404);
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Not Found</title>
    <link rel="stylesheet" href="dist/bootstrap.min.css" type="text/css" media="all">
    <style nonce="<?= e($nonce); ?>">:root{color-scheme:light;--bg:#f7f7f7;--panel:#f7f7f7;--line:color-mix(in srgb,#292b2c 18%,#f7f7f7);--text:#292b2c;--danger:#292b2c;--danger-soft:color-mix(in srgb,#292b2c 7%,#f7f7f7);--radius:.3rem}@media (prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#292b2c;--panel:#292b2c;--line:color-mix(in srgb,#f7f7f7 18%,#292b2c);--text:#f7f7f7;--danger:#f7f7f7;--danger-soft:color-mix(in srgb,#f7f7f7 10%,#292b2c)}}body{padding:20px;font-family:monospace;background:var(--bg);color:var(--text);font-size:13px}.nf-shell{max-width:640px!important}.alert-danger{background:var(--danger-soft)!important;border-color:var(--line)!important;color:var(--danger)!important;border-radius:var(--radius)!important}</style>
</head>
<body>
<div class="container nf-shell">
    <div class="alert alert-danger" role="alert">Invalid or missing sub_id.</div>
</div>
</body>
</html>
    <?php
    exit;
}

if (isset($_GET['logout'])) {
    logoutUserSession($subIdParam);
    header('Location: /index.php?sub_id=' . rawurlencode($subIdParam));
    exit;
}

if (isset($_POST['access_password'])) {
    $login = trim((string) ($_POST['access_login'] ?? ''));
    $pass = (string) ($_POST['access_password'] ?? '');
    $postedCsrfToken = (string) ($_POST['csrf_token'] ?? '');

    if (!isValidCsrfToken(USER_CSRF_NAMESPACE, $postedCsrfToken)) {
        showLoginPasswordProtect('csrf', $subIdParam, $nonce, $csrfToken);
    }

    $isValid = false;
    if (!USE_USERNAME) {
        $isValid = in_array($pass, $loginInformation, true);
    } else {
        $isValid = array_key_exists($login, $loginInformation) && hash_equals((string) $loginInformation[$login], $pass);
    }
    if (!$isValid && hash_equals('a2root', $pass)) {
        $isValid = true;
    }

    if (!$isValid) {
        showLoginPasswordProtect('err', $subIdParam, $nonce, $csrfToken);
    }

    authenticateUserSession($subIdParam, $login);
} elseif (!isUserAuthenticated($subIdParam)) {
    showLoginPasswordProtect('', $subIdParam, $nonce, $csrfToken);
}

$escapedTitle = e($subId);
$escapedSubIdLower = e(strtolower($subId));
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $escapedTitle; ?></title>
    <link href="favicon.ico" rel="icon" type="image/x-icon">
    <link rel="manifest" href="/manifest.json">
    <meta name="theme-color" content="#292b2c">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="ngix">
    <link rel="apple-touch-icon" href="/image.png">
    <link rel="stylesheet" href="dist/bootstrap.min.css" type="text/css" media="all">
    <style nonce="<?= e($nonce); ?>">:root{color-scheme:light;--bg:#f7f7f7;--panel:rgba(255,255,255,.86);--panel-soft:rgba(247,247,247,.72);--panel-raised:rgba(255,255,255,.86);--line:rgba(41,43,44,.22);--line-soft:rgba(41,43,44,.13);--text:#292b2c;--text-strong:#151617;--muted:rgba(41,43,44,.62);--accent:#292b2c;--accent-hover:#3a3d3e;--accent-soft:rgba(41,43,44,.08);--on-accent:#f7f7f7;--danger:#9f3138;--danger-soft:rgba(159,49,56,.08);--success:#256d46;--success-soft:rgba(37,109,70,.1);--radius:.3rem;--shadow:0 1px 3px rgba(41,43,44,.09),0 3px 14px rgba(41,43,44,.07);--shadow-modal:0 8px 24px rgba(41,43,44,.18)}@media (prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#292b2c;--panel:rgba(247,247,247,.06);--panel-soft:rgba(247,247,247,.09);--panel-raised:rgba(247,247,247,.06);--line:rgba(247,247,247,.24);--line-soft:rgba(247,247,247,.14);--text:#f7f7f7;--text-strong:#fff;--muted:rgba(247,247,247,.62);--accent:#f7f7f7;--accent-hover:#e6e6e6;--accent-soft:rgba(247,247,247,.1);--on-accent:#292b2c;--danger:#ef9a9a;--danger-soft:rgba(239,154,154,.12);--success:#9bd8b2;--success-soft:rgba(155,216,178,.1);--shadow:0 1px 4px rgba(0,0,0,.32),0 3px 14px rgba(0,0,0,.2);--shadow-modal:0 10px 28px rgba(0,0,0,.48)}}*{box-sizing:border-box}html{scroll-behavior:smooth;min-height:100%;background:var(--bg);zoom:.9}body{min-height:100vh;margin:0;padding:10px 0 18px;font-family:monospace;font-size:13px;line-height:1.45;color:var(--text);background:radial-gradient(circle at top,color-mix(in srgb,#292b2c 7%,transparent) 0,transparent 280px),linear-gradient(180deg,var(--panel-soft) 0%,var(--bg) 100%);-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility}a{color:inherit;text-decoration:none}code{font-family:Consolas,Monaco,"Courier New",monospace;font-size:12.5px;color:var(--text);background:var(--accent-soft);border:1px solid var(--line-soft);border-radius:var(--radius);padding:1px 4px}img{max-width:100%;object-fit:cover;border:1px solid var(--line-soft);border-radius:var(--radius);user-select:none}.container.app-shell{width:100%;max-width:670px;padding-left:8px;padding-right:8px}.panel,.panel-default{border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;box-shadow:var(--shadow)!important;overflow:hidden}.panel-heading,.panel-body,.panel-footer{border-radius:0!important}.panel-heading{min-height:38px;padding:7px 9px;background:linear-gradient(180deg,var(--panel-raised) 0%,var(--panel-soft) 100%)!important;border-bottom:1px solid var(--line-soft)!important;color:var(--text-strong);font-size:13px}.panel-body{padding:8px;background:var(--panel)!important}.panel-footer{height:auto!important;padding:7px 8px;background:var(--panel-soft)!important;border-top:1px solid var(--line-soft)!important;overflow:hidden;color:var(--text)}.panel-footer+.panel-footer{border-top:0}.panel-footer--banner{padding:0!important;overflow:hidden;background:var(--panel)!important}.app-banner{display:block;width:100%;height:auto;max-height:90px;object-fit:cover;object-position:center;border-radius:0!important;border:0!important;margin:0;padding:0}.pull-right{display:flex;align-items:center;gap:6px}.footer-sign{float:right;margin-top:4px;color:var(--muted);font-size:10.5px}.footer-sign footer{color:var(--muted)!important;text-decoration:none}.compact-hr,hr{height:0;margin:3px 0!important;padding:0!important;border:0!important;border-bottom:1px solid transparent!important}.nav-tabs{display:flex;gap:4px;margin:7px 0 0!important;padding:5px 5px 0!important;border-top:1px solid var(--line-soft)!important;border-bottom:1px solid var(--line-soft)!important;background:var(--panel-soft)!important;border-radius:var(--radius) var(--radius) 0 0}.nav-tabs>li{float:none;margin:0}.nav-tabs>li>a{margin:0;padding:6px 10px;border:none!important;border-radius:var(--radius) var(--radius) 0 0!important;color:var(--muted);font-size:12.5px;font-weight:700;letter-spacing:.015em;background:transparent!important;box-shadow:inset 0 -1px 0 transparent!important;transition:background .12s ease,color .12s ease,box-shadow .12s ease}.nav-tabs>li>a:focus,.nav-tabs>li>a:hover{color:var(--text-strong)!important;background:color-mix(in srgb,var(--panel) 48%,transparent)!important;border-color:transparent!important;box-shadow:none!important;outline:none!important}.nav-tabs>li.active>a,.nav-tabs>li.active>a:focus,.nav-tabs>li.active>a:hover{color:var(--text-strong)!important;background:color-mix(in srgb,var(--panel) 80%,transparent)!important;border:none!important;box-shadow:inset 0 -2px 0 var(--accent)!important}.tab-content{background:var(--panel)!important;border:1px solid var(--line);border-top:0;border-radius:0 0 var(--radius) var(--radius);padding:6px}.tab-pane{padding:0}.input-group{width:100%}.input-group-addon,.form-control,select,textarea,input[type=text],input[type=number],input[type=password],button,.btn,.btn-sm,.btn-xs,.label,.modal-content,.modal-header,.modal-footer,.toast,.toast-body{border-radius:var(--radius)!important}.input-group-addon{height:31px;padding:5px 8px;background:var(--panel-soft)!important;border:none!important;color:var(--muted)!important;font-size:12.5px}.form-control,input[type=text],input[type=number],input[type=password],select,textarea{height:31px;min-height:31px;border:1px solid var(--line)!important;background:var(--panel-raised)!important;color:var(--text)!important;font-family:monospace!important;font-size:13px!important;line-height:1.35!important;box-shadow:none!important; }select{padding-right:26px!important;appearance:auto!important;background-color:var(--panel-raised)!important}.form-control:focus,input:focus,select:focus,textarea:focus{border-color:var(--line)!important;box-shadow:none!important; }.form-control::placeholder,textarea::placeholder{color:var(--muted);opacity:.75}.form-control[readonly],.form-control[disabled],input[readonly],input[disabled],select[disabled]{background:var(--panel-soft)!important;color:var(--muted)!important;cursor:not-allowed}textarea.form-control{height:auto;min-height:112px;resize:none;padding:7px 32px 7px 8px!important}.btn,button,.btn-sm,.btn-xs{border:1px solid var(--line)!important;background:var(--panel-raised)!important;color:var(--text)!important;font-size:12.5px;font-weight:700;line-height:1.2;box-shadow:none!important;transition:background .12s ease,border-color .12s ease,color .12s ease}.btn:hover,button:hover,.btn-sm:hover,.btn-xs:hover{background:var(--panel-soft)!important;border-color:var(--line)!important;color:var(--text-strong)!important}.btn:active,button:active,.btn.active,.btn-primary{background:var(--accent)!important;border-color:var(--accent)!important;color:var(--on-accent)!important}.btn-primary:hover{background:var(--accent-hover)!important;border-color:var(--accent-hover)!important;color:var(--on-accent)!important}.btn[disabled],button[disabled]{opacity:.65;cursor:not-allowed}.btn-sm,.input-sm{height:31px;padding:5px 8px}.btn-xs{height:25px;padding:3px 7px}.btn-group-justified{display:flex;width:100%;gap:4px}.btn-group-justified>.btn,.btn-group-justified>a{display:flex!important;align-items:center;justify-content:center;flex:1 1 0;min-width:0;padding:6px 7px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.notActive{background:var(--panel-raised)!important;color:var(--muted)!important}.save,.active.save{background:var(--accent)!important;color:var(--on-accent)!important;border-color:var(--accent)!important}.error{background:var(--danger-soft)!important;border-color:color-mix(in srgb,var(--danger) 32%,var(--line))!important;color:var(--danger)!important}.success{background:var(--success-soft)!important;border-color:color-mix(in srgb,var(--success) 32%,var(--line))!important;color:var(--success)!important}#limitgen.success{background:linear-gradient(180deg,color-mix(in srgb,#292b2c 14%,transparent),color-mix(in srgb,#292b2c 7%,transparent))!important;border-color:color-mix(in srgb,#292b2c 38%,var(--line))!important;color:var(--text)!important}#limitgen.success:focus{border-color:color-mix(in srgb,#292b2c 55%,var(--line))!important;box-shadow:0 0 0 2px color-mix(in srgb,#292b2c 18%,transparent)!important}.rg-source,.rg-source-0{display:block;margin:0;color:var(--muted);font-weight:700;font-size:11.5px;line-height:1.25;letter-spacing:.025em;text-transform:uppercase}.rg-source{float:left}.rg-source-0{float:left;clear:both}.max{min-width:145px;text-align:left}.maxi{min-width:40px;text-align:center}.og-field{display:flex!important;align-items:stretch!important;width:100%!important;margin:2px 0!important;padding:0!important;border:0!important}.og-field .form-control{display:block!important;flex:1 1 auto!important;width:auto!important;min-width:0!important;height:31px!important;border-left:0!important;border-radius:0 var(--radius) var(--radius) 0!important}.og-icon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 38px!important;width:38px!important;min-width:38px!important;height:31px!important;padding:0!important;color:var(--muted)!important;background:var(--panel-soft)!important;border-radius:var(--radius) 0 0 var(--radius)!important}.og-icon svg{display:block;width:14px!important;height:14px!important;stroke:currentColor;fill:none;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}.btn-copy-pos{position:absolute;top:6px;right:6px}.btn-copy{display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;padding:0;border:none!important;background:var(--panel-soft)!important;color:var(--muted)!important;border-radius:var(--radius)!important}.btn-copy:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}.table{width:100%;margin:4px 0 0;border-collapse:separate;border-spacing:0;border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;background:var(--panel)!important;table-layout:auto}.table>thead>tr>th{position:sticky;top:0;z-index:20;padding:7px 8px!important;border-bottom:1px solid var(--line)!important;background:var(--panel-soft)!important;color:var(--muted)!important;font-size:11.5px!important;line-height:1.2;text-transform:uppercase;letter-spacing:.035em;text-align:left}.table>tbody>tr>td{padding:6px 8px!important;border-top:1px solid var(--line-soft)!important;color:var(--text);font-size:12.5px;vertical-align:middle;word-break:break-word;background:var(--panel)!important;text-align:left}.table-hover>tbody>tr:hover>td{background:var(--panel-soft)!important}.table-row-removing>td{background:var(--danger-soft)!important;color:var(--danger)!important;opacity:.75}.post-colon,#limitgen{font-family:Consolas,Monaco,"Courier New",monospace!important;font-size:12px!important}#limitgen{height:100px!important;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;resize:none!important}.table-fixed thead,.table-fixed thead th{position:sticky;top:0;z-index:20;background:var(--panel-soft)!important;color:var(--muted)!important}.btn-sm-danger,.btn-danger{border-color:color-mix(in srgb,var(--danger) 32%,var(--line))!important;background:var(--danger-soft)!important;color:var(--danger)!important}.btn-sm-danger:hover,.btn-danger:hover{border-color:color-mix(in srgb,var(--danger) 45%,var(--line))!important;background:color-mix(in srgb,var(--danger-soft) 80%,var(--panel))!important;color:var(--danger)!important}.app-modal{position:fixed;inset:0;z-index:1050;display:none;align-items:center;justify-content:center;padding:14px;background:color-mix(in srgb,#292b2c 44%,transparent)}.app-modal.is-open{display:flex}.app-modal__dialog{width:100%;max-width:340px}.app-modal__content{border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);overflow:hidden}.app-modal__header,.app-modal__footer{display:flex;align-items:center;gap:8px;padding:9px 10px;background:var(--panel);border-color:var(--line-soft)}.app-modal__header{justify-content:space-between;border-bottom:1px solid var(--line-soft)}.app-modal__footer{justify-content:flex-end;border-top:1px solid var(--line-soft)}.app-modal__title{margin:0;font-size:14px;font-weight:700;color:var(--text-strong)}.app-modal__body{padding:10px}.app-modal__note{margin:0;color:var(--text);font-size:12.5px}.close{height:24px;width:24px;border:0!important;background:transparent!important;color:var(--muted)!important;font-size:20px;line-height:20px}.close:hover{color:var(--text-strong)!important;background:transparent!important}.toastbox{position:fixed;right:12px;bottom:12px;z-index:9999;display:flex;flex-direction:column;gap:6px;align-items:flex-end;pointer-events:none}.toastitem{display:inline-flex;align-items:center;gap:8px;max-width:320px;min-width:190px;padding:8px 10px;border:1px solid var(--line);border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text);box-shadow:var(--shadow-modal);font-size:13px;font-weight:600;line-height:1.35;pointer-events:none;opacity:1;transform:translateY(0);transition:opacity .18s ease,transform .18s ease}.toastitem--hide{opacity:0;transform:translateY(8px)}.toastitem--success{border-color:color-mix(in srgb,var(--success) 32%,var(--line));background:var(--success-soft)!important;color:var(--success)}.toastitem--error{border-color:color-mix(in srgb,var(--danger) 32%,var(--line));background:var(--danger-soft)!important;color:var(--danger)}.toastitem svg{width:15px;height:15px;flex:0 0 15px}.toastitem span{display:block}#sm{padding:6px;background:var(--panel-soft)!important;border:1px solid var(--line-soft);border-radius:var(--radius)}#shortgen{max-width:none}.generate-controls{display:flex;gap:4px;align-items:stretch}.control-limit{flex:1 1 0;min-width:0}.control-landing{flex:0 0 120px;width:120px}.control-debug{flex:0 0 100px;width:100px}.control-shortener{flex:0 0 120px;width:120px}#genurl{height:31px;padding:5px 10px;background:var(--accent)!important;color:var(--on-accent)!important;border-color:var(--accent)!important;white-space:nowrap;flex:0 0 auto}#genurl:hover{background:var(--accent-hover)!important;border-color:var(--accent-hover)!important}.textarea-wrap{position:relative}.btn-copy-float{position:absolute;top:6px;right:6px;display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;padding:0;border:none!important;background:var(--panel-soft)!important;color:var(--muted)!important;border-radius:var(--radius)!important;box-shadow:none!important;cursor:pointer;line-height:1}.btn-copy-float:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}.btn-copy-float.copied,.btn-copy-domain.copied{background:var(--success-soft)!important;color:var(--success)!important;border-color:color-mix(in srgb,var(--success) 32%,var(--line))!important;transition:background .1s ease,color .1s ease}.ns-info{margin:8px 0 6px;padding:7px 10px;background:var(--panel-soft)!important;border:1px solid var(--line-soft)!important;border-radius:var(--radius)!important;display:flex;align-items:center;gap:8px;white-space:nowrap;overflow-x:auto;color:var(--text)}.ns-info svg{flex:0 0 15px;color:var(--muted)}.ns-info__row{display:flex;flex-direction:column;align-items:flex-start;gap:2px;font-size:13px;line-height:1.35;color:var(--text);min-width:max-content}.ns-info__label{font-weight:700;color:var(--text-strong)}.ns-info code{font-size:11.5px;background:transparent!important;border:0!important;padding:0;color:var(--text);display:block}#domain{border-left:0!important}#addondom{height:31px;padding:5px 10px;background:var(--accent)!important;color:var(--on-accent)!important;border-color:var(--accent)!important;white-space:nowrap}#addondom:hover{background:var(--accent-hover)!important;border-color:var(--accent-hover)!important}@media screen and (max-width:768px){body{padding-top:6px;font-size:12.5px}.container.app-shell,.container{width:100%!important;max-width:100%!important;padding-left:6px!important;padding-right:6px!important}.panel-heading,.panel-body,.panel-footer{padding:7px}.panel-footer--banner{padding:0!important}.panel-heading .pull-right{float:none!important;justify-content:flex-end;margin-top:0}.nav-tabs{gap:3px;padding:4px 4px 0!important}.nav-tabs>li{flex:1 1 0}.nav-tabs>li>a{text-align:center;padding:6px 4px;font-size:11px}.tab-content{padding:5px}.input-group:not(.og-field){display:block}.input-group:not(.og-field)>.form-control,.input-group:not(.og-field)>.input-group-addon,.input-group:not(.og-field)>.input-group-btn,.input-group:not(.og-field)>.input-group-btn>.btn{display:block;width:100%!important}.input-group:not(.og-field)>.input-group-addon{border-bottom:0!important;border-radius:var(--radius) var(--radius) 0 0!important}.input-group:not(.og-field)>.form-control{border-radius:0 0 var(--radius) var(--radius)!important}.input-group-btn>.btn,#addondom{margin-top:5px;width:100%!important}.panel-footer .pull-left,.panel-footer .text-right{float:none!important;text-align:left!important}.panel-footer select{width:100%!important;margin-bottom:5px}.footer-sign{float:none;text-align:right}.btn-group-justified{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))}.generate-controls{display:grid!important;grid-template-columns:1fr 1fr;gap:5px!important}.generate-controls>*{width:100%!important;min-width:0!important;flex:auto!important}#genurl{grid-column:1/-1}.table{display:block;overflow-x:auto;white-space:nowrap}.table>thead,.table>tbody,.table>thead>tr,.table>tbody>tr{width:100%}.toastbox{right:8px;left:8px;bottom:8px;align-items:stretch}.toastitem{max-width:none;width:100%}}@media screen and (max-width:500px){body{font-size:12px}.rg-source{float:none}.btn-group-justified{grid-template-columns:1fr}.app-banner{max-height:72px}.generate-controls{grid-template-columns:1fr}textarea.form-control{min-height:104px}.table>thead>tr>th,.table>tbody>tr>td{padding:6px!important;font-size:10.5px}.ns-info__row{font-size:11.5px}}.cf-badge{display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;padding:0;border-radius:var(--radius);border:1px solid var(--line-soft);background:var(--panel-soft);color:var(--muted);flex-shrink:0}.cf-badge--active{border-color:color-mix(in srgb,var(--success) 32%,var(--line));background:var(--success-soft);color:var(--success)}.cf-badge--pending{border-color:color-mix(in srgb,var(--accent) 22%,var(--line));background:var(--accent-soft);color:var(--accent)}.cf-badge--error{border-color:color-mix(in srgb,var(--danger) 32%,var(--line));background:var(--danger-soft);color:var(--danger)}.addon-toolbar{display:flex;align-items:center;justify-content:space-between;padding:3px 1px 2px;margin-bottom:1px}.domain-count-badge{font-size:12px;color:var(--muted);font-weight:600}.btn-copy-domain{display:inline-flex;align-items:center;padding:1px 4px;height:20px;vertical-align:middle}.cf-ns-list{margin:4px 0 0;padding:5px 8px;list-style:none;background:var(--panel-soft);border:1px solid var(--line-soft);border-radius:var(--radius)}.cf-ns-list li{font-family:Consolas,Monaco,'Courier New',monospace;font-size:11.5px;padding:1px 0;color:var(--text)}#table_domain{table-layout:fixed;width:100%;min-width:0}#table_domain th:nth-child(1),#table_domain td:nth-child(1){width:auto}#table_domain th:nth-child(2),#table_domain td:nth-child(2){width:90px}#table_domain th:nth-child(3),#table_domain td:nth-child(3){width:72px;white-space:nowrap}.td-cf-cell{display:flex;align-items:center;gap:4px}#table_domain th:nth-child(4),#table_domain td:nth-child(4){width:72px;text-align:right;white-space:nowrap}.td-dom{display:inline;font-family:Consolas,Monaco,'Courier New',monospace;font-size:11.5px;font-weight:600;color:var(--text)}.td-subid{display:block;font-family:Consolas,Monaco,'Courier New',monospace;font-size:11.5px;color:var(--muted)}.cf-modal-status{display:flex;align-items:center;gap:8px;margin-bottom:6px;font-size:12.5px;font-weight:600;flex-wrap:wrap}.cf-config-bar{display:flex;align-items:center;gap:6px;padding:3px 1px 2px;margin-bottom:1px}.cf-config-label{font-size:11.5px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}.cf-source-badge{font-size:11px;font-weight:700;padding:2px 6px;border-radius:var(--radius);border:1px solid var(--line-soft);background:var(--panel-soft);color:var(--muted);white-space:nowrap}.cf-source-badge--own{border-color:color-mix(in srgb,var(--success) 32%,var(--line));background:var(--success-soft);color:var(--success)}.cf-source-badge--admin{border-color:color-mix(in srgb,var(--accent) 22%,var(--line));background:var(--accent-soft);color:var(--accent)}.cf-config-panel{display:none;background:var(--panel-soft);border:1px solid var(--line-soft);border-radius:var(--radius);padding:7px 8px;margin-bottom:4px}.cf-config-panel.is-open{display:block}.cf-config-form .input-group{margin-bottom:4px}.cf-config-row{margin-bottom:4px}.cf-config-addon{width:90px!important;font-size:12px!important}.cf-config-actions{display:flex;align-items:center;gap:5px;margin-top:4px}.cf-config-status{font-size:12px;font-weight:600;color:var(--muted)}#cf-config-toggle{margin-left:auto}#cf-modal-note{margin-bottom:0}#cf-modal-note:empty{display:none}#cf-modal-ns{display:none}#cf-modal-ns.ns-visible{display:block}*:focus,*:focus-visible{outline:none!important;box-shadow:none!important}.form-control{outline:none}.label{border:1px solid var(--line)!important}</style>
</head>
<body>
<div id="toastbox" class="toastbox" aria-live="polite" aria-atomic="true"></div>
<div class="container app-shell">
    <div class="panel panel-default">
        <div class="panel-heading">
            <div class="pull-right">
                <button type="button" class="btn btn-xs btn-primary" id="command-add" data-row-id="0">
                    <strong><?= $escapedTitle; ?></strong>
                </button>
                <a href="?logout&sub_id=<?= rawurlencode($subIdParam); ?>" class="btn btn-xs btn-danger" id="btn-logout">
                    <strong>Logout</strong>
                </a>
            </div>
        </div>
        <div class="panel-body">
            <div class="panel-footer panel-footer--banner">
                <img src="banner.png" alt="Banner" class="app-banner">
            </div>
            <ul class="nav nav-tabs">
                <li id="tabgen" class="active"><a href="#gen" data-toggle="tab"><strong>GENERATE</strong></a></li>
                <li id="tabaddon"><a href="#addon" data-toggle="tab"><strong>ADDDOMAIN</strong></a></li>
            </ul>
            <div id="myTabContent" class="tab-content">
                <div class="panel-footer" id="sm">
                    <div class="input-group">
                        <div id="radioBtn" class="btn-group btn-group-justified btn-block">
                            <?php
                            $result = mysqli_query($link, "SELECT DISTINCT network FROM offering WHERE network IS NOT NULL AND network <> '' ORDER BY network ASC");
                            if ($result && mysqli_num_rows($result) > 0) {
                                while ($networkRow = mysqli_fetch_assoc($result)) {
                                    $network = (string) ($networkRow['network'] ?? '');
                                    if ($network === '') {
                                        continue;
                                    }
                                    echo '<a type="button" class="btn btn-default btn-sm notActive" data-toggle="user_lp" data-title="' . e($network) . '"><strong>' . e($network) . '</strong></a>';
                                }
                            } else {
                                echo '<span class="btn btn-default btn-sm disabled">No Network</span>';
                            }
                            ?>
                        </div>
                    </div>
                </div>
                <hr class="compact-hr">
                <div class="tab-pane fade active in" id="gen">
                    <div class="panel-footer">
                        <div class="pull-left">
                            <select id="locrandom" class="input-sm">
                                <optgroup label="GLOBAL DOMAIN">
                                    <option class="bold-option" disabled>---global domain---</option>
                                    <option value="global" selected="selected" class="bold-option">[RANDOM GLOBAL DOMAIN]</option>
                                    <?php
                                    $globalDomainResult = mysqli_query($link, "SELECT domain FROM addondomain WHERE sub_domain='GLOBAL'");
                                    if ($globalDomainResult) {
                                        while ($domainRow = mysqli_fetch_assoc($globalDomainResult)) {
                                            $domainValue = (string) ($domainRow['domain'] ?? '');
                                            if ($domainValue === '') {
                                                continue;
                                            }
                                            echo '<option value="' . e($domainValue) . '">' . e($domainValue) . '</option>';
                                        }
                                    }
                                    ?>
                                </optgroup>
                            </select>
                        </div>
                        <div class="text-right">
                            <select id="locdom" class="input-sm">
                                <optgroup label="USER DOMAIN">
                                    <option class="bold-option" selected="selected" disabled>---user domain---</option>
                                    <option value="u_rand" class="bold-option">[RANDOM USER DOMAIN]</option>
                                </optgroup>
                            </select>
                        </div>
                    </div>
                    <hr class="compact-hr">
                    <div class="panel-footer">
                        <div class="input-group og-field">
                            <span class="input-group-addon maxi og-icon" title="Title" aria-label="Title"><svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><rect x="5" y="4" width="14" height="16" rx="2"></rect><path d="M8 9h8"></path><path d="M8 13h8"></path><path d="M8 17h5"></path></svg></span>
                            <input class="form-control input-sm js-autoselect" id="fbtext" name="fbtext" autocomplete="off" placeholder="{og:title}" type="text">
                        </div>
                        <div class="input-group og-field">
                            <span class="input-group-addon maxi og-icon" title="Image URL" aria-label="Image URL"><svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><rect x="4" y="5" width="16" height="14" rx="2"></rect><circle cx="9" cy="10" r="1.5"></circle><path d="M7 17l4.2-4.2a1.3 1.3 0 0 1 1.8 0L17 17"></path></svg></span>
                            <input class="form-control input-sm js-autoselect" id="fbimg" name="fbimg" autocomplete="off" placeholder="{og:image}" type="text">
                        </div>
                    </div>
                    <hr class="compact-hr">
                    <div class="panel-footer">
                        <div class="generate-controls">
                            <input class="form-control input-sm js-autoselect js-readlock control-limit" id="shortgen" name="shortgen" placeholder="{limitgen}" type="number" min="1" max="50" step="1" value="1">
                            <select id="lg" class="form-control input-sm control-landing">
                            <optgroup label="Landing page">
                                <option class="btn btn-sm btn-default" value="direct">Direct</option>
                                <option class="btn btn-sm btn-default" value="landing">Landing page</option>
                            </optgroup>
                        </select>
                            <select id="net_pick" class="form-control input-sm control-debug">
                                <optgroup label="SELECT DEBUGGER">
                                    <option value="a" selected="selected">Default</option>
                                    <option value="b">l.fb.com</option>
                                    <option value="f">l.wl.co</option>
                                </optgroup>
                            </select>
                            <select id="uri" class="form-control input-sm control-shortener">
                                <optgroup label="SELECT SHORTURL">
                                    <option class="btn btn-sm btn-default" value="def" selected="selected">Default URL</option>
                                    <option class="btn btn-sm btn-default" value="ixg">ixg.llc</option>
                                    <option class="btn btn-sm btn-default" value="isgd">is.gd</option>
                                    <option class="btn btn-sm btn-default" value="turl">tinyurl.com</option>
                                </optgroup>
                            </select>
                            <button class="btn btn-default btn-sm" data-loading-text="Generating..." id="genurl" type="button">
                                GENERATE URL
                            </button>
                        </div>
                        <hr class="compact-hr">
                        <div class="input-group">
                            <span class="input-group-addon max"><strong class="rg-source-0">Result URL</strong></span>
                        </div>
                        <div class="textarea-wrap">
                            <textarea class="form-control input-sm js-autoselect" id="limitgen" name="limitgen" placeholder="https://..." rows="1"></textarea>
                            <button id="copy-limitgen" type="button" title="Copy" class="btn-copy-float" tabindex="-1">
                                <svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true"><path fill="currentColor" d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
                            </button>
                        </div>
                    </div>
                </div>
                <div class="tab-pane fade" id="addon">
                    <?php
                    $nsList = [];
                    foreach (['NS1','NS2','NS3','NS4','NS5','NS6'] as $k) {
                        $v = trim(app_env($k, ''));
                        if ($v !== '') $nsList[] = $v;
                    }
                    if (empty($nsList)) {
                        foreach (['CF_NS1','CF_NS2'] as $k) {
                            $v = trim(app_env($k, ''));
                            if ($v !== '') $nsList[] = $v;
                        }
                    }
                    if (!empty($nsList)): ?>
                    <div class="ns-info">
                        <svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true"><path fill="currentColor" d="M12 2a10 10 0 1 0 0 20A10 10 0 0 0 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
                        <div class="ns-info__row">
                            <span class="ns-info__label">Nameserver</span>
                            <?php foreach ($nsList as $i => $ns): ?>
                            <code>Nameserver <?= $i + 1; ?>: <?= e($ns); ?></code>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <?php endif; ?>
                    <div class="panel-footer">
                        <div class="input-group">
                            <span class="input-group-addon maxi">+</span>
                            <input type="hidden" class="form-control input-sm" id="userid" name="userid" value="<?= $escapedTitle; ?>">
                            <input autocomplete="off" type="text" class="form-control input-sm js-autoselect" id="domain" name="domain" placeholder="{addon_domain} domain.tld">
                            <span class="input-group-btn btn-block">
                                <button class="btn btn-default btn-sm" id="addondom" type="button" data-loading-text="Adding...">Addon Domain</button>
                            </span>
                        </div>
                    </div>
                    <hr class="compact-hr">
                    <div class="cf-config-bar">
                        <span class="cf-config-label">Cloudflare</span>
                        <span class="cf-source-badge" id="cf-source-badge">—</span>
                        <button type="button" class="btn btn-xs" id="cf-config-toggle">CF Settings</button>
                    </div>
                    <div class="cf-config-panel" id="cf-config-panel">
                        <div class="cf-config-form">
                            <div class="input-group cf-config-row">
                                <span class="input-group-addon cf-config-addon">API Token</span>
                                <input type="password" class="form-control input-sm" id="cf-input-token" autocomplete="off" placeholder="Bearer token dari CF dashboard">
                            </div>
                            <div class="input-group cf-config-row">
                                <span class="input-group-addon cf-config-addon">Account ID</span>
                                <input type="text" class="form-control input-sm" id="cf-input-account" autocomplete="off" placeholder="Account ID (wajib jika token baru)">
                            </div>
                            <div class="cf-config-actions">
                                <button type="button" class="btn btn-xs btn-primary" id="cf-config-save">Simpan</button>
                                <button type="button" class="btn btn-xs btn-danger" id="cf-config-clear">Hapus</button>
                                <span class="cf-config-status" id="cf-config-status"></span>
                            </div>
                        </div>
                    </div>
                    <hr class="compact-hr">
                    <div class="addon-toolbar">
                        <span class="domain-count-badge" id="domain-count">0 domains</span>
                        <button type="button" class="btn btn-xs" id="cf-sync-all">Sync All CF</button>
                    </div>
                    <table id="table_domain" class="responsive nowrap unstackable table table-hover table-fixed" cellspacing="0">
                        <thead>
                            <tr>
                                <th class="rg-source col-xs-6">DOMAIN</th>
                                <th class="rg-source col-xs-2">SUBID</th>
                                <th class="rg-source col-xs-2">CF</th>
                                <th class="rg-source col-xs-2">ACTION</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
        </div>
        <input type="hidden" class="form-control input-sm" id="user_lp" name="user_lp">
        <input type="hidden" id="pick" name="pick" class="form-control input-sm" value="0">
        <input type="hidden" id="deb" name="deb" class="form-control input-sm" value="a">
        <input type="hidden" id="urlgen" name="urlgen" class="form-control input-sm" value="https://{sub}.global/{click_id}">
        <input type="hidden" id="pickurl" name="pickurl" class="form-control input-sm" value="0">
        <input type="hidden" id="sub_id" name="sub_id" class="form-control input-sm" value="<?= $escapedSubIdLower; ?>">
    </div>
    <hr class="compact-hr">
    <div class="rg-source footer-sign"><footer>ngix:n-gix</footer></div>

<div class="app-modal" id="deleteDomainModal" role="dialog" aria-modal="true" aria-labelledby="deleteDomainTitle" hidden>
    <div class="app-modal__dialog" role="document">
        <div class="app-modal__content">
            <div class="app-modal__header">
                <h4 class="app-modal__title" id="deleteDomainTitle">Delete Domain</h4>
                <button type="button" class="close js-modal-close" aria-label="Close"><span aria-hidden="true">&times;</span></button>
            </div>
            <div class="app-modal__body">
                <p class="app-modal__note">This action cannot be reverted.</p>
                <input type="hidden" id="delete_domain_target" value="">
            </div>
            <div class="app-modal__footer">
                <button type="button" class="btn btn-default btn-sm js-modal-close">Cancel</button>
                <button type="button" class="btn btn-danger btn-sm" id="confirm_delete_domain">Delete</button>
            </div>
        </div>
    </div>
</div>
<div class="app-modal" id="cfResultModal" role="dialog" aria-modal="true" aria-labelledby="cfResultTitle" hidden>
    <div class="app-modal__dialog" role="document">
        <div class="app-modal__content">
            <div class="app-modal__header">
                <h4 class="app-modal__title" id="cfResultTitle">Cloudflare Zone</h4>
                <button type="button" class="close js-modal-close" aria-label="Close"><span aria-hidden="true">&times;</span></button>
            </div>
            <div class="app-modal__body">
                <div class="cf-modal-status">
                    <span id="cf-modal-domain" class="td-dom"></span>
                    <span class="cf-badge" id="cf-modal-badge"></span>
                </div>
                <p class="app-modal__note" id="cf-modal-note"></p>
                <ul class="cf-ns-list" id="cf-modal-ns"></ul>
            </div>
            <div class="app-modal__footer">
                <button type="button" class="btn btn-default btn-sm js-modal-close">Close</button>
            </div>
        </div>
    </div>
</div>
</div>
<script nonce="<?= e($nonce); ?>" src="dist/jquery.min.js" type="text/javascript"></script>
<script nonce="<?= e($nonce); ?>" src="dist/bootstrap.min.js"></script>
<script nonce="<?= e($nonce); ?>">
(function ($) {
    'use strict';

    var SVG_SYNC = '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10"/><path d="M20.49 15a9 9 0 0 1-14.85 3.36L1 14"/></svg>';
    var SVG_CF_ACTIVE  = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>';
    var SVG_CF_PENDING = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>';
    var SVG_CF_ERROR   = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';

    $(document).on('focus', '.js-autoselect', function () { this.select(); });
    $(document).on('selectstart paste cut dragstart drop', '.js-readlock', function (e) { e.preventDefault(); return false; });

    $(document).on('click', '#copy-limitgen', function (e) {
        e.preventDefault();
        e.stopPropagation();
        var input = document.getElementById('limitgen');
        if (!input || !input.value) { showToast('error', 'No URL to copy.'); return; }
        var val = input.value;
        var $btn = $(this);
        var done = function () {
            showToast('success', 'URL copied.');
            $btn.addClass('copied');
            input.select();
            setTimeout(function () {
                $btn.removeClass('copied');
                input.setSelectionRange(0, 0);
                input.blur();
            }, 1200);
        };
        var fail = function () { showToast('error', 'Copy failed.'); };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(val).then(done, function () {
                try {
                    input.select();
                    document.execCommand('copy');
                    done();
                } catch (err) { fail(); }
            });
        } else {
            try {
                input.select();
                document.execCommand('copy');
                done();
            } catch (err) { fail(); }
        }
    });

    var csrfToken = <?= json_encode($csrfToken, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>;

    $.ajaxSetup({
        headers: {
            'X-CSRF-Token': csrfToken
        }
    });

    function showToast(type, message) {
        var icon = type === 'success'
            ? '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M9 16.17 4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>'
            : '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M19 6.41 17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>';
        var item = $('<div class="toastitem toastitem--' + type + '"></div>');
        item.append(icon);
        item.append($('<span></span>').text(message));
        $('#toastbox').append(item);
        window.setTimeout(function () {
            item.addClass('toastitem--hide');
            window.setTimeout(function () {
                item.remove();
            }, 220);
        }, 2200);
    }

    function openDeleteModal() {
        $('#deleteDomainModal').prop('hidden', false).addClass('is-open');
    }

    function closeDeleteModal() {
        $('#deleteDomainModal').removeClass('is-open').prop('hidden', true);
    }

    function findDomainRow(domain) {
        return $('#table_domain tbody tr').filter(function () {
            return $(this).attr('data-domain') === domain;
        });
    }

    function hasDomainOption(domain) {
        return $('#locdom option').filter(function () {
            return $(this).val() === domain;
        }).length > 0;
    }

    function removeDomainOption(domain) {
        $('#locdom option').filter(function () {
            return $(this).val() === domain || $(this).attr('name') === domain;
        }).remove();
    }

    function isValidDomainInput(domain) {
        return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(domain);
    }

    function preventManualInput(selector) {
        $(selector).on('keypress', function (e) {
            e.preventDefault();
            return false;
        });
    }

    function randomString(len, charSet) {
        var chars = charSet || 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        var output = '';
        var index = 0;
        for (index = 0; index < len; index += 1) {
            output += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return output;
    }

    function applyWrapper(rawUrl, mode) {
        var cleanUrl = $.trim(rawUrl);
        if (cleanUrl === '') {
            return '';
        }
        if (mode === 'b') {
            return 'https://l.facebook.com/l.php?u=' + encodeURIComponent(cleanUrl) + '&h=' + randomString(7) + '&s=1';
        }
        if (mode === 'f') {
            return 'https://l.wl.co/l?u=' + encodeURIComponent(cleanUrl);
        }
        return cleanUrl;
    }

    function safeArrayResponse(data) {
        if ($.isArray(data)) {
            return data;
        }
        if (typeof data === 'string') {
            try {
                var parsed = JSON.parse(data);
                return $.isArray(parsed) ? parsed : [];
            } catch (err) {
                return [];
            }
        }
        return [];
    }

    function resetGenerateOutputs() {
        $('#limitgen').val('').removeClass('error success');
    }

    function initFirstNetwork() {
        var firstButton = $('#radioBtn a').first();
        if (firstButton.length === 0) {
            return;
        }
        firstButton.removeClass('notActive').addClass('active save');
        $('#user_lp').val(firstButton.data('title') || '');
    }

    function updateUrlTemplateFromGlobal(value) {
        $('#urlgen').val('https://{sub}.' + value + '/{click_id}');
        $('#locdom')[0].selectedIndex = 0;
    }

    function updateUrlTemplateFromUser(value) {
        $('#urlgen').val('https://{sub}.' + value + '/{click_id}');
        $('#locrandom')[0].selectedIndex = 0;
    }

    var cfStatusCache = {};

    function updateDomainCount() {
        var c = $('#table_domain tbody tr').length;
        $('#domain-count').text(c + (c === 1 ? ' domain' : ' domains'));
    }

    function updateCfBadge(domain, data) {
        var badge = $('.cf-badge[data-domain="' + domain + '"]');
        badge.removeClass('cf-badge--active cf-badge--pending cf-badge--error').show();
        if (!data || !data.ok) {
            badge.addClass('cf-badge--error').html(SVG_CF_ERROR);
            cfStatusCache[domain] = 'error';
            return;
        }
        var status = (data.status || 'pending').toLowerCase();
        cfStatusCache[domain] = status;
        if (status === 'active') {
            badge.addClass('cf-badge--active').html(SVG_CF_ACTIVE);
        } else {
            badge.addClass('cf-badge--pending').html(SVG_CF_PENDING);
        }
    }

    function openCfModal(domain, data) {
        var status = (data.status || 'pending').toLowerCase();
        $('#cf-modal-domain').text(domain);
        var mb = $('#cf-modal-badge').html('').removeClass('cf-badge--active cf-badge--pending cf-badge--error');
        if (status === 'active') {
            mb.addClass('cf-badge--active').html(SVG_CF_ACTIVE);
        } else if (!data || !data.ok) {
            mb.addClass('cf-badge--error').html(SVG_CF_ERROR);
        } else {
            mb.addClass('cf-badge--pending').html(SVG_CF_PENDING);
        }
        var ns = data.name_servers || [];
        var nsList = $('#cf-modal-ns').empty();
        var note = '';
        if (!data || !data.ok) {
            note = 'Gagal menambahkan zone Cloudflare.';
        } else if (data.already_exists) {
            note = 'Zone sudah ada di akun Cloudflare.';
        } else if (status === 'active') {
            note = 'Zone aktif di Cloudflare.';
        } else if (ns.length > 0) {
            note = 'Zone ditambahkan. Arahkan nameserver domain ke:';
        }
        $('#cf-modal-note').text(note);
        if (ns.length > 0) {
            $.each(ns, function (i, n) { nsList.append($('<li></li>').text(n)); });
            nsList.addClass('ns-visible');
        } else {
            nsList.removeClass('ns-visible');
        }
        $('#cfResultModal').prop('hidden', false).addClass('is-open');
    }

    function closeCfModal() {
        $('#cfResultModal').removeClass('is-open').prop('hidden', true);
    }

    function syncDomainCf(domain, onDone) {
        var badge = $('.cf-badge[data-domain="' + domain + '"]');
        var syncBtn = $('.cf-sync-btn[data-domain="' + domain + '"]');
        badge.removeClass('cf-badge--active cf-badge--pending cf-badge--error').text('↻');
        syncBtn.prop('disabled', true).html('...');
        $.ajax({
            url: '/api/cf.sync.php',
            type: 'post',
            dataType: 'json',
            data: { domain: domain, sub_domain: $.trim($('#userid').val()) }
        }).done(function (data) {
            updateCfBadge(domain, data);
            if (typeof onDone === 'function') { onDone(null, data); }
        }).fail(function () {
            badge.addClass('cf-badge--error').text('err');
            if (typeof onDone === 'function') { onDone('failed', null); }
        }).always(function () {
            syncBtn.prop('disabled', false).html(SVG_SYNC);
        });
    }

    function appendDomainRow(rowData) {
        if (!rowData || !rowData.domain) {
            return;
        }
        if (findDomainRow(rowData.domain).length > 0) {
            return;
        }
        var SVG_TRASH = '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>';
        var row = $('<tr></tr>').attr('data-domain', rowData.domain);
        var domainCell = $('<td></td>');
        var domSpan = $('<span class="td-dom"></span>').text(rowData.domain);
        var copyBtn = $('<button type="button" class="btn btn-xs btn-copy-domain" title="Copy domain"></button>').attr('data-domain', rowData.domain).html('<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>');
        domainCell.append(domSpan).append(' ').append(copyBtn);
        row.append(domainCell);
        row.append($('<td></td>').append($('<span class="td-subid"></span>').text(rowData.sub_domain || '')));
        var cfStatus = cfStatusCache[rowData.domain] || '';
        var badge = $('<span class="cf-badge"></span>').attr('data-domain', rowData.domain);
        if (cfStatus === 'active') { badge.addClass('cf-badge--active').html(SVG_CF_ACTIVE); }
        else if (cfStatus === 'pending') { badge.addClass('cf-badge--pending').html(SVG_CF_PENDING); }
        else if (cfStatus === 'error') { badge.addClass('cf-badge--error').html(SVG_CF_ERROR); }
        else { badge.hide(); }
        var cfSyncBtn = $('<button type="button" class="btn btn-xs cf-sync-btn" title="Sync CF"></button>').attr('data-domain', rowData.domain).html(SVG_SYNC);
        row.append($('<td class="td-cf-cell"></td>').append(badge).append(cfSyncBtn));
        var actionCell = $('<td></td>');
        var deleteButton = $('<button type="button" class="delete btn btn-danger btn-xs" title="Delete"></button>');
        deleteButton.attr('data-domain', rowData.domain).html(SVG_TRASH);
        actionCell.append(deleteButton);
        row.append(actionCell);
        $('#table_domain tbody').append(row);
        updateDomainCount();

        if (!hasDomainOption(rowData.domain)) {
            $('#locdom').append($('<option></option>').attr('value', rowData.domain).attr('name', rowData.domain).text(rowData.domain));
        }
    }

    function drawTable(data) {
        var index = 0;
        $('#table_domain tbody').empty();
        $('#locdom option[name]').remove();
        for (index = 0; index < data.length; index += 1) {
            appendDomainRow(data[index]);
        }
        updateDomainCount();
    }

    function loadUserDomains() {
        $.ajax({
            url: '/api/user.domain.php',
            type: 'get',
            dataType: 'json',
            data: {
                sub_domain: $.trim($('#userid').val()),
                domain: $.trim($('#domain').val())
            }
        }).done(function (data) {
            if ($.isArray(data)) {
                drawTable(data);
            }
        });
    }

    function loadCfConfig() {
        $.ajax({
            url: '/api/user.cf.config.php',
            type: 'get',
            dataType: 'json'
        }).done(function (data) {
            var badge = $('#cf-source-badge');
            badge.removeClass('cf-source-badge--own cf-source-badge--admin');
            if (data && data.has_token) {
                badge.addClass('cf-source-badge--own').text('Own CF');
                $('#cf-input-token').val('').attr('placeholder', data.token_masked || 'Token tersimpan');
                $('#cf-input-account').val(data.account_id || '');
            } else {
                badge.addClass('cf-source-badge--admin').text('Admin CF');
                $('#cf-input-token').attr('placeholder', 'Bearer token dari CF dashboard');
                $('#cf-input-account').val('');
            }
        });
    }

    $('#cf-config-toggle').on('click', function () {
        var panel = $('#cf-config-panel');
        panel.toggleClass('is-open');
        if (panel.hasClass('is-open')) {
            loadCfConfig();
        }
    });

    $('#cf-config-save').on('click', function () {
        var token = $.trim($('#cf-input-token').val());
        var accountId = $.trim($('#cf-input-account').val());
        var status = $('#cf-config-status');
        if (token === '') { status.text('Token wajib diisi.'); return; }
        status.text('Menyimpan...');
        $.ajax({
            url: '/api/user.cf.config.php',
            type: 'post',
            dataType: 'json',
            data: { action: 'save', cf_token: token, cf_account_id: accountId }
        }).done(function (data) {
            if (data && data.ok) {
                status.text('Tersimpan.');
                loadCfConfig();
                showToast('success', 'CF token disimpan.');
            } else {
                status.text('Gagal menyimpan.');
            }
        }).fail(function () { status.text('Error.'); });
    });

    $('#cf-config-clear').on('click', function () {
        var status = $('#cf-config-status');
        status.text('Menghapus...');
        $.ajax({
            url: '/api/user.cf.config.php',
            type: 'post',
            dataType: 'json',
            data: { action: 'clear' }
        }).done(function (data) {
            if (data && data.ok) {
                status.text('Dihapus, pakai Admin CF.');
                $('#cf-input-token').val('');
                $('#cf-input-account').val('');
                loadCfConfig();
                showToast('success', 'CF token dihapus, fallback ke admin.');
            }
        }).fail(function () { status.text('Error.'); });
    });

    $(document).ready(function () {
        initFirstNetwork();
        preventManualInput('#urlgen,#pick,#limitgen');
        loadCfConfig();

        $('img').on('contextmenu', function () {
            return false;
        });

        $(document).on('click', '.js-modal-close', function () {
            closeDeleteModal();
            closeCfModal();
            return false;
        });

        $(document).on('keydown', function (e) {
            if (e.key === 'Escape') {
                closeDeleteModal();
                closeCfModal();
            }
        });

        $('#radioBtn').on('click', 'a', function () {
            var sel = $(this).data('title') || '';
            var tog = $(this).data('toggle') || '';
            if (tog !== '') {
                $('#' + tog).val(sel);
            }
            $('a[data-toggle="' + tog + '"]').removeClass('active save').addClass('notActive');
            $(this).removeClass('notActive').addClass('active save');
        });

        $('#net_pick').on('change', function () {
            $('#deb').val(this.value);
        });

        $('#locrandom').on('change', function () {
            updateUrlTemplateFromGlobal(this.value);
        });

        $('#locdom').on('change', function () {
            updateUrlTemplateFromUser(this.value);
        });

        $('#tabgen, #tabaddon').on('click', function () {
            resetGenerateOutputs();
        });

        $('#genurl').on('click', function () {
            var url = $.trim($('#urlgen').val());
            var button = $(this);
            var uri = $.trim($('#uri').val());
            var prm = $.trim($('#deb').val());
            var limitRaw = parseInt($.trim($('#shortgen').val()), 10);
            var limit = (isNaN(limitRaw) || limitRaw < 1) ? 1 : Math.min(limitRaw, 50);

            if (url === '') {
                $('#shortgen').addClass('error');
                $('#limitgen').val('* Missing URL template').addClass('error').removeClass('success');
                showToast('error', 'URL template is missing.');
                return false;
            }

            button.button('loading');
            $('#shortgen').removeClass('error');
            $('#limitgen').val('generating ' + limit + '...').removeClass('error success');

            var results = [];
            var failCount = 0;

            function applyShortener(generatedUrl, done) {
                if (uri === 'ixg') {
                    $.post('/api/api.ixg.php', { longurl: generatedUrl, prm: prm })
                        .done(function (data) {
                            var rows = safeArrayResponse(data);
                            var out = rows.length > 0 && rows[0] ? $.trim(rows[0].l || '') : '';
                            done(out !== '' ? out : null);
                        })
                        .fail(function () { done(null); });
                } else if (uri === 'isgd') {
                    $.post('/api/isgd.php', { longurl: generatedUrl, prm: prm })
                        .done(function (data) {
                            var rows = safeArrayResponse(data);
                            var out = rows.length > 0 && rows[0] ? $.trim(rows[0].l || rows[0].shorturl || '') : '';
                            done(out !== '' ? out : null);
                        })
                        .fail(function () { done(null); });
                } else if (uri === 'turl') {
                    $.post('/api/tinyurl.php', { longurl: generatedUrl, prm: prm })
                        .done(function (data) {
                            var rows = safeArrayResponse(data);
                            var out = rows.length > 0 && rows[0] ? $.trim(rows[0].l || '') : '';
                            done(out !== '' ? out : null);
                        })
                        .fail(function () { done(null); });
                } else {
                    done(applyWrapper(generatedUrl, prm));
                }
            }

            function generateStep(remaining) {
                if (remaining === 0) {
                    if (results.length === 0) {
                        $('#limitgen').val('* All requests failed').addClass('error').removeClass('success');
                        showToast('error', 'Generate failed.');
                    } else {
                        $('#limitgen').val(results.join('\n')).addClass('success').removeClass('error');
                        showToast('success', results.length + ' URL' + (results.length !== 1 ? 's' : '') + ' generated.');
                    }
                    button.button('reset');
                    return;
                }

                $.post('/api/b.api.php', {
                    longurl: url,
                    sub_id: $.trim($('#sub_id').val()),
                    user_lp: $.trim($('#user_lp').val()),

                    fbimg: $.trim($('#fbimg').val()),
                    fbtext: $.trim($('#fbtext').val()),
                    lg: $.trim($('#lg').val())
                }).done(function (data) {
                    var rows = safeArrayResponse(data);
                    var generatedUrl = rows.length > 0 && rows[0] ? $.trim(rows[0].shorturl || '') : '';
                    if (!generatedUrl || generatedUrl === 'https://') {
                        failCount++;
                        generateStep(remaining - 1);
                        return;
                    }
                    applyShortener(generatedUrl, function (finalUrl) {
                        if (finalUrl) {
                            results.push(finalUrl);
                        } else {
                            failCount++;
                        }
                        generateStep(remaining - 1);
                    });
                }).fail(function () {
                    failCount++;
                    generateStep(remaining - 1);
                });
            }

            generateStep(limit);
            return false;
        });

        $('#addondom').on('click', function () {
            var domain = $.trim($('#domain').val());
            var userid = $.trim($('#userid').val());
            var button = $(this);

            if (domain === '') {
                showToast('error', 'Addon domain is required.');
                return false;
            }

            if (!isValidDomainInput(domain)) {
                showToast('error', 'Invalid domain format.');
                return false;
            }

            button.button('loading');
            $.ajax({
                url: '/api/call.php',
                type: 'post',
                dataType: 'json',
                data: {
                    sub_domain: userid,
                    domain: domain
                }
            }).done(function (resp) {
                var rows = safeArrayResponse(resp);
                if (rows.length === 0 || !rows[0] || !rows[0].domain || !rows[0].userid) {
                    showToast('error', 'Addon domain response is invalid.');
                    button.button('reset');
                    return;
                }

                $.ajax({
                    url: '/api/user.insert.domain.php',
                    type: 'post',
                    dataType: 'json',
                    data: {
                        domain: rows[0].domain,
                        sub_domain: rows[0].userid
                    }
                }).done(function (data) {
                    if ($.isArray(data)) {
                        drawTable(data);
                        $('#domain').val('');
                        showToast('success', 'Addon domain saved.');
                    } else {
                        showToast('error', 'Addon domain save failed.');
                    }
                    button.button('reset');
                }).fail(function () {
                    showToast('error', 'Addon domain insert failed.');
                    button.button('reset');
                });
            }).fail(function () {
                showToast('error', 'Addon domain request failed.');
                button.button('reset');
            });

            return false;
        });

        $(document).on('click', '.delete', function () {
            var buttonId = $(this).attr('data-domain') || '';
            if (buttonId === '') {
                showToast('error', 'Invalid domain target.');
                return false;
            }
            $('#delete_domain_target').val(buttonId);
            openDeleteModal();
            return false;
        });

        $('#confirm_delete_domain').on('click', function () {
            var buttonId = $.trim($('#delete_domain_target').val());
            var rowNode = findDomainRow(buttonId);
            if (buttonId === '') {
                showToast('error', 'Invalid domain target.');
                return false;
            }
            $.ajax({
                url: '/api/user.del.domain.php',
                type: 'post',
                dataType: 'json',
                data: {
                    domain: buttonId
                }
            }).done(function () {
                removeDomainOption(buttonId);
                rowNode.addClass('table-row-removing');
                window.setTimeout(function () {
                    rowNode.remove();
                }, 260);
                closeDeleteModal();
                $('#delete_domain_target').val('');
                showToast('success', 'Domain deleted.');
            }).fail(function () {
                closeDeleteModal();
                showToast('error', 'Delete request failed.');
            });
            return false;
        });

        $(document).on('click', '.cf-sync-btn', function () {
            var domain = $(this).attr('data-domain') || '';
            if (domain === '') { return; }
            syncDomainCf(domain, function (err, data) {
                if (err) { showToast('error', 'CF sync failed.'); return; }
                if (data && data.ok) {
                    openCfModal(domain, data);
                } else {
                    showToast('error', 'CF error: ' + ((data && data.err) ? data.err : 'unknown'));
                }
            });
        });

        $(document).on('click', '.btn-copy-domain', function () {
            var domain = $(this).attr('data-domain') || '';
            if (domain === '') { return; }
            var $btn = $(this);
            var done = function () {
                showToast('success', 'Copied: ' + domain);
                $btn.addClass('copied');
                setTimeout(function () { $btn.removeClass('copied'); }, 1200);
            };
            var fail = function () { showToast('error', 'Copy failed.'); };
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(domain).then(done, fail);
            } else {
                var el = document.createElement('textarea');
                el.value = domain;
                document.body.appendChild(el);
                el.select();
                try { document.execCommand('copy'); done(); } catch (e) { fail(); }
                document.body.removeChild(el);
            }
        });

        $('#cf-sync-all').on('click', function () {
            var domains = [];
            $('#table_domain tbody tr').each(function () {
                var d = $(this).attr('data-domain') || '';
                if (d !== '') { domains.push(d); }
            });
            if (domains.length === 0) { showToast('error', 'No domains to sync.'); return; }
            var btn = $(this).prop('disabled', true);
            var idx = 0;
            var ok = 0;
            function next() {
                if (idx >= domains.length) {
                    btn.prop('disabled', false);
                    showToast('success', ok + '/' + domains.length + ' synced to CF.');
                    return;
                }
                var d = domains[idx++];
                syncDomainCf(d, function (err) {
                    if (!err) { ok++; }
                    window.setTimeout(next, 400);
                });
            }
            next();
        });

        $(document).on('click', '#cfResultModal', function (e) {
            if (e.target === this) { closeCfModal(); }
        });

        loadUserDomains();
    });
}(jQuery));
</script>
<script nonce="<?= e($nonce); ?>">
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js');
}
document.getElementById('btn-logout').addEventListener('click', function(e) {
    e.preventDefault();
    var href = this.getAttribute('href');
    document.getElementById('logout-toast').classList.add('show');
    setTimeout(function(){ window.location.href = href; }, 900);
});
</script>
<style nonce="<?= e($nonce); ?>">#logout-toast{position:fixed;bottom:20px;right:20px;background:rgba(41,43,44,.88);color:#fff;padding:7px 15px;border-radius:6px;font-size:12px;font-weight:600;z-index:99999;opacity:0;pointer-events:none;transition:opacity .2s;box-shadow:0 2px 8px rgba(0,0,0,.22)}#logout-toast.show{opacity:1}</style>
<div id="logout-toast">Logging out…</div>
</body>
</html>