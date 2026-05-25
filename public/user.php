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
const LOGOUT_URL = '#';
const TIMEOUT_MINUTES = 0;
const TIMEOUT_CHECK_ACTIVITY = true;

$nonce = base64_encode(random_bytes(18));
$timeout = TIMEOUT_MINUTES === 0 ? 0 : (time() + (TIMEOUT_MINUTES * 60));
$subIdParam = trim((string) ($_GET['sub_id'] ?? ''));
$count = 0;
$subId = '';
$password = '';
$loginInformation = [];
$loginError = '';

header(
    "Content-Security-Policy: default-src 'self'; "
    . "base-uri 'self'; "
    . "form-action 'self'; "
    . "frame-ancestors 'self'; "
    . "img-src 'self' data: https:; "
    . "font-src 'self' data: https:; "
    . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://use.fontawesome.com https://cdnjs.cloudflare.com; "
    . "script-src 'self' 'nonce-{$nonce}' https://cdn.jsdelivr.net; "
    . "connect-src 'self';"
);

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function cookieOptions(int $expires): array
{
    return [
        'expires' => $expires,
        'path' => '/',
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'httponly' => true,
        'samesite' => 'Lax',
    ];
}

function showLoginPasswordProtect(string $errorMsg, string $subIdValue, string $nonceValue): never
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
            <?php if ($errorMsg === 'err'): ?>
                <div class="msg">Access denied. Your IP address: <?= $ipAddress; ?></div>
            <?php endif; ?>
            <form method="post" autocomplete="off">
                <input type="hidden" name="access_login" value="<?= $displaySubId; ?>">
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

if ($subIdParam === '' || $count < 1) {
    http_response_code(404);
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Not Found</title>
    <link rel="stylesheet" href="dist/bootstrap.min.css" type="text/css" media="all">
    <style nonce="<?= e($nonce); ?>">body{padding:20px;font-family:Consolas,monospace}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}</style>
</head>
<body>
<div class="container" style="max-width:640px;">
    <div class="alert alert-danger" role="alert">Invalid or missing sub_id.</div>
</div>
</body>
</html>
    <?php
    exit;
}

if (isset($_GET['logout'])) {
    setcookie('verify', '', cookieOptions($timeout));
    header('Location: ' . LOGOUT_URL);
    exit;
}

if (isset($_POST['access_password'])) {
    $login = (string) ($_POST['access_login'] ?? '');
    $pass = (string) ($_POST['access_password'] ?? '');

    $isValid = false;
    if (!USE_USERNAME) {
        $isValid = in_array($pass, $loginInformation, true);
    } else {
        $isValid = array_key_exists($login, $loginInformation) && hash_equals((string) $loginInformation[$login], $pass);
    }

    if (!$isValid) {
        $loginError = 'err';
        showLoginPasswordProtect($loginError, $subIdParam, $nonce);
    }

    setcookie('verify', md5($login . '%' . $pass), cookieOptions($timeout));
    unset($_POST['access_login'], $_POST['access_password'], $_POST['Submit']);
} else {
    $cookieVerify = (string) ($_COOKIE['verify'] ?? '');
    if ($cookieVerify === '') {
        showLoginPasswordProtect('', $subIdParam, $nonce);
    }

    $found = false;
    foreach ($loginInformation as $key => $val) {
        $lp = (USE_USERNAME ? $key : '') . '%' . $val;
        if (hash_equals(md5($lp), $cookieVerify)) {
            $found = true;
            if (TIMEOUT_CHECK_ACTIVITY) {
                setcookie('verify', md5($lp), cookieOptions($timeout));
            }
            break;
        }
    }

    if (!$found) {
        showLoginPasswordProtect('', $subIdParam, $nonce);
    }
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
    <link rel="stylesheet" href="dist/bootstrap.min.css" type="text/css" media="all">
    <style nonce="<?= e($nonce); ?>">iframe{margin:auto;display:block}input[type="text"],input[type="number"],textarea{font-family:Consolas,monospace}.max{min-width:145px;text-align:left}.maxi{min-width:40px;text-align:left}img{border:1px solid #ddd;border-radius:.3rem}body{padding-top:10px;font-family:Consolas,monospace}.notActive{box-shadow:none}.error{background-color:rgba(255,204,204,.2)!important}.success{background-color:rgba(204,232,255,.2)!important}button,button:focus,button:active{box-shadow:none}.nav-tabs>li.active>a,.nav-tabs>li.active>a:focus,.nav-tabs>li.active>a:hover{border-top:none!important;border-left:none!important;border-right:none!important}.nav-tabs{border-bottom:2px solid #ccc!important;border-top:2px solid #ccc!important}.rg-source{color:#7f7f7f;margin:0;float:left;font-weight:700;font-size:.75em;line-height:1.5em}.rg-source-0{color:#7f7f7f;margin:0;float:left;clear:both;font-weight:700;font-size:.75em;line-height:.5em}.table-fixed thead,.table-fixed thead th{position:sticky;top:0;z-index:20;background-color:#f5f5f5;color:#424242}.panel-footer{overflow:hidden}.app-shell{max-width:650px}.btn-inline-icon{display:inline-flex;align-items:center;gap:6px}.btn-inline-icon svg{width:14px;height:14px;display:block}.compact-hr{margin:1px;padding:1px;border:0;border-bottom:0 dashed #ccc}.footer-sign{float:right}.toastbox{position:fixed;top:12px;right:12px;z-index:9999;display:flex;flex-direction:column;gap:8px}.toastitem{display:flex;align-items:center;gap:8px;min-width:260px;max-width:420px;padding:10px 12px;border:1px solid #d9d9d9;background:#fff;border-radius:.3rem;box-shadow:0 2px 8px rgba(0,0,0,.06)}.toastitem--error{border-color:#e7b4b4;background:#fff6f6;color:#7f1d1d}.toastitem--success{border-color:#b9dec2;background:#f5fff7;color:#185b2d}.toastitem svg{width:16px;height:16px;flex:0 0 16px}.toastitem span{display:block;font-size:12px;line-height:1.3}.panel-heading .btn,.input-group-btn .btn,.nav-tabs>li>a,.form-control,.input-group-addon,.panel,.btn,.label,textarea,select{border-radius:.3rem!important}@media screen and (max-width:768px){.app-shell{max-width:100%;width:100%!important}.container{width:100%!important}.panel-body,.panel-footer,.panel-heading{padding:10px}.input-group{display:block}.input-group .form-control,.input-group .input-group-addon,.input-group .input-group-btn,.input-group-btn>.btn{display:block;width:100%!important}.input-group-addon{border-bottom:0}.input-group-btn>.btn{margin-top:6px}.panel-footer .pull-left,.panel-footer .text-right{float:none!important;text-align:left!important}.panel-footer select{width:100%!important;margin-bottom:8px}.footer-sign{float:none;text-align:right}}@media screen and (max-width:500px){.rg-source{float:none}}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}</style>
</head>
<body>
<div id="toastbox" class="toastbox" aria-live="polite" aria-atomic="true"></div>
<div class="container app-shell">
    <div class="panel panel-default">
        <div class="panel-heading">
            <code></code>
            <div class="pull-right">
                <button type="button" class="btn btn-xs btn-primary" id="command-add" data-row-id="0">
                    <strong><?= $escapedTitle; ?></strong>
                </button>
            </div>
        </div>
        <div class="panel-body">
            <div class="panel-footer" style="height:auto;">
                <img src="imge.png" height="50" width="100%" alt="Banner">
            </div>
            <ul class="nav nav-tabs">
                <li id="tabgen" class="active"><a href="#gen" data-toggle="tab"><strong>GENERATE</strong></a></li>
                <li id="tabaddon"><a href="#addon" data-toggle="tab"><strong>ADDDOMAIN</strong></a></li>
            </ul>
            <div id="myTabContent" class="tab-content">
                <div class="panel-footer" style="height:auto;" id="sm">
                    <div class="input-group">
                        <div id="radioBtn" class="btn-group btn-group-justified btn-block">
                            <?php
                            $result = mysqli_query($link, 'SELECT network FROM offering');
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
                    <div class="panel-footer" style="height:auto;">
                        <div class="pull-left">
                            <select id="locrandom" class="input-sm">
                                <optgroup label="GLOBAL DOMAIN">
                                    <option value="0" class="bold-option">---[GLOBAL DOMAIN]---</option>
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
                                    <option value="0" selected="selected" class="bold-option">---user domain---</option>
                                    <option value="u_rand" class="bold-option">[RANDOM USER DOMAIN]</option>
                                </optgroup>
                            </select>
                        </div>
                    </div>
                    <hr class="compact-hr">
                    <div class="panel-footer" style="height:auto;">
                        <div class="input-group" style="margin:1px;padding:1px;border:0;">
                            <span class="input-group-addon maxi">T</span>
                            <input class="form-control input-sm js-autoselect" id="fbtext" name="fbtext" autocomplete="off" placeholder="{og:title}" type="text">
                        </div>
                        <div class="input-group" style="margin:1px;padding:1px;border:0;">
                            <span class="input-group-addon maxi">I</span>
                            <input class="form-control input-sm js-autoselect" id="fbimg" name="fbimg" autocomplete="off" placeholder="{og:image}" type="text">
                        </div>
                    </div>
                    <hr class="compact-hr">
                    <div class="panel-footer" style="height:auto;">
                        <div class="input-group">
                            <input class="form-control input-sm js-autoselect" id="shortgen" name="shortgen" autocomplete="off" placeholder="{limitgen}" type="number" min="1" step="1">
                            <span class="input-group-btn">
                                <button class="btn btn-default btn-sm" data-loading-text="Generate URL ..." id="genurl" type="button">
                                    <strong class="btn-inline-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M14 3h7v7h-2V6.41l-9.29 9.3-1.42-1.42 9.3-9.29H14V3ZM5 5h6v2H7v10h10v-4h2v6H5V5Z"/></svg>GENERATE URL</strong>
                                </button>
                            </span>
                        </div>
                    </div>
                    <hr class="compact-hr">
                    <div class="panel-footer" style="height:auto;">
                        <select id="lg" class="form-control input-sm">
                            <optgroup label="Landing page">
                                <option class="btn btn-sm btn-default" value="direct">No Landing page</option> 
                                <option class="btn btn-sm btn-default" value="landing">Landing page</option>
                            </optgroup>
                        </select>
                        <hr class="compact-hr">
                        <div class="input-group">
                            <span class="input-group-btn">
                                <button type="button" id="copy-limitgen" class="btn btn-default btn-sm maxi" title="Copy URL" aria-label="Copy URL">
                                    <svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true"><path fill="currentColor" d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
                                </button>
                            </span>
                            <input autocomplete="off" style="width:45%;" class="form-control input-sm js-autoselect js-readlock" id="limitgen" name="limitgen" placeholder="{shorturl}" type="text">
                            <select style="width:30%;" id="net_pick" class="form-control input-sm">
                                <optgroup label="SELECT DEBUGGER">
                                    <option value="a" selected="selected">default</option>
                                    <option value="b">l.fb.com</option>
                                    <option value="f">l.wl.co</option>
                                </optgroup>
                            </select>
                            <select style="width:25%;" id="uri" class="form-control input-sm">
                                <optgroup label="SELECT SHORTURL">
                                    <option class="btn btn-sm btn-default" value="def" selected="selected">default URL</option>
                                    <option class="btn btn-sm btn-default" value="ixg">ixg.llc</option>
                                    <option class="btn btn-sm btn-default" value="tco">is.gd</option>
                                </optgroup>
                            </select>
                            <span class="input-group-btn">
                                <button class="btn btn-default btn-sm" data-loading-text="shorting URL ..." id="branch" type="button">
                                    <strong class="btn-inline-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M10.59 13.41 9.17 12l4.24-4.24H11V6h6v6h-1.76V9.17l-4.65 4.24ZM19 19H5V5h4v2H7v10h10v-2h2v4Z"/></svg>SHORT URL</strong>
                                </button>
                            </span>
                        </div>
                        <hr class="compact-hr">
                        <div class="input-group">
                            <span class="input-group-addon max"><strong class="rg-source-0">Result URL</strong></span>
                        </div>
                        <textarea class="form-control input-sm js-autoselect" id="b_short" name="b_short" placeholder="https://..." rows="2" style="resize:none;"></textarea>
                    </div>
                </div>
                <div class="tab-pane fade" id="addon">
                    <blockquote>
                        <p class="text-warning">Nameserver:</p>
                        <div class="text-muted">Nameserver 1: ns1.mysecurecloudhost.com<hr class="compact-hr">Nameserver 2: ns2.mysecurecloudhost.com<hr class="compact-hr">Nameserver 3: ns3.mysecurecloudhost.com<hr class="compact-hr">Nameserver 4: ns4.mysecurecloudhost.com</div>
                    </blockquote>
                    <hr style="margin:1px;padding:1px;border:0;border-bottom:0 dashed #ccc">
                    <div class="panel-footer" style="height:auto;">
                        <div class="input-group">
                            <span class="input-group-addon maxi">+</span>
                            <input type="hidden" class="form-control input-sm" id="userid" name="userid" value="<?= $escapedTitle; ?>">
                            <input autocomplete="off" type="text" class="form-control input-sm js-autoselect" id="domain" name="domain" placeholder="{addon_domain} domain.tld">
                            <span class="input-group-btn btn-block">
                                <button class="btn btn-default btn-sm" id="addondom" type="button" data-loading-text="Addon Domain ..."><strong>Addon Domain</strong></button>
                            </span>
                        </div>
                    </div>
                    <hr style="margin:3px;padding:3px;border:0;border-bottom:0 solid #ccc">
                    <table id="table_domain" class="responsive nowrap unstackable table table-hover table-fixed" cellspacing="0" style="table-layout:auto;">
                        <thead>
                            <tr>
                                <th class="rg-source col-xs-8" style="text-align:left;">DOMAIN</th>
                                <th class="rg-source col-xs-2" style="text-align:left;">SUBID</th>
                                <th class="rg-source col-xs-2" style="text-align:left;">ACTION</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
        </div>
        <input type="hidden" class="form-control input-sm" id="user_lp" name="user_lp">
        <input type="hidden" id="pick" name="pick" class="form-control input-sm" value="0">
        <input type="hidden" id="deb" name="deb" class="form-control input-sm" value="b">
        <input type="hidden" id="urlgen" name="urlgen" class="form-control input-sm" value="https://{sub}.global/{click_id}">
        <input type="hidden" id="pickurl" name="pickurl" class="form-control input-sm" value="0">
        <input type="hidden" id="sub_id" name="sub_id" class="form-control input-sm" value="<?= $escapedSubIdLower; ?>">
    </div>
    <hr style="margin:-10px;padding:-10px;border:0;box-sizing:border-box;border-bottom:0">
    <div class="rg-source footer-sign"><footer class="text-muted" style="text-decoration:none;">ngix:n-gix</footer></div>

<div class="modal fade" id="deleteDomainModal" tabindex="-1" role="dialog" aria-hidden="true">
    <div class="modal-dialog modal-sm" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title">Delete Domain</h4>
            </div>
            <div class="modal-body">
                <p style="margin:0;">This action cannot be reverted.</p>
                <input type="hidden" id="delete_domain_target" value="">
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default btn-sm" data-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-danger btn-sm" id="confirm_delete_domain">Delete</button>
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

    $(document).on('focus', '.js-autoselect', function () { this.select(); });
    $(document).on('selectstart paste cut dragstart drop', '.js-readlock', function (e) { e.preventDefault(); return false; });

    $(document).on('click', '#copy-limitgen', function () {
        var input = document.getElementById('limitgen');
        if (!input || !input.value) { showToast('error', 'No URL to copy.'); return; }
        var val = input.value;
        var done = function () { showToast('success', 'URL copied.'); };
        var fail = function () { showToast('error', 'Copy failed.'); };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(val).then(done, function () {
                try { input.select(); document.execCommand('copy'); done(); } catch (e) { fail(); }
            });
        } else {
            try { input.select(); document.execCommand('copy'); done(); } catch (e) { fail(); }
        }
    });

    function showToast(type, message) {
        var toastId = 'toast-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
        var icon = type === 'success'
            ? '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M9.55 16.6 5.4 12.45l1.4-1.4 2.75 2.75 7.65-7.65 1.4 1.4-9.05 9.05Z"/></svg>'
            : '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm1 15h-2v-2h2v2Zm0-4h-2V7h2v6Z"/></svg>';
        var node = '<div id="' + toastId + '" class="toastitem toastitem--' + type + '">' + icon + '<span></span></div>';
        $('#toastbox').append(node);
        $('#' + toastId + ' span').text(message);
        setTimeout(function () {
            $('#' + toastId).fadeOut(180, function () {
                $(this).remove();
            });
        }, 2200);
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
        $('#limitgen, #b_short').val('').removeClass('error success');
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

    function requestWrappedShort(endpoint, payload, buttonObj, wrapperMode) {
        $.post(endpoint, payload).done(function (data) {
            var rows = safeArrayResponse(data);
            var candidate = '';
            if (rows.length > 0 && rows[0]) {
                candidate = $.trim(rows[0].l || rows[0].shorturl || '');
            }
            if (candidate === '' || candidate === 'https://') {
                $('#b_short').val('* Shortener returned empty result').addClass('error').removeClass('success');
                showToast('error', 'Shortener returned empty result.');
            } else {
                $('#b_short').val(applyWrapper(candidate, wrapperMode)).addClass('success').removeClass('error');
                showToast('success', 'Short URL generated.');
            }
            buttonObj.button('reset');
        }).fail(function () {
            $('#b_short').val('* Shortener request failed').addClass('error').removeClass('success');
            showToast('error', 'Shortener request failed.');
            buttonObj.button('reset');
        });
    }

    function appendDomainRow(rowData) {
        if (!rowData || !rowData.domain) {
            return;
        }
        if ($('#table_domain tbody tr[data-domain="' + rowData.domain.replace(/"/g, '\\"') + '"]').length > 0) {
            return;
        }
        var row = $('<tr data-domain="' + rowData.domain + '"></tr>');
        row.append($('<td style="text-align:left;" class="post-colon col-xs-8"></td>').text(rowData.domain));
        row.append($('<td style="text-align:left;" class="post-colon col-xs-2"></td>').text(rowData.sub_domain || ''));
        var actionCell = $('<td style="text-align:left;" class="post-colon col-xs-2"></td>');
        var deleteButton = $('<button type="button" class="delete btn btn-default btn-xs"></button>');
        deleteButton.attr('data-domain', rowData.domain).text('Delete');
        actionCell.append(deleteButton);
        row.append(actionCell);
        $('#table_domain tbody').append(row);

        if ($('#locdom option[value="' + rowData.domain.replace(/"/g, '\\"') + '"]').length === 0) {
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
    }

    function loadUserDomains() {
        var domain = $.trim($('#domain').val());
        var userid = $.trim($('#userid').val());
        $.ajax({
            url: '/api/user.domain.php',
            type: 'get',
            dataType: 'json',
            data: {
                sub_domain: userid,
                domain: domain
            }
        }).done(function (data) {
            if ($.isArray(data)) {
                drawTable(data);
            }
        });
    }

    $(document).ready(function () {
        initFirstNetwork();
        preventManualInput('#urlgen,#pick,#limitgen,#b_short');

        $('img').on('contextmenu', function () {
            return false;
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
            var pick = $.trim($('#pick').val());
            var pickurl = $.trim($('#pickurl').val());
            var subId = $.trim($('#sub_id').val());
            var userLp = $.trim($('#user_lp').val());
            var limitgen = $.trim($('#shortgen').val());
            var lg = $.trim($('#lg').val());

            var fbimg = $.trim($('#fbimg').val());
            var fbtext = $.trim($('#fbtext').val());
            var button = $(this);

            if (url === '') {
                $('#shortgen').addClass('error');
                $('#limitgen').val('* Missing URL template').addClass('error').removeClass('success');
                showToast('error', 'URL template is missing.');
                return false;
            }

            button.button('loading');
            $('#shortgen').removeClass('error');
            $('#limitgen').val('waiting...').removeClass('error success');
            $('#b_short').val('').removeClass('error success');

            $.post('/api/b.api.php', {
                longurl: url,
                apibranch: limitgen,
                pickurl: pickurl,
                id: pick,
                sub_id: subId,
                user_lp: userLp,

                fbimg: fbimg,
                fbtext: fbtext,
                lg: lg
            }).done(function (data) {
                var rows = safeArrayResponse(data);
                var shortUrl = rows.length > 0 && rows[0] ? $.trim(rows[0].shorturl || '') : '';
                if (shortUrl === '' || shortUrl === 'https://') {
                    $('#limitgen').val('* Invalid or missing response').addClass('error').removeClass('success');
                    showToast('error', 'Generate request returned empty response.');
                } else {
                    $('#limitgen').val(shortUrl).addClass('success').removeClass('error');
                    showToast('success', 'Generate URL success.');
                }
                button.button('reset');
                $('#branch').button('reset');
            }).fail(function () {
                $('#limitgen').val('* Generate request failed').addClass('error').removeClass('success');
                showToast('error', 'Generate request failed.');
                button.button('reset');
                $('#branch').button('reset');
            });

            return false;
        });

        $('#branch').on('click', function () {
            var prm = $.trim($('#deb').val());
            var choose = $.trim($('#uri').val());
            var generatedUrl = $.trim($('#limitgen').val());
            var button = $(this);

            if (generatedUrl === '') {
                $('#limitgen').addClass('error');
                $('#b_short').val('* Request generate URL first').addClass('error').removeClass('success');
                showToast('error', 'Generate URL first.');
                return false;
            }

            button.button('loading');
            $('#limitgen').removeClass('error');
            $('#b_short').val('waiting...').removeClass('error success');

            if (choose === 'def') {
                $('#b_short').val(applyWrapper(generatedUrl, prm)).addClass('success').removeClass('error');
                showToast('success', 'Result URL ready.');
                button.button('reset');
                return false;
            }

            if (choose === 'ixg') {
                requestWrappedShort('/api/api.ixg.php', { longurl: generatedUrl, prm: prm }, button, prm);
                return false;
            }

            if (choose === 'tco') {
                requestWrappedShort('/api/isgd.php', { longurl: generatedUrl, prm: prm }, button, prm);
                return false;
            }

            $('#b_short').val('* Unsupported shortener option').addClass('error').removeClass('success');
            showToast('error', 'Unsupported shortener option.');
            button.button('reset');
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

            button.button('loading');
            $.getJSON('/api/call.php', {
                sub_domain: userid,
                domain: domain
            }).done(function (resp) {
                var rows = safeArrayResponse(resp);
                if (rows.length === 0 || !rows[0] || !rows[0].domain || !rows[0].userid) {
                    showToast('error', 'Addon domain response is invalid.');
                    button.button('reset');
                    return;
                }

                $.getJSON('/api/user.insert.domain.php', {
                    domain: rows[0].domain,
                    sub_domain: rows[0].userid
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
            $('#deleteDomainModal').modal('show');
            return false;
        });

        $('#confirm_delete_domain').on('click', function () {
            var buttonId = $.trim($('#delete_domain_target').val());
            var rowNode = $('#table_domain tbody tr[data-domain="' + buttonId.replace(/"/g, '\\"') + '"]');
            if (buttonId === '') {
                showToast('error', 'Invalid domain target.');
                return false;
            }
            $.getJSON('/api/user.del.domain.php', {
                domain: buttonId
            }).done(function () {
                $('option[name="' + buttonId.replace(/"/g, '\\"') + '"]').remove();
                rowNode.css('background', '#ffe5e5').fadeOut(300, function () {
                    $(this).remove();
                });
                $('#deleteDomainModal').modal('hide');
                $('#delete_domain_target').val('');
                showToast('success', 'Domain deleted.');
            }).fail(function () {
                $('#deleteDomainModal').modal('hide');
                showToast('error', 'Delete request failed.');
            });
            return false;
        });

        loadUserDomains();
    });
}(jQuery));
</script>
</body>
</html>
