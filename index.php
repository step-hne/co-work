<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/helpers.php';

use MailboxControl\EmailService;
use function MailboxControl\loadConfig;
use function MailboxControl\configString;
use function MailboxControl\configInt;
use function MailboxControl\requireConfigValue;
use function MailboxControl\mailboxStorePath;
use function MailboxControl\loadMailboxStore;
use function MailboxControl\saveMailboxStore;
use function MailboxControl\cpanelCreateMailbox;
use function MailboxControl\cpanelDeleteMailbox;

const APP_NAME = 'Mailbox Control';
const SESSION_NAME = 'mailbox_control_app';

function isHttpsRequest(): bool
{
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== '' && $_SERVER['HTTPS'] !== 'off') {
        return true;
    }

    if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower((string) $_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https') {
        return true;
    }

    if (isset($_SERVER['HTTP_CF_VISITOR']) && stripos((string) $_SERVER['HTTP_CF_VISITOR'], '"scheme":"https"') !== false) {
        return true;
    }

    return false;
}

function bootSession(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    session_name(SESSION_NAME);

    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => isHttpsRequest(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);

    session_start();

    $timeout = 1800;
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $timeout) {
        $_SESSION = [];
        session_destroy();
        session_start();
    }
    $_SESSION['last_activity'] = time();

    if (!isset($_SESSION['created_at'])) {
        $_SESSION['created_at'] = time();
        session_regenerate_id(true);
    }
}

function sendSecurityHeaders(string $nonce): void
{
    if (headers_sent()) {
        return;
    }

    header('Content-Type: text/html; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('Referrer-Policy: same-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');

    $csp = [
        "default-src 'self'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'self'",
        "object-src 'none'",
        "img-src 'self' data:",
        "font-src 'self' data:",
        "style-src 'self' 'nonce-" . $nonce . "'",
        "script-src 'self' 'nonce-" . $nonce . "'",
        "connect-src 'self'",
    ];

    header('Content-Security-Policy: ' . implode('; ', $csp));
}

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function linkifyText(string $value): string
{
    $escaped = htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    return preg_replace(
        '/(https?:\/\/[^\s<]+)/i',
        '<a href="$1" target="_blank" rel="noopener noreferrer">$1</a>',
        $escaped
    );
}

function csrfToken(): string
{
    if (!isset($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token']) || $_SESSION['csrf_token'] === '') {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

function validateCsrf(string $token): bool
{
    if (!isset($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        return false;
    }

    return hash_equals($_SESSION['csrf_token'], $token);
}

function postString(string $key, int $maxLength = 255): string
{
    if (!isset($_POST[$key])) {
        return '';
    }

    $value = trim((string) $_POST[$key]);

    if (strlen($value) > $maxLength) {
        return substr($value, 0, $maxLength);
    }

    return $value;
}

function hasSuspiciousPattern(string $value): bool
{
    if ($value === '') {
        return false;
    }

    $patterns = [
        '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/',
        '/(?:https?:|data:|javascript:)/i',
        '/[<>{}\[\]`"\\\\]/',
        '/(?:--|\/\*|\*\/|;)/',
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $value) === 1) {
            return true;
        }
    }

    return false;
}

function normalizeLocalPart(string $value): string
{
    $value = strtolower(trim($value));
    $value = preg_replace('/[^a-z0-9._-]+/', '', $value) ?? '';
    $value = trim($value, '.-_');

    return $value;
}

function isValidLocalPart(string $value): bool
{
    if ($value === '' || strlen($value) > 64) {
        return false;
    }

    if ($value === 'cpanel') {
        return false;
    }

    return preg_match('/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/', $value) === 1;
}

function isValidMailbox(string $email, string $domain): bool
{
    $email = strtolower(trim($email));
    $domain = strtolower(trim($domain));

    if ($email === '' || $domain === '') {
        return false;
    }

    if (!str_ends_with($email, '@' . $domain)) {
        return false;
    }

    $local = substr($email, 0, -1 * (strlen($domain) + 1));

    return isValidLocalPart($local);
}

function appIsAuthenticated(): bool
{
    return isset($_SESSION['admin_ok']) && $_SESSION['admin_ok'] === true;
}

function generateRandomLocalPart(string $prefix, int $length = 8): string
{
    $alphabet = 'abcdefghijkmnpqrstuvwxyz23456789';
    $alphabetLength = strlen($alphabet);
    $suffix = '';

    for ($i = 0; $i < $length; $i++) {
        $suffix .= $alphabet[random_int(0, $alphabetLength - 1)];
    }

    $local = $prefix . $suffix;
    return normalizeLocalPart($local);
}

function generateRandomPassword(int $length = 20): string
{
    $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    $lower = 'abcdefghjkmnpqrstuvwxyz';
    $digits = '23456789';
    $symbols = '!@#$%^&*-_=+';

    $required = [
        $upper[random_int(0, strlen($upper) - 1)],
        $lower[random_int(0, strlen($lower) - 1)],
        $digits[random_int(0, strlen($digits) - 1)],
        $symbols[random_int(0, strlen($symbols) - 1)],
    ];

    $pool = $upper . $lower . $digits . $symbols;
    $poolLength = strlen($pool);
    $password = $required;

    for ($i = count($required); $i < $length; $i++) {
        $password[] = $pool[random_int(0, $poolLength - 1)];
    }

    for ($i = count($password) - 1; $i > 0; $i--) {
        $j = random_int(0, $i);
        [$password[$i], $password[$j]] = [$password[$j], $password[$i]];
    }

    return implode('', $password);
}

function loadInboxMessages(array $config, string $email, string $password, int $limit, int $retries = 0): array
{
    $imapHost = configString($config, 'imap_host');
    $imapPort = configInt($config, 'imap_port', 993);

    if ($imapHost === '') {
        return ['ok' => false, 'message' => 'IMAP server is not configured.', 'messages' => []];
    }

    $attempt = 0;
    $lastError = '';

    while ($attempt <= $retries) {
        $emailService = new EmailService($imapHost, $imapPort);
        try {
            if ($emailService->connect($email, $password)) {
                $messages = [];
                foreach ($emailService->fetchMessages($limit) as $emailMessage) {
                    $messages[] = $emailMessage->toArray();
                }
                return ['ok' => true, 'message' => '', 'messages' => $messages];
            }
            $lastError = 'IMAP authentication failed.';
        } catch (\Throwable $exception) {
            $lastError = 'IMAP error: ' . $exception->getMessage();
        }

        $attempt++;
        if ($attempt <= $retries) {
            sleep(2);
        }
    }

    return ['ok' => false, 'message' => $lastError, 'messages' => []];
}

bootSession();

$nonce = bin2hex(random_bytes(16));
sendSecurityHeaders($nonce);

$config = loadConfig();
$csrf = csrfToken();
$errors = [];
$notice = '';
$messages = [];

if (isset($config['__config_error']) && is_string($config['__config_error'])) {
    $errors[] = $config['__config_error'];
}

$adminPasswordHash = configString($config, 'admin_password_hash');
$emailDomain = configString($config, 'email_domain');
$autoMailboxPrefix = configString($config, 'mailbox_prefix');
$autoMailboxQuota = configInt($config, 'mailbox_auto_quota_mib', 50);
$autoMailboxTtlHours = configInt($config, 'mailbox_ttl_hours', 24);
$autoMailboxRateLimitPerHour = configInt($config, 'mailbox_auto_rate_limit_per_hour', 10);

$generatedMailbox = null;

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $action = postString('action', 32);

    if ($action === 'login') {
        $_SESSION['login_attempts'] ??= 0;
        $_SESSION['login_last_attempt'] ??= 0;

        $timeSinceLastAttempt = time() - $_SESSION['login_last_attempt'];

        if ($_SESSION['login_attempts'] >= 5 && $timeSinceLastAttempt < 900) {
            $errors[] = 'Too many login attempts. Try again in 15 minutes.';
        }
    }

    $token = postString('csrf_token', 128);

    if (!validateCsrf($token)) {
        $errors[] = 'Invalid CSRF token.';
    }

    if ($errors === [] && $action === 'login') {
        $password = postString('admin_password', 200);

        if ($adminPasswordHash === '') {
            $errors[] = 'Admin password hash is not configured.';
        } elseif (password_verify($password, $adminPasswordHash)) {
            session_regenerate_id(true);
            $_SESSION['admin_ok'] = true;
            $_SESSION['login_attempts'] = 0;
            $notice = 'Admin session opened.';
        } else {
            $_SESSION['login_last_attempt'] = time();
            $_SESSION['login_attempts']++;
            $errors[] = 'Invalid admin password.';
        }
    }

    if ($errors === [] && $action === 'logout') {
        $_SESSION = [];
        session_destroy();
        header('Location: ' . $_SERVER['REQUEST_URI']);
        exit;
    }

    if ($errors === [] && appIsAuthenticated() && $action === 'create_mailbox') {
        $localPart = normalizeLocalPart(postString('local_part', 80));
        $mailboxPassword = postString('mailbox_password', 200);
        $quota = (int) postString('quota', 8);

        if (hasSuspiciousPattern($localPart)) {
            $errors[] = 'Suspicious local part blocked.';
        }

        if (!isValidLocalPart($localPart)) {
            $errors[] = 'Invalid mailbox local part.';
        }

        if (strlen($mailboxPassword) < 12 || strlen($mailboxPassword) > 128) {
            $errors[] = 'Mailbox password must be 12-128 characters.';
        }

        if ($quota < 50 || $quota > 4096) {
            $errors[] = 'Quota must be between 50 and 4096 MiB.';
        }

        if ($errors === []) {
            $result = cpanelCreateMailbox($config, $localPart, $mailboxPassword, $quota);

            if ($result['ok'] === true) {
                $notice = $result['message'];
            } else {
                $errors[] = $result['message'];
            }
        }
    }

    if ($errors === [] && appIsAuthenticated() && $action === 'auto_create_mailbox') {
        $_SESSION['auto_create_log'] ??= [];
        $now = time();
        $oneHourAgo = $now - 3600;
        $_SESSION['auto_create_log'] = array_values(array_filter(
            $_SESSION['auto_create_log'],
            static fn ($t) => is_int($t) && $t >= $oneHourAgo
        ));

        if (count($_SESSION['auto_create_log']) >= $autoMailboxRateLimitPerHour) {
            $errors[] = 'Auto-create rate limit reached. Try again later.';
        } elseif ($emailDomain === '') {
            $errors[] = 'Email domain is not configured.';
        } else {
            $localPart = generateRandomLocalPart($autoMailboxPrefix);
            $password = generateRandomPassword();

            if (!isValidLocalPart($localPart)) {
                $errors[] = 'Generated local part failed validation.';
            } else {
                $result = cpanelCreateMailbox($config, $localPart, $password, $autoMailboxQuota);

                if ($result['ok'] === true) {
                    $email = $localPart . '@' . $emailDomain;
                    $createdAt = time();
                    $expiresAt = $createdAt + ($autoMailboxTtlHours * 3600);

                    $store = loadMailboxStore();
                    $store['mailboxes'][$email] = [
                        'local_part' => $localPart,
                        'created_at' => $createdAt,
                        'last_access_at' => $createdAt,
                        'expires_at' => $expiresAt,
                        'ttl_hours' => $autoMailboxTtlHours,
                    ];
                    saveMailboxStore($store);

                    $_SESSION['auto_create_log'][] = $createdAt;

                    $generatedMailbox = [
                        'email' => $email,
                        'password' => $password,
                        'expires_at' => $expiresAt,
                        'ttl_hours' => $autoMailboxTtlHours,
                    ];

                    $_SESSION['active_mailbox'] = [
                        'email' => $email,
                        'password' => $password,
                        'expires_at' => $expiresAt,
                        'ttl_hours' => $autoMailboxTtlHours,
                    ];

                    $inbox = loadInboxMessages($config, $email, $password, 10, 2);
                    if ($inbox['ok'] === true) {
                        $messages = $inbox['messages'];
                        $notice = 'Mailbox generated. Inbox auto-refreshes every 10s. Save the password — it will not be shown again.';
                    } else {
                        $notice = 'Mailbox generated. Save the password. Inbox warming up: ' . $inbox['message'];
                    }
                } else {
                    $errors[] = $result['message'];
                }
            }
        }
    }

    if ($errors === [] && appIsAuthenticated() && $action === 'clear_active_mailbox') {
        unset($_SESSION['active_mailbox']);
        $notice = 'Active mailbox cleared.';
    }
}

$isAuthed = appIsAuthenticated();

if (
    $isAuthed
    && isset($_GET['ajax'])
    && $_GET['ajax'] === 'inbox'
    && isset($_SESSION['active_mailbox'])
    && is_array($_SESSION['active_mailbox'])
) {
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

    $am = $_SESSION['active_mailbox'];
    $inbox = loadInboxMessages(
        $config,
        (string) ($am['email'] ?? ''),
        (string) ($am['password'] ?? ''),
        10
    );

    echo json_encode([
        'ok' => $inbox['ok'],
        'message' => $inbox['message'] ?? '',
        'email' => (string) ($am['email'] ?? ''),
        'expires_at' => (int) ($am['expires_at'] ?? 0),
        'polled_at' => time(),
        'messages' => $inbox['messages'] ?? [],
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

if (
    $isAuthed
    && ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET'
    && $messages === []
    && isset($_SESSION['active_mailbox'])
    && is_array($_SESSION['active_mailbox'])
    && $generatedMailbox === null
) {
    $am = $_SESSION['active_mailbox'];
    $inbox = loadInboxMessages(
        $config,
        (string) ($am['email'] ?? ''),
        (string) ($am['password'] ?? ''),
        10
    );
    if ($inbox['ok'] === true) {
        $messages = $inbox['messages'];
    }
}

$activeMailbox = $_SESSION['active_mailbox'] ?? null;

?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/svg+xml" href="favicon.svg">
<title><?= e(APP_NAME) ?></title>
<style nonce="<?= e($nonce) ?>">
:root{color-scheme:light;--bg:#f7f7f7;--panel:rgba(255,255,255,.86);--panel2:rgba(255,255,255,.62);--line:rgba(41,43,44,.15);--line2:rgba(41,43,44,.08);--text:#292b2c;--muted:#687078;--strong:#151617;--primary:#292b2c;--primary2:#3a3d3e;--on:#f7f7f7;--bad:#9f3138;--good:#27724d;--warn:#8a641c;--radius:.3rem;--shadow:0 1px 4px rgba(41,43,44,.08);--font:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;--mono:"Lucida Console","Courier New",Consolas,Monaco,monospace}@media(prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#292b2c;--panel:rgba(247,247,247,.07);--panel2:rgba(247,247,247,.045);--line:rgba(247,247,247,.16);--line2:rgba(247,247,247,.09);--text:#e8e8e8;--muted:#a9adb2;--strong:#fff;--primary:#f7f7f7;--primary2:#e1e1e1;--on:#292b2c;--bad:#ff7d87;--good:#74d7a2;--warn:#f1c36d;--shadow:0 1px 4px rgba(0,0,0,.16)}}*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:radial-gradient(circle at 18% 8%,rgba(120,120,120,.10),transparent 30%),var(--bg);color:var(--text);font-family:var(--font);font-size:14px;line-height:1.45;-webkit-font-smoothing:antialiased;text-rendering:geometricPrecision}button,input,select,textarea{font:inherit}.wrap{width:min(1120px,calc(100% - 24px));margin:0 auto;padding:22px 0}.top{display:grid;grid-template-columns:1fr auto;gap:12px;align-items:end;margin-bottom:14px}.eyebrow{font-family:var(--mono);font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin:0 0 5px}.title{font-size:24px;line-height:1.1;margin:0;color:var(--strong);font-weight:700;letter-spacing:-.035em}.sub{margin:7px 0 0;color:var(--muted);max-width:720px}.badge{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);background:var(--panel2);border-radius:var(--radius);padding:6px 8px;color:var(--muted);font-family:var(--mono);font-size:11px;white-space:nowrap}.dot{width:7px;height:7px;border-radius:999px;background:var(--good);display:inline-block}.grid{display:grid;grid-template-columns:390px 1fr;gap:14px;align-items:start}.panel{border:1px solid var(--line);background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden}.panel-h{padding:12px 13px;border-bottom:1px solid var(--line2);display:flex;align-items:center;justify-content:space-between;gap:10px}.panel-title{font-size:13px;margin:0;color:var(--strong);font-weight:700}.panel-body{padding:13px}.form{display:grid;gap:10px}.field{display:grid;gap:5px}.label{font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}.input,.select{width:100%;border:1px solid var(--line);background:var(--panel2);color:var(--text);border-radius:var(--radius);height:36px;padding:0 10px;outline:none}.input:focus,.select:focus{border-color:var(--primary);box-shadow:0 0 0 2px rgba(127,127,127,.14)}.hint{font-size:12px;color:var(--muted)}.btn{border:1px solid var(--line);background:var(--panel2);color:var(--text);border-radius:var(--radius);height:36px;padding:0 11px;display:inline-flex;align-items:center;justify-content:center;gap:8px;cursor:pointer;text-decoration:none;user-select:none}.btn:hover{border-color:var(--primary)}.btn-primary{background:var(--primary);border-color:var(--primary);color:var(--on);font-weight:700}.btn-primary:hover{background:var(--primary2)}.btn-sm{height:28px;padding:0 8px;font-size:12px}.actions{display:flex;gap:8px;flex-wrap:wrap}.icon{width:14px;height:14px;display:block;flex:0 0 auto}.alert,.notice{border:1px solid var(--line);background:var(--panel2);border-radius:var(--radius);padding:10px;margin-bottom:12px;color:var(--text)}.alert{border-left:3px solid var(--bad)}.notice{border-left:3px solid var(--good)}.alert strong{color:var(--bad)}.notice strong{color:var(--good)}.split{display:grid;grid-template-columns:1fr 1fr;gap:14px}.mail{border:1px solid var(--line2);background:var(--panel2);border-radius:var(--radius);padding:10px;margin-bottom:8px;cursor:pointer;transition:border-color .2s ease}.mail:hover{border-color:var(--primary)}.mail:focus{outline:2px solid var(--primary);outline-offset:2px}.mail-subject{font-size:13px;font-weight:700;color:var(--strong);margin:0 0 5px}.mail.open .mail-subject{color:var(--primary)}.mail-meta{font-family:var(--mono);font-size:11px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.mail-body{font-size:12px;color:var(--text);margin:8px 0 0;white-space:pre-wrap;overflow-wrap:anywhere;display:none;max-height:0;overflow:hidden;transition:max-height .2s ease}.mail-body a{color:var(--primary);text-decoration:underline}.mail.open .mail-body{display:block;max-height:1000px}.empty{padding:26px 14px;text-align:center;color:var(--muted)}.footer{margin-top:14px;color:var(--muted);font-size:12px}.kbd{font-family:var(--mono);border:1px solid var(--line);border-radius:var(--radius);padding:2px 5px;background:var(--panel2);color:var(--text)}.mt-14{margin-top:14px}.pwrow{display:flex;gap:6px;align-items:stretch}.pwrow .input{flex:1 1 auto;min-width:0}.pwrow .btn-sm{height:36px;flex:0 0 auto}@media(max-width:900px){.grid,.split,.top{grid-template-columns:1fr}.badge{justify-self:start}}@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
</style>
</head>
<body>
<div class="wrap">
    <header class="top">
        <div>
            <p class="eyebrow">cPanel Mailbox Manager</p>
            <h1 class="title"><?= e(APP_NAME) ?></h1>
            <p class="sub">Create mailbox accounts through cPanel UAPI and read incoming messages through IMAP.</p>
        </div>
        <div class="badge"><span class="dot"></span><?= $isAuthed ? 'Admin unlocked' : 'Admin locked' ?></div>
    </header>

    <?php if ($errors !== []) : ?>
        <div class="alert"><strong>Blocked:</strong> <?= e(implode(' ', $errors)) ?></div>
    <?php endif; ?>

    <?php if ($notice !== '') : ?>
        <div class="notice"><strong>Status:</strong> <?= e($notice) ?></div>
    <?php endif; ?>

    <?php if (!$isAuthed) : ?>
        <section class="panel">
            <div class="panel-h">
                <h2 class="panel-title">Admin Login</h2>
                <span class="badge">Required</span>
            </div>
            <div class="panel-body">
                <form class="form" method="post" action="">
                    <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
                    <input type="hidden" name="action" value="login">

                    <div class="field">
                        <label class="label" for="admin_password">Admin Password</label>
                        <div class="pwrow">
                            <input class="input" id="admin_password" name="admin_password" type="password" maxlength="200" autocomplete="current-password" required>
                            <button class="btn btn-sm" type="button" data-toggle-pass="admin_password" aria-label="Show password">Show</button>
                        </div>
                        <div class="hint">This protects mailbox creation from public abuse.</div>
                    </div>

                    <button class="btn btn-primary" type="submit">
                        <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 1a5 5 0 0 0-5 5v3H5a2 2 0 0 0-2 2v10h18V11a2 2 0 0 0-2-2h-2V6a5 5 0 0 0-5-5Zm-3 8V6a3 3 0 1 1 6 0v3H9Zm2 5h2v4h-2v-4Z"/></svg>
                        Unlock
                    </button>
                </form>
            </div>
        </section>
    <?php else : ?>
        <main>
            <section class="panel">
                <div class="panel-h">
                    <h2 class="panel-title">Create Mailbox</h2>
                    <span class="badge">@<?= e($emailDomain) ?></span>
                </div>
                <div class="panel-body">
                    <form class="form" method="post" action="">
                        <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
                        <input type="hidden" name="action" value="auto_create_mailbox">
                        <div class="hint">One-click: random <span class="kbd"><?= $autoMailboxPrefix === '' ? 'xxxxxxxx' : e($autoMailboxPrefix) . 'xxxxxxxx' ?>@<?= e($emailDomain) ?></span>, strong password, quota <?= (int) $autoMailboxQuota ?> MiB, TTL <?= (int) $autoMailboxTtlHours ?> h. Inbox auto-loads.</div>
                        <button class="btn btn-primary" type="submit">
                            <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M13 2 4 14h7l-1 8 9-12h-7l1-8Z"/></svg>
                            Generate Random Mailbox
                        </button>
                    </form>

                    <?php if ($generatedMailbox !== null) : ?>
                        <div class="notice mt-14">
                            <strong>Generated:</strong>
                            <div class="field mt-14">
                                <label class="label" for="gen_email">Email</label>
                                <input class="input" id="gen_email" type="text" value="<?= e($generatedMailbox['email']) ?>" readonly data-select-on-focus>
                            </div>
                            <div class="field">
                                <label class="label" for="gen_pass">Password (shown once)</label>
                                <div class="pwrow">
                                    <input class="input" id="gen_pass" type="password" value="<?= e($generatedMailbox['password']) ?>" readonly data-select-on-focus>
                                    <button class="btn btn-sm" type="button" data-toggle-pass="gen_pass" aria-label="Show password">Show</button>
                                </div>
                            </div>
                            <div class="hint">Auto-delete after <?= (int) $generatedMailbox['ttl_hours'] ?>h (<?= e(gmdate('Y-m-d H:i', $generatedMailbox['expires_at'])) ?> UTC).</div>
                        </div>
                    <?php endif; ?>

                    <details class="mt-14">
                        <summary class="hint">Manual create</summary>
                    <form class="form mt-14" method="post" action="">
                        <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
                        <input type="hidden" name="action" value="create_mailbox">

                        <div class="field">
                            <label class="label" for="local_part">Mailbox Name</label>
                            <input class="input" id="local_part" name="local_part" maxlength="64" placeholder="account" autocomplete="off" required>
                            <div class="hint">Final email: <span class="kbd">name@<?= e($emailDomain) ?></span></div>
                        </div>

                        <div class="field">
                            <label class="label" for="mailbox_password_create">Mailbox Password</label>
                            <div class="pwrow">
                                <input class="input" id="mailbox_password_create" name="mailbox_password" type="password" maxlength="128" autocomplete="new-password" required>
                                <button class="btn btn-sm" type="button" data-toggle-pass="mailbox_password_create" aria-label="Show password">Show</button>
                            </div>
                            <div class="hint">Minimum 12 chars. Do not reuse cPanel password.</div>
                        </div>

                        <div class="field">
                            <label class="label" for="quota">Quota MiB</label>
                            <input class="input" id="quota" name="quota" type="number" min="50" max="4096" value="250" required>
                        </div>

                        <button class="btn btn-primary" type="submit">
                            <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2Z"/></svg>
                            Create Mailbox
                        </button>
                    </form>
                    </details>
                </div>
            </section>

        </main>

        <section class="panel mt-14" data-active-mailbox="<?= $activeMailbox !== null ? '1' : '0' ?>">
            <div class="panel-h">
                <h2 class="panel-title">Incoming Messages <span id="poll-status" class="badge">idle</span></h2>
                <div class="actions">
                    <?php if ($activeMailbox !== null) : ?>
                        <form method="post" action="">
                            <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
                            <input type="hidden" name="action" value="clear_active_mailbox">
                            <button class="btn btn-sm" type="submit" title="Stop auto-refresh and forget this mailbox">Clear</button>
                        </form>
                    <?php endif; ?>
                    <div class="hint">Click any message to open or close the full body.</div>
                    <form method="post" action="">
                        <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
                        <input type="hidden" name="action" value="logout">
                        <button class="btn btn-sm" type="submit">Logout</button>
                    </form>
                </div>
            </div>
            <div class="panel-body">
                <div id="messages-container">
                    <?php if ($messages === []) : ?>
                        <div class="empty"><?= $activeMailbox !== null ? 'Inbox empty. Waiting for new mail...' : 'Generate a mailbox to start receiving.' ?></div>
                    <?php else : ?>
                        <?php foreach ($messages as $message) : ?>
                            <article class="mail" tabindex="0" role="button" aria-expanded="false">
                                <h3 class="mail-subject"><?= e((string) $message['subject']) ?></h3>
                                <div class="mail-meta">From: <?= e((string) $message['from']) ?></div>
                                <div class="mail-meta">Date: <?= e((string) $message['date']) ?></div>
                                <p class="mail-body"><?= linkifyText((string) $message['body']) ?></p>
                            </article>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>
        </section>
    <?php endif; ?>

    <footer class="footer">
        Required PHP extensions: <span class="kbd">curl</span>, <span class="kbd">imap</span>, <span class="kbd">openssl</span>. Keep cPanel API token outside public_html.
    </footer>
</div>
<script nonce="<?= e($nonce) ?>">
document.querySelectorAll('[data-select-on-focus]').forEach(function(el){
    el.addEventListener('focus', function(){ this.select(); });
    el.addEventListener('click', function(){ this.select(); });
});
document.querySelectorAll('[data-toggle-pass]').forEach(function(btn){
    btn.addEventListener('click', function(){
        var target = document.getElementById(btn.getAttribute('data-toggle-pass'));
        if (!target) return;
        var hidden = target.type === 'password';
        target.type = hidden ? 'text' : 'password';
        btn.textContent = hidden ? 'Hide' : 'Show';
        btn.setAttribute('aria-label', (hidden ? 'Hide' : 'Show') + ' password');
    });
});

(function(){
    var panel = document.querySelector('[data-active-mailbox="1"]');
    if (!panel) return;
    var container = document.getElementById('messages-container');
    var statusEl = document.getElementById('poll-status');
    if (!container || !statusEl) return;

    var POLL_MS = 10000;
    var inFlight = false;

    function escapeHtml(s){
        return String(s).replace(/[&<>"']/g, function(c){
            return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c];
        });
    }

    function linkifyText(s){
        var text = escapeHtml(s || '');
        return text.replace(/(https?:\/\/[^\s<]+)/gi, function(url){
            return '<a href="' + url + '" target="_blank" rel="noopener noreferrer">' + url + '</a>';
        });
    }

    function renderMessages(messages){
        if (!messages || messages.length === 0) {
            container.innerHTML = '<div class="empty">Inbox empty. Waiting for new mail...</div>';
            return;
        }
        var html = '';
        for (var i = 0; i < messages.length; i++) {
            var m = messages[i];
            html += '<article class="mail" tabindex="0" role="button" aria-expanded="false">'
                + '<h3 class="mail-subject">' + escapeHtml(m.subject || '') + '</h3>'
                + '<div class="mail-meta">From: ' + escapeHtml(m.from || '') + '</div>'
                + '<div class="mail-meta">Date: ' + escapeHtml(m.date || '') + '</div>'
                + '<p class="mail-body">' + linkifyText(m.body || '') + '</p>'
                + '</article>';
        }
        container.innerHTML = html;
        attachMessageToggles();
    }

    function attachMessageToggles(){
        container.querySelectorAll('.mail').forEach(function(mail){
            mail.addEventListener('click', function(){
                var open = mail.classList.toggle('open');
                mail.setAttribute('aria-expanded', open ? 'true' : 'false');
            });
            mail.addEventListener('keydown', function(event){
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    mail.click();
                }
            });
        });
    }

    function setStatus(text, kind){
        statusEl.textContent = text;
        statusEl.style.borderLeft = kind === 'err' ? '3px solid var(--bad)' : (kind === 'ok' ? '3px solid var(--good)' : '');
    }

    function poll(){
        if (inFlight) return;
        inFlight = true;
        setStatus('refreshing...', '');
        fetch('?ajax=inbox', { credentials: 'same-origin', cache: 'no-store' })
            .then(function(r){ return r.json(); })
            .then(function(data){
                if (data && data.ok === true) {
                    renderMessages(data.messages || []);
                    var ts = new Date((data.polled_at || 0) * 1000);
                    var hh = String(ts.getHours()).padStart(2,'0');
                    var mm = String(ts.getMinutes()).padStart(2,'0');
                    var ss = String(ts.getSeconds()).padStart(2,'0');
                    setStatus('updated ' + hh + ':' + mm + ':' + ss, 'ok');
                } else {
                    setStatus(data && data.message ? data.message.substring(0, 60) : 'error', 'err');
                }
            })
            .catch(function(){ setStatus('network error', 'err'); })
            .finally(function(){ inFlight = false; });
    }

    poll();
    attachMessageToggles();
    setInterval(poll, POLL_MS);
})();
</script>
</body>
</html>
