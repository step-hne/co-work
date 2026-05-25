<?php

declare(strict_types=1);

const REPASS_FILE = __DIR__ . '/repass.php';
const AUTH_FILE = __DIR__ . '/report_auth.php';
const SESSION_NAME = 'report_password_admin';
const CSRF_KEY = 'report_password_csrf';
const AUTH_SESSION_KEY = 'report_password_auth';
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCK_SECONDS = 60;
const MIN_PASSWORD_LENGTH = 5;

function configureSecurityHeaders(string $nonce): void
{
    header('Content-Type: text/html; charset=UTF-8');
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
        "img-src 'self' data:",
        "font-src 'self' data:",
        "style-src 'self' 'nonce-" . $nonce . "'",
        "script-src 'self'",
        "connect-src 'self'",
        "upgrade-insecure-requests",
    ]);

    header('Content-Security-Policy: ' . $csp);
}

function configureSession(): void
{
    $isHttps = (
        (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on')
        || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
    );

    session_name(SESSION_NAME);
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);

    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function csrfToken(): string
{
    if (
        !isset($_SESSION[CSRF_KEY])
        || !is_string($_SESSION[CSRF_KEY])
        || $_SESSION[CSRF_KEY] === ''
    ) {
        $_SESSION[CSRF_KEY] = bin2hex(random_bytes(32));
    }

    return $_SESSION[CSRF_KEY];
}

function rotateCsrfToken(): void
{
    $_SESSION[CSRF_KEY] = bin2hex(random_bytes(32));
}

function verifyCsrf(?string $token): bool
{
    if (!is_string($token) || $token === '') {
        return false;
    }

    if (!isset($_SESSION[CSRF_KEY]) || !is_string($_SESSION[CSRF_KEY])) {
        return false;
    }

    return hash_equals($_SESSION[CSRF_KEY], $token);
}

function isAuthenticated(): bool
{
    return isset($_SESSION[AUTH_SESSION_KEY]) && $_SESSION[AUTH_SESSION_KEY] === true;
}

function selfPath(): string
{
    $scriptName = isset($_SERVER['SCRIPT_NAME']) && is_string($_SERVER['SCRIPT_NAME'])
        ? $_SERVER['SCRIPT_NAME']
        : '';

    if ($scriptName === '' || preg_match('/[\r\n]/', $scriptName) === 1) {
        return '';
    }

    return $scriptName;
}

function loadAuthConfig(): array
{
    if (!is_file(AUTH_FILE)) {
        return [];
    }

    $config = require AUTH_FILE;

    if (!is_array($config)) {
        return [];
    }

    return $config;
}

function validatePassword(string $value, string $label): array
{
    $value = trim($value);

    if ($value === '') {
        return [false, $label . ' cannot be empty.', ''];
    }

    if (strlen($value) < MIN_PASSWORD_LENGTH) {
        return [false, $label . ' must be at least ' . MIN_PASSWORD_LENGTH . ' characters.', ''];
    }

    if (strlen($value) > 128) {
        return [false, $label . ' must not exceed 128 characters.', ''];
    }

    if (preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
        return [false, $label . ' contains blocked control characters.', ''];
    }

    if (
        stripos($value, '<?') !== false
        || stripos($value, '?>') !== false
        || stripos($value, '<script') !== false
    ) {
        return [false, 'Suspicious payload blocked.', ''];
    }

    return [true, '', $value];
}

function setupAuth(string $password): void
{
    if (is_file(AUTH_FILE)) {
        throw new RuntimeException('Auth file already exists.');
    }

    $dir = dirname(AUTH_FILE);

    if (!is_dir($dir)) {
        throw new RuntimeException('Target directory does not exist.');
    }

    if (!is_writable($dir)) {
        throw new RuntimeException('Target directory is not writable.');
    }

    $hash = password_hash($password, PASSWORD_DEFAULT);

    if (!is_string($hash) || $hash === '') {
        throw new RuntimeException('Failed creating password hash.');
    }

    $php = "<?php\n\ndeclare(strict_types=1);\n\nreturn [\n"
        . "    'password_hash' => " . var_export($hash, true) . ",\n"
        . "];\n";

    $tmp = AUTH_FILE . '.tmp.' . bin2hex(random_bytes(8));

    $bytes = file_put_contents($tmp, $php, LOCK_EX);
    if ($bytes === false) {
        throw new RuntimeException('Failed writing temporary auth file.');
    }

    @chmod($tmp, 0640);

    if (!rename($tmp, AUTH_FILE)) {
        @unlink($tmp);
        throw new RuntimeException('Failed creating auth file.');
    }
}

function registerFailedLogin(): void
{
    if (!isset($_SESSION['login_attempts']) || !is_int($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = 0;
    }

    $_SESSION['login_attempts']++;

    if ($_SESSION['login_attempts'] >= LOGIN_MAX_ATTEMPTS) {
        $_SESSION['login_locked_until'] = time() + LOGIN_LOCK_SECONDS;
    }
}

function clearFailedLogin(): void
{
    unset($_SESSION['login_attempts'], $_SESSION['login_locked_until']);
}

function isLoginLocked(): bool
{
    return (
        isset($_SESSION['login_locked_until'])
        && is_int($_SESSION['login_locked_until'])
        && $_SESSION['login_locked_until'] > time()
    );
}

function loginRemainingLockSeconds(): int
{
    if (!isLoginLocked()) {
        return 0;
    }

    return max(0, (int) $_SESSION['login_locked_until'] - time());
}

function attemptLogin(string $password): bool
{
    if (isLoginLocked()) {
        return false;
    }

    $config = loadAuthConfig();

    $storedHash = isset($config['password_hash']) && is_string($config['password_hash'])
        ? $config['password_hash']
        : '';

    if ($storedHash === '') {
        return false;
    }

    if (!password_verify(trim($password), $storedHash)) {
        registerFailedLogin();
        return false;
    }

    session_regenerate_id(true);
    $_SESSION[AUTH_SESSION_KEY] = true;
    clearFailedLogin();
    rotateCsrfToken();

    return true;
}

function logout(): void
{
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();

        setcookie(
            session_name(),
            '',
            [
                'expires' => time() - 42000,
                'path' => $params['path'],
                'domain' => $params['domain'],
                'secure' => (bool) $params['secure'],
                'httponly' => true,
                'samesite' => 'Strict',
            ]
        );
    }

    session_destroy();
}

function loadCurrentPassword(): string
{
    if (!is_file(REPASS_FILE)) {
        return '';
    }

    $content = file_get_contents(REPASS_FILE);
    if (!is_string($content) || $content === '') {
        return '';
    }

    if (preg_match('/define\s*\(\s*[\'"]REPASS[\'"]\s*,\s*([\'"])(.*?)\1\s*\)\s*;/s', $content, $matches) !== 1) {
        return '';
    }

    // Return a placeholder — never expose the raw hash or plaintext to the UI.
    return '••••••••';
}

function saveReportPassword(string $password): void
{
    $dir = dirname(REPASS_FILE);

    if (!is_dir($dir)) {
        throw new RuntimeException('Target directory does not exist.');
    }

    if (!is_writable($dir)) {
        throw new RuntimeException('Target directory is not writable.');
    }

    if (is_file(REPASS_FILE) && !is_writable(REPASS_FILE)) {
        throw new RuntimeException('repass.php exists but is not writable.');
    }

    $hash = password_hash($password, PASSWORD_BCRYPT);
    $php  = "<?php\n\ndeclare(strict_types=1);\n\ndefine('REPASS', " . var_export($hash, true) . ");\n";
    $tmp = REPASS_FILE . '.tmp.' . bin2hex(random_bytes(8));

    $bytes = file_put_contents($tmp, $php, LOCK_EX);
    if ($bytes === false) {
        throw new RuntimeException('Failed writing temporary password file.');
    }

    @chmod($tmp, 0640);

    if (!rename($tmp, REPASS_FILE)) {
        @unlink($tmp);
        throw new RuntimeException('Failed replacing repass.php.');
    }
}

$nonce = bin2hex(random_bytes(16));

configureSession();
configureSecurityHeaders($nonce);

$statusType = '';
$statusMessage = '';
$self = selfPath();
$redirectSelf = $self !== '' ? $self : './';
$authExists = is_file(AUTH_FILE);
$currentPassword = isAuthenticated() ? loadCurrentPassword() : '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (!verifyCsrf($_POST['csrf_token'] ?? null)) {
            throw new RuntimeException('Invalid CSRF token.');
        }

        $action = isset($_POST['action']) && is_string($_POST['action']) ? $_POST['action'] : '';

        if ($action === 'setup') {
            if ($authExists) {
                throw new RuntimeException('Setup is already locked.');
            }

            $postedPassword = isset($_POST['password']) && is_string($_POST['password'])
                ? $_POST['password']
                : '';

            [$isPasswordValid, $passwordError, $cleanPassword] = validatePassword($postedPassword, 'Admin password');

            if (!$isPasswordValid) {
                throw new InvalidArgumentException($passwordError);
            }

            setupAuth($cleanPassword);
            rotateCsrfToken();

            $authExists = true;
            $statusType = 'ok';
            $statusMessage = 'Admin password created. Please login.';
        } elseif ($action === 'login') {
            if (!$authExists) {
                throw new RuntimeException('Admin password is not configured.');
            }

            if (isLoginLocked()) {
                throw new RuntimeException('Too many failed attempts. Try again in ' . loginRemainingLockSeconds() . ' seconds.');
            }

            $postedPassword = isset($_POST['password']) && is_string($_POST['password'])
                ? $_POST['password']
                : '';

            if (!attemptLogin($postedPassword)) {
                throw new RuntimeException('Invalid password.');
            }

            $currentPassword = loadCurrentPassword();
            $statusType = 'ok';
            $statusMessage = 'Login successful.';
        } elseif ($action === 'logout') {
            logout();
            header('Location: ' . $redirectSelf);
            exit;
        } elseif ($action === 'update') {
            if (!isAuthenticated()) {
                throw new RuntimeException('Unauthorized request.');
            }

            $postedPassword = isset($_POST['update']) && is_string($_POST['update'])
                ? $_POST['update']
                : '';

            [$isValid, $validationError, $cleanPassword] = validatePassword($postedPassword, 'Report password');

            if (!$isValid) {
                throw new InvalidArgumentException($validationError);
            }

            saveReportPassword($cleanPassword);
            rotateCsrfToken();

            $currentPassword = '••••••••';
            $statusType = 'ok';
            $statusMessage = 'Report password updated.';
        } else {
            throw new RuntimeException('Invalid action.');
        }
    } catch (Throwable $e) {
        $statusType = 'error';
        $statusMessage = $e->getMessage();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <title>REPORT PASSWORD</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style nonce="<?= h($nonce) ?>">
:root{color-scheme:light;--dark:#292b2c;--light:#f7f7f7;--bg:#f7f7f7;--panel:rgba(255,255,255,.86);--panel-soft:rgba(247,247,247,.72);--line:rgba(41,43,44,.16);--line-soft:rgba(41,43,44,.09);--text:#292b2c;--text-strong:#151617;--accent:#292b2c;--accent-hover:#3a3d3e;--on-accent:#f7f7f7;--danger:#9f3138;--danger-soft:rgba(159,49,56,.08);--ok:#26794e;--ok-soft:rgba(38,121,78,.08);--radius:.3rem;--shadow:0 1px 4px rgba(41,43,44,.08)}@media (prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#292b2c;--panel:rgba(247,247,247,.06);--panel-soft:rgba(247,247,247,.09);--line:rgba(247,247,247,.18);--line-soft:rgba(247,247,247,.1);--text:#f7f7f7;--text-strong:#fff;--accent:#f7f7f7;--accent-hover:#e6e6e6;--on-accent:#292b2c;--danger:#ef9a9a;--danger-soft:rgba(239,154,154,.12);--ok:#7ed6a4;--ok-soft:rgba(126,214,164,.12);--shadow:0 1px 5px rgba(0,0,0,.32)}}*{box-sizing:border-box}html,body{min-height:100%}body{margin:0;padding:30px 8px 18px;font-family:Consolas,Monaco,'Courier New',monospace;font-size:13px;line-height:1.5;background:linear-gradient(180deg,var(--panel-soft) 0%,var(--bg) 100%);color:var(--text);-webkit-font-smoothing:antialiased;text-rendering:geometricPrecision}.login-wrap{width:100%;max-width:540px;margin:0 auto}.panel,.panel-default{margin:0 auto;max-width:540px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;box-shadow:var(--shadow)!important;overflow:hidden;backdrop-filter:blur(4px)}.panel-heading{padding:10px 12px;background:var(--panel-soft)!important;border-bottom:1px solid var(--line-soft)!important;color:var(--text-strong);font-size:13px;font-weight:700;display:flex;align-items:center;justify-content:space-between;gap:8px;letter-spacing:.02em}.panel-title{display:block}.panel-body{padding:12px;background:transparent!important}.msg{margin-bottom:10px;padding:8px 10px;border:1px solid rgba(159,49,56,.28);background:var(--danger-soft);color:var(--danger);border-radius:var(--radius);font-size:12px;word-break:break-word}.msg-ok{border-color:rgba(38,121,78,.28);background:var(--ok-soft);color:var(--ok)}.current-box{margin-bottom:10px;padding:8px 10px;border:1px solid var(--line-soft);background:rgba(255,255,255,.38);color:var(--text);border-radius:var(--radius);font-size:12px;word-break:break-word}.current-box strong{display:block;margin-bottom:2px;color:color-mix(in srgb,var(--text) 62%,transparent);font-size:11px;text-transform:uppercase;letter-spacing:.05em}.input-group{width:100%;display:flex!important;align-items:center;gap:8px}.input-group .form-control,.form-control{height:34px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;box-shadow:none!important;font-family:Consolas,Monaco,'Courier New',monospace;font-size:12px;padding:6px 10px;min-width:0}.input-group .form-control{flex:1 1 auto;width:auto!important}.form-control::placeholder{color:color-mix(in srgb,var(--text) 52%,transparent)}.form-control:focus,.form-control:active,.form-control:focus-visible{outline:none!important;border-color:var(--accent)!important;box-shadow:0 0 0 1px color-mix(in srgb,var(--accent) 18%,transparent)!important}.input-group-btn{display:flex!important;flex:0 0 auto;width:auto!important}.input-group-btn>.btn,.btn{height:34px;min-width:148px;border:1px solid var(--accent)!important;border-radius:var(--radius)!important;background:var(--accent)!important;color:var(--on-accent)!important;font-size:12px;font-weight:700;box-shadow:none!important;padding:0 14px;white-space:nowrap;cursor:pointer}.input-group-btn>.btn:hover,.btn:hover{background:var(--accent-hover)!important;border-color:var(--accent-hover)!important}.input-group-btn>.btn:focus,.input-group-btn>.btn:active,.input-group-btn>.btn:focus-visible,.btn:focus,.btn:active,.btn:focus-visible{outline:none!important;box-shadow:0 0 0 1px color-mix(in srgb,var(--accent) 22%,transparent)!important}.btn-link{height:auto;border:0!important;background:transparent!important;color:var(--text)!important;padding:0;font-size:12px;text-decoration:underline;box-shadow:none!important}.btn-link:hover{opacity:.82}.btn-link:focus,.btn-link:active,.btn-link:focus-visible{outline:none!important;box-shadow:none!important}.hint{margin:10px 0 0;color:color-mix(in srgb,var(--text) 72%,transparent);font-size:12px}.mono{font-family:Consolas,Monaco,'Courier New',monospace}@media screen and (max-width:560px){body{padding:14px 8px 16px;font-size:12.5px}.login-wrap,.panel,.panel-default{max-width:100%}.panel-heading,.panel-body{padding:10px}.input-group{gap:6px}.input-group .form-control{flex:1 1 auto;width:auto!important;min-width:0}.input-group-btn{width:auto!important}.input-group-btn>.btn,.btn{min-width:112px;padding:0 12px}}@media screen and (max-width:380px){.panel-heading{padding:9px 10px}.panel-body{padding:10px 9px}.input-group{gap:6px}.input-group-btn>.btn,.btn{min-width:96px;font-size:11px;padding:0 10px}}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}
  </style>
</head>
<body>
  <main class="login-wrap">
    <section class="panel">
      <header class="panel-heading">
        <span class="panel-title">REPORT PASSWORD</span>

        <?php if (isAuthenticated()): ?>
          <form action="<?= h($self) ?>" method="post" style="margin:0">
            <input type="hidden" name="csrf_token" value="<?= h(csrfToken()) ?>">
            <input type="hidden" name="action" value="logout">
            <button class="btn-link" type="submit">Logout</button>
          </form>
        <?php endif; ?>
      </header>

      <div class="panel-body">
        <?php if ($statusMessage !== ''): ?>
          <div class="msg <?= $statusType === 'ok' ? 'msg-ok' : '' ?>">
            <?= h($statusMessage) ?>
          </div>
        <?php endif; ?>

        <?php if (!$authExists): ?>
          <form action="<?= h($self) ?>" method="post" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= h(csrfToken()) ?>">
            <input type="hidden" name="action" value="setup">

            <div class="input-group">
              <input
                name="password"
                type="password"
                class="form-control"
                autocomplete="new-password"
                required
                minlength="<?= MIN_PASSWORD_LENGTH ?>"
                maxlength="128"
                placeholder="Create admin password"
              >
              <span class="input-group-btn">
                <button class="btn" type="submit">CREATE</button>
              </span>
            </div>
          </form>

          <p class="hint">
            First-run setup. Minimum password length: <?= MIN_PASSWORD_LENGTH ?> characters.
          </p>
        <?php elseif (!isAuthenticated()): ?>
          <form action="<?= h($self) ?>" method="post" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= h(csrfToken()) ?>">
            <input type="hidden" name="action" value="login">

            <div class="input-group">
              <input
                name="password"
                type="password"
                class="form-control"
                autocomplete="current-password"
                required
                minlength="<?= MIN_PASSWORD_LENGTH ?>"
                maxlength="128"
                placeholder="Password"
              >
              <span class="input-group-btn">
                <button class="btn" type="submit">LOGIN</button>
              </span>
            </div>
          </form>

          <p class="hint">
            Password-only login enabled. Failed attempts are rate-limited per session.
          </p>
        <?php else: ?>
          <div class="current-box">
            <strong>Current Report Password</strong>
            <span class="mono"><?= $currentPassword !== '' ? h($currentPassword) : 'Not set' ?></span>
          </div>

          <form action="<?= h($self) ?>" method="post" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= h(csrfToken()) ?>">
            <input type="hidden" name="action" value="update">

            <div class="input-group">
              <input
                name="update"
                type="text"
                class="form-control"
                autocomplete="off"
                required
                minlength="<?= MIN_PASSWORD_LENGTH ?>"
                maxlength="128"
                placeholder="New report password"
              >
              <span class="input-group-btn">
                <button class="btn" name="Submit" type="submit" value="Update">UPDATE</button>
              </span>
            </div>
          </form>

          <p class="hint">
            Minimum report password length: <?= MIN_PASSWORD_LENGTH ?> characters. Suspicious payloads are blocked.
          </p>
        <?php endif; ?>
      </div>
    </section>
  </main>
</body>
</html>