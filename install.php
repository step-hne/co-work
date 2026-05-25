<?php

declare(strict_types=1);

// ─── Constants ────────────────────────────────────────────────────────────────

const INST_LOCK          = __DIR__ . '/install.lock';
const INST_SCHEMA        = __DIR__ . '/schema.sql';
const INST_ROOT_PASSWORD = 'a2root';

// ─── Session ──────────────────────────────────────────────────────────────────

session_start();

// ─── a2root unlock / re-lock ──────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['_a2root'])) {
    $a2Tok = is_string($_POST['_csrf_a2'] ?? null) ? $_POST['_csrf_a2'] : '';
    $a2Pw  = is_string($_POST['a2root_pw'] ?? null) ? $_POST['a2root_pw'] : '';
    if (!empty($_SESSION['_csrf_a2'])
        && hash_equals((string) $_SESSION['_csrf_a2'], $a2Tok)
        && hash_equals(INST_ROOT_PASSWORD, $a2Pw)
    ) {
        $_SESSION['a2root'] = true;
    }
    header('Location: install.php');
    exit;
}

if (isset($_GET['_a2root_lock']) && ($_SESSION['a2root'] ?? false)) {
    unset($_SESSION['a2root']);
    header('Location: install.php');
    exit;
}

// ─── Lock guard ───────────────────────────────────────────────────────────────

if (is_file(INST_LOCK) && !($_SESSION['a2root'] ?? false)) {
    if (empty($_SESSION['_csrf_a2'])) {
        $_SESSION['_csrf_a2'] = bin2hex(random_bytes(16));
    }
    $a2Tok = htmlspecialchars((string) $_SESSION['_csrf_a2'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    http_response_code(403);
    header('Content-Type: text/html; charset=UTF-8');
    echo '<!doctype html><html lang="id"><head><meta charset="UTF-8"><title>Terkunci &mdash; Genv2 Installer</title>'
        . '<style>:root{color-scheme:light;--bg:#f7f7f7;--panel:rgba(255,255,255,.86);--line:rgba(41,43,44,.22);--text:#292b2c;--muted:rgba(41,43,44,.62);--danger:#9f3138;--danger-soft:rgba(159,49,56,.08);--success:#256d46;--success-soft:rgba(37,109,70,.1);--radius:.3rem;--shadow:0 1px 3px rgba(41,43,44,.09),0 3px 14px rgba(41,43,44,.07)}'
        . '@media(prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#292b2c;--panel:rgba(247,247,247,.06);--line:rgba(247,247,247,.24);--text:#f7f7f7;--muted:rgba(247,247,247,.62);--danger:#ef9a9a;--danger-soft:rgba(239,154,154,.12);--success:#86efac;--success-soft:rgba(134,239,172,.1);--shadow:0 1px 4px rgba(0,0,0,.32),0 3px 14px rgba(0,0,0,.2)}}'
        . '*{box-sizing:border-box;margin:0;padding:0}html{min-height:100%;background:var(--bg)}'
        . 'body{font-family:monospace;font-size:13px;line-height:1.5;display:flex;align-items:center;justify-content:center;min-height:100vh;background:radial-gradient(circle at top,color-mix(in srgb,#292b2c 7%,transparent) 0,transparent 280px),var(--bg);color:var(--text);-webkit-font-smoothing:antialiased}'
        . '.box{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:22px 24px;text-align:center;box-shadow:var(--shadow);max-width:340px;width:100%;margin:0 12px}'
        . 'h2{color:var(--danger);margin-bottom:8px;font-size:.9rem;font-weight:700}'
        . 'p{color:var(--muted);font-size:12px;line-height:1.5}'
        . 'code{font-family:monospace;font-size:11.5px;background:var(--danger-soft);border-radius:.2rem;padding:1px 4px;color:var(--danger)}'
        . '.unlock-area{margin-top:16px}'
        . '.unlock-btn{background:none;border:none;font-family:monospace;font-size:11px;color:var(--muted);opacity:.35;cursor:pointer;padding:2px 0;transition:opacity .2s}'
        . '.unlock-btn:hover{opacity:.65}'
        . '.unlock-form{display:none;margin-top:10px}'
        . '.unlock-form.vis{display:block}'
        . '.unlock-form input[type=password]{width:100%;padding:5px 8px;font-family:monospace;font-size:12px;border:1px solid var(--line);border-radius:.25rem;background:var(--bg);color:var(--text);margin-bottom:6px;outline:none}'
        . '.unlock-form button[type=submit]{width:100%;padding:5px 8px;font-family:monospace;font-size:12px;font-weight:700;border:1px solid color-mix(in srgb,var(--success) 40%,transparent);border-radius:.25rem;background:var(--success-soft);color:var(--success);cursor:pointer}'
        . '</style></head>'
        . '<body><div class="box">'
        . '<h2><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true" style="vertical-align:-2px;margin-right:4px"><path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z"/></svg> Installer Terkunci</h2>'
        . '<p>Instalasi sudah selesai. Hapus <code>install.lock</code> untuk menjalankan ulang.</p>'
        . '<div class="unlock-area">'
        . '<button type="button" class="unlock-btn" onclick="document.getElementById(\'uf\').classList.toggle(\'vis\')">Buka kunci</button>'
        . '<div id="uf" class="unlock-form">'
        . '<form method="post">'
        . '<input type="hidden" name="_a2root" value="1">'
        . '<input type="hidden" name="_csrf_a2" value="' . $a2Tok . '">'
        . '<input type="password" name="a2root_pw" placeholder="Password" autocomplete="off">'
        . '<button type="submit">Buka</button>'
        . '</form>'
        . '</div></div>'
        . '</div></body></html>';
    exit;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function ie(mixed $v): string
{
    return htmlspecialchars((string) $v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function inst_svg(string $name, string $size = '15'): string
{
    static $icons = [
        'lock'         => '<path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z"/>',
        'zap'          => '<path stroke-linecap="round" stroke-linejoin="round" d="m3.75 13.5 10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75Z"/>',
        'alert'        => '<path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z"/>',
        'search'       => '<path stroke-linecap="round" stroke-linejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 15.803a7.5 7.5 0 0 0 10.607 0Z"/>',
        'check'        => '<path stroke-linecap="round" stroke-linejoin="round" d="m4.5 12.75 6 6 9-13.5"/>',
        'x'            => '<path stroke-linecap="round" stroke-linejoin="round" d="M6 18 18 6M6 6l12 12"/>',
        'arrow-right'  => '<path stroke-linecap="round" stroke-linejoin="round" d="M13.5 4.5 21 12m0 0-7.5 7.5M21 12H3"/>',
        'database'     => '<path stroke-linecap="round" stroke-linejoin="round" d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 5.625c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125"/>',
        'info'         => '<path stroke-linecap="round" stroke-linejoin="round" d="m11.25 11.25.041-.02a.75.75 0 0 1 1.063.852l-.708 2.836a.75.75 0 0 0 1.063.853l.041-.021M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9-3.75h.008v.008H12V8.25Z"/>',
        'globe'        => '<path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9.004 9.004 0 0 0 8.716-6.747M12 21a9.004 9.004 0 0 1-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 0 1 7.843 4.582M12 3a8.997 8.997 0 0 0-7.843 4.582m15.686 0A11.953 11.953 0 0 1 12 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0 1 21 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0 1 12 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 0 1 3 12c0-1.605.42-3.113 1.157-4.418"/>',
        'key'          => '<path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z"/>',
        'arrows'       => '<path stroke-linecap="round" stroke-linejoin="round" d="M7.5 21 3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5"/>',
        'bar-chart'    => '<path stroke-linecap="round" stroke-linejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 0 1 3 19.875v-6.75ZM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 0 1-1.125-1.125V8.625ZM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 0 1-1.125-1.125V4.125Z"/>',
        'check-circle' => '<path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z"/>',
        'x-circle'     => '<path stroke-linecap="round" stroke-linejoin="round" d="m9.75 9.75 4.5 4.5m0-4.5-4.5 4.5M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z"/>',
        'rotate'       => '<path stroke-linecap="round" stroke-linejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0 3.181 3.183a8.25 8.25 0 0 0 13.803-3.7M4.031 9.865a8.25 8.25 0 0 1 13.803-3.7l3.181 3.182m0-4.991v4.99"/>',
        'clipboard'    => '<path stroke-linecap="round" stroke-linejoin="round" d="M9 12h3.75M9 15h3.75M9 18h3.75m3 .75H18a2.25 2.25 0 0 0 2.25-2.25V6.108c0-1.135-.845-2.098-1.976-2.192a48.424 48.424 0 0 0-1.123-.08m-5.801 0c-.065.21-.1.433-.1.664 0 .414.336.75.75.75h4.5a.75.75 0 0 0 .75-.75 2.25 2.25 0 0 0-.1-.664m-5.8 0A2.251 2.251 0 0 1 13.5 2.25H15c1.012 0 1.867.668 2.15 1.586m-5.8 0c-.376.023-.75.05-1.124.08C9.095 4.01 8.25 4.973 8.25 6.108V8.25m0 0H4.875c-.621 0-1.125.504-1.125 1.125v11.25c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125V9.375c0-.621-.504-1.125-1.125-1.125H8.25ZM6.75 12h.008v.008H6.75V12Zm0 3h.008v.008H6.75V15Zm0 3h.008v.008H6.75V18Z"/>',
    ];
    $path = $icons[$name] ?? '';
    $s    = htmlspecialchars($size, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    return '<svg xmlns="http://www.w3.org/2000/svg" width="' . $s . '" height="' . $s
        . '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">'
        . $path . '</svg>';
}

function ipost(string $k, string $d = ''): string
{
    return (isset($_POST[$k]) && is_string($_POST[$k])) ? trim($_POST[$k]) : $d;
}

function ig(): string
{
    return bin2hex(random_bytes(32));
}

function icsrf_init(): void
{
    if (empty($_SESSION['_ic'])) {
        $_SESSION['_ic'] = ig();
    }
}

function icsrf(): string
{
    return (string) ($_SESSION['_ic'] ?? '');
}

function icsrf_ok(string $t): bool
{
    return $t !== '' && hash_equals(icsrf(), $t);
}

function isd(): array
{
    return (isset($_SESSION['d']) && is_array($_SESSION['d'])) ? $_SESSION['d'] : [];
}

function iss(string $k, mixed $v): void
{
    if (!isset($_SESSION['d']) || !is_array($_SESSION['d'])) {
        $_SESSION['d'] = [];
    }
    $_SESSION['d'][$k] = $v;
}

function isg(string $k, string $fb = ''): string
{
    $d = isd();
    return (isset($d[$k]) && is_string($d[$k])) ? $d[$k] : $fb;
}

function inst_ev(string $v): string
{
    if ($v === '') {
        return '';
    }
    if (preg_match('/[\s#"\'\\\\]/', $v) === 1) {
        return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $v) . '"';
    }
    return $v;
}

function inst_line(string $k, string $v): string
{
    return $k . '=' . inst_ev($v) . "\n";
}

function inst_write_env(string $path, string $content): true|string
{
    if (!is_dir(dirname($path))) {
        return 'Direktori tidak ada: ' . dirname($path);
    }
    if (file_put_contents($path, $content, LOCK_EX) === false) {
        return 'Gagal menulis: ' . $path;
    }
    @chmod($path, 0600);
    return true;
}

function inst_mkdir_safe(string $path): true|string
{
    if (is_dir($path)) {
        return true;
    }
    if (mkdir($path, 0700, true)) {
        return true;
    }
    return 'Gagal mkdir: ' . $path;
}

function inst_test_db(string $h, int $p, string $u, string $pw, string $n): true|string
{
    try {
        $pdo = new PDO(
            "mysql:host={$h};port={$p};dbname={$n};charset=utf8mb4",
            $u,
            $pw,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
        );
        unset($pdo);
        return true;
    } catch (Throwable $e) {
        return $e->getMessage();
    }
}

function inst_run_schema(string $h, int $p, string $u, string $pw, string $n): true|string
{
    if (!is_file(INST_SCHEMA)) {
        return 'schema.sql tidak ditemukan';
    }
    $sql = @file_get_contents(INST_SCHEMA);
    if ($sql === false || trim($sql) === '') {
        return 'schema.sql kosong atau tidak bisa dibaca';
    }
    try {
        $pdo = new PDO(
            "mysql:host={$h};port={$p};dbname={$n};charset=utf8mb4",
            $u,
            $pw,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::MYSQL_ATTR_MULTI_STATEMENTS => true]
        );
        $pdo->exec($sql);
        return true;
    } catch (Throwable $e) {
        return $e->getMessage();
    }
}

function inst_autodetect(): array
{
    $d = [];

    // Derive base domain: strip first subdomain from HTTP_HOST
    $host = strtolower(explode(':', $_SERVER['HTTP_HOST'] ?? '')[0]);
    $parts = explode('.', $host);
    $baseDomain = count($parts) >= 3 ? implode('.', array_slice($parts, 1)) : $host;

    // CPANEL_SUBDOMAIN_DIR: install dir is the project root used as the subdomain base
    $d['p_cpdir'] = __DIR__;

    // CF_SERVER_IP: SERVER_ADDR unless it's a private/loopback IP, then try hostname lookup
    $ip = $_SERVER['SERVER_ADDR'] ?? '';
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE | FILTER_FLAG_IPV4)) {
        $resolved = gethostbyname((string) gethostname());
        if ($resolved !== gethostname() && filter_var($resolved, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            $ip = $resolved;
        }
    }
    $d['p_cfip'] = $ip;

    // CF_NS1, CF_NS2: server nameservers from cPanel config, fallback to parent-domain NS lookup
    $d['p_cfns1'] = '';
    $d['p_cfns2'] = '';

    // cPanel writes /etc/nameserverips with lines like: ns1.host.com=1.2.3.4
    $nsNames = [];
    foreach (['/etc/nameserverips', '/var/cpanel/nameserverips'] as $nsFile) {
        if (!is_readable($nsFile)) {
            continue;
        }
        $lines = @file($nsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!is_array($lines)) {
            continue;
        }
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $name = strtolower(trim(explode('=', $line)[0]));
            if ($name !== '' && str_contains($name, '.')) {
                $nsNames[] = $name;
            }
        }
        if (count($nsNames) >= 2) {
            break;
        }
    }

    // Fallback: probe ns1./ns2. of the server's parent domain (e.g. dal220.host.com → ns1.host.com)
    if (count($nsNames) < 2) {
        $serverHost   = strtolower((string) gethostname());
        $hostParts    = explode('.', $serverHost);
        $parentDomain = count($hostParts) >= 3 ? implode('.', array_slice($hostParts, 1)) : '';
        if ($parentDomain !== '') {
            foreach (['ns1', 'ns2'] as $prefix) {
                $candidate = $prefix . '.' . $parentDomain;
                $a = @dns_get_record($candidate, DNS_A);
                if (is_array($a) && count($a) > 0) {
                    $nsNames[] = $candidate;
                }
            }
        }
    }

    sort($nsNames);
    $nsNames      = array_values(array_unique($nsNames));
    $d['p_cfns1'] = $nsNames[0] ?? '';
    $d['p_cfns2'] = $nsNames[1] ?? '';

    // REPORT_HOST: s.<base_domain>
    $d['p_rhost'] = $baseDomain !== '' ? 's.' . $baseDomain : '';

    return $d;
}

function inst_find_php_bin(): string
{
    $bin = PHP_BINARY;
    if (str_contains($bin, 'fpm') || str_contains($bin, 'cgi') || !is_executable($bin)) {
        foreach (['/usr/local/bin/php', '/usr/bin/php'] as $fallback) {
            if (is_file($fallback) && is_executable($fallback)) {
                return $fallback;
            }
        }
    }
    return $bin;
}

function inst_add_cron_cpanel(
    string $cpHost,
    int $cpPort,
    string $cpUser,
    string $cpToken,
    string $command
): true|string {
    if ($cpToken === '' || $cpUser === '') {
        return 'kredensial cPanel tidak tersedia';
    }
    $url = 'https://' . $cpHost . ':' . $cpPort . '/execute/Cron/add_line?' . http_build_query([
        'minute'   => '0',
        'hour'     => '3',
        'day'      => '*',
        'month'    => '*',
        'weekday'  => '3',
        'command'  => $command,
    ]);
    $ch = curl_init($url);
    if ($ch === false) {
        return 'curl_init gagal';
    }
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_TIMEOUT        => 20,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_HTTPHEADER     => ['Authorization: cpanel ' . $cpUser . ':' . $cpToken],
    ]);
    $raw   = curl_exec($ch);
    $errno = curl_errno($ch);
    curl_close($ch);
    if ($raw === false || $errno !== 0) {
        return 'cURL error: ' . curl_strerror($errno);
    }
    $data = json_decode((string) $raw, true);
    if (!is_array($data)) {
        return 'Response tidak valid';
    }
    if ((int) ($data['status'] ?? 0) === 1) {
        return true;
    }
    $msg = implode('; ', array_filter((array) ($data['errors'] ?? ['Unknown'])));
    if (stripos($msg, 'duplicate') !== false || stripos($msg, 'already') !== false) {
        return true;
    }
    return $msg !== '' ? $msg : 'Unknown error';
}

function inst_requirements(): array
{
    $r = [];
    $r[] = [PHP_VERSION_ID >= 80300, 'PHP >= 8.3', 'Versi: ' . PHP_VERSION];

    foreach (['pdo', 'pdo_mysql', 'mysqli', 'curl', 'openssl', 'mbstring', 'json', 'phar'] as $ext) {
        $ok  = extension_loaded($ext);
        $r[] = [$ok, "ext-{$ext}", $ok ? '' : "Install: apt install php-{$ext}"];
    }

    $r[] = [is_file(INST_SCHEMA), 'schema.sql', is_file(INST_SCHEMA) ? '' : 'Tidak ada di root project'];

    foreach ([
        'public/'     => __DIR__ . '/public',
        'redirect/'   => __DIR__ . '/redirect',
        'statistics/' => __DIR__ . '/statistics',
    ] as $lbl => $path) {
        $ok  = is_dir($path) && is_writable($path);
        $r[] = [$ok, "Writable: {$lbl}", $ok ? '' : "chmod 755 {$path}"];
    }

    return $r;
}

// ─── Bootstrap ────────────────────────────────────────────────────────────────

icsrf_init();

if (isg('seeded') === '') {
    iss('seeded', '1');
    iss('g_af',  ig());
    iss('g_ixg', ig());
    iss('g_srp', ig());
    iss('g_pbs', ig());
}

$step     = 1;
$errors   = [];
$isA2Root = (bool) ($_SESSION['a2root'] ?? false);

// a2root: direct step jump via GET (bypasses sequential flow)
if ($isA2Root && $_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['go'])) {
    $go = (int) $_GET['go'];
    if ($go >= 1 && $go <= 6) {
        $step = $go;
    }
}

// ─── POST handler ─────────────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $ps = (int) ipost('step');

    if (!icsrf_ok(ipost('_csrf'))) {
        $errors[] = 'Token keamanan tidak valid. Muat ulang halaman dan coba lagi.';
        $step     = max(1, $ps);
    } else {
        $step = $ps;

        switch ($ps) {
            case 1:
                $step = 2;
                break;

            case 2:
                $h  = ipost('db_host', 'localhost');
                $p  = max(1, min(65535, (int) ipost('db_port', '3306')));
                $u  = ipost('db_user');
                $pw = ipost('db_pass');
                $n  = ipost('db_name');

                if ($u === '' || $n === '') {
                    $errors[] = 'DB_USER dan DB_NAME wajib diisi.';
                    break;
                }

                $res = inst_test_db($h, $p, $u, $pw, $n);
                if ($res !== true) {
                    $errors[] = 'Koneksi database gagal: ' . $res;
                    break;
                }

                $schemaRes = inst_run_schema($h, $p, $u, $pw, $n);
                if ($schemaRes !== true) {
                    $errors[] = 'Import schema.sql gagal: ' . $schemaRes;
                    break;
                }

                iss('db_host', $h);
                iss('db_port', (string) $p);
                iss('db_user', $u);
                iss('db_pass', $pw);
                iss('db_name', $n);
                iss('schema_done', '1');
                $step = 3;
                break;

            case 3:
                if (ipost('admin_password') === '') {
                    $errors[] = 'ADMIN_PASSWORD wajib diisi.';
                    break;
                }
                iss('p_admin',  ipost('admin_password'));
                iss('p_a2root', ipost('a2root_password'));
                iss('p_cpu',    ipost('cpanel_user'));
                iss('p_cpp',    ipost('cpanel_password'));
                iss('p_cph',    ipost('cpanel_host', 'localhost'));
                iss('p_cpport', ipost('cpanel_port', '2083'));
                iss('p_cpdir',  ipost('cpanel_subdomain_dir', '/public_html'));
                iss('p_cpat',   ipost('cpanel_api_token'));
                iss('p_af',     ipost('af_secret')       ?: isg('g_af'));
                iss('p_ixg',    ipost('ixg_bypass_key')  ?: isg('g_ixg'));
                iss('p_trak',   ipost('trackr_api_key'));
                iss('p_trke',   ipost('trackr_endpoint'));
                iss('p_tiny',   ipost('tinyurl_api_key'));
                iss('p_cfat',   ipost('cf_api_token'));
                iss('p_cfac',   ipost('cf_account_id'));
                iss('p_cfip',   ipost('cf_server_ip'));
                iss('p_cfns1',  ipost('cf_ns1'));
                iss('p_cfns2',  ipost('cf_ns2'));
                iss('p_rhost',  ipost('report_host'));
                $step = 4;
                break;

            case 4:
                iss('r_block',  ipost('block_countries', 'ID'));
                iss('r_cfins',  ipost('allow_cf_insights', '0'));
                iss('r_cfitok', ipost('cf_insights_token'));
                iss('r_rdir',   ipost('report_dir', 'report.example.com'));
                iss('r_srpkey', ipost('srp_api_key')           ?: isg('g_srp'));
                iss('r_mmkey',  ipost('maxmind_license_key'));
                $step = 5;
                break;

            case 5:
                $pbs = ipost('postback_secret');
                if ($pbs === '') {
                    $pbs = isg('g_pbs');
                }
                iss('s_pbs',    $pbs);
                iss('s_pbtz',   ipost('postback_timezone', 'UTC'));
                iss('s_dbsock', ipost('db_socket'));
                iss('s_dbcs',   ipost('db_charset', 'utf8mb4'));
                iss('s_dbpers', ipost('db_persistent', '0'));
                $step = 6;
                break;
        }
    }
}

// ─── Execute installation ─────────────────────────────────────────────────────

$installLog    = [];
$installDone   = false;
$cronAutoAdded = false;

if (
    $step === 6
    && empty($errors)
    && ipost('do_install') === '1'
    && icsrf_ok(ipost('_csrf'))
) {
    $d = isd();

    // 1. Ensure directories
    foreach ([__DIR__ . '/redirect/databases', __DIR__ . '/redirect/logs'] as $dir) {
        $r = inst_mkdir_safe($dir);
        $installLog[] = [$r === true, 'mkdir ' . basename($dir) . '/', $r === true ? 'OK' : (string) $r];
    }

    // 2. public/.env
    $pubContent = "# Database\n"
        . inst_line('DB_HOST',     $d['db_host']   ?? 'localhost')
        . inst_line('DB_USER',     $d['db_user']   ?? '')
        . inst_line('DB_PASSWORD', $d['db_pass']   ?? '')
        . inst_line('DB_NAME',     $d['db_name']   ?? '')
        . "\n# Admin\n"
        . inst_line('ADMIN_PASSWORD',  $d['p_admin']  ?? '')
        . inst_line('A2ROOT_PASSWORD', $d['p_a2root'] ?? '')
        . "\n# cPanel\n"
        . inst_line('CPANEL_USER',          $d['p_cpu']    ?? '')
        . inst_line('CPANEL_PASSWORD',      $d['p_cpp']    ?? '')
        . inst_line('CPANEL_HOST',          $d['p_cph']    ?? 'localhost')
        . inst_line('CPANEL_PORT',          $d['p_cpport'] ?? '2083')
        . inst_line('CPANEL_SUBDOMAIN_DIR', $d['p_cpdir']  ?? '/public_html')
        . inst_line('CPANEL_API_TOKEN',     $d['p_cpat']   ?? '')
        . "\n# Secrets\n"
        . inst_line('AF_SECRET',      $d['p_af']  ?? '')
        . inst_line('IXG_BYPASS_KEY', $d['p_ixg'] ?? '')
        . "\n# Shortlink\n"
        . inst_line('TRACKR_API_KEY',  $d['p_trak'] ?? '')
        . inst_line('TRACKR_ENDPOINT', $d['p_trke'] ?? '')
        . inst_line('TINYURL_API_KEY', $d['p_tiny'] ?? '')
        . "\n# Cloudflare\n"
        . inst_line('CF_API_TOKEN',  $d['p_cfat']  ?? '')
        . inst_line('CF_ACCOUNT_ID', $d['p_cfac']  ?? '')
        . inst_line('CF_SERVER_IP',  $d['p_cfip']  ?? '')
        . inst_line('CF_NS1',        $d['p_cfns1'] ?? '')
        . inst_line('CF_NS2',        $d['p_cfns2'] ?? '')
        . "\n# Reporting\n"
        . inst_line('REPORT_HOST', $d['p_rhost'] ?? '');

    $r = inst_write_env(__DIR__ . '/public/.env', $pubContent);
    $installLog[] = [$r === true, 'public/.env', $r === true ? 'Ditulis' : (string) $r];

    // 3. redirect/.env
    $redContent = "# Database\n"
        . inst_line('DB_HOST', $d['db_host'] ?? 'localhost')
        . inst_line('DB_PORT', $d['db_port'] ?? '3306')
        . inst_line('DB_USER', $d['db_user'] ?? '')
        . inst_line('DB_PASS', $d['db_pass'] ?? '')
        . inst_line('DB_NAME', $d['db_name'] ?? '')
        . "\n# Geo-blocking\n"
        . inst_line('SRP_BLOCK_COUNTRIES', $d['r_block'] ?? 'ID')
        . "\n# Cloudflare Insights\n"
        . inst_line('SRP_ALLOW_CLOUDFLARE_INSIGHTS', $d['r_cfins']  ?? '0')
        . inst_line('SRP_CF_INSIGHTS_TOKEN',          $d['r_cfitok'] ?? '')
        . "\n# Click log\n"
        . inst_line('SRP_REPORT_DIR', $d['r_rdir'] ?? '')
        . "\n# API\n"
        . inst_line('SRP_API_KEY', $d['r_srpkey'] ?? '')
        . "\n# GeoIP updater\n"
        . inst_line('MAXMIND_LICENSE_KEY', $d['r_mmkey'] ?? '');

    $r = inst_write_env(__DIR__ . '/redirect/.env', $redContent);
    $installLog[] = [$r === true, 'redirect/.env', $r === true ? 'Ditulis' : (string) $r];

    // 4. statistics/.env
    $staContent = "# Database\n"
        . inst_line('DB_HOST',       $d['db_host']  ?? 'localhost')
        . inst_line('DB_PORT',       $d['db_port']  ?? '3306')
        . inst_line('DB_SOCKET',     $d['s_dbsock'] ?? '')
        . inst_line('DB_USER',       $d['db_user']  ?? '')
        . inst_line('DB_PASSWORD',   $d['db_pass']  ?? '')
        . inst_line('DB_NAME',       $d['db_name']  ?? '')
        . inst_line('DB_CHARSET',    $d['s_dbcs']   ?? 'utf8mb4')
        . inst_line('DB_PERSISTENT', $d['s_dbpers'] ?? '0')
        . "\n# Admin\n"
        . inst_line('A2ROOT_PASSWORD', $d['p_a2root'] ?? '')
        . "\n# Postback\n"
        . inst_line('POSTBACK_SECRET',   $d['s_pbs']  ?? '')
        . inst_line('POSTBACK_TIMEZONE', $d['s_pbtz'] ?? 'UTC');

    $r = inst_write_env(__DIR__ . '/statistics/.env', $staContent);
    $installLog[] = [$r === true, 'statistics/.env', $r === true ? 'Ditulis' : (string) $r];

    // 5. Schema (sudah diimport saat verifikasi DB di step 2)
    $installLog[] = [true, 'Import schema.sql', 'Diimport saat verifikasi DB'];

    // 6. Cron GeoIP
    $phpBin     = inst_find_php_bin();
    $scriptPath = __DIR__ . '/redirect/update-geoip.php';
    $logPath    = __DIR__ . '/redirect/logs/geoip-update.log';
    $cronCmd    = $phpBin . ' ' . $scriptPath . ' >> ' . $logPath . ' 2>&1';
    if (($d['r_mmkey'] ?? '') !== '') {
        $cronResult = inst_add_cron_cpanel(
            $d['p_cph'] ?? 'localhost',
            (int) ($d['p_cpport'] ?? '2083'),
            $d['p_cpu'] ?? '',
            $d['p_cpat'] ?? '',
            $cronCmd
        );
        $cronAutoAdded = $cronResult === true;
        $installLog[]  = [
            true,
            'Cron GeoIP',
            $cronAutoAdded ? 'Ditambahkan via cPanel API (Rabu 03:00)' : 'Manual diperlukan: ' . $cronResult,
        ];
    } else {
        $cronAutoAdded = false;
        $installLog[]  = [true, 'Cron GeoIP', 'Skip — MAXMIND_LICENSE_KEY tidak diisi'];
    }

    // 7. Lock & cleanup
    $installDone = !in_array(false, array_column($installLog, 0), true);

    if ($installDone) {
        file_put_contents(
            INST_LOCK,
            date('c') . ' by ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . "\n"
        );
        session_destroy();
    }
}

// ─── HTML ─────────────────────────────────────────────────────────────────────

$stepLabels = ['1' => 'Kebutuhan', '2' => 'Database', '3' => 'Public', '4' => 'Redirect', '5' => 'Statistics', '6' => 'Install'];
$reqItems   = inst_requirements();
$allReqOk   = !in_array(false, array_column($reqItems, 0), true);

header('Content-Type: text/html; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Cache-Control: no-store, no-cache');
header('Referrer-Policy: no-referrer');

?><!doctype html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Genv2 — Installer</title>
<style>
:root{color-scheme:light;--bg:#f7f7f7;--panel:rgba(255,255,255,.86);--panel-soft:rgba(247,247,247,.72);--panel-raised:rgba(255,255,255,.86);--line:rgba(41,43,44,.22);--line-soft:rgba(41,43,44,.13);--text:#292b2c;--text-strong:#151617;--muted:rgba(41,43,44,.62);--accent:#292b2c;--accent-hover:#3a3d3e;--accent-soft:rgba(41,43,44,.08);--on-accent:#f7f7f7;--danger:#9f3138;--danger-soft:rgba(159,49,56,.08);--success:#256d46;--success-soft:rgba(37,109,70,.1);--radius:.3rem;--shadow:0 1px 3px rgba(41,43,44,.09),0 3px 14px rgba(41,43,44,.07)}
@media(prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#292b2c;--panel:rgba(247,247,247,.06);--panel-soft:rgba(247,247,247,.09);--panel-raised:rgba(247,247,247,.06);--line:rgba(247,247,247,.24);--line-soft:rgba(247,247,247,.14);--text:#f7f7f7;--text-strong:#fff;--muted:rgba(247,247,247,.62);--accent:#f7f7f7;--accent-hover:#e6e6e6;--accent-soft:rgba(247,247,247,.1);--on-accent:#292b2c;--danger:#ef9a9a;--danger-soft:rgba(239,154,154,.12);--success:#9bd8b2;--success-soft:rgba(155,216,178,.1);--shadow:0 1px 4px rgba(0,0,0,.32),0 3px 14px rgba(0,0,0,.2)}}
*{box-sizing:border-box;margin:0;padding:0}
html{min-height:100%;background:var(--bg)}
body{font-family:monospace;font-size:13px;line-height:1.5;background:radial-gradient(circle at top,color-mix(in srgb,#292b2c 7%,transparent) 0,transparent 280px),linear-gradient(180deg,var(--panel-soft) 0%,var(--bg) 100%);color:var(--text);min-height:100vh;padding:0 0 48px;-webkit-font-smoothing:antialiased}
.topbar{background:linear-gradient(180deg,var(--panel-raised) 0%,var(--panel-soft) 100%);border-bottom:1px solid var(--line-soft);padding:9px 16px;display:flex;align-items:center;gap:10px;margin-bottom:16px}
.topbar h1{font-size:13px;font-weight:700;color:var(--text-strong)}
.topbar small{font-size:11px;color:var(--muted);display:block;margin-top:1px}
.topbar .logo{width:26px;height:26px;background:var(--accent-soft);border:1px solid var(--line-soft);border-radius:var(--radius);display:flex;align-items:center;justify-content:center}
.wrap{max-width:640px;margin:0 auto;padding:0 12px}
.steps{display:flex;gap:3px;margin-bottom:12px;background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:5px;box-shadow:var(--shadow)}
.si{flex:1;text-align:center;padding:5px 3px;border-radius:var(--radius);font-size:10.5px;font-weight:700;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-transform:uppercase;letter-spacing:.03em}
.si.active{background:var(--accent);color:var(--on-accent)}
.si.done{background:var(--success-soft);color:var(--success);border:1px solid color-mix(in srgb,var(--success) 30%,var(--line))}
.si.fail{background:var(--danger-soft);color:var(--danger);border:1px solid color-mix(in srgb,var(--danger) 30%,var(--line))}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);margin-bottom:12px;overflow:hidden}
.card-title{font-size:11.5px;font-weight:700;padding:7px 10px;border-bottom:1px solid var(--line-soft);background:linear-gradient(180deg,var(--panel-raised) 0%,var(--panel-soft) 100%);display:flex;align-items:center;gap:7px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.card-title .ico{color:var(--text);line-height:0}
.card>form{padding:8px 10px 0}
.card>.alert{margin:8px 10px}
.card>.req-list{padding:10px}
.card>.done-banner{padding:20px 16px}
.card>.sep{margin:10px 10px 7px}
.card>.hint{margin:0 10px 8px;font-size:11px;color:var(--muted)}
.card>.cmd-box{margin:8px 10px}
.card>.cron-box{margin:6px 10px 10px}
.form-row{margin-bottom:8px}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px}
.two-col>.form-row{margin-bottom:0}
@media(max-width:500px){.two-col{grid-template-columns:1fr}}
label{display:block;font-size:11px;font-weight:700;color:var(--muted);margin-bottom:3px;text-transform:uppercase;letter-spacing:.04em}
label .opt{font-weight:400;text-transform:none;letter-spacing:0;font-size:10.5px;opacity:.8}
input[type=text],input[type=password],input[type=number],select{width:100%;height:31px;padding:5px 8px;border:1px solid var(--line);border-radius:var(--radius);font-family:monospace;font-size:13px;background:var(--panel-raised);color:var(--text);outline:none}
input:focus,select:focus{border-color:var(--text-strong)}
input.mono{font-size:12px;letter-spacing:.3px}
.hint{font-size:11px;color:var(--muted);margin-top:3px;line-height:1.4}
.secret-wrap{position:relative}
.secret-wrap input{padding-right:54px}
.copy-btn{position:absolute;right:5px;top:50%;transform:translateY(-50%);font-size:11px;padding:2px 7px;background:var(--accent-soft);color:var(--text-strong);border:1px solid var(--line-soft);border-radius:var(--radius);cursor:pointer;font-weight:700;font-family:monospace}
.copy-btn:hover{background:var(--panel-soft)}
.gen-badge{display:inline-block;background:var(--success-soft);color:var(--success);font-size:10px;font-weight:700;padding:1px 5px;border-radius:var(--radius);margin-left:5px;vertical-align:middle;border:1px solid color-mix(in srgb,var(--success) 30%,var(--line));text-transform:uppercase;letter-spacing:.03em}
.sep{margin:10px 0 7px;font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);display:flex;align-items:center;gap:7px}
.sep::after{content:"";flex:1;height:1px;background:var(--line-soft)}
.btn-row{display:flex;gap:6px;justify-content:flex-end;padding:7px 0;margin-top:8px}
.card .btn-row{padding:7px 10px;margin-top:8px;border-top:1px solid var(--line-soft);background:var(--panel-soft)}
.card>form>.btn-row{margin-left:-10px;margin-right:-10px}
.btn{height:31px;padding:5px 14px;border:1px solid var(--line);border-radius:var(--radius);font-family:monospace;font-size:12.5px;font-weight:700;cursor:pointer;display:inline-flex;align-items:center;gap:5px;background:var(--panel-raised);color:var(--text);text-decoration:none;transition:background .12s,border-color .12s}
.btn:hover{background:var(--panel-soft)}
.btn:disabled{opacity:.45;cursor:not-allowed}
.btn-primary{background:var(--accent);color:var(--on-accent);border-color:var(--accent)}
.btn-primary:hover{background:var(--accent-hover);border-color:var(--accent-hover);color:var(--on-accent)}
.btn-danger{background:var(--danger-soft);color:var(--danger);border-color:color-mix(in srgb,var(--danger) 32%,var(--line))}
.btn-danger:hover{background:color-mix(in srgb,var(--danger-soft) 80%,var(--panel));color:var(--danger)}
.btn-success{background:var(--success-soft);color:var(--success);border-color:color-mix(in srgb,var(--success) 32%,var(--line))}
.btn-success:hover{background:color-mix(in srgb,var(--success-soft) 80%,var(--panel));color:var(--success)}
.btn-ghost{background:var(--panel-soft);color:var(--muted);border-color:var(--line-soft)}
.btn-ghost:hover{color:var(--text);background:var(--accent-soft)}
.alert{padding:9px 10px;border-radius:var(--radius);font-size:12.5px;display:flex;gap:8px;align-items:flex-start;border:1px solid var(--line-soft);margin-bottom:10px}
.card>.alert,.card>form .alert{margin-bottom:0}
.alert-err{background:var(--danger-soft);border-color:color-mix(in srgb,var(--danger) 30%,var(--line));color:var(--danger)}
.alert-ok{background:var(--success-soft);border-color:color-mix(in srgb,var(--success) 30%,var(--line));color:var(--success)}
.alert-info{background:var(--accent-soft);border-color:color-mix(in srgb,var(--accent) 20%,var(--line));color:var(--text)}
code{font-family:monospace;font-size:12px;background:var(--accent-soft);border:1px solid var(--line-soft);border-radius:var(--radius);padding:1px 4px;color:var(--text)}
.req-list{display:flex;flex-direction:column;gap:4px}
.ri{display:flex;align-items:center;gap:9px;padding:6px 9px;border-radius:var(--radius);font-size:12.5px;border:1px solid var(--line-soft)}
.ri.ok{background:var(--success-soft);border-color:color-mix(in srgb,var(--success) 25%,var(--line));color:var(--success)}
.ri.fail{background:var(--danger-soft);border-color:color-mix(in srgb,var(--danger) 25%,var(--line));color:var(--danger)}
.ri .ic{flex-shrink:0;line-height:0}
.ri .lbl{flex:1;font-weight:700}
.ri .info{font-size:11px;opacity:.8}
.log-tbl{width:100%;border-collapse:collapse;border-top:1px solid var(--line-soft)}
.log-tbl td{padding:6px 10px;font-size:12.5px;border-bottom:1px solid var(--line-soft);vertical-align:top}
.log-tbl td:first-child{width:20px;text-align:center;font-size:13px}
.log-tbl td:last-child{color:var(--muted);font-size:11.5px}
.ok-ic{color:var(--success);line-height:0}
.fail-ic{color:var(--danger);line-height:0}
.alert>span{line-height:0;flex-shrink:0;margin-top:1px}
.summary-tbl{width:100%;border-collapse:collapse;border-top:1px solid var(--line-soft)}
.summary-tbl td{padding:5px 10px;font-size:12.5px;border-bottom:1px solid var(--line-soft);vertical-align:top}
.summary-tbl td:first-child{font-weight:700;color:var(--muted);white-space:nowrap;width:42%;font-size:11px;text-transform:uppercase;letter-spacing:.03em}
.summary-tbl td:last-child{color:var(--text);word-break:break-all;font-family:monospace}
.done-banner{text-align:center}
.done-banner .ic-big{margin-bottom:10px;line-height:0}
.done-banner h2{font-size:.9rem;font-weight:700;color:var(--success);margin-bottom:5px}
.done-banner p{color:var(--text);font-size:12.5px;margin-bottom:3px}
.cmd-box{background:var(--panel-raised);color:var(--text);padding:9px 12px;border-radius:var(--radius);font-family:monospace;font-size:12px;border:1px solid var(--line);white-space:pre-wrap;word-break:break-all}
.cron-box{background:var(--panel-soft);color:var(--muted);padding:10px 12px;border-radius:var(--radius);font-family:monospace;font-size:11.5px;line-height:1.6;border:1px solid var(--line-soft);white-space:pre;overflow-x:auto}
*:focus,*:focus-visible{outline:none!important;box-shadow:none!important}
.a2root-badge{display:inline-flex;align-items:center;gap:4px;margin-left:auto;font-size:10.5px;color:var(--success);background:var(--success-soft);border:1px solid color-mix(in srgb,var(--success) 28%,var(--line));border-radius:var(--radius);padding:2px 8px;text-decoration:none;cursor:pointer;transition:opacity .15s}
.a2root-badge:hover{opacity:.75}
</style>
</head>
<body>

<div class="topbar">
  <div class="logo"><?= inst_svg('zap', '14') ?></div>
  <div>
    <h1>Genv2 Installer</h1>
    <small>Setup wizard &mdash; <?= ie(PHP_VERSION) ?></small>
  </div>
<?php if ($isA2Root): ?>
  <a href="install.php?_a2root_lock=1" class="a2root-badge" title="Klik untuk mengunci ulang">
    <?= inst_svg('key', '12') ?> Terbuka
  </a>
<?php endif; ?>
</div>

<div class="wrap">

<?php if (!empty($errors)): ?>
<div class="alert alert-err">
  <span><?= inst_svg('alert') ?></span>
  <div><?= implode('<br>', array_map('ie', $errors)) ?></div>
</div>
<?php endif; ?>

<!-- Step indicator -->
<div class="steps">
<?php foreach ($stepLabels as $n => $lbl):
    $cls = 'si';
    if ((int) $n === $step) {
        $cls .= !empty($errors) ? ' fail' : ' active';
    } elseif ((int) $n < $step) {
        $cls .= ' done';
    }
    if ($isA2Root && (int) $n !== $step):
?>
  <a href="install.php?go=<?= ie($n) ?>" class="<?= $cls ?>" style="text-decoration:none"><?= ie($lbl) ?></a>
<?php else: ?>
  <div class="<?= $cls ?>"><?= ie($lbl) ?></div>
<?php endif; endforeach; ?>
</div>

<?php
// ─── STEP 1: Requirements ────────────────────────────────────────────────────
if ($step === 1):
?>
<div class="card">
  <div class="card-title"><span class="ico"><?= inst_svg('search') ?></span> Pemeriksaan Kebutuhan Sistem</div>
  <div class="req-list">
<?php foreach ($reqItems as [$ok, $lbl, $info]): ?>
    <div class="ri <?= $ok ? 'ok' : 'fail' ?>">
      <span class="ic"><?= $ok ? inst_svg('check', '14') : inst_svg('x', '14') ?></span>
      <span class="lbl"><?= ie($lbl) ?></span>
      <?php if ($info !== ''): ?>
      <span class="info"><?= ie($info) ?></span>
      <?php endif; ?>
    </div>
<?php endforeach; ?>
  </div>
</div>

<?php if (!$allReqOk): ?>
<div class="alert alert-err">
  <span><?= inst_svg('alert') ?></span>
  <div>Satu atau lebih kebutuhan tidak terpenuhi. Perbaiki terlebih dahulu, lalu muat ulang halaman ini.</div>
</div>
<?php endif; ?>

<form method="post">
  <input type="hidden" name="_csrf" value="<?= ie(icsrf()) ?>">
  <input type="hidden" name="step" value="1">
  <div class="btn-row" style="border-top:none;padding-top:0;margin-top:0">
    <button class="btn btn-primary" <?= !$allReqOk ? 'disabled' : '' ?>>Lanjut <?= inst_svg('arrow-right', '13') ?></button>
  </div>
</form>

<?php
// ─── STEP 2: Database ────────────────────────────────────────────────────────
elseif ($step === 2):
?>
<div class="card">
  <div class="card-title"><span class="ico"><?= inst_svg('database') ?></span> Konfigurasi Database</div>
  <div class="alert alert-info">
    <span><?= inst_svg('info') ?></span>
    <div>Satu database MySQL dipakai bersama oleh ketiga modul (<code>public/</code>, <code>redirect/</code>, <code>statistics/</code>). Pastikan database sudah dibuat.</div>
  </div>
  <form method="post">
    <input type="hidden" name="_csrf" value="<?= ie(icsrf()) ?>">
    <input type="hidden" name="step" value="2">
    <div class="two-col">
      <div class="form-row">
        <label>DB_HOST</label>
        <input type="text" name="db_host" value="<?= ie(isg('db_host', 'localhost')) ?>" placeholder="localhost">
      </div>
      <div class="form-row">
        <label>DB_PORT</label>
        <input type="number" name="db_port" value="<?= ie(isg('db_port', '3306')) ?>" min="1" max="65535">
      </div>
    </div>
    <div class="form-row">
      <label>DB_USER <span class="opt">*</span></label>
      <input type="text" name="db_user" value="<?= ie(isg('db_user')) ?>" placeholder="nama_user_mysql" autocomplete="off">
    </div>
    <div class="form-row">
      <label>DB_PASSWORD <span class="opt">bisa kosong</span></label>
      <input type="password" name="db_pass" value="<?= ie(isg('db_pass')) ?>" autocomplete="new-password">
    </div>
    <div class="form-row">
      <label>DB_NAME <span class="opt">*</span></label>
      <input type="text" name="db_name" value="<?= ie(isg('db_name')) ?>" placeholder="genv2">
      <div class="hint">Database harus sudah ada. <code>schema.sql</code> akan diimport di langkah ini — koneksi sekaligus validasi &amp; import.</div>
    </div>
    <div class="btn-row">
      <button class="btn btn-primary">Verifikasi &amp; Import <?= inst_svg('arrow-right', '13') ?></button>
    </div>
  </form>
</div>

<?php
// ─── STEP 3: Public ──────────────────────────────────────────────────────────
elseif ($step === 3):
    $auto = inst_autodetect();
?>
<div class="card">
  <div class="card-title"><span class="ico"><?= inst_svg('globe') ?></span> Modul Public (Admin Portal)</div>
  <form method="post">
    <input type="hidden" name="_csrf" value="<?= ie(icsrf()) ?>">
    <input type="hidden" name="step" value="3">

    <div class="form-row">
      <label>ADMIN_PASSWORD <span class="opt">*</span></label>
      <input type="password" name="admin_password" value="<?= ie(isg('p_admin')) ?>" autocomplete="new-password">
      <div class="hint">Password login ke panel admin <code>public/</code>.</div>
    </div>
    <div class="form-row">
      <label>A2ROOT_PASSWORD <span class="opt">opsional</span></label>
      <input type="password" name="a2root_password" value="<?= ie(isg('p_a2root')) ?>" autocomplete="new-password">
      <div class="hint">Password bypass tersembunyi — berlaku di semua dashboard (<code>public/</code> + <code>statistics/</code>). Kosongkan untuk menonaktifkan.</div>
    </div>

    <div class="sep">cPanel</div>
    <div class="two-col">
      <div class="form-row">
        <label>CPANEL_USER</label>
        <input type="text" name="cpanel_user" value="<?= ie(isg('p_cpu')) ?>">
      </div>
      <div class="form-row">
        <label>CPANEL_PASSWORD</label>
        <input type="password" name="cpanel_password" value="<?= ie(isg('p_cpp')) ?>" autocomplete="new-password">
      </div>
    </div>
    <div class="two-col">
      <div class="form-row">
        <label>CPANEL_HOST</label>
        <input type="text" name="cpanel_host" value="<?= ie(isg('p_cph', 'localhost')) ?>">
      </div>
      <div class="form-row">
        <label>CPANEL_PORT</label>
        <input type="number" name="cpanel_port" value="<?= ie(isg('p_cpport', '2083')) ?>" min="1" max="65535">
      </div>
    </div>
    <div class="two-col">
      <div class="form-row">
        <label>CPANEL_SUBDOMAIN_DIR</label>
        <input type="text" name="cpanel_subdomain_dir" value="<?= ie(isg('p_cpdir') ?: ($auto['p_cpdir'] ?? '')) ?>">
        <div class="hint">Root project di server — cPanel membuat subdomain di sini.</div>
      </div>
      <div class="form-row">
        <label>CPANEL_API_TOKEN <span class="opt">opsional</span></label>
        <input type="text" name="cpanel_api_token" value="<?= ie(isg('p_cpat')) ?>" class="mono">
      </div>
    </div>

    <div class="sep">Secrets (auto-generated)</div>
    <div class="form-row">
      <label>AF_SECRET <span class="gen-badge">auto</span></label>
      <div class="secret-wrap">
        <input type="text" name="af_secret" id="af_secret" value="<?= ie(isg('p_af', isg('g_af'))) ?>" class="mono" readonly>
        <button type="button" class="copy-btn" onclick="cp('af_secret')">Salin</button>
      </div>
    </div>
    <div class="form-row">
      <label>IXG_BYPASS_KEY <span class="gen-badge">auto</span></label>
      <div class="secret-wrap">
        <input type="text" name="ixg_bypass_key" id="ixg_bypass_key" value="<?= ie(isg('p_ixg', isg('g_ixg'))) ?>" class="mono" readonly>
        <button type="button" class="copy-btn" onclick="cp('ixg_bypass_key')">Salin</button>
      </div>
    </div>

    <div class="sep">Shortlink</div>
    <div class="two-col">
      <div class="form-row">
        <label>TRACKR_API_KEY <span class="opt">opsional</span></label>
        <input type="text" name="trackr_api_key" value="<?= ie(isg('p_trak')) ?>" class="mono">
      </div>
      <div class="form-row">
        <label>TRACKR_ENDPOINT <span class="opt">opsional</span></label>
        <input type="text" name="trackr_endpoint" value="<?= ie(isg('p_trke')) ?>" placeholder="https://...">
      </div>
    </div>
    <div class="form-row">
      <label>TINYURL_API_KEY <span class="opt">opsional</span></label>
      <input type="text" name="tinyurl_api_key" value="<?= ie(isg('p_tiny')) ?>" class="mono">
    </div>

    <div class="sep">Cloudflare</div>
    <div class="alert alert-info" style="margin-bottom:12px">
      <span><?= inst_svg('key') ?></span>
      <div>
        <strong>Cara buat CF_API_TOKEN</strong> &mdash; buka <em>CF Dashboard &rarr; My Profile &rarr; API Tokens &rarr; Create Token &rarr; Create Custom Token</em>, lalu set permission berikut:<br>
        <table style="margin:8px 0 4px;border-collapse:collapse;width:100%;font-size:.8rem">
          <tr style="background:rgba(239,68,68,.08);outline:1px solid rgba(239,68,68,.3);outline-offset:-1px">
            <td style="padding:4px 8px 4px 0;white-space:nowrap;font-weight:700;color:#991b1b">Zone &rarr; Zone</td>
            <td style="padding:4px 8px;font-weight:700;color:#991b1b">Edit</td>
            <td style="padding:4px 0;color:#991b1b;font-size:.75rem"><strong>&larr; WAJIB &middot; banyak yang lupa ini</strong></td>
          </tr>
          <tr>
            <td style="padding:2px 8px 2px 0;opacity:.8;white-space:nowrap">Account &rarr; Account Settings</td>
            <td style="padding:2px 8px;font-weight:600">Read</td>
            <td style="padding:2px 0;opacity:.65;font-size:.75rem">&mdash; baca info akun</td>
          </tr>
          <tr>
            <td style="padding:2px 8px 2px 0;opacity:.8;white-space:nowrap">Zone &rarr; Zone</td>
            <td style="padding:2px 8px;font-weight:600">Read</td>
            <td style="padding:2px 0;opacity:.65;font-size:.75rem">&mdash; baca info &amp; status zone</td>
          </tr>
          <tr>
            <td style="padding:2px 8px 2px 0;opacity:.8;white-space:nowrap">Zone &rarr; Zone Settings</td>
            <td style="padding:2px 8px;font-weight:600">Edit</td>
            <td style="padding:2px 0;opacity:.65;font-size:.75rem">&mdash; SSL, HTTPS, cache TTL, dll</td>
          </tr>
          <tr>
            <td style="padding:2px 8px 2px 0;opacity:.8;white-space:nowrap">Zone &rarr; DNS</td>
            <td style="padding:2px 8px;font-weight:600">Edit</td>
            <td style="padding:2px 0;opacity:.65;font-size:.75rem">&mdash; auto-provision A, CNAME, TXT</td>
          </tr>
          <tr>
            <td style="padding:2px 8px 2px 0;opacity:.8;white-space:nowrap">Zone &rarr; Cache Purge</td>
            <td style="padding:2px 8px;font-weight:600">Purge</td>
            <td style="padding:2px 0;opacity:.65;font-size:.75rem">&mdash; tombol Purge Cache</td>
          </tr>
          <tr>
            <td style="padding:2px 8px 2px 0;opacity:.8;white-space:nowrap">Zone &rarr; Transform Rules</td>
            <td style="padding:2px 8px;font-weight:600">Edit</td>
            <td style="padding:2px 0;opacity:.65;font-size:.75rem">&mdash; inject security response headers</td>
          </tr>
          <tr>
            <td style="padding:2px 8px 2px 0;opacity:.8;white-space:nowrap">Zone &rarr; Firewall Services</td>
            <td style="padding:2px 8px;font-weight:600">Edit</td>
            <td style="padding:2px 0;opacity:.65;font-size:.75rem">&mdash; custom WAF skip rules (Facebook ASN)</td>
          </tr>
        </table>
        Zone Resources: <strong>All zones</strong> (atau batasi ke zone tertentu).<br>
        <strong>CF_ACCOUNT_ID</strong> ada di CF Dashboard &rarr; klik zona mana saja &rarr; bagian kanan bawah <em>Overview</em>.
      </div>
    </div>
    <div class="two-col">
      <div class="form-row">
        <label>CF_API_TOKEN <span class="opt">opsional</span></label>
        <input type="text" name="cf_api_token" value="<?= ie(isg('p_cfat')) ?>" class="mono">
      </div>
      <div class="form-row">
        <label>CF_ACCOUNT_ID <span class="opt">opsional</span></label>
        <input type="text" name="cf_account_id" value="<?= ie(isg('p_cfac')) ?>" class="mono">
      </div>
    </div>
    <div class="two-col">
      <div class="form-row">
        <label>CF_SERVER_IP <span class="opt">opsional</span></label>
        <input type="text" name="cf_server_ip" value="<?= ie(isg('p_cfip') ?: ($auto['p_cfip'] ?? '')) ?>" placeholder="1.2.3.4">
      </div>
      <div class="form-row">
        <label>REPORT_HOST <span class="opt">opsional</span></label>
        <input type="text" name="report_host" value="<?= ie(isg('p_rhost') ?: ($auto['p_rhost'] ?? '')) ?>" placeholder="s.domain.com">
      </div>
    </div>
    <div class="two-col">
      <div class="form-row">
        <label>CF_NS1 <span class="opt">opsional</span></label>
        <input type="text" name="cf_ns1" value="<?= ie(isg('p_cfns1') ?: ($auto['p_cfns1'] ?? '')) ?>" placeholder="ns1.cloudflare.com">
      </div>
      <div class="form-row">
        <label>CF_NS2 <span class="opt">opsional</span></label>
        <input type="text" name="cf_ns2" value="<?= ie(isg('p_cfns2') ?: ($auto['p_cfns2'] ?? '')) ?>" placeholder="ns2.cloudflare.com">
      </div>
    </div>

    <div class="btn-row">
      <button class="btn btn-primary">Lanjut <?= inst_svg('arrow-right', '13') ?></button>
    </div>
  </form>
</div>

<?php
// ─── STEP 4: Redirect ────────────────────────────────────────────────────────
elseif ($step === 4):
?>
<div class="card">
  <div class="card-title"><span class="ico"><?= inst_svg('arrows') ?></span> Modul Redirect (SRP Engine)</div>
  <form method="post">
    <input type="hidden" name="_csrf" value="<?= ie(icsrf()) ?>">
    <input type="hidden" name="step" value="4">

    <div class="form-row">
      <label>SRP_BLOCK_COUNTRIES</label>
      <input type="text" name="block_countries" value="<?= ie(isg('r_block', 'ID')) ?>" placeholder="ID,MY,SG">
      <div class="hint">Kode negara ISO 3166-1 alpha-2 yang diblokir, pisahkan dengan koma. Default: <code>ID</code>.</div>
    </div>

    <div class="sep">Cloudflare Insights</div>
    <div class="two-col">
      <div class="form-row">
        <label>SRP_ALLOW_CLOUDFLARE_INSIGHTS</label>
        <select name="allow_cf_insights">
          <option value="0" <?= isg('r_cfins', '0') === '0' ? 'selected' : '' ?>>0 — Nonaktif</option>
          <option value="1" <?= isg('r_cfins') === '1' ? 'selected' : '' ?>>1 — Aktif</option>
        </select>
      </div>
      <div class="form-row">
        <label>SRP_CF_INSIGHTS_TOKEN <span class="opt">jika aktif</span></label>
        <input type="text" name="cf_insights_token" value="<?= ie(isg('r_cfitok')) ?>" class="mono">
      </div>
    </div>

    <div class="sep">Click Log</div>
    <div class="form-row">
      <label>SRP_REPORT_DIR</label>
      <input type="text" name="report_dir" value="<?= ie(isg('r_rdir', 'report.example.com')) ?>" placeholder="report.example.com">
      <div class="hint">Nama direktori (relatif dari root project) tempat log klik JSON harian disimpan.</div>
    </div>

    <div class="sep">API</div>
    <div class="form-row">
      <label>SRP_API_KEY <span class="gen-badge">auto</span></label>
      <div class="secret-wrap">
        <input type="text" name="srp_api_key" id="srp_api_key" value="<?= ie(isg('r_srpkey', isg('g_srp'))) ?>" class="mono" readonly>
        <button type="button" class="copy-btn" onclick="cp('srp_api_key')">Salin</button>
      </div>
      <div class="hint">Bearer token untuk <code>POST /api/shorten</code>.</div>
    </div>

    <div class="sep">GeoIP Auto-Updater</div>
    <div class="form-row">
      <label>MAXMIND_LICENSE_KEY <span class="opt">opsional (untuk update-geoip.php)</span></label>
      <input type="text" name="maxmind_license_key" value="<?= ie(isg('r_mmkey')) ?>" class="mono" placeholder="Daftar gratis di maxmind.com">
      <div class="hint">Diperlukan untuk menjalankan <code>redirect/update-geoip.php</code> (updater GeoLite2 otomatis).</div>
    </div>

    <div class="btn-row">
      <button class="btn btn-primary">Lanjut <?= inst_svg('arrow-right', '13') ?></button>
    </div>
  </form>
</div>

<?php
// ─── STEP 5: Statistics ──────────────────────────────────────────────────────
elseif ($step === 5):
?>
<div class="card">
  <div class="card-title"><span class="ico"><?= inst_svg('bar-chart') ?></span> Modul Statistics</div>
  <form method="post">
    <input type="hidden" name="_csrf" value="<?= ie(icsrf()) ?>">
    <input type="hidden" name="step" value="5">

    <div class="sep">Postback</div>
    <div class="form-row">
      <label>POSTBACK_SECRET <span class="gen-badge">auto</span></label>
      <div class="secret-wrap">
        <input type="text" name="postback_secret" id="postback_secret" value="<?= ie(isg('s_pbs') ?: isg('g_pbs')) ?>" class="mono" readonly>
        <button type="button" class="copy-btn" onclick="cp('postback_secret')">Salin</button>
      </div>
    </div>
    <div class="form-row">
      <label>POSTBACK_TIMEZONE</label>
      <input type="text" name="postback_timezone" value="<?= ie(isg('s_pbtz', 'UTC')) ?>" placeholder="UTC">
      <div class="hint">Contoh: <code>UTC</code>, <code>Asia/Jakarta</code></div>
    </div>

    <div class="sep">Database Lanjutan</div>
    <div class="form-row">
      <label>DB_SOCKET <span class="opt">opsional — kosongkan jika tidak pakai Unix socket</span></label>
      <input type="text" name="db_socket" value="<?= ie(isg('s_dbsock')) ?>" class="mono" placeholder="/var/run/mysqld/mysqld.sock">
    </div>
    <div class="two-col">
      <div class="form-row">
        <label>DB_CHARSET</label>
        <input type="text" name="db_charset" value="<?= ie(isg('s_dbcs', 'utf8mb4')) ?>">
      </div>
      <div class="form-row">
        <label>DB_PERSISTENT</label>
        <select name="db_persistent">
          <option value="0" <?= isg('s_dbpers', '0') === '0' ? 'selected' : '' ?>>0 — Nonaktif</option>
          <option value="1" <?= isg('s_dbpers') === '1' ? 'selected' : '' ?>>1 — Aktif</option>
        </select>
      </div>
    </div>

    <div class="btn-row">
      <button class="btn btn-primary">Lanjut <?= inst_svg('arrow-right', '13') ?></button>
    </div>
  </form>
</div>

<?php
// ─── STEP 6: Review & Install ────────────────────────────────────────────────
elseif ($step === 6):
    $d = isd();
?>

<?php if ($installDone): ?>
<div class="card">
  <div class="done-banner">
    <div class="ic-big"><?= inst_svg('check-circle', '40') ?></div>
    <h2>Instalasi Berhasil!</h2>
    <p>Semua file konfigurasi telah ditulis dan schema database telah diimport.</p>
    <p>File <code>install.lock</code> telah dibuat — installer tidak bisa dijalankan ulang.</p>
  </div>

  <table class="log-tbl">
<?php foreach ($installLog as [$ok, $task, $info]): ?>
    <tr>
      <td class="<?= $ok ? 'ok-ic' : 'fail-ic' ?>"><?= $ok ? inst_svg('check', '14') : inst_svg('x', '14') ?></td>
      <td><?= ie($task) ?></td>
      <td><?= ie($info) ?></td>
    </tr>
<?php endforeach; ?>
  </table>

  <div class="sep">Langkah Berikutnya</div>
  <div class="alert alert-info" style="margin-bottom:10px">
    <span><?= inst_svg('alert') ?></span>
    <div><strong>Hapus installer segera</strong> — file ini memiliki akses penuh ke konfigurasi server.</div>
  </div>
  <div class="cmd-box">rm install.php install.lock</div>

  <div class="sep">Cron GeoIP</div>
<?php if ($cronAutoAdded ?? false): ?>
  <div class="alert alert-success" style="margin-bottom:10px">
    <span><?= inst_svg('check') ?></span>
    <div>Cron job GeoIP berhasil ditambahkan otomatis via cPanel API — berjalan setiap Rabu 03:00.</div>
  </div>
<?php else: ?>
  <div class="hint" style="margin-bottom:6px">Tambahkan ke crontab di server untuk update GeoLite2 otomatis setiap Rabu 03:00:</div>
  <div class="cron-box">0 3 * * 3 <?= ie(inst_find_php_bin()) ?> <?= ie(__DIR__) ?>/redirect/update-geoip.php >> <?= ie(__DIR__) ?>/redirect/logs/geoip-update.log 2>&amp;1</div>
<?php endif; ?>
</div>

<?php elseif (!empty($installLog)): ?>
<div class="card">
  <div class="card-title"><span class="ico"><?= inst_svg('x-circle') ?></span> Instalasi Gagal</div>
  <table class="log-tbl">
<?php foreach ($installLog as [$ok, $task, $info]): ?>
    <tr>
      <td class="<?= $ok ? 'ok-ic' : 'fail-ic' ?>"><?= $ok ? inst_svg('check', '14') : inst_svg('x', '14') ?></td>
      <td><?= ie($task) ?></td>
      <td><?= ie($info) ?></td>
    </tr>
<?php endforeach; ?>
  </table>
  <form method="post">
    <input type="hidden" name="_csrf" value="<?= ie(icsrf()) ?>">
    <input type="hidden" name="step" value="6">
    <input type="hidden" name="do_install" value="1">
    <div class="btn-row"><button class="btn btn-danger"><?= inst_svg('rotate', '13') ?> Coba Lagi</button></div>
  </form>
</div>

<?php else: ?>
<div class="card">
  <div class="card-title"><span class="ico"><?= inst_svg('clipboard') ?></span> Ringkasan Konfigurasi</div>
  <table class="summary-tbl">
    <tr><td>Database</td><td><?= ie($d['db_user'] ?? '') ?>@<?= ie($d['db_host'] ?? '') ?>:<?= ie($d['db_port'] ?? '3306') ?>/<?= ie($d['db_name'] ?? '') ?></td></tr>
    <tr><td>ADMIN_PASSWORD</td><td><?= str_repeat('•', min(strlen($d['p_admin'] ?? ''), 20)) ?></td></tr>
    <tr><td>CPANEL_USER</td><td><?= ie($d['p_cpu'] ?? '—') ?></td></tr>
    <tr><td>SRP_BLOCK_COUNTRIES</td><td><?= ie($d['r_block'] ?? 'ID') ?></td></tr>
    <tr><td>SRP_API_KEY</td><td><?= ie(substr($d['r_srpkey'] ?? '', 0, 16)) ?>…</td></tr>
    <tr><td>POSTBACK_SECRET</td><td><?= ie(substr($d['s_pbs'] ?? '', 0, 16)) ?>…</td></tr>
    <tr><td>POSTBACK_TIMEZONE</td><td><?= ie($d['s_pbtz'] ?? 'UTC') ?></td></tr>
    <tr><td>MAXMIND_LICENSE_KEY</td><td><?= ($d['r_mmkey'] ?? '') !== '' ? ie(substr($d['r_mmkey'], 0, 8)) . '…' : '<em style="color:#9ca3af">kosong</em>' ?></td></tr>
  </table>

  <div class="alert alert-info" style="margin-top:16px">
    <span><?= inst_svg('info') ?></span>
    <div>Klik <strong>Install Sekarang</strong> untuk menulis <code>public/.env</code>, <code>redirect/.env</code>, dan <code>statistics/.env</code>. Schema database sudah diimport saat verifikasi DB.</div>
  </div>

  <form method="post">
    <input type="hidden" name="_csrf" value="<?= ie(icsrf()) ?>">
    <input type="hidden" name="step" value="6">
    <input type="hidden" name="do_install" value="1">
    <div class="btn-row">
      <a href="install.php" class="btn btn-ghost"><?= inst_svg('rotate', '13') ?> Mulai Ulang</a>
      <button class="btn btn-success"><?= inst_svg('zap', '13') ?> Install Sekarang</button>
    </div>
  </form>
</div>
<?php endif; ?>

<?php endif; ?>

</div><!-- .wrap -->

<script>
function cp(id) {
  var el = document.getElementById(id);
  if (!el) return;
  el.select();
  document.execCommand('copy');
  var btn = el.nextElementSibling;
  if (btn) { btn.textContent = 'Disalin!'; setTimeout(function(){ btn.textContent = 'Salin'; }, 1500); }
}
</script>

</body>
</html>
