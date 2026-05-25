<?php

declare(strict_types=1);

include_once('../login.php');

function pcSendSecurityHeaders(): void
{
    if (headers_sent()) {
        return;
    }

    header_remove('Content-Security-Policy');
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
        "script-src 'self' 'unsafe-inline' https://www.gstatic.com https:",
        "script-src-elem 'self' 'unsafe-inline' https://www.gstatic.com https:",
        "connect-src 'self' https:",
    ]);

    header('Content-Security-Policy: ' . $csp);
}

function pcEnsureSession(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
}

function pcH(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function pcCsrfToken(): string
{
    pcEnsureSession();

    if (
        !isset($_SESSION['pc_csrf_token'])
        || !is_string($_SESSION['pc_csrf_token'])
        || $_SESSION['pc_csrf_token'] === ''
    ) {
        $_SESSION['pc_csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['pc_csrf_token'];
}

function pcVerifyCsrf(?string $token): bool
{
    pcEnsureSession();

    if (!is_string($token) || $token === '') {
        return false;
    }

    if (!isset($_SESSION['pc_csrf_token']) || !is_string($_SESSION['pc_csrf_token'])) {
        return false;
    }

    return hash_equals($_SESSION['pc_csrf_token'], $token);
}

function pcSelfPath(): string
{
    $scriptName = isset($_SERVER['SCRIPT_NAME']) && is_string($_SERVER['SCRIPT_NAME'])
        ? $_SERVER['SCRIPT_NAME']
        : '/click/';

    if ($scriptName === '' || preg_match('/[
]/', $scriptName) === 1) {
        return '/click/';
    }

    return $scriptName;
}

/**
 * @return array{total: int, rows: array<int, mixed>}
 */
function pcReadJsonPage(string $filename, int $offset, int $limit): array
{
    if (!is_file($filename) || !is_readable($filename)) {
        return ['total' => 0, 'rows' => []];
    }

    $handle = fopen($filename, 'rb');
    if (!is_resource($handle)) {
        return ['total' => 0, 'rows' => []];
    }

    $total = 0;
    $rows = [];
    $inArray = false;
    $started = false;
    $complexElement = false;
    $depth = 0;
    $inString = false;
    $escaped = false;
    $element = '';

    while (!feof($handle)) {
        $chunk = fread($handle, 8192);
        if (!is_string($chunk) || $chunk === '') {
            continue;
        }

        $length = strlen($chunk);
        for ($index = 0; $index < $length; $index++) {
            $char = $chunk[$index];

            if (!$inArray) {
                if ($char === '[') {
                    $inArray = true;
                }
                continue;
            }

            if (!$started) {
                if ($char === ']' || $char === ',' || trim($char) === '') {
                    continue;
                }

                $started = true;
                $complexElement = $char === '{' || $char === '[';
                $depth = $complexElement ? 1 : 0;
                $inString = $char === '"';
                $escaped = false;
                $element = $char;
                continue;
            }

            if (!$complexElement && !$inString && ($char === ',' || $char === ']')) {
                pcCollectJsonElement($element, $total, $rows, $offset, $limit);
                $started = false;
                $element = '';
                if ($char === ']') {
                    break 2;
                }
                continue;
            }

            $element .= $char;

            if ($inString) {
                if ($escaped) {
                    $escaped = false;
                } elseif ($char === '\\') {
                    $escaped = true;
                } elseif ($char === '"') {
                    $inString = false;
                }
                continue;
            }

            if ($char === '"') {
                $inString = true;
                continue;
            }

            if ($complexElement && ($char === '{' || $char === '[')) {
                $depth++;
                continue;
            }

            if ($complexElement && ($char === '}' || $char === ']')) {
                $depth--;
                if ($depth === 0) {
                    pcCollectJsonElement($element, $total, $rows, $offset, $limit);
                    $started = false;
                    $element = '';
                }
            }
        }
    }

    fclose($handle);

    if ($started && trim($element) !== '') {
        pcCollectJsonElement($element, $total, $rows, $offset, $limit);
    }

    return ['total' => $total, 'rows' => $rows];
}

/**
 * @param array<int, mixed> $rows
 */
function pcCollectJsonElement(string $element, int &$total, array &$rows, int $offset, int $limit): void
{
    $position = $total;
    $total++;

    if ($position < $offset || count($rows) >= $limit) {
        return;
    }

    try {
        $decoded = json_decode($element, true, 32, JSON_THROW_ON_ERROR);
    } catch (Throwable $e) {
        return;
    }

    $rows[] = $decoded;
}

function pcCurrentPage(int $totalPages): int
{
    $rawPage = isset($_GET['page']) && is_scalar($_GET['page']) ? (string) $_GET['page'] : '1';

    if (preg_match('/\A\d{1,6}\z/', $rawPage) !== 1) {
        return 1;
    }

    return max(1, min($totalPages, (int) $rawPage));
}

function pcPageUrl(int $page): string
{
    return '?page=' . rawurlencode((string) max(1, $page));
}

function pcHandlePostLogout(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return;
    }

    $action = isset($_POST['action']) && is_string($_POST['action']) ? $_POST['action'] : '';
    if ($action !== 'logout') {
        return;
    }

    if (!pcVerifyCsrf($_POST['csrf_token'] ?? null)) {
        http_response_code(403);
        echo 'Invalid CSRF token.';
        exit;
    }

    pcEnsureSession();
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

    header('Location: ' . pcSelfPath());
    exit;
}

function pcSafeCountryCode(mixed $value): string
{
    $code = strtolower((string) $value);
    $code = preg_replace('/[^a-z]/', '', $code);

    if (!is_string($code) || $code === '') {
        return '--';
    }

    return substr($code, 0, 3);
}

function pcIconImg(string $src, string $label, int $size = 16): string
{
    $class = $size <= 13 ? 'pc-icon pc-icon-sm' : 'pc-icon';

    return '<img src="' . pcH($src) . '" class="' . pcH($class) . '" alt="' . pcH($label) . '" title="' . pcH($label) . '" width="' . $size . '" height="' . $size . '">';
}

function pcRenderCountry(mixed $countryCode): string
{
    $code = pcSafeCountryCode($countryCode);
    $label = strtoupper($code === '--' ? '-' : $code);

    return '<span class="flag flag-' . pcH($code) . '"></span> <strong class="pc-country">' . pcH($label) . '</strong>';
}

function pcRenderUserAgent(mixed $userAgent): string
{
    $raw = strtoupper(trim((string) $userAgent));
    $key = strtolower(trim((string) $userAgent));

    $map = [
        'wap' => ['/dist/wap.svg', 'WAP'],
        'web' => ['/dist/web.svg', 'WEB'],
        'tablet' => ['/dist/tablet.svg', 'TABLET'],
    ];

    if (isset($map[$key])) {
        return pcIconImg($map[$key][0], $map[$key][1], 14);
    }

    return '<code>' . pcH($raw) . '</code>';
}

function pcRenderNetwork(mixed $info): string
{
    $raw = trim((string) $info);
    $key = strtolower($raw);

    $map = [
        'lospollos' => ['/dist/lp.svg', 'LosPollos'],
        'imonetizeit' => ['/dist/imo.svg', 'iMonetizeIt'],
        'imonetizeit-1' => ['/dist/imo.svg', 'iMonetizeIt-1'],
        'imonetizeit-2' => ['/dist/imo.svg', 'iMonetizeIt-2'],
        'trafee' => ['/dist/tf.svg', 'Trafee'],
        'custom' => ['/dist/custom.svg', 'Custom'],
        'torazzo' => ['/dist/custom.svg', 'Torazzo'],
    ];

    if (isset($map[$key])) {
        return pcIconImg($map[$key][0], $map[$key][1], 16);
    }

    return '<code>' . pcH($raw) . '</code>';
}

pcSendSecurityHeaders();
pcHandlePostLogout();

$pageName = basename(__DIR__);
$isPerformanceClick = $pageName === 'click';
$title = $isPerformanceClick ? 'PERFOMANCE CLICK' : 'REALTIME CONVERSION';

$time = date('Y-m-d', strtotime('today'));
$filename = '../temp/' . $time . '.json';

$perPage = 100;
$requestedPage = pcCurrentPage(1000000);
$offset = ($requestedPage - 1) * $perPage;
$pageData = pcReadJsonPage($filename, $offset, $perPage);
$total = $pageData['total'];
$totalPages = max(1, (int) ceil($total / $perPage));
$page = min($requestedPage, $totalPages);
$offset = ($page - 1) * $perPage;
$rows = $page === $requestedPage ? $pageData['rows'] : pcReadJsonPage($filename, $offset, $perPage)['rows'];
$self = pcSelfPath();

include_once('../header.php');
?>
<style>
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
/* performance click shared-layout patch */.pc-toolbar{margin-bottom:6px}.pc-search{display:flex!important;align-items:stretch!important;flex-wrap:nowrap!important;width:100%!important}.pc-search .input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;min-width:34px!important;height:31px!important;border-right:0!important;border-radius:var(--radius) 0 0 var(--radius)!important}.pc-search .form-control{flex:1 1 auto!important;width:auto!important;min-width:0!important;border-left:0!important;border-radius:0 var(--radius) var(--radius) 0!important}.pc-table-wrap{border:1px solid var(--line-soft);border-radius:var(--radius);background:var(--panel);box-shadow:var(--shadow);overflow-x:auto}.pc-icon{display:inline-block;width:16px;height:16px;vertical-align:middle}.pc-icon-sm{width:13px;height:13px}.pc-country{color:var(--danger)!important}.pc-click{font-family:Consolas,Monaco,'Courier New',monospace;font-weight:700;color:var(--text-strong)}.pc-page-meta{color:var(--text);font-size:11px;margin-left:8px}.pc-pagination{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:10px 0 4px}.pc-pagination .pagination{margin:0!important;display:flex;flex-wrap:wrap}.logout-form{margin:0}.logout-btn{padding:12px 10px!important;color:var(--text)!important;text-decoration:none!important;background:transparent!important;border:0!important}.rg-source{margin:8px 0 0;padding:7px 10px;border:1px solid var(--line-soft);border-radius:var(--radius);background:var(--panel-fade);font-size:11px;color:var(--text)}.rg-source .pre-colon{font-weight:800;color:var(--text-strong)}.rg-source .post-colon{font-family:Consolas,Monaco,'Courier New',monospace}.is-hidden{display:none!important}#logout-toast{position:fixed;right:12px;bottom:12px;z-index:10050;display:none;padding:8px 10px;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:12px}#logout-toast.show{display:block}@media screen and (max-width:768px){.pc-search{display:flex!important}.pc-search .input-group-addon{width:34px!important}.pc-search .form-control{width:auto!important}.pc-table-wrap .table{min-width:760px!important}.pc-page-meta{display:block;width:100%;margin-left:0}.navbar-btn.logout-btn{padding:9px 10px!important}}
:root{--font-mono-old:"Lucida Console","Courier New",Consolas,Monaco,monospace}body,.navbar,.panel,.table,.form-control,input,select,textarea,button,.btn,.dropdown-menu,.notice,.rt-notice-line,.rg-source,code,pre,kbd,samp{font-family:var(--font-mono-old)!important;font-size-adjust:none}.table>thead>tr>th{font-family:var(--font-mono-old)!important;font-size:10.5px!important}.table>tbody>tr>td{font-family:var(--font-mono-old)!important;font-size:12px!important}.form-control,input,select,textarea,.btn,button{font-family:var(--font-mono-old)!important;font-size:11.5px!important}
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
          <a class="navbar-brand" href="#"><strong><?= pcIconImg('/dist/chart.svg', '', 13) ?> <?= pcH($title) ?></strong></a>
        </div>
        <div id="navbar" class="navbar-collapse collapse">
          <ul class="nav navbar-nav navbar-right">
            <li class="dropdown active">
              <a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-haspopup="true" aria-expanded="false"><strong><?= pcH($title) ?> <?= pcIconImg('/dist/info.svg', '', 13) ?></strong> <span class="caret"></span></a>
              <ul class="dropdown-menu">
                <li class="dropdown-header">REALTIME CONVERSION <?= pcIconImg('/dist/info.svg', '', 13) ?></li>
                <li role="separator" class="divider"></li>
                <li><a href="/realtime/?date=rt_1"><strong>TODAY</strong></a></li>
                <li role="separator" class="divider"></li>
                <li><a href="/realtime/?date=rt_2"><strong>YESTERDAY</strong></a></li>
                <li role="separator" class="divider"></li>
                <li class="active"><a href="#"><strong>PERFOMANCE CLICK <?= pcIconImg('/dist/chart.svg', '', 13) ?></strong></a></li>
              </ul>
            </li>
            <li><a><strong><?= pcIconImg('/dist/menu.svg', '', 13) ?></strong></a></li>
            <li><a href="/performance/"><strong>PERFORMANCE NETWORK</strong> <?= pcIconImg('/dist/menu.svg', '', 13) ?></a></li>
            <li>
              <form method="post" action="<?= pcH($self) ?>" id="logout-form" class="logout-form">
                <input type="hidden" name="csrf_token" value="<?= pcH(pcCsrfToken()) ?>">
                <input type="hidden" name="action" value="logout">
                <button type="submit" id="btn-logout" class="btn btn-link navbar-btn logout-btn"><strong>LOGOUT</strong></button>
              </form>
            </li>
          </ul>
        </div>
      </div>
    </nav>

    <div class="container">
        <div class="panel panel-default pc-toolbar">
            <div class="panel-heading"><strong>auto reset table randomly!</strong></div>
        </div>

        <div class="pc-toolbar">
            <div class="input-group pc-search">
                <span class="input-group-addon"><?= pcIconImg('/dist/search.svg', '', 13) ?></span>
                <input type="text" class="form-control input-sm filter" id="search" placeholder="Search for ID.." title="Type in a name" autocomplete="off">
            </div>
        </div>

        <div class="pc-table-wrap">
            <table class="table table-condensed table-hover table-striped" id="perf-click-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>CLICKID</th>
                        <th>COUNTRY</th>
                        <th>TRAFFIC</th>
                        <th>IP ADDRESS</th>
                        <th>NETWORK</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($rows as $row): ?>
                        <?php
                        if (!is_array($row)) {
                            continue;
                        }

                        $id = isset($row['id']) ? (int) $row['id'] : 0;
                        $clickId = strtoupper(trim((string) ($row['click_id'] ?? '')));
                        $countryCode = pcRenderCountry($row['country_code'] ?? '');
                        $userAgent = pcRenderUserAgent($row['user_agent'] ?? '');
                        $ipAddress = trim((string) ($row['ip_address'] ?? ''));
                        $network = pcRenderNetwork($row['info'] ?? '');
                        ?>
                        <tr class="pc-row" data-click-id="<?= pcH(strtolower($clickId)) ?>">
                            <td><?= (int) $id ?></td>
                            <td><span class="pc-click"><?= pcH($clickId) ?></span></td>
                            <td><?= $countryCode ?></td>
                            <td><?= $userAgent ?></td>
                            <td><code><?= pcH($ipAddress) ?></code></td>
                            <td><?= $network ?></td>
                        </tr>
                    <?php endforeach; ?>

                    <?php if (count($rows) === 0): ?>
                        <tr>
                            <td colspan="6">There are currently no clicks available for this page.</td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

        <?php if ($totalPages > 1): ?>
            <nav class="pc-pagination">
                <ul class="pagination pagination-sm">
                    <li class="<?= $page <= 1 ? 'disabled' : '' ?>">
                        <a href="<?= pcH(pcPageUrl($page - 1)) ?>">&laquo;</a>
                    </li>
                    <?php
                    $startPage = max(1, $page - 4);
                    $endPage = min($totalPages, $page + 4);
                    ?>

                    <?php if ($startPage > 1): ?>
                        <li class="disabled"><a href="#">…</a></li>
                    <?php endif; ?>

                    <?php for ($p = $startPage; $p <= $endPage; $p++): ?>
                        <li class="<?= $p === $page ? 'active' : '' ?>">
                            <a href="<?= pcH(pcPageUrl($p)) ?>"><?= (int) $p ?></a>
                        </li>
                    <?php endfor; ?>

                    <?php if ($endPage < $totalPages): ?>
                        <li class="disabled"><a href="#">…</a></li>
                    <?php endif; ?>

                    <li class="<?= $page >= $totalPages ? 'disabled' : '' ?>">
                        <a href="<?= pcH(pcPageUrl($page + 1)) ?>">&raquo;</a>
                    </li>
                </ul>
                <small class="pc-page-meta">
                    <?= number_format($total > 0 ? $offset + 1 : 0) ?>–<?= number_format(min($offset + $perPage, $total)) ?>
                    of <?= number_format($total) ?>
                </small>
            </nav>
        <?php endif; ?>

        <div class="rg-source">
            <span class="pre-colon">SOURCE</span>: <span class="post-colon">NGIX!</span>
        </div>
    </div>

<script src="https://www.gstatic.com/firebasejs/4.1.2/firebase-app.js" type="text/javascript"></script>
<script src="https://www.gstatic.com/firebasejs/4.1.2/firebase-messaging.js" type="text/javascript"></script>
<script type="text/javascript">
$(document).ready(function () {
    'use strict';

    $('.filter').on('input', function () {
        var needle = String($(this).val() || '').toLowerCase();

        $('.pc-row').each(function () {
            var $row = $(this);
            var clickId = String($row.attr('data-click-id') || '');

            if (clickId.indexOf(needle) !== -1) {
                $row.removeClass('is-hidden');
            } else {
                $row.addClass('is-hidden');
            }
        });
    });

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
});
</script>
<div id="logout-toast">Logging out…</div>
</body></html>
