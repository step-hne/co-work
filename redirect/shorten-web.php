<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/env.php';

load_env_file(__DIR__ . '/.env');

// ── Security headers ──────────────────────────────────────────────────────────
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

$isHttps = (
    (isset($_SERVER['HTTPS']) && is_string($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off')
    || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && is_string($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https')
    || (isset($_SERVER['SERVER_PORT']) && is_string($_SERVER['SERVER_PORT']) && (int) $_SERVER['SERVER_PORT'] === 443)
);

if ($isHttps) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

// ── Session ───────────────────────────────────────────────────────────────────
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
if ($isHttps) {
    ini_set('session.cookie_secure', '1');
}
session_start();

// ── API key dari env ──────────────────────────────────────────────────────────
$apiKey = app_env('SRP_API_KEY', '') ?? '';

if ($apiKey === '') {
    http_response_code(503);
    exit('SRP_API_KEY tidak dikonfigurasi.');
}

// ── Resolve URL endpoint (self) ───────────────────────────────────────────────
$scheme   = $isHttps ? 'https' : 'http';
$host     = isset($_SERVER['HTTP_HOST']) && is_string($_SERVER['HTTP_HOST'])
    ? preg_replace('/[^a-zA-Z0-9.\-:]/', '', $_SERVER['HTTP_HOST'])
    : 'localhost';
$selfBase = $scheme . '://' . $host;
$apiUrl   = $selfBase . '/api/shorten';

// ── Auth sederhana: password = API key ───────────────────────────────────────
$isAuthed = isset($_SESSION['srp_web_authed']) && $_SESSION['srp_web_authed'] === true;

if (!$isAuthed) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['web_password'])) {
        $entered = is_string($_POST['web_password']) ? $_POST['web_password'] : '';
        if (hash_equals($apiKey, $entered)) {
            session_regenerate_id(true);
            $_SESSION['srp_web_authed'] = true;
            $_SESSION['srp_csrf']       = bin2hex(random_bytes(32));
            header('Location: ' . htmlspecialchars($selfBase . '/shorten-web.php', ENT_QUOTES | ENT_HTML5, 'UTF-8'));
            exit;
        }

        srp_web_render_login('Password salah.');
        exit;
    }

    srp_web_render_login('');
    exit;
}

// ── Init CSRF ─────────────────────────────────────────────────────────────────
if (empty($_SESSION['srp_csrf']) || !is_string($_SESSION['srp_csrf'])) {
    $_SESSION['srp_csrf'] = bin2hex(random_bytes(32));
}
$csrfToken = (string) $_SESSION['srp_csrf'];

// ── Handle form submission ────────────────────────────────────────────────────
$result  = null;
$errors  = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedCsrf = isset($_POST['csrf_token']) && is_string($_POST['csrf_token'])
        ? $_POST['csrf_token'] : '';

    if (!hash_equals($csrfToken, $postedCsrf)) {
        $errors[] = 'Token CSRF tidak valid. Muat ulang halaman.';
    } else {
        $modeRaw = isset($_POST['mode']) && is_string($_POST['mode']) ? $_POST['mode'] : 'sub_id';
        $mode    = in_array($modeRaw, ['fields', 'url_mode'], true) ? $modeRaw : 'sub_id';

        if ($mode === 'url_mode') {
            $targetUrl = srp_web_str($_POST['target_url'] ?? null);
            if ($targetUrl === null) {
                $errors[] = 'URL tidak boleh kosong.';
            } elseif (filter_var($targetUrl, FILTER_VALIDATE_URL) === false) {
                $errors[] = 'URL tidak valid.';
            } else {
                $result = srp_web_call_api_mode_b($apiUrl, $apiKey, $targetUrl);
            }
        } elseif ($mode === 'sub_id') {
            $subId = srp_web_str($_POST['sub_id'] ?? null);
            if ($subId === null) {
                $errors[] = 'sub_id tidak boleh kosong.';
            } elseif (preg_match('/^[A-Za-z0-9_=+\/-]{1,2048}$/', $subId) !== 1) {
                $errors[] = 'sub_id mengandung karakter tidak valid.';
            } else {
                $body = ['sub_id' => $subId];
            }
        } else {
            $clickId = srp_web_str($_POST['click_id'] ?? null);
            $userLp  = srp_web_str($_POST['user_lp'] ?? null);

            if ($clickId === null) {
                $errors[] = 'click_id tidak boleh kosong.';
            }

            if ($userLp === null) {
                $errors[] = 'user_lp tidak boleh kosong.';
            }

            if ($errors === []) {
                $body = [
                    'click_id' => $clickId,
                    'user_lp'  => $userLp,
                ];

                $canonicalUrl = srp_web_str($_POST['canonical_url'] ?? null);
                if ($canonicalUrl !== null) {
                    $body['canonical_url'] = $canonicalUrl;
                }

                $title = srp_web_str($_POST['title'] ?? null);
                if ($title !== null) {
                    $body['title'] = $title;
                }

                $imageUrl = srp_web_str($_POST['image_url'] ?? null);
                if ($imageUrl !== null) {
                    $body['image_url'] = $imageUrl;
                }

                $lg = srp_web_str($_POST['lg'] ?? null);
                if ($lg !== null) {
                    $body['lg'] = $lg;
                }
            }
        }

        if ($mode !== 'url_mode' && $errors === []) {
            $code = srp_web_str($_POST['code'] ?? null);
            if ($code !== null) {
                /** @var array<string, mixed> $body */
                $body['code'] = $code;
            }

            $baseUrl = srp_web_str($_POST['base_url'] ?? null);
            if ($baseUrl !== null) {
                /** @var array<string, mixed> $body */
                $body['base_url'] = $baseUrl;
            }

            /** @var array<string, mixed> $body */
            $result = srp_web_call_api($apiUrl, $apiKey, $body);
        }
    }
}

// ── Render ────────────────────────────────────────────────────────────────────
// Pre-extract result strings untuk template
$resultOk    = $result !== null && ($result['ok'] ?? false) === true;
$resultUrl   = $result !== null && is_string($result['url'] ?? null) ? (string) $result['url'] : '';
$resultCode  = $result !== null && is_string($result['code'] ?? null) ? (string) $result['code'] : '-';
$resultToken = $result !== null && is_string($result['token'] ?? null) ? (string) $result['token'] : '-';
$resultError = $result !== null && is_string($result['error'] ?? null) ? (string) $result['error'] : 'Unknown error';
/** @var array<string, string> $_POST */
$nonce = base64_encode(random_bytes(16));
header("Content-Security-Policy: default-src 'none'; style-src 'nonce-{$nonce}'; script-src 'nonce-{$nonce}'; form-action 'self'; frame-ancestors 'none';");

?><!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shorten Link</title>
<style nonce="<?= htmlspecialchars($nonce, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: system-ui, sans-serif; background: #0f1117; color: #e2e8f0; min-height: 100vh; display: flex; align-items: flex-start; justify-content: center; padding: 2rem 1rem; }
.card { background: #1e2230; border: 1px solid #2d3348; border-radius: 10px; width: 100%; max-width: 580px; padding: 2rem; }
h1 { font-size: 1.25rem; font-weight: 700; margin-bottom: 1.5rem; color: #a78bfa; }
label { display: block; font-size: .8rem; color: #94a3b8; margin-bottom: .35rem; }
input, select, textarea { width: 100%; background: #0f1117; border: 1px solid #2d3348; border-radius: 6px; color: #e2e8f0; font-size: .9rem; padding: .55rem .75rem; outline: none; }
input:focus, select:focus, textarea:focus { border-color: #a78bfa; }
textarea { resize: vertical; min-height: 60px; }
.field { margin-bottom: 1rem; }
.row { display: flex; gap: .75rem; }
.row .field { flex: 1; }
.tabs { display: flex; gap: .5rem; margin-bottom: 1.25rem; }
.tab-btn { flex: 1; padding: .5rem; background: #0f1117; border: 1px solid #2d3348; border-radius: 6px; color: #94a3b8; font-size: .85rem; cursor: pointer; }
.tab-btn.active { border-color: #a78bfa; color: #a78bfa; }
.section { display: none; }
.section.show { display: block; }
.btn { width: 100%; padding: .65rem 1rem; background: #7c3aed; border: none; border-radius: 6px; color: #fff; font-size: .95rem; font-weight: 600; cursor: pointer; margin-top: .5rem; }
.btn:hover { background: #6d28d9; }
.alert-err { background: #3b0f0f; border: 1px solid #7f1d1d; border-radius: 6px; padding: .75rem 1rem; margin-bottom: 1rem; color: #fca5a5; font-size: .875rem; }
.alert-ok { background: #0e2918; border: 1px solid #166534; border-radius: 6px; padding: .75rem 1rem; margin-bottom: 1rem; color: #86efac; font-size: .875rem; }
.result-url { word-break: break-all; font-weight: 700; font-size: 1.05rem; color: #34d399; margin-top: .35rem; }
.meta { font-size: .8rem; color: #94a3b8; margin-top: .25rem; }
hr { border: none; border-top: 1px solid #2d3348; margin: 1.25rem 0; }
</style>
</head>
<body>
<div class="card">
  <h1>&#9889; Shorten Link</h1>

<?php if ($errors !== []): ?>
  <div class="alert-err">
    <?php foreach ($errors as $e): ?>
      <div><?= htmlspecialchars($e, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?></div>
    <?php endforeach; ?>
  </div>
<?php endif; ?>

<?php if ($result !== null): ?>
  <?php if ($resultOk): ?>
    <div class="alert-ok">
      <div>Short link berhasil dibuat!</div>
      <div class="result-url">
        <a href="<?= htmlspecialchars($resultUrl, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>"
           target="_blank" rel="noopener noreferrer" style="color:inherit">
          <?= htmlspecialchars($resultUrl !== '' ? $resultUrl : '-', ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>
        </a>
      </div>
      <div class="meta">Code: <strong><?= htmlspecialchars($resultCode, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?></strong>
        &nbsp;|&nbsp; Token: <code><?= htmlspecialchars($resultToken, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?></code>
      </div>
    </div>
  <?php else: ?>
    <div class="alert-err">
      Gagal: <?= htmlspecialchars($resultError, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>
    </div>
  <?php endif; ?>
<?php endif; ?>

  <form method="POST" action="">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">

    <div class="tabs">
      <button type="button" class="tab-btn active" data-tab="sub_id">Legacy sub_id</button>
      <button type="button" class="tab-btn" data-tab="fields">Fields manual</button>
      <button type="button" class="tab-btn" data-tab="url_mode">URL Langsung</button>
      <input type="hidden" name="mode" id="mode-input" value="sub_id">
    </div>

    <div class="section show" id="tab-sub_id">
      <div class="field">
        <label for="sub_id">sub_id (base64url token)</label>
        <textarea id="sub_id" name="sub_id" rows="3" maxlength="2048"
          placeholder="QXRzajgsU0lFTE9XLDE3NzU4OTc2MyxJTU9ORVRJWUVJVA"><?= htmlspecialchars((string) ($_POST['sub_id'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') ?></textarea>
      </div>
    </div>

    <div class="section" id="tab-fields">
      <div class="row">
        <div class="field">
          <label for="click_id">click_id *</label>
          <input type="text" id="click_id" name="click_id" maxlength="256"
            value="<?= htmlspecialchars((string) ($_POST['click_id'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
        </div>
        <div class="field">
          <label for="user_lp">user_lp *</label>
          <input type="text" id="user_lp" name="user_lp" maxlength="64"
            value="<?= htmlspecialchars((string) ($_POST['user_lp'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
        </div>
      </div>
      <div class="field">
        <label for="canonical_url">canonical_url</label>
        <input type="url" id="canonical_url" name="canonical_url" maxlength="2048"
          value="<?= htmlspecialchars((string) ($_POST['canonical_url'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
      </div>
      <div class="row">
        <div class="field">
          <label for="title">title</label>
          <input type="text" id="title" name="title" maxlength="512"
            value="<?= htmlspecialchars((string) ($_POST['title'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
        </div>
        <div class="field">
          <label for="lg">lg</label>
          <select id="lg" name="lg">
            <option value="">— pilih —</option>
            <option value="landing" <?= (($_POST['lg'] ?? '') === 'landing') ? 'selected' : '' ?>>landing</option>
            <option value="direct" <?= (($_POST['lg'] ?? '') === 'direct') ? 'selected' : '' ?>>direct</option>
          </select>
        </div>
      </div>
      <div class="field">
        <label for="image_url">image_url</label>
        <input type="url" id="image_url" name="image_url" maxlength="2048"
          value="<?= htmlspecialchars((string) ($_POST['image_url'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
      </div>
    </div>

    <div class="section" id="tab-url_mode">
      <div class="field">
        <label for="target_url">URL target (sub_id di path)</label>
        <input type="url" id="target_url" name="target_url" maxlength="2048"
          placeholder="https://example.com/s-QXRzajgs..."
          value="<?= htmlspecialchars((string) ($_POST['target_url'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
      </div>
    </div>

    <div id="optional-fields">
    <hr>

    <div class="row">
      <div class="field">
        <label for="code">code kustom (opsional)</label>
        <input type="text" id="code" name="code" maxlength="32" pattern="[A-Za-z0-9_\-]+"
          placeholder="slug-kustom"
          value="<?= htmlspecialchars((string) ($_POST['code'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
      </div>
      <div class="field">
        <label for="base_url">base_url (opsional)</label>
        <input type="url" id="base_url" name="base_url" maxlength="256"
          placeholder="https://domain.tld"
          value="<?= htmlspecialchars((string) ($_POST['base_url'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
      </div>
    </div>
    </div><!-- /#optional-fields -->

    <button type="submit" class="btn">Buat Short Link</button>
  </form>
</div>

<script nonce="<?= htmlspecialchars($nonce, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
(function () {
    var tabs = document.querySelectorAll('.tab-btn');
    var modeInput = document.getElementById('mode-input');
    var optFields = document.getElementById('optional-fields');

    function setOptional(tab) {
        if (optFields) { optFields.style.display = tab === 'url_mode' ? 'none' : ''; }
    }

    tabs.forEach(function (btn) {
        btn.addEventListener('click', function () {
            var tab = btn.getAttribute('data-tab');
            tabs.forEach(function (b) { b.classList.remove('active'); });
            btn.classList.add('active');
            document.querySelectorAll('.section').forEach(function (s) { s.classList.remove('show'); });
            var section = document.getElementById('tab-' + tab);
            if (section) { section.classList.add('show'); }
            if (modeInput) { modeInput.value = tab; }
            setOptional(tab);
        });
    });

    <?php if (($_POST['mode'] ?? 'sub_id') === 'fields'): ?>
    document.querySelector('[data-tab="fields"]').click();
    <?php elseif (($_POST['mode'] ?? 'sub_id') === 'url_mode'): ?>
    document.querySelector('[data-tab="url_mode"]').click();
    <?php endif; ?>
}());
</script>
</body>
</html>
<?php

// ── Fungsi helper ─────────────────────────────────────────────────────────────

/**
 * @param array<string, mixed> $body
 * @return array<string, mixed>
 */
function srp_web_call_api(string $apiUrl, string $apiKey, array $body): array
{
    $jsonBody = json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

    $ch = curl_init();
    assert($apiUrl !== '');
    curl_setopt_array($ch, [
        CURLOPT_URL            => $apiUrl,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $jsonBody,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_HTTPHEADER     => [
            'Content-Type: application/json',
            'Accept: application/json',
            'Authorization: Bearer ' . $apiKey,
        ],
        CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS | CURLPROTO_HTTP,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);

    $raw      = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr  = curl_error($ch);

    if ($raw === false || $curlErr !== '') {
        return ['ok' => false, 'error' => 'cURL error: ' . $curlErr];
    }

    try {
        $decoded = json_decode((string) $raw, true, 8, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        return ['ok' => false, 'error' => 'Response bukan JSON valid (HTTP ' . $httpCode . ')'];
    }

    if (!is_array($decoded)) {
        return ['ok' => false, 'error' => 'Response tidak terduga (HTTP ' . $httpCode . ')'];
    }

    /** @var array<string, mixed> $decoded */
    return $decoded;
}

/**
 * @return array<string, mixed>
 */
function srp_web_call_api_mode_b(string $apiUrl, string $apiKey, string $targetUrl): array
{
    $endpointUrl = $apiUrl . '?' . http_build_query(['key' => $apiKey, 'url' => $targetUrl]);

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $endpointUrl,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => '',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_HTTPHEADER     => [
            'Content-Length: 0',
            'Accept: application/json',
        ],
        CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS | CURLPROTO_HTTP,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);

    $raw      = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr  = curl_error($ch);

    if ($raw === false || $curlErr !== '') {
        return ['ok' => false, 'error' => 'cURL error: ' . $curlErr];
    }

    try {
        $decoded = json_decode((string) $raw, true, 8, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        return ['ok' => false, 'error' => 'Response bukan JSON valid (HTTP ' . $httpCode . ')'];
    }

    if (!is_array($decoded)) {
        return ['ok' => false, 'error' => 'Response tidak terduga (HTTP ' . $httpCode . ')'];
    }

    /** @var array<string, mixed> $decoded */
    return $decoded;
}

function srp_web_str(mixed $value): ?string
{
    if (!is_scalar($value)) {
        return null;
    }
    $value = trim((string) $value);
    return $value !== '' ? $value : null;
}

function srp_web_render_login(string $error): void
{
    $nonce = base64_encode(random_bytes(16));
    header("Content-Security-Policy: default-src 'none'; style-src 'nonce-{$nonce}'; form-action 'self'; frame-ancestors 'none';");
    ?><!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shorten Link — Login</title>
<style nonce="<?= htmlspecialchars($nonce, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: system-ui, sans-serif; background: #0f1117; color: #e2e8f0; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
.card { background: #1e2230; border: 1px solid #2d3348; border-radius: 10px; width: 100%; max-width: 340px; padding: 2rem; }
h1 { font-size: 1.1rem; font-weight: 700; margin-bottom: 1.25rem; color: #a78bfa; }
label { display: block; font-size: .8rem; color: #94a3b8; margin-bottom: .35rem; }
input[type=password] { width: 100%; background: #0f1117; border: 1px solid #2d3348; border-radius: 6px; color: #e2e8f0; font-size: .9rem; padding: .55rem .75rem; outline: none; }
input[type=password]:focus { border-color: #a78bfa; }
.btn { width: 100%; padding: .65rem 1rem; background: #7c3aed; border: none; border-radius: 6px; color: #fff; font-size: .95rem; font-weight: 600; cursor: pointer; margin-top: 1rem; }
.btn:hover { background: #6d28d9; }
.alert-err { background: #3b0f0f; border: 1px solid #7f1d1d; border-radius: 6px; padding: .65rem .9rem; margin-bottom: 1rem; color: #fca5a5; font-size: .875rem; }
</style>
</head>
<body>
<div class="card">
  <h1>&#128274; Shorten Link</h1>
  <?php if ($error !== ''): ?>
    <div class="alert-err"><?= htmlspecialchars($error, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?></div>
  <?php endif; ?>
  <form method="POST" action="">
    <div>
      <label for="web_password">Password (API Key)</label>
      <input type="password" id="web_password" name="web_password" autocomplete="current-password" required>
    </div>
    <button type="submit" class="btn">Masuk</button>
  </form>
</div>
</body>
</html>
<?php
}
