<?php

declare(strict_types=1);

error_reporting(0);

include_once __DIR__ . '/../password.login.php';

const ADMIN_CSRF_NAMESPACE = 'admin_panel';

function adminIsHttpsRequest(): bool
{
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') { return true; }
    return (int) ($_SERVER['SERVER_PORT'] ?? 0) === 443;
}

function startAdminSession(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) { return; }
    session_name('sslmgr_admin');
    session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => adminIsHttpsRequest(), 'httponly' => true, 'samesite' => 'Strict']);
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

function showLoginPasswordProtect(string $errorMsg, string $nonce, string $csrfToken): never
{
    header('Location: /login.php');
    exit;
}

startAdminSession();

$nonce     = base64_encode(random_bytes(18));
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
    . "base-uri 'self'; form-action 'self'; frame-ancestors 'self'; "
    . "img-src 'self' data: https:; font-src 'self' data: https:; "
    . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    . "script-src 'self' 'nonce-{$nonce}'; connect-src 'self';"
);

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
<title>Shortlinks — Admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="csrf-token" content="<?= adminEsc($csrfToken); ?>">
<link href="/favicon.ico" rel="icon" type="image/x-icon">
<link rel="stylesheet" href="../dist/bootstrap.min.css" type="text/css" media="all">
<link href="//fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style nonce="<?= adminEsc($nonce); ?>">
:root{color-scheme:light;--bg:#f7f7f7;--panel:#fff;--panel-soft:#f7f7f7;--panel-fade:rgba(255,255,255,.66);--line:rgba(41,43,44,.18);--line-soft:rgba(41,43,44,.1);--text:#292b2c;--text-strong:#111;--accent:#292b2c;--accent-hover:#3a3d3f;--on-accent:#f7f7f7;--danger:#9f3138;--danger-soft:rgba(159,49,56,.08);--blue-soft:rgba(37,99,235,.08);--blue-line:rgba(37,99,235,.28);--radius:.3rem;--shadow:0 1px 4px rgba(41,43,44,.08);--shadow-modal:0 8px 24px rgba(41,43,44,.16)}
@media(prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#292b2c;--panel:#303334;--panel-soft:#35393a;--panel-fade:rgba(247,247,247,.045);--line:rgba(247,247,247,.18);--line-soft:rgba(247,247,247,.1);--text:#f7f7f7;--text-strong:#fff;--accent:#f7f7f7;--accent-hover:#e7e7e7;--on-accent:#292b2c;--danger:#ef9a9a;--danger-soft:rgba(239,154,154,.11);--blue-soft:rgba(147,197,253,.1);--blue-line:rgba(147,197,253,.34);--shadow:0 1px 5px rgba(0,0,0,.28);--shadow-modal:0 10px 28px rgba(0,0,0,.42)}}
*{box-sizing:border-box}html{min-height:100%;background:var(--bg)}body{min-height:100vh;margin:0;padding:58px 8px 18px!important;background:linear-gradient(180deg,var(--panel-soft) 0%,var(--bg) 100%)!important;color:var(--text)!important;font-family:monospace!important;font-size:13px;line-height:1.45;-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration:none}.container{width:100%;max-width:1280px;margin:0 auto}
.navbar.navbar-default{min-height:44px;border:0!important;border-bottom:0!important;background:color-mix(in srgb,var(--panel) 94%,transparent)!important;box-shadow:var(--shadow)!important}.navbar .container{max-width:1280px}.navbar-brand{height:44px!important;padding:12px 10px!important;color:var(--text-strong)!important;font-size:13px;line-height:20px}.navbar-nav>li>a{padding-top:12px!important;padding-bottom:12px!important;color:var(--text)!important;font-size:12px}.navbar-default .navbar-nav>li>a:hover,.navbar-default .navbar-nav>li>a:focus{box-shadow:inset 0 -1px 0 var(--line)!important;background:transparent!important;color:var(--text-strong)!important}.navbar-default .navbar-nav>.active>a,.navbar-default .navbar-nav>.active>a:hover,.navbar-default .navbar-nav>.active>a:focus{background:transparent!important;color:var(--text-strong)!important;box-shadow:inset 0 -2px 0 var(--accent)!important}.navbar-toggle{margin-top:5px!important;margin-bottom:5px!important;border-color:var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important}.navbar-toggle .icon-bar{background:var(--text)!important}.navbar-collapse{border-color:var(--line)!important;background:var(--panel)!important}
.panel,.panel-default{border:0!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;box-shadow:var(--shadow)!important;overflow:visible!important}.panel-body{padding:0!important;background:transparent!important;overflow:visible!important}
.btn,button{display:inline-flex;align-items:center;justify-content:center;gap:5px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-size:11.5px;font-weight:700;line-height:1.2;box-shadow:none!important;outline:none;transition:background .12s,border-color .12s,color .12s}.btn:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}.btn-primary,.btn-primary:focus,.btn-primary:active{background:var(--accent)!important;border-color:var(--accent)!important;color:var(--on-accent)!important}.btn-primary:hover{background:var(--accent-hover)!important;border-color:var(--accent-hover)!important;color:var(--on-accent)!important}.btn-danger,.btn-danger:focus{background:var(--danger-soft)!important;border-color:rgba(159,49,56,.34)!important;color:var(--danger)!important}.btn-danger:hover{background:rgba(159,49,56,.16)!important}
.form-control,input,select{height:31px;min-height:31px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-family:monospace!important;font-size:12px!important;box-shadow:none!important}.form-control:focus,input:focus,select:focus{outline:none;border-color:var(--accent)!important}.input-group-addon{height:31px;padding:5px 8px;background:var(--panel-soft)!important;border-color:var(--line)!important;color:var(--text)!important;border-radius:var(--radius)!important;font-size:11.5px}
.table{width:100%;border-collapse:collapse;font-size:12.5px;margin:0!important;border:0!important;border-radius:0!important;background:transparent!important}.table>thead>tr>th{height:34px;padding:0 10px!important;text-align:left;font-size:11px;font-weight:600;color:var(--text-strong);text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--line)!important;border-top:0!important;background:var(--panel-soft)!important;white-space:nowrap;position:static}.table>tbody>tr>td{padding:7px 10px!important;vertical-align:middle;border-bottom:1px solid var(--line-soft)!important;border-top:0!important;font-size:12.5px;color:var(--text)!important;background:transparent!important}.table>tbody>tr:last-child>td{border-bottom:0!important}.table-hover>tbody>tr:hover>td{background:var(--panel-soft)!important}
.tbl-toolbar{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 12px;flex-wrap:wrap;border-bottom:1px solid var(--line)}.tbl-toolbar-left{display:flex;align-items:center;gap:6px}.tbl-footer{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 12px;border-top:1px solid var(--line);font-size:12px;color:var(--text);flex-wrap:wrap}
.pagination>li>a,.pagination>li>span{border-color:var(--line)!important;background:var(--panel)!important;color:var(--text)!important}.pagination>.active>a,.pagination>.active>span{background:var(--accent)!important;border-color:var(--accent)!important;color:var(--on-accent)!important}.pagination{margin:0!important}
.admin-toast-root{position:fixed;right:12px;bottom:12px;z-index:10050;display:flex;flex-direction:column;gap:6px;align-items:flex-end}.admin-toast{max-width:340px;padding:8px 10px;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:12px;line-height:1.35}.admin-toast strong{display:block;margin-bottom:2px;color:var(--text-strong)}.admin-toast--error{border-color:rgba(159,49,56,.34);background:var(--danger-soft);color:var(--danger)}.admin-toast--success{border-color:var(--blue-line);background:var(--blue-soft)}
.admin-fallback-backdrop{position:fixed;inset:0;z-index:10040;display:flex;align-items:center;justify-content:center;padding:12px;background:rgba(0,0,0,.36)}.admin-fallback-dialog{width:min(400px,100%);border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);overflow:hidden}.admin-fallback-head{padding:10px;border-bottom:1px solid var(--line-soft);font-weight:800;color:var(--text-strong)}.admin-fallback-body{padding:10px;font-size:12px}.admin-fallback-actions{display:flex;gap:6px;justify-content:flex-end;padding:10px;border-top:1px solid var(--line-soft);background:var(--panel-soft)}
.sl-code{font-family:monospace;font-size:11.5px;font-weight:700;letter-spacing:.03em;display:inline-block;padding:2px 7px;background:var(--panel-soft);border:1px solid var(--line);border-radius:var(--radius)}.sl-short{font-family:monospace;font-size:11.5px;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block}.sl-long{font-family:monospace;font-size:11px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block;color:color-mix(in srgb,var(--text) 64%,transparent)}.sl-title{font-size:12px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block}.sl-date{font-size:11px;white-space:nowrap;color:color-mix(in srgb,var(--text) 62%,transparent)}.sl-actions{display:flex;align-items:center;gap:4px;justify-content:flex-end;white-space:nowrap}
.action-btn{display:inline-flex;align-items:center;justify-content:center;width:28px;height:26px;padding:0;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important}.action-btn:hover{background:var(--panel-soft)!important}.action-btn.btn-del{color:var(--danger)!important}.action-btn.btn-del:hover{background:var(--danger-soft)!important;border-color:rgba(159,49,56,.34)!important}.action-btn svg{display:block;width:14px;height:14px;pointer-events:none}
#tbl-shortlinks{table-layout:fixed;width:100%;min-width:820px}#tbl-shortlinks th:nth-child(1),#tbl-shortlinks td:nth-child(1){width:44px;text-align:center}#tbl-shortlinks th:nth-child(2),#tbl-shortlinks td:nth-child(2){width:100px}#tbl-shortlinks th:nth-child(3),#tbl-shortlinks td:nth-child(3){width:260px}#tbl-shortlinks th:nth-child(4),#tbl-shortlinks td:nth-child(4){width:190px}#tbl-shortlinks th:nth-child(5),#tbl-shortlinks td:nth-child(5){width:270px}#tbl-shortlinks th:nth-child(6),#tbl-shortlinks td:nth-child(6){width:110px}#tbl-shortlinks th:nth-child(7),#tbl-shortlinks td:nth-child(7){width:90px;text-align:right}
.td-num{display:block;font-size:11px;font-weight:600;font-family:monospace;color:color-mix(in srgb,var(--text) 44%,transparent);text-align:center}
#logout-toast{position:fixed;bottom:20px;right:20px;background:rgba(41,43,44,.88);color:#fff;padding:7px 15px;border-radius:6px;font-size:12px;font-weight:600;z-index:99999;opacity:0;pointer-events:none;transition:opacity .2s;box-shadow:0 2px 8px rgba(0,0,0,.22)}#logout-toast.show{opacity:1}
@media(max-width:768px){body{padding:58px 6px 12px!important}.container{width:100%!important;max-width:100%!important;padding:0 6px!important}.navbar .container{padding:0 8px!important}.tbl-toolbar{flex-wrap:wrap}.tbl-toolbar-left{flex:1 0 100%}.table{display:block;overflow-x:auto}}
*:focus,*:focus-visible{outline:none!important;box-shadow:none!important}
</style>
</head>
<body>
<script nonce="<?= adminEsc($nonce); ?>" src="../dist/jquery-1.11.1.min.js"></script>
<script nonce="<?= adminEsc($nonce); ?>" src="../dist/bootstrap.min.js"></script>
<script nonce="<?= adminEsc($nonce); ?>">
(function($){ 'use strict'; $.ajaxSetup({ headers: { 'X-CSRF-Token': <?= json_encode($csrfToken, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?> } }); }(jQuery));
</script>
<script nonce="<?= adminEsc($nonce); ?>">
(function(w,d){
'use strict';
function ensureToastRoot(){var r=d.querySelector('.admin-toast-root');if(r)return r;r=d.createElement('div');r.className='admin-toast-root';r.setAttribute('aria-live','polite');d.body.appendChild(r);return r;}
function showToast(type,title,text){var r=ensureToastRoot();var el=d.createElement('div');el.className='admin-toast admin-toast--'+(type==='error'?'error':type==='success'?'success':'info');if(title){var s=d.createElement('strong');s.textContent=title;el.appendChild(s);}if(text){var sp=d.createElement('span');sp.textContent=text;el.appendChild(sp);}r.appendChild(el);w.setTimeout(function(){if(el.parentNode)el.parentNode.removeChild(el);},2400);}
function confirmDialog(opts){return new Promise(function(resolve){var bd=d.createElement('div');bd.className='admin-fallback-backdrop';var dl=d.createElement('div');dl.className='admin-fallback-dialog';var hd=d.createElement('div');hd.className='admin-fallback-head';hd.textContent=opts.title||'Confirm';var bo=d.createElement('div');bo.className='admin-fallback-body';bo.textContent=opts.text||'';var ac=d.createElement('div');ac.className='admin-fallback-actions';var cn=d.createElement('button');cn.className='btn btn-xs';cn.textContent='Cancel';var ok=d.createElement('button');ok.className='btn btn-xs btn-danger';ok.textContent=opts.confirmText||'Delete';cn.onclick=function(){if(bd.parentNode)bd.parentNode.removeChild(bd);resolve(false);};ok.onclick=function(){if(bd.parentNode)bd.parentNode.removeChild(bd);resolve(true);};ac.appendChild(cn);ac.appendChild(ok);dl.appendChild(hd);dl.appendChild(bo);dl.appendChild(ac);bd.appendChild(dl);d.body.appendChild(bd);});}
w._adminUI={showToast:showToast,confirmDialog:confirmDialog};
}(window,document));
</script>

<div role="navigation" class="navbar navbar-default navbar-fixed-top">
    <div class="container">
        <div class="navbar-header">
            <button data-target=".navbar-collapse" data-toggle="collapse" class="navbar-toggle" type="button">
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span><span class="icon-bar"></span><span class="icon-bar"></span>
            </button>
            <a href="#" class="navbar-brand"><strong>Admin Panel</strong></a>
        </div>
        <div class="navbar-collapse collapse navbar-right">
            <ul class="nav navbar-nav">
                <li><a href="/dashboard/"><strong>Dashboard</strong></a></li>
                <li><a href="/campaigns/"><strong>Campaigns</strong></a></li>
                <li><a href="/addondomain/"><strong>Addon Domain</strong></a></li>
                <li class="active"><a href="#"><strong>Shortlinks</strong></a></li>
                <li><a href="?logout" id="btn-logout" class="btn-danger"><strong>Logout</strong></a></li>
            </ul>
        </div>
    </div>
</div>

<div class="container">
    <div class="panel panel-default">
        <div class="tbl-toolbar">
            <div class="tbl-toolbar-left">
                <div class="input-group" style="width:200px;">
                    <span class="input-group-addon"><span class="glyphicon glyphicon-search"></span></span>
                    <input type="text" class="form-control" id="tbl-search" placeholder="Search code / title / URL…">
                </div>
                <select id="tbl-rowcount" class="form-control" style="width:70px;height:31px;display:inline-block;">
                    <option value="25">25</option>
                    <option value="50">50</option>
                    <option value="100">100</option>
                    <option value="-1">All</option>
                </select>
            </div>
            <span id="tbl-total-badge" style="font-size:11.5px;color:var(--text);"></span>
        </div>
        <div style="overflow-x:auto;">
            <table id="tbl-shortlinks" class="table table-hover">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Code</th>
                        <th>Short URL</th>
                        <th>OG Title</th>
                        <th>Long URL</th>
                        <th>Created</th>
                        <th style="text-align:right;">Action</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
        <div class="tbl-footer">
            <span id="tbl-info" style="font-size:12px;"></span>
            <ul class="pagination" id="tbl-pagination"></ul>
        </div>
    </div>
</div>

<div id="logout-toast">Logging out…</div>

<script nonce="<?= adminEsc($nonce); ?>">
$(document).ready(function() {
    'use strict';

    var SVG_COPY   = '<svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
    var SVG_DELETE = '<svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M6 7l1 13h10l1-13"/><path d="M9 7V4h6v3"/></svg>';
    var SVG_OPEN   = '<svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>';

    function escHtml(v) {
        return String(v == null ? '' : v)
            .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    var state = { current: 1, rowCount: 25, search: '', rows: [] };

    function renderRow(row, idx) {
        var shortEsc = escHtml(row.short_url);
        var longEsc  = escHtml(row.long_url);
        var titleEsc = escHtml(row.og_title);
        var codeEsc  = escHtml(row.code);
        return '<tr>' +
            '<td><span class="td-num">' + ((state.current - 1) * (state.rowCount === -1 ? 0 : state.rowCount) + idx + 1) + '</span></td>' +
            '<td><span class="sl-code">' + codeEsc + '</span></td>' +
            '<td><span class="sl-short" title="' + shortEsc + '">' + shortEsc + '</span></td>' +
            '<td><span class="sl-title" title="' + titleEsc + '">' + (titleEsc || '<span style="opacity:.4">—</span>') + '</span></td>' +
            '<td><span class="sl-long" title="' + longEsc + '">' + longEsc + '</span></td>' +
            '<td><span class="sl-date">' + escHtml(row.created_at) + '</span></td>' +
            '<td>' +
                '<div class="sl-actions">' +
                    '<button type="button" class="action-btn btn-copy" title="Copy short URL" data-url="' + shortEsc + '">' + SVG_COPY + '</button>' +
                    '<a href="' + shortEsc + '" target="_blank" rel="noopener noreferrer" class="action-btn" title="Open">' + SVG_OPEN + '</a>' +
                    '<button type="button" class="action-btn btn-del" title="Delete" data-code="' + codeEsc + '">' + SVG_DELETE + '</button>' +
                '</div>' +
            '</td></tr>';
    }

    function renderPagination(total, current, rowCount) {
        var $pg = $('#tbl-pagination');
        if (rowCount === -1 || total === 0) { $pg.empty(); return; }
        var pages = Math.ceil(total / rowCount);
        if (pages <= 1) { $pg.empty(); return; }
        var html = '', start = Math.max(1, current - 2), end = Math.min(pages, current + 2);
        html += '<li class="' + (current <= 1 ? 'disabled' : '') + '"><a href="#" data-page="' + (current - 1) + '">&laquo;</a></li>';
        if (start > 1) { html += '<li><a href="#" data-page="1">1</a></li>' + (start > 2 ? '<li class="disabled"><span>…</span></li>' : ''); }
        for (var p = start; p <= end; p++) {
            html += '<li class="' + (p === current ? 'active' : '') + '"><a href="#" data-page="' + p + '">' + p + '</a></li>';
        }
        if (end < pages) { html += (end < pages - 1 ? '<li class="disabled"><span>…</span></li>' : '') + '<li><a href="#" data-page="' + pages + '">' + pages + '</a></li>'; }
        html += '<li class="' + (current >= pages ? 'disabled' : '') + '"><a href="#" data-page="' + (current + 1) + '">&raquo;</a></li>';
        $pg.html(html).off('click','a').on('click','a',function(e){
            e.preventDefault();
            var pg = parseInt($(this).data('page'));
            if (!isNaN(pg) && pg >= 1 && pg <= pages && pg !== state.current) {
                state.current = pg; loadData();
            }
        });
    }

    function bindRowActions() {
        var $tbody = $('#tbl-shortlinks tbody');

        $tbody.find('.btn-copy').off('click').on('click', function() {
            var url = $(this).data('url');
            if (!url) return;
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(url).then(function() {
                    window._adminUI.showToast('success', 'Copied', url);
                }).catch(function() {
                    fallbackCopy(url);
                });
            } else {
                fallbackCopy(url);
            }
        });

        $tbody.find('.btn-del').off('click').on('click', function() {
            var code = $(this).data('code');
            window._adminUI.confirmDialog({
                title: 'Delete shortlink?',
                text: 'Code: ' + code + ' — this cannot be undone.',
                confirmText: 'Delete'
            }).then(function(confirmed) {
                if (!confirmed) return;
                $.ajax({
                    type: 'POST', url: 'response.php',
                    data: { action: 'delete', code: code },
                    dataType: 'json',
                    success: function(res) {
                        if (res && res.ok) {
                            window._adminUI.showToast('success', 'Deleted', 'Code ' + code + ' removed.');
                            loadData();
                        } else {
                            window._adminUI.showToast('error', 'Error', 'Delete failed.');
                        }
                    },
                    error: function() {
                        window._adminUI.showToast('error', 'Error', 'Request failed.');
                    }
                });
            });
        });
    }

    function fallbackCopy(text) {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px;opacity:0';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); window._adminUI.showToast('success', 'Copied', text); }
        catch(e) { window._adminUI.showToast('error', 'Copy failed', ''); }
        document.body.removeChild(ta);
    }

    function loadData() {
        $.ajax({
            type: 'POST', url: 'response.php',
            data: { current: state.current, rowCount: state.rowCount, searchPhrase: state.search },
            dataType: 'json',
            success: function(data) {
                state.rows = data.rows || [];
                var total  = data.total || 0;
                var html   = '';
                for (var i = 0; i < state.rows.length; i++) { html += renderRow(state.rows[i], i); }
                $('#tbl-shortlinks tbody').html(html || '<tr><td colspan="7" style="text-align:center;padding:20px;color:var(--text);opacity:.6;">No shortlinks found.</td></tr>');
                var from = total === 0 ? 0 : ((state.current - 1) * (state.rowCount === -1 ? total : state.rowCount)) + 1;
                var to   = state.rowCount === -1 ? total : Math.min(state.current * state.rowCount, total);
                $('#tbl-info').text('Showing ' + from + '–' + to + ' of ' + total);
                $('#tbl-total-badge').text(total + ' total');
                renderPagination(total, state.current, state.rowCount);
                bindRowActions();
            },
            error: function() {
                window._adminUI.showToast('error', 'Load failed', 'Could not fetch data.');
            }
        });
    }

    var searchTimer;
    $('#tbl-search').on('input', function() {
        clearTimeout(searchTimer);
        var val = $(this).val();
        searchTimer = setTimeout(function() { state.search = val; state.current = 1; loadData(); }, 280);
    });
    $('#tbl-rowcount').on('change', function() {
        state.rowCount = parseInt(this.value) || 25; state.current = 1; loadData();
    });

    document.getElementById('btn-logout').addEventListener('click', function(e) {
        e.preventDefault();
        var href = this.getAttribute('href');
        document.getElementById('logout-toast').classList.add('show');
        setTimeout(function(){ window.location.href = href; }, 900);
    });

    loadData();
});
</script>
</body>
</html>
