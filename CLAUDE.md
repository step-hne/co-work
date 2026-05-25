# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Language & Standards

- PHP 8.3 only. Every file must open with `declare(strict_types=1);`.
- PSR-12 code style.
- All DB queries must use prepared statements (PDO or mysqli).
- All state-changing requests must include CSRF validation.
- Output must be escaped per context: HTML → `htmlspecialchars(..., ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8')`, URL → `rawurlencode`, JS → `json_encode`.
- Exception handling: always catch `Throwable $e`, never catch bare `Exception` alone.
- Forbidden calls: `eval`, `exec`, `shell_exec`, `system`, `passthru`, `popen`, `proc_open`, `var_dump`, `print_r`, `die`, `dump`.
- Do not use `fn()` (arrow functions).
- CSS must be minified in any frontend output.

## Architecture

This is a PHP affiliate/performance-marketing platform ("Genv2") with **three independent modules** deployed as separate web roots, sharing one MySQL database.

### Module Map

| Directory | Domain | Web Root | Role | Entry Point |
|-----------|--------|----------|------|-------------|
| `public/` | `gen.pmbk.it.com` | `/pmbk.it.com/public` | Admin/tracker portal — manages trackers, campaigns, domains, shortlinks | `public/index.php` |
| `redirect/` | `r.pmbk.it.com` | `/pmbk.it.com/redirect` | SRP redirect engine — decodes payload, resolves geo/device, fires click, redirects visitor | `redirect/index.php` |
| `statistics/` | `s.pmbk.it.com` | `/pmbk.it.com/statistics` | Reporting dashboard — click performance, realtime view, postback conversions | `statistics/login.php` |

Repo root (`pmbk.it.com`) is served at the domain root and is not a public web root — it houses only shared utilities.

### Shared Root Utilities

These files live in the repo root and are `require_once`-d by all three modules:

- `env.php` — custom `.env` parser; exposes `load_env_file()`, `app_env()`, `app_required_env()`.
- `Base64URL.php` — URL-safe base64 encode/decode used to pass click payloads between modules.
- `ip_address.php` — client IP detection that handles Cloudflare and reverse proxies.
- `Mobile_Detect.php` — minimal UA-based device detection.

### Database (single shared MySQL DB — `schema.sql` is canonical)

| Table | Written by | Read by |
|-------|-----------|---------|
| `generate` | `public/` portal | `redirect/` (auth check), `statistics/` |
| `addondomain` | `public/api/` | `public/` portal |
| `offering` | `public/api/` | `redirect/_meetups/r.php` (offer selection) |
| `clickrecord` | `redirect/_meetups/index.php` (clicks), `statistics/postback/` (leads/payout) | `statistics/` dashboard |
| `leadreport` | `statistics/postback/index.php` | `statistics/` dashboard |
| `srp_short_links` | `redirect/api/shorten.php` | `redirect/public_link.php` |
| `shortlinks` | `public/shortlinks/response.php` | `redirect/public_link.php` (fallback) |

`sub_id` / `click_id` values are always stored **UPPERCASE**. `clickrecord` is created at runtime via `meetup_ensure_clickrecord_table()` if it doesn't exist.

### Token Format

The base64url-encoded `sub_id` token is a comma-separated string. CSV field positions (0-indexed):

| Index | Field |
|-------|-------|
| 0 | (unused / reserved) |
| 1 | `click_id` (stored UPPERCASE) |
| 2 | (unused / reserved) |
| 3 | `canonical_url` |
| 4 | `user_lp` (user landing page URL) |
| 5 | `title` (OG title) |
| 6 | `image_url` (OG image) |
| 7 | `lg` (landing mode: `'landing'` or `'1'`) |

Short links use the path prefix `s-<code>` to distinguish them from full tokens. Resolution order: `srp_short_links` → fallback to legacy `shortlinks` table.

### Data Flow

1. **Click generation** — `public/index.php` generates a base64url-encoded token (CSV format above). This token becomes the `sub_id` URL path on the redirect domain.
2. **Redirect** — `redirect/index.php` runs in this order: social-bot check (serves OG HTML, no redirect) → geo detection (Cloudflare header, then MaxMind MMDB cached 24 h in `{tmp}/srp_bb/geo_{md5_ip}.json`) → geo-block → VPN/proxy check (Tor via CF header, proxy headers, then `blackbox.ipinfo.app` cached 1 h) → timed filter → device detection → 302 to `redirect/_meetups/index.php?rk=<encoded_payload>` (`SRP_TARGET_BASE`).
3. **Bot OG response** — if a known social crawler UA is detected (FacebookExternalHit, Twitterbot, WhatsApp, Telegram, Slack, Discord, etc.), `redirect/index.php` renders OG meta tags inline and exits. `og:image` is proxied through the same-origin `/imgp` endpoint so scrapers can always fetch the image.
4. **Landing page mode** — when `lg='landing'` or `lg='1'`, the redirect renders an inline HTML page with a JS redirect, CSP nonce, and a dark-overlay call-to-action instead of issuing a bare 302.
5. **Click recording** — `redirect/_meetups/index.php` upserts a row in `clickrecord` (PDO), then redirects visitor to the offer URL via `redirect/_meetups/r.php`. Offer selection picks a random ID within the country/network's configured min–max range (anti-harvesting).
6. **Postback** — affiliate network fires `statistics/postback/index.php?click_id=<payload>&payout=<n>&token=<HMAC>`. Handler validates HMAC, then in a single transaction inserts into `leadreport` and updates `clickrecord.leads`/`payout`.
7. **Short links** — two independent systems: legacy (`shortlinks` table, managed via `public/shortlinks/response.php`, served via `public/s.php`); current (`srp_short_links` table, created via `redirect/api/shorten.php` Bearer-auth API, resolved in `redirect/public_link.php`).

### Connection Patterns (differ per module)

- `public/` — uses `dbObj` class (`connection.php`) which wraps `mysqli_connect`; older files use `connection.config.php` which exposes a bare `$link` (mysqli).
- `redirect/` — `connection.config.php` returns a **PDO** instance (not mysqli). Files use `/** @var PDO $pdo */ $pdo = require __DIR__ . '/connection.config.php';`.
- `statistics/` — hardened `connection.config.php` exposes `$link` (mysqli) with retry logic, socket support, and `DB_PERSISTENT` flag.

### Timed Filter (redirect only)

`redirect/index.php` implements a 5-minute cycle: 120 s "filter window" → 180 s "normal". During the filter window, mobile non-tablet visitors without a VPN are sent to `SRP_FILTER_URL` instead of the offer. The active filter URL can be overridden at runtime by writing to `{sys_get_temp_dir()}/srp_bb/filter_url.txt`. GeoIP lookups are cached in the same directory as `geo_{md5(ip)}.json` (24 h TTL); VPN lookups as `vpn_{md5(ip)}.json` (1 h TTL).

### Schema Gotchas

- `clickrecord.leads` and `clickrecord.payout` are stored as **TEXT**, not numeric types — arithmetic in queries must cast explicitly.
- `shortlinks.created_at` is a Unix timestamp (INT), not a `TIMESTAMP` column.
- `clickrecord` does not exist in `schema.sql`; it is created at runtime by `meetup_ensure_clickrecord_table()` in `redirect/_meetups/index.php`.

### Cloudflare Integration (`public/` only)

`public/api/cf.sync.php` and `public/api/user.cf.config.php` provision DNS records and store per-tracker `cf_token` / `cf_account_id` in the `generate` table. The `addondomain` table stores `cf_zone_id`, `cf_status`, `cf_ns`. Bypass header `X-Bypass-Key` is compared against `IXG_BYPASS_KEY` env var.

### Vendor (redirect only)

`redirect/vendor/` contains MaxMind GeoIP2 installed via Composer. No other module has a `vendor/` or Composer setup.

## Setup

Each module is configured independently via its own `.env` file copied from `.env.example`:

```
cp public/.env.example public/.env
cp redirect/.env.example redirect/.env
cp statistics/.env.example statistics/.env
```

Apply the database schema once against the shared database:

```
mysql -u <user> -p <dbname> < schema.sql
```

`redirect/databases/GeoLite2-Country.mmdb` must be present (MaxMind free download, requires account). The path is the constant `SRP_GEOIP2LITE_DB` in `redirect/index.php`.

## Linting & Static Analysis

No automated test suite is configured. Composer and linting tools are only present in `redirect/` (the only module with a `vendor/`). Run from that directory:

```bash
# Code style check (dry run)
redirect/vendor/bin/php-cs-fixer fix --dry-run --diff

# Static analysis (level 8)
redirect/vendor/bin/phpstan analyse --level=8

# PSR-12 compliance
redirect/vendor/bin/phpcs --standard=PSR12

# Auto-fix code style
redirect/vendor/bin/php-cs-fixer fix
```

Update the GeoIP database (requires `MAXMIND_LICENSE_KEY` in `redirect/.env`):

```bash
cd redirect && php update_geoip.php
```

## Review Format

When reviewing code, start findings with:
`[Severity][Area][Impact][Fix]`

Review focus: SQL injection, XSS, CSRF, auth/authorization, session/cookie, upload handling, security headers, CSP nonce, ENV/secrets exposure, logging sensitive data, raw queries, dangerous calls, production bugs, edge cases.

## Workflow

Review/Triage → Reproduce + Baseline → Root Cause Analysis → Implement Fix → Targeted Verification → Refactor → Regression Verification → Optimize → Security/Hardening → Cleanup → Production Build → Smoke Test
