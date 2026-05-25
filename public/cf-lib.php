<?php

declare(strict_types=1);

/**
 * Shared Cloudflare API library.
 * Included by addondomain/cf.php (admin) and api/cf.sync.php (user portal).
 * Every function accepts an optional $token — if empty, falls back to CF_API_TOKEN env.
 *
 * Public entry point for zone provisioning:
 *   cfApplyAllRecommended($zoneId, $token)
 */

function cfResolveToken(string $token = ''): string
{
    return $token !== '' ? $token : app_required_env('CF_API_TOKEN');
}

/**
 * Make a Cloudflare API v4 call.
 */
function cfApi(string $method, string $path, ?array $body = null, string $token = ''): array
{
    $url = 'https://api.cloudflare.com/client/v4' . $path;
    $ch  = curl_init($url);

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT        => 20,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HTTPHEADER     => [
            'Authorization: Bearer ' . cfResolveToken($token),
            'Content-Type: application/json',
        ],
        CURLOPT_CUSTOMREQUEST  => strtoupper($method),
    ]);

    if ($body !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
    }

    $raw   = curl_exec($ch);
    $errno = curl_errno($ch);
    curl_close($ch);

    if ($errno !== 0 || $raw === false) {
        throw new RuntimeException('CF API transport error: ' . curl_strerror($errno));
    }

    $data = json_decode($raw, true);
    if (!is_array($data)) {
        throw new RuntimeException('CF API returned non-JSON response.');
    }

    return $data;
}

// ---------------------------------------------------------------------------
// Zone settings (PATCH /zones/{id}/settings/*)
// ---------------------------------------------------------------------------

function cfApplySettings(string $zoneId, string $token = ''): void
{
    $settings = [
        // ── SSL / TLS ────────────────────────────────────────────────────
        'ssl'                      => ['value' => 'full'],
        'always_use_https'         => ['value' => 'on'],
        'automatic_https_rewrites' => ['value' => 'on'],
        'min_tls_version'          => ['value' => '1.2'],
        'tls_1_3'                  => ['value' => 'on'],
        'opportunistic_encryption' => ['value' => 'on'],

        // ── Security ─────────────────────────────────────────────────────
        'security_level'           => ['value' => 'medium'],
        'bot_fight_mode'           => ['value' => 'on'],
        'browser_check'            => ['value' => 'on'],
        'challenge_ttl'            => ['value' => 1800],
        'privacy_pass'             => ['value' => 'on'],
        'email_obfuscation'        => ['value' => 'on'],
        'hotlink_protection'       => ['value' => 'off'], // dikelola via Configuration Rule
        'server_side_exclude'      => ['value' => 'on'],

        // ── Network ──────────────────────────────────────────────────────
        'http2'                    => ['value' => 'on'],
        'http3'                    => ['value' => 'on'],
        '0rtt'                     => ['value' => 'on'],
        'ipv6'                     => ['value' => 'on'],
        'websockets'               => ['value' => 'on'],
        'grpc'                     => ['value' => 'on'],
        'opportunistic_onion'      => ['value' => 'on'],
        'pseudo_ipv4'              => ['value' => 'add_header'],
        'ip_geolocation'           => ['value' => 'on'],

        // ── Performance / Speed ──────────────────────────────────────────
        'brotli'                   => ['value' => 'on'],
        'early_hints'              => ['value' => 'on'],
        'h2_prioritization'        => ['value' => 'on'],
        'rocket_loader'            => ['value' => 'off'],
        'prefetch_preload'         => ['value' => 'on'],
        'fonts'                    => ['value' => 'on'],
        'minify'                   => ['value' => ['css' => 'on', 'html' => 'on', 'js' => 'on']],
        'polish'                   => ['value' => 'lossless'],
        'mirage'                   => ['value' => 'on'],

        // ── Caching ──────────────────────────────────────────────────────
        'browser_cache_ttl'        => ['value' => 14400],
        'cache_level'              => ['value' => 'aggressive'],
        'always_online'            => ['value' => 'on'],
        'crawler_hints'            => ['value' => 'on'],

        // ── Image / Speed ─────────────────────────────────────────────────
        'image_resizing'           => ['value' => 'on'],
        'speed_brain'              => ['value' => 'on'],
    ];

    foreach ($settings as $key => $body) {
        try {
            cfApi('PATCH', '/zones/' . $zoneId . '/settings/' . $key, $body, $token);
        } catch (Throwable $e) {
            // best-effort — some require higher plan tier
        }
    }
}

/**
 * Enable HSTS with max-age 1 year, includeSubDomains, preload, nosniff.
 */
function cfApplyHsts(string $zoneId, string $token = ''): void
{
    try {
        cfApi('PATCH', '/zones/' . $zoneId . '/settings/security_header', [
            'value' => [
                'strict_transport_security' => [
                    'enabled'            => true,
                    'max_age'            => 31536000,
                    'include_subdomains' => true,
                    'preload'            => true,
                    'nosniff'            => true,
                ],
            ],
        ], $token);
    } catch (Throwable $e) {
        // best-effort
    }
}

// ---------------------------------------------------------------------------
// HTTP Response Headers Transform (Ruleset API)
// ---------------------------------------------------------------------------

function cfApplyHeaderRules(string $zoneId, string $token = ''): void
{
    $rules = [[
        'action'            => 'rewrite',
        'action_parameters' => [
            'headers' => [
                'X-Powered-By'           => ['operation' => 'remove'],
                'Server'                 => ['operation' => 'remove'],
                'X-AspNet-Version'       => ['operation' => 'remove'],
                'X-AspNetMvc-Version'    => ['operation' => 'remove'],
                'X-Content-Type-Options' => ['operation' => 'set', 'value' => 'nosniff'],
                'X-Frame-Options'        => ['operation' => 'set', 'value' => 'SAMEORIGIN'],
                'X-XSS-Protection'       => ['operation' => 'set', 'value' => '1; mode=block'],
                'Referrer-Policy'        => ['operation' => 'set', 'value' => 'strict-origin-when-cross-origin'],
                'Permissions-Policy'     => ['operation' => 'set', 'value' => 'geolocation=(), microphone=(), camera=(), payment=()'],
            ],
        ],
        'expression'  => 'true',
        'description' => 'Auto security headers',
        'enabled'     => true,
    ]];

    try {
        cfApi(
            'PUT',
            '/zones/' . $zoneId . '/rulesets/phases/http_response_headers_transform/entrypoints',
            ['rules' => $rules],
            $token
        );
    } catch (Throwable $e) {
        // best-effort
    }
}

// ---------------------------------------------------------------------------
// Feature-specific endpoints (non-settings paths)
// ---------------------------------------------------------------------------

/**
 * Enable Page Shield — client-side script monitoring and security.
 */
function cfEnableClientSideSecurity(string $zoneId, string $token = ''): void
{
    try {
        cfApi('PUT', '/zones/' . $zoneId . '/page_shield', [
            'enabled'                           => true,
            'use_cloudflare_reporting_endpoint' => true,
            'use_connection_url_path'           => true,
        ], $token);
    } catch (Throwable $e) {
        // best-effort
    }
}

/**
 * Enable leaked credentials detection.
 */
function cfEnableLeakedCredentials(string $zoneId, string $token = ''): void
{
    try {
        cfApi('PATCH', '/zones/' . $zoneId . '/leaked-credential-checks', ['enabled' => true], $token);
    } catch (Throwable $e) {
        // best-effort
    }
}

/**
 * Allow Facebook's crawler (facebookexternalhit / Facebot) to bypass
 * Bot Fight Mode — otherwise CF returns 403 to the OG scraper.
 */
function cfAllowFacebookCrawler(string $zoneId, string $token = ''): void
{
    $rules = [[
        'action'      => 'skip',
        'action_parameters' => [
            // Required: bypass Security Level challenge
            'products' => ['securityLevel'],
            // Optional: also bypass WAF Managed Rules + Super Bot Fight Mode
            // CF silently ignores phases not available on current plan
            'phases'   => ['http_request_firewall_managed', 'http_request_sbfm'],
        ],
        'expression'  => '(http.user_agent contains "facebookexternalhit") or (http.user_agent contains "Facebot") or (ip.src.asnum in {32934 63293} and (http.request.uri.path starts_with "/s-"))',
        'description' => 'Allow Facebook OG scraper (UA) + ASN skip on /s-*',
        'enabled'     => true,
        'logging'     => ['enabled' => false],
    ]];

    try {
        cfApi(
            'PUT',
            '/zones/' . $zoneId . '/rulesets/phases/http_request_firewall_custom/entrypoints',
            ['rules' => $rules],
            $token
        );
    } catch (Throwable $e) {
        // best-effort
    }
}

// ---------------------------------------------------------------------------
// DNS provisioning
// ---------------------------------------------------------------------------

/**
 * Auto-provision wildcard A, root A, www CNAME, SPF TXT, DMARC TXT.
 */
function cfProvisionDns(string $zoneId, string $domain, string $serverIp, string $token = ''): array
{
    $desired = [
        ['type' => 'A',     'name' => '*',     'content' => $serverIp,                                          'proxied' => true],
        ['type' => 'A',     'name' => '@',     'content' => $serverIp,                                          'proxied' => true],
        ['type' => 'CNAME', 'name' => 'www',   'content' => $domain,                                            'proxied' => true],
        ['type' => 'TXT',   'name' => '@',     'content' => 'v=spf1 -all',                                     'proxied' => false],
        ['type' => 'TXT',   'name' => '_dmarc','content' => 'v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;', 'proxied' => false],
    ];

    $log = [];
    foreach ($desired as $rec) {
        try {
            $fullName = $rec['name'] === '@' ? $domain : $rec['name'] . '.' . $domain;
            $existing = cfApi(
                'GET',
                '/zones/' . $zoneId . '/dns_records?type=' . urlencode($rec['type']) . '&name=' . urlencode($fullName),
                null,
                $token
            );

            $body = [
                'type'    => $rec['type'],
                'name'    => $rec['name'],
                'content' => $rec['content'],
                'ttl'     => 1,
                'proxied' => $rec['proxied'],
            ];

            if (!empty($existing['result'][0]['id'])) {
                cfApi('PUT', '/zones/' . $zoneId . '/dns_records/' . $existing['result'][0]['id'], $body, $token);
                $log[] = 'updated:' . $rec['type'] . ':' . $fullName;
            } else {
                cfApi('POST', '/zones/' . $zoneId . '/dns_records', $body, $token);
                $log[] = 'created:' . $rec['type'] . ':' . $fullName;
            }
        } catch (Throwable $e) {
            $log[] = 'error:' . $rec['type'] . ':' . ($rec['name'] === '@' ? $domain : $rec['name'] . '.' . $domain) . ':' . $e->getMessage();
        }
    }

    return $log;
}

// ---------------------------------------------------------------------------
// Super Bot Fight Mode (Smart Shield)
// ---------------------------------------------------------------------------

function cfEnableSmartShield(string $zoneId, string $token = ''): void
{
    try {
        cfApi('PUT', '/zones/' . $zoneId . '/bot_management', [
            'sbfm_definitely_automated'           => 'managed_challenge',
            'sbfm_likely_automated'               => 'managed_challenge',
            'sbfm_verified_bots'                  => 'allow',
            'sbfm_static_resource_protection'     => false,
            'optimize_wordpress'                  => false,
        ], $token);
    } catch (Throwable) {
        // best-effort — requires Business plan or above
    }
}

// ---------------------------------------------------------------------------
// Real User Monitoring (RUM / Zaraz / Web Analytics)
// ---------------------------------------------------------------------------

function cfEnableRum(string $zoneId, string $token = ''): void
{
    try {
        cfApi('POST', '/zones/' . $zoneId . '/rum/site_info', [
            'auto_install' => true,
        ], $token);
    } catch (Throwable) {
        // best-effort
    }
}

// ---------------------------------------------------------------------------
// Email Routing — enable catch-all forward
// ---------------------------------------------------------------------------

function cfEnableEmailRouting(string $zoneId, string $token = ''): void
{
    try {
        cfApi('POST', '/zones/' . $zoneId . '/email/routing/enable', null, $token);
    } catch (Throwable) {
        // best-effort — zone must already have email routing DNS records
    }
}

// ---------------------------------------------------------------------------
// Configuration Rule — disable Hotlink Protection via http_config_settings
// ---------------------------------------------------------------------------

function cfApplyConfigRules(string $zoneId, string $token = ''): void
{
    $rules = [[
        'action'            => 'set_config',
        'action_parameters' => [
            'hotlink_protection' => false,
        ],
        'expression'  => 'true',
        'description' => 'Disable hotlink protection (managed here)',
        'enabled'     => true,
    ]];

    try {
        cfApi(
            'PUT',
            '/zones/' . $zoneId . '/rulesets/phases/http_config_settings/entrypoints',
            ['rules' => $rules],
            $token
        );
    } catch (Throwable) {
        // best-effort
    }
}

// ---------------------------------------------------------------------------
// One-click: apply ALL recommended settings at once
// ---------------------------------------------------------------------------

/**
 * Apply every recommended Cloudflare setting in a single call.
 * Used by both admin zone_add and user cf.sync.php.
 *
 * Covers: zone settings, HSTS, response header rules, config rules,
 *         Page Shield, leaked credentials, Smart Shield, RUM,
 *         Email Routing, Facebook crawler bypass.
 * DNS provisioning is handled separately (needs serverIp).
 */
function cfApplyAllRecommended(string $zoneId, string $token = ''): void
{
    cfApplySettings($zoneId, $token);
    cfApplyHsts($zoneId, $token);
    cfApplyHeaderRules($zoneId, $token);
    cfApplyConfigRules($zoneId, $token);
    cfEnableClientSideSecurity($zoneId, $token);
    cfEnableLeakedCredentials($zoneId, $token);
    cfEnableSmartShield($zoneId, $token);
    cfEnableRum($zoneId, $token);
    cfEnableEmailRouting($zoneId, $token);
    cfAllowFacebookCrawler($zoneId, $token);
}
