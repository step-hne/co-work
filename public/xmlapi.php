<?php

declare(strict_types=1);

if (!class_exists('xmlapi')) {
    class xmlapi
    {
        private string $host;
        private int $port = 2083;
        private string $output = 'json';
        private string $username = '';
        private string $password = '';
        private string $token = '';
        private bool $debug = false;

        public function __construct(string $host = 'localhost')
        {
            $this->host = $host;
        }

        public function set_port(int $port): void
        {
            $this->port = $port;
        }

        public function set_output(string $output): void
        {
            $this->output = $output;
        }

        public function password_auth(string $username, string $password): void
        {
            $this->username = $username;
            $this->password = $password;
            $this->token    = '';
        }

        public function token_auth(string $username, string $token): void
        {
            $this->username = $username;
            $this->token    = $token;
            $this->password = '';
        }

        public function set_debug(int $debug): void
        {
            $this->debug = $debug === 1;
        }

        public function api2_query(string $account, string $module, string $function, array $params = []): mixed
        {
            $query = array_merge(
                [
                    'cpanel_jsonapi_user'       => $account,
                    'cpanel_jsonapi_apiversion' => '2',
                    'cpanel_jsonapi_module'     => $module,
                    'cpanel_jsonapi_func'       => $function,
                ],
                $params
            );

            $url = sprintf(
                'https://%s:%d/json-api/cpanel?%s',
                $this->host,
                $this->port,
                http_build_query($query)
            );

            $curl = curl_init();
            if ($curl === false) {
                return null;
            }

            $opts = [
                CURLOPT_URL            => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_SSL_VERIFYHOST => 0,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_TIMEOUT        => 20,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_HEADER         => false,
            ];

            if ($this->token !== '') {
                $opts[CURLOPT_HTTPHEADER] = [
                    'Authorization: cpanel ' . $this->username . ':' . $this->token,
                ];
            } else {
                $opts[CURLOPT_HTTPAUTH] = CURLAUTH_BASIC;
                $opts[CURLOPT_USERPWD]  = $this->username . ':' . $this->password;
            }

            curl_setopt_array($curl, $opts);

            $response = curl_exec($curl);
            $error    = curl_error($curl);
            $errno    = curl_errno($curl);
            $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            curl_close($curl);

            if ($response === false || $errno !== 0) {
                if ($this->debug) {
                    error_log('xmlapi request failed: ' . $error);
                }
                return null;
            }

            // HTTP 401/403 with token auth = treat as failure so caller can fallback
            if ($this->token !== '' && in_array($httpCode, [401, 403], true)) {
                if ($this->debug) {
                    error_log('xmlapi token auth rejected: HTTP ' . $httpCode);
                }
                return null;
            }

            if ($this->output === 'json') {
                $decoded = json_decode((string) $response, true);
                return $decoded !== null ? $decoded : $response;
            }

            return $response;
        }
    }
}
