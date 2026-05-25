<?php

declare(strict_types=1);

if (!class_exists('Mobile_Detect')) {
    final class Mobile_Detect
    {
        private string $userAgent;

        public function __construct(?string $userAgent = null)
        {
            if ($userAgent === null && isset($_SERVER['HTTP_USER_AGENT']) && is_string($_SERVER['HTTP_USER_AGENT'])) {
                $userAgent = $_SERVER['HTTP_USER_AGENT'];
            }

            $this->userAgent = strtolower(trim((string) $userAgent));
        }

        public function isTablet(): bool
        {
            if ($this->userAgent === '') {
                return false;
            }

            if (str_contains($this->userAgent, 'android') && !str_contains($this->userAgent, 'mobile')) {
                return true;
            }

            return preg_match(
                '/ipad|tablet|kindle|silk|playbook|nexus 7|nexus 9|sm-t|lenovo tab|xoom|sch-i800/i',
                $this->userAgent
            ) === 1;
        }

        public function isMobile(): bool
        {
            if ($this->userAgent === '') {
                return false;
            }

            return preg_match(
                '/iphone|ipod|android|blackberry|bb10|windows phone|opera mini|opera mobi|mobile|iemobile|webos/i',
                $this->userAgent
            ) === 1;
        }
    }
}
