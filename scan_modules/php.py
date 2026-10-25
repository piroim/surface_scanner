"""PHP runtime and PHP framework fingerprints."""

from __future__ import annotations

import re

from .base import Signature, TechnologyModule, regex


# PHP 전용 경로와 탐지 패턴은 이 파일에서 관리한다.
INFO_PATHS = (
    "/phpinfo.php", "/info.php", "/infophp.php", "/php-info.php",
    "/phpinfo", "/status.php", "/health.php", "/?phpinfo=1",
)
WORDPRESS_PROBE_PATHS = ("/wp-login.php", "/wp-json/", "/xmlrpc.php")
PHP_VERSION = re.compile(
    r"\bPHP(?:\s+Version|\s*버전|/|_VERSION\s*[:=]\s*['\"]?)\s*"
    r"(?:</?[^>]{1,80}>\s*){0,3}[:=]?\s*"
    r"(\d+\.\d+(?:\.\d+)?(?:[-+~][\w.+~-]+|(?:RC|dev|alpha|beta)\d*)?)", re.I
)
ADVERTISED_PHP_VERSION = re.compile(r"\bPHP[ /]([^\s,;)]+)", re.I)
WORDPRESS_HINT = re.compile(
    r"\bWordPress\b|/wp-content/|/wp-includes/|wp-json|wp-embed\.min\.js", re.I
)
PHP_ERROR = re.compile(
    r"\b(?:Fatal error|Parse error|Warning):\ .*?\bin\b|\bPHP\b.*\bon line\b|"
    r"Allowed memory size|post_max_size|upload_max_filesize|PHP Session", re.I
)
PHP_SAPI = re.compile(r"Server API\s*=>\s*([^\n<]+)", re.I)
PHP_HINT = re.compile(r"\b(?:PHPSESSID|PHP_VERSION|phpversion\s*\()|<\?php\b", re.I)
INFO_TITLE = re.compile(r"<title[^>]*>\s*phpinfo\s*\(\s*\)\s*</title>", re.I)


class PhpModule(TechnologyModule):
    key = "php"
    label = "PHP"
    aliases = ("php",)
    route_suffixes = (
        ".php", ".php3", ".php4", ".php5", ".php7", ".php8",
        ".phtml", ".pht", ".phtm", ".phar", ".phps",
    )
    signatures = (
        Signature("header", regex(r"\bPHP(?:[/\s]|$)"), "런타임", "PHP", "high", "x-powered-by"),
        Signature("header", regex(r"\bPHP(?:[/\s]|$)"), "런타임", "PHP", "high", "server"),
        Signature("header", regex(r"^\s*\d+\.\d+"), "런타임", "PHP", "high", "x-php-version"),
        Signature("header", regex(r"PHPSESSID"), "세션", "PHPSESSID", "high", "set-cookie"),
        Signature("header", regex(r"laravel_session"), "프레임워크", "Laravel", "high", "set-cookie"),
        Signature("header", regex(r"ci_session"), "프레임워크", "CodeIgniter", "high", "set-cookie"),
        Signature("header", regex(r"(?:^|;\s*)CAKEPHP="), "프레임워크", "CakePHP", "high", "set-cookie"),
        Signature("header", regex(r"wordpress_(?:logged_in_)?|wp-settings-|wp_woocommerce_session_"), "CMS", "WordPress/WooCommerce", "high", "set-cookie"),
        Signature("header", regex(r"MoodleSession"), "CMS", "Moodle", "high", "set-cookie"),
        Signature("header", regex(r"PrestaShop-[\w-]+="), "CMS", "PrestaShop", "high", "set-cookie"),
        Signature("header", regex(r"Drupal"), "CMS", "Drupal", "high", "x-generator"),
        Signature("header", regex(r"Drupal"), "CMS", "Drupal", "high", "x-drupal-cache"),
        Signature("header", regex(r"/wp-json/|/xmlrpc\.php"), "CMS", "WordPress", "high", "link"),
        Signature("header", regex(r"/xmlrpc\.php"), "CMS", "WordPress", "high", "x-pingback"),
        Signature("body", regex(r"\bWordPress\b|/wp-content/|/wp-includes/|wp-json"), "CMS", "WordPress", "high"),
        Signature("body", regex(r"/sites/default/files/|Drupal\.settings"), "CMS", "Drupal", "high"),
        Signature("body", regex(r"Joomla!|/components/com_"), "CMS", "Joomla", "medium"),
        Signature("body", regex(r"Magento_Ui|mage-cache-storage|/static/version\d+/frontend/"), "CMS", "Magento", "high"),
        Signature("body", regex(r"\bMoodle\b|/theme/image\.php/|M\.cfg\s*="), "CMS", "Moodle", "medium"),
        Signature("body", regex(r"mw\.config\.set\s*\(|/w/load\.php"), "CMS", "MediaWiki", "high"),
        Signature("body", regex(r"\bTYPO3 CMS\b|/typo3temp/|/typo3conf/"), "CMS", "TYPO3", "high"),
        Signature("body", regex(r"\bphpMyAdmin\b|pmahomme|PMA_VERSION"), "제품", "phpMyAdmin", "high"),
        Signature("body", regex(r"\bPrestaShop\b|prestashop\.version"), "CMS", "PrestaShop", "medium"),
        Signature("body", regex(r"\bLaravel\b|laravel_session"), "프레임워크", "Laravel", "medium"),
        Signature("body", regex(r"/_profiler/|/_wdt/|sf-toolbar|\bSymfony\\Component\\"), "프레임워크", "Symfony", "high"),
        Signature("body", regex(r"\bCakePHP\b|cake-error|CAKEPHP"), "프레임워크", "CakePHP", "medium"),
        Signature("body", regex(r"yii\.getCsrfToken|YII_CSRF_TOKEN"), "프레임워크", "Yii", "medium"),
        Signature("body", regex(r"\b(?:Fatal error|Parse error|Warning):.*\bin\b|PHP .* on line|Uncaught (?:Error|Exception|TypeError):"), "런타임", "PHP 오류 응답", "high"),
        Signature("body", PHP_VERSION, "런타임", "PHP 버전 문자열", "high"),
        Signature("body", regex(r"\b(?:apache2handler|fpm-fcgi|cgi-fcgi)\b"), "SAPI", "PHP SAPI 문자열", "medium"),
    )


MODULE = PhpModule()
