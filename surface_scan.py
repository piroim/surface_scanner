#!/usr/bin/env python3
"""Modular web-surface technology scanner for authorized assets."""

from __future__ import annotations

import argparse
import csv
import os
import re
import socket
import sys
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit

import requests
from requests.exceptions import RequestException

SCANNER_DIR = Path(__file__).resolve().parent
if str(SCANNER_DIR) not in sys.path:
    sys.path.insert(0, str(SCANNER_DIR))

from scan_modules import (  # noqa: E402
    Finding,
    MODULES,
    ResponseView,
    TechnologyModule,
    inspect_server,
    resolve_modules,
)
from scan_modules.php import (  # noqa: E402
    ADVERTISED_PHP_VERSION,
    INFO_PATHS,
    INFO_TITLE,
    PHP_ERROR,
    PHP_SAPI,
    PHP_VERSION,
    WORDPRESS_HINT,
    WORDPRESS_PROBE_PATHS,
)

QUOTED_REFERENCE = re.compile(r"['\"`]([^'\"`\s<>]{1,256})['\"`]", re.I)
USER_AGENT = "web-surface-scanner/2.0 (authorized inventory)"
MAX_BYTES = 1_000_000
BANNER = r"""
create by. piroim
███████╗██████╗  █████╗ ███╗   ███╗███████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔════╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
█████╗  ██████╔╝███████║██╔████╔██║█████╗  ██║ █╗ ██║██║   ██║██████╔╝█████╔╝     ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ██║███╗██║██║   ██║██╔══██╗██╔═██╗     ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║     ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                                                                                                                        v1.0.0
""".strip("\n")


# =============================================================================
# 스캔 유형 커스터마이징 안내
#
# 각 유형의 구현은 아래 Scanner.scan_type_* 메서드에 독립적으로 모아 두었다.
# 경로 목록은 INFO_PATHS / WORDPRESS_PROBE_PATHS, 탐지식은 *_HINT / *_PATH
# 상수를 수정하면 된다. 이 목록은 상세 결과에 표시되는 순서도 결정한다.
# =============================================================================
@dataclass(frozen=True)
class ScanTypeDefinition:
    key: str
    label: str
    method: str
    customize: str


SCAN_TYPES = (
    ScanTypeDefinition("dns", "DNS/IP", "resolve_ips", "도메인의 IPv4/IPv6 주소 확인"),
    ScanTypeDefinition("headers", "HTTP 서버", "scan_type_server_technology", "서버/런타임 헤더 수집"),
    ScanTypeDefinition("technology", "기술 탐지", "scan_type_server_technology", "선택한 기술·프레임워크 탐지"),
    ScanTypeDefinition("html_js", "HTML/JS", "scan_type_html_js", "본문·동일 호스트 JS 판별"),
    ScanTypeDefinition("backend_paths", "백엔드 경로", "scan_type_backend_paths", "발견된 서버 경로 확인"),
    ScanTypeDefinition("wordpress", "WordPress", "scan_type_wordpress", "WordPress 경로와 흔적 확인"),
    ScanTypeDefinition("info_pages", "정보 페이지", "scan_type_info_pages", "phpinfo 후보 경로 확인"),
)

STATUS_DETECTED = "탐지"
STATUS_NOT_DETECTED = "미탐"
STATUS_COLOR = {STATUS_DETECTED: "1;32", STATUS_NOT_DETECTED: "90"}
SERVER_INFO_COLOR = "1;36"  # 서버/인프라 제품은 동일한 중립 색상
FRAMEWORK_COLOR = {
    "php": "1;35",       # 자홍색
    "jsp": "1;33",       # 노란색
    "asp": "1;34",       # 파란색
    "nodejs": "1;32",    # 초록색
}
DETECTION_PRIORITY = {"path": 4, "cookie": 3, "header": 2, "body": 1}
DETECTION_SOURCE = {
    "path": "URL 확장자/경로", "cookie": "세션 쿠키",
    "header": "응답 헤더", "body": "HTML 본문",
}


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: list[str] = []
        self.scripts: list[str] = []
        self.generators: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag in {"a", "link", "script", "form", "iframe"}:
            value = values.get("href") or values.get("src") or values.get("action")
            if value:
                self.urls.append(value)
                if tag == "script":
                    self.scripts.append(value)
        if tag == "meta" and (values.get("name") or "").lower() == "generator":
            if values.get("content"):
                self.generators.append(values["content"] or "")


@dataclass
class Fetch:
    url: str
    status: int
    headers: dict[str, str]
    text: str
    content_type: str


@dataclass
class Result:
    target: str
    domain: str = ""
    resolved_ips: list[str] = field(default_factory=list)
    landing: str = ""
    status: int | None = None
    evidence: dict[str, list[str]] = field(default_factory=lambda: {
        "headers": [], "client": [], "info_pages": [], "php_paths": [], "wordpress": []
    })
    checked_info: list[str] = field(default_factory=list)
    checked_js: list[str] = field(default_factory=list)
    checked_wordpress: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    advertised_versions: list[str] = field(default_factory=list)
    content_advertised_versions: list[str] = field(default_factory=list)
    wordpress_detected: bool = False
    sapi_hints: list[str] = field(default_factory=list)
    selected_modules: list[str] = field(default_factory=lambda: list(MODULES))
    server_info: list[str] = field(default_factory=list)
    technology_evidence: dict[str, list[str]] = field(default_factory=dict)
    primary_modules: list[str] = field(default_factory=list)
    technology_priority: int = 0
    technology_source: str = ""
    backend_paths: dict[str, list[str]] = field(default_factory=dict)
    checked_backend_urls: list[str] = field(default_factory=list)

    def add(self, category: str, value: str) -> None:
        if value not in self.evidence[category]:
            self.evidence[category].append(value)

    def add_server_info(self, value: str) -> None:
        if value not in self.server_info:
            self.server_info.append(value)

    def add_technology(self, module: str, value: str) -> None:
        entries = self.technology_evidence.setdefault(module, [])
        if value not in entries:
            entries.append(value)

    def add_backend_path(self, module: str, url: str) -> None:
        entries = self.backend_paths.setdefault(module, [])
        if url not in entries:
            entries.append(url)

    def reset_technology(self, modules: list[str], priority: int, source: str) -> None:
        """Update the strongest identification without discarding other evidence."""
        self.primary_modules = modules
        self.technology_priority = priority
        self.technology_source = source

    @property
    def detected(self) -> bool:
        return bool(self.server_info or any(self.technology_evidence.values()))

    @property
    def detection_status(self) -> str:
        return STATUS_DETECTED if self.detected else STATUS_NOT_DETECTED

    @property
    def versions(self) -> list[str]:
        values: list[str] = []
        for entries in self.evidence.values():
            for entry in entries:
                for version in PHP_VERSION.findall(entry):
                    if version not in values:
                        values.append(version)
        return values

    def scan_type_summary(self) -> list[tuple[str, str]]:
        """Report each collection method independently of the overall status."""
        if not self.landing:
            return [
                ("DNS/IP", ", ".join(self.resolved_ips) if self.resolved_ips else "미확인"),
                *((item.label, "실행 안 됨") for item in SCAN_TYPES[1:]),
            ]
        detected = [value for _key, _detail, value in framework_groups(self)]
        discovered_paths = sum(len(values) for values in self.backend_paths.values())
        return [
            ("DNS/IP", ", ".join(self.resolved_ips) if self.resolved_ips else "미확인"),
            ("HTTP 서버", f"정보 {len(self.server_info)}개"),
            ("기술 탐지", ", ".join(detected) if detected else "선택 기술 미탐지"),
            ("HTML/JS", f"단서 {len(self.evidence['client'])}개, JS 요청 {len(self.checked_js)}개"),
            ("백엔드 경로", f"발견 {discovered_paths}개, 요청 {len(self.checked_backend_urls)}개"),
            ("WordPress", f"{'탐지' if self.wordpress_detected else '미탐지'}, "
                          f"경로 요청 {len(self.checked_wordpress)}개"
                          if self.checked_wordpress or self.wordpress_detected else "실행 안 됨"),
            ("정보 페이지", f"경로 요청 {len(self.checked_info)}개, "
                            f"{'발견' if self.evidence['info_pages'] else '미발견'}"
                            if self.checked_info else "실행 안 됨"),
        ]


def infer_sapi_hints(result: Result) -> list[str]:
    hints: list[str] = []
    server_values = " ".join(
        item.split(":", 1)[1] if ":" in item else item
        for item in result.evidence["headers"]
        if item.lower().startswith("server:")
    ).lower()
    has_php_banner = bool(result.advertised_versions or result.content_advertised_versions)
    has_php_paths = bool(result.evidence["php_paths"])
    if "apache" in server_values and (has_php_banner or has_php_paths):
        hints.append("Apache + PHP 단서: mod_php 가능성(확정 아님)")
    if any("PHPSESSID" in item for item in result.evidence["headers"]):
        hints.append("PHP 세션 쿠키 관측")
    for entry in result.evidence["info_pages"] + result.evidence["client"]:
        match = PHP_SAPI.search(entry)
        if match:
            hints.append(f"phpinfo SAPI: {match.group(1).strip()}")
    if result.wordpress_detected:
        hints.append("WordPress 스택(PHP 기반 CMS)")
    out: list[str] = []
    for hint in hints:
        if hint not in out:
            out.append(hint)
    return out


def finalize_result(result: Result) -> None:
    result.sapi_hints = infer_sapi_hints(result)


class Scanner:
    def __init__(
        self,
        timeout: float,
        max_js: int,
        insecure: bool,
        max_php_links: int = 5,
        wordpress_probe: str = "auto",
        modules: tuple[TechnologyModule, ...] | None = None,
    ) -> None:
        self.timeout = timeout
        self.max_js = max_js
        self.insecure = insecure
        self.max_php_links = max_php_links
        self.wordpress_probe = wordpress_probe
        self.modules = modules if modules is not None else resolve_modules(None)
        self.module_keys = {module.key for module in self.modules}
        if insecure:
            requests.packages.urllib3.disable_warnings(  # type: ignore[attr-defined]
                requests.packages.urllib3.exceptions.InsecureRequestWarning  # type: ignore[attr-defined]
            )

    @staticmethod
    def allowed_hosts(hostname: str) -> set[str]:
        hostname = hostname.lower()
        return {hostname, hostname[4:] if hostname.startswith("www.") else "www." + hostname}

    @staticmethod
    def resolve_ips(hostname: str, result: Result) -> None:
        try:
            addresses = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            result.errors.append(f"DNS {hostname}: {exc}")
            return
        for entry in addresses:
            address = entry[4][0]
            if address not in result.resolved_ips:
                result.resolved_ips.append(address)

    def _read_limited_body(self, response: requests.Response, content_type: str) -> str:
        body = bytearray()
        if any(part in content_type.lower() for part in ("text/", "javascript", "json", "xml")):
            for chunk in response.iter_content(chunk_size=16384):
                body.extend(chunk)
                if len(body) >= MAX_BYTES:
                    del body[MAX_BYTES:]
                    break
        encoding = response.encoding or "utf-8"
        return body.decode(encoding, errors="replace")

    @staticmethod
    def _headers_with_session_cookie_names(
        headers: dict[str, str], session: requests.Session
    ) -> dict[str, str]:
        """Expose cookie names set on redirects without retaining cookie values."""
        merged = dict(headers)
        cookie_names = list(dict.fromkeys(cookie.name for cookie in session.cookies))
        if not cookie_names:
            return merged
        set_cookie_key = next(
            (name for name in merged if name.lower() == "set-cookie"), "Set-Cookie"
        )
        existing = merged.pop(set_cookie_key, "")
        redacted = "; ".join(f"{name}=<session>" for name in cookie_names)
        merged["Set-Cookie"] = "; ".join(value for value in (existing, redacted) if value)
        return merged

    def fetch(self, session: requests.Session, url: str, hosts: set[str]) -> Fetch:
        for _ in range(4):
            if urlsplit(url).hostname not in hosts or urlsplit(url).scheme not in {"http", "https"}:
                raise ValueError(f"허용 범위 밖의 URL: {url}")
            with session.get(url, timeout=self.timeout, verify=not self.insecure,
                             allow_redirects=False, stream=True) as response:
                if response.is_redirect and response.headers.get("Location"):
                    next_url = urljoin(url, response.headers["Location"])
                    if urlsplit(next_url).hostname not in hosts:
                        raise ValueError(f"외부 리디렉션 중단: {next_url}")
                    url = next_url
                    continue
                content_type = response.headers.get("Content-Type", "")
                text = self._read_limited_body(response, content_type)
                headers = self._headers_with_session_cookie_names(
                    dict(response.headers), session
                )
                return Fetch(response.url, response.status_code, headers,
                             text, content_type)
        raise ValueError(f"리디렉션 횟수 초과: {url}")

    def ingest_fetch(
        self, response: Fetch, result: Result, *, allow_path_evidence: bool = True
    ) -> None:
        self.scan_type_server_technology(
            response, result, allow_path_evidence=allow_path_evidence
        )
        if not self._technology_response_usable(response.status):
            return
        if allow_path_evidence:
            self.check_backend_url(response.url, response.status, result)
        if "php" in result.primary_modules:
            self.scan_type_headers(response, result)
            if not self._is_javascript(response):
                self.check_client_text(response.text, response.url, result)
                self.check_wordpress_text(response.text, response.url, result)
            if allow_path_evidence and MODULES["php"].matches_path(response.url):
                result.add("php_paths", response.url)

    @staticmethod
    def _is_javascript(response: Fetch) -> bool:
        path = urlsplit(response.url).path.lower()
        return ("javascript" in response.content_type.lower()
                or path.endswith((".js", ".mjs", ".cjs")))

    @staticmethod
    def _technology_response_usable(status: int) -> bool:
        """Reject error pages that commonly echo requested paths or generic stack text."""
        return status != 404 and status < 500

    @staticmethod
    def _finding_priority(finding: Finding) -> int:
        # 식별 순서: URL 경로 > 세션 쿠키 > 응답 헤더 > HTML 본문.
        return DETECTION_PRIORITY.get(finding.location, 0)

    # -------------------------------------------------------------------------
    # 스캔 유형: 공통 서버 정보 + 선택 기술 모듈
    # 새 기술은 scan_modules/ 아래에 모듈을 추가하고 registry에 등록한다.
    # -------------------------------------------------------------------------
    def scan_type_server_technology(
        self, response: Fetch, result: Result, *, allow_path_evidence: bool = True
    ) -> None:
        view = ResponseView(
            url=response.url,
            status=response.status,
            headers=response.headers,
            text=response.text,
            content_type=response.content_type,
        )
        for finding in inspect_server(view):
            result.add_server_info(finding.render())
        if not self._technology_response_usable(response.status):
            return
        findings: list[Finding] = []
        for module in self.modules:
            module_findings = module.inspect(view)
            if not allow_path_evidence:
                module_findings = [
                    item for item in module_findings if item.location != "path"
                ]
            if self._is_javascript(response):
                module_findings = [item for item in module_findings if item.location != "body"]
            findings.extend(module_findings)
        if not findings:
            return

        priority = max(self._finding_priority(finding) for finding in findings)
        winners = {
            finding.module for finding in findings
            if self._finding_priority(finding) == priority
        }
        ordered_winners = [module.key for module in self.modules if module.key in winners]
        if priority > result.technology_priority:
            source = next(
                finding.location for finding in findings
                if self._finding_priority(finding) == priority
            )
            result.reset_technology(ordered_winners, priority, source)
        elif priority == result.technology_priority:
            for key in ordered_winners:
                if key not in result.primary_modules:
                    result.primary_modules.append(key)

        for finding in findings:
            result.add_technology(finding.module, finding.render())

    # -------------------------------------------------------------------------
    # 스캔 유형: HTML/JS
    # -------------------------------------------------------------------------
    def scan_type_html_js(
        self, session: requests.Session, landing: Fetch, hosts: set[str], result: Result
    ) -> bool:
        """Inspect the landing HTML and only JS files referenced by that page."""
        page = PageParser()
        wordpress_hint = False
        if "html" in landing.content_type.lower():
            page.feed(landing.text)
            self.check_backend_references(landing.text, landing.url, hosts, result)
            for generator in page.generators:
                if "php" in result.primary_modules and "php" in generator.lower():
                    result.add("client", f"generator 메타 태그: {generator[:160]} ({landing.url})")
                if "php" in result.primary_modules and "wordpress" in generator.lower():
                    wordpress_hint = True
                    result.add("wordpress", f"generator: {generator[:160]} ({landing.url})")
            for raw in page.urls:
                link = normalized_link(landing.url, raw)
                if link and urlsplit(link).hostname in hosts:
                    self.check_backend_url(link, None, result)
                    if "php" in result.primary_modules and WORDPRESS_HINT.search(raw):
                        wordpress_hint = True
            if "php" in result.primary_modules and WORDPRESS_HINT.search(landing.text):
                wordpress_hint = True
            for raw in page.scripts:
                if len(result.checked_js) >= self.max_js:
                    break
                link = normalized_link(landing.url, raw)
                if not link or urlsplit(link).hostname not in hosts:
                    continue
                result.checked_js.append(link)
                try:
                    script = self.fetch(session, link, hosts)
                    if script.status == 200:
                        self.ingest_fetch(script, result)
                        self.check_backend_references(script.text, script.url, hosts, result)
                except (RequestException, ValueError) as exc:
                    result.errors.append(f"JS {link}: {exc}")
        return wordpress_hint

    # -------------------------------------------------------------------------
    # 스캔 유형: PHP/JSP/ASP 등 발견된 백엔드 경로
    # -------------------------------------------------------------------------
    def scan_type_backend_paths(
        self, session: requests.Session, hosts: set[str], result: Result
    ) -> None:
        """Fetch a bounded number of routes discovered for selected modules."""
        seen = set(result.checked_backend_urls)
        if result.landing:
            seen.add(result.landing)
        for module in self.modules:
            for link in result.backend_paths.get(module.key, []):
                if len(result.checked_backend_urls) >= self.max_php_links:
                    return
                if link in seen:
                    continue
                seen.add(link)
                result.checked_backend_urls.append(link)
                try:
                    page_response = self.fetch(session, link, hosts)
                    self.ingest_fetch(page_response, result)
                except (RequestException, ValueError) as exc:
                    result.errors.append(f"{module.label} {link}: {exc}")

    # -------------------------------------------------------------------------
    # 스캔 유형: WordPress
    # -------------------------------------------------------------------------
    def scan_type_wordpress(
        self, session: requests.Session, origin: str, hosts: set[str],
        result: Result, wordpress_hint: bool
    ) -> None:
        """Probe WordPress paths only when requested or hinted by observed content."""
        run_wordpress = self.wordpress_probe == "force" or (
            self.wordpress_probe == "auto" and (wordpress_hint or result.wordpress_detected)
        )
        if run_wordpress:
            for path in WORDPRESS_PROBE_PATHS:
                url = origin + path
                result.checked_wordpress.append(url)
                try:
                    wp_response = self.fetch(session, url, hosts)
                    self.ingest_fetch(
                        wp_response, result, allow_path_evidence=False
                    )
                    if 200 <= wp_response.status < 400 and (
                        "wordpress" in wp_response.text.lower()
                        or "wp-login" in wp_response.text.lower()
                        or path == "/wp-json/"
                    ):
                        result.wordpress_detected = True
                        result.add("wordpress", f"WordPress 경로 응답: {url} (HTTP {wp_response.status})")
                except (RequestException, ValueError) as exc:
                    result.errors.append(f"WordPress {url}: {exc}")

    # -------------------------------------------------------------------------
    # 스캔 유형: phpinfo 등 정보 페이지
    # -------------------------------------------------------------------------
    def scan_type_info_pages(
        self, session: requests.Session, origin: str, hosts: set[str], result: Result
    ) -> None:
        """Check a bounded set of common PHP information-page paths."""
        for path in INFO_PATHS:
            url = origin + path
            result.checked_info.append(url)
            try:
                page_response = self.fetch(session, url, hosts)
                self.ingest_fetch(
                    page_response, result, allow_path_evidence=False
                )
                if page_response.status in {403, 429}:
                    result.errors.append(
                        f"{url}: HTTP {page_response.status}; 추가 정보 페이지 탐색 중단"
                    )
                    break
                info_page = INFO_TITLE.search(page_response.text)
                match = PHP_VERSION.search(page_response.text)
                if page_response.status == 200 and (info_page or match):
                    version = f"PHP Version {match.group(1)}" if match else "버전 추출 실패"
                    kind = "phpinfo" if info_page else "PHP 정보"
                    result.add("info_pages", f"{kind} 노출: {url} ({version})")
                    sapi_match = PHP_SAPI.search(page_response.text)
                    if sapi_match:
                        result.add("info_pages", f"Server API => {sapi_match.group(1).strip()} ({url})")
                    break
            except (RequestException, ValueError) as exc:
                result.errors.append(f"{url}: {exc}")

    def scan(self, target: str, progress=lambda _stage: None) -> Result:
        result = Result(target=target, selected_modules=[module.key for module in self.modules])
        candidates = candidate_urls(target)
        result.domain = urlsplit(candidates[0]).hostname or ""
        self.resolve_ips(result.domain, result)
        hosts = self.allowed_hosts(result.domain)
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})
        landing: Fetch | None = None

        progress("시작 페이지")
        for candidate in candidates:
            try:
                landing = self.fetch(session, candidate, hosts)
                break
            except RequestException as exc:
                result.errors.append(f"{candidate}: {exc}")
            except ValueError as exc:
                result.errors.append(f"{candidate}: {exc}")
                break
        if landing is None:
            session.close()
            finalize_result(result)
            return result

        result.landing, result.status = landing.url, landing.status
        origin = f"{urlsplit(landing.url).scheme}://{urlsplit(landing.url).netloc}"
        self.ingest_fetch(landing, result)

        progress("HTML 및 JS")
        wordpress_hint = self.scan_type_html_js(session, landing, hosts, result)
        if self.max_php_links > 0 and any(result.backend_paths.values()):
            progress("발견된 백엔드 URL")
            self.scan_type_backend_paths(session, hosts, result)
        php_fallback_allowed = (
            "php" in self.module_keys
            and (not result.primary_modules or "php" in result.primary_modules)
        )
        if php_fallback_allowed and (self.wordpress_probe == "force" or (
            self.wordpress_probe == "auto" and (wordpress_hint or result.wordpress_detected)
        )):
            progress("WordPress")
        if php_fallback_allowed:
            self.scan_type_wordpress(session, origin, hosts, result, wordpress_hint)
        if php_fallback_allowed:
            progress("기본 정보 페이지")
            self.scan_type_info_pages(session, origin, hosts, result)

        progress("완료")
        session.close()
        finalize_result(result)
        return result

    # -------------------------------------------------------------------------
    # 스캔 유형: HTTP 헤더
    # -------------------------------------------------------------------------
    @staticmethod
    def scan_type_headers(response: Fetch, result: Result) -> None:
        for name, value in response.headers.items():
            lower_name = name.lower()
            if lower_name in {"server", "x-powered-by", "x-php-version", "x-generator"}:
                result.add("headers", f"{name}: {value[:200]} ({response.url})")
            if lower_name in {"server", "x-powered-by"}:
                for match in ADVERTISED_PHP_VERSION.finditer(value):
                    if match.group(1) not in result.advertised_versions:
                        result.advertised_versions.append(match.group(1))
            if lower_name == "x-php-version":
                for match in PHP_VERSION.finditer(f"PHP/{value}"):
                    if match.group(1) not in result.advertised_versions:
                        result.advertised_versions.append(match.group(1))
            if lower_name == "set-cookie" and "PHPSESSID" in value.upper():
                result.add("headers", f"PHPSESSID 쿠키 ({response.url})")

    @staticmethod
    def check_client_text(text: str, source: str, result: Result) -> None:
        for match in list(PHP_VERSION.finditer(text))[:5]:
            version = match.group(1)
            result.add("client", f"PHP Version {version} 문자열 ({source})")
            if version not in result.content_advertised_versions:
                result.content_advertised_versions.append(version)
        if PHP_ERROR.search(text):
            result.add("client", f"PHP 런타임 오류 패턴 ({source})")

    @staticmethod
    def check_wordpress_text(text: str, source: str, result: Result) -> None:
        if WORDPRESS_HINT.search(text):
            result.wordpress_detected = True
            result.add("wordpress", f"WordPress 흔적 ({source})")

    def check_backend_references(
        self, text: str, source: str, hosts: set[str], result: Result
    ) -> None:
        """Collect quoted PHP/JSP/ASP routes handled by selected modules."""
        for match in list(QUOTED_REFERENCE.finditer(text))[:200]:
            link = normalized_link(source, match.group(1))
            if link and urlsplit(link).hostname in hosts:
                self.check_backend_url(link, None, result)

    def check_backend_url(self, url: str, status: int | None, result: Result) -> None:
        if status is not None and status >= 400:
            return
        for module in self.modules:
            if module.matches_path(url):
                result.add_backend_path(module.key, url)

def normalized_link(base: str, raw: str) -> str | None:
    url = urldefrag(urljoin(base, raw.strip()))[0]
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def candidate_urls(target: str) -> list[str]:
    target = target.strip()
    if not target:
        raise ValueError("빈 대상")
    if "://" in target:
        parsed = urlsplit(target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"지원하지 않는 URL: {target}")
        return [target]
    if any(char.isspace() for char in target):
        raise ValueError(f"잘못된 도메인: {target}")
    parsed = urlsplit("https://" + target)
    if not parsed.hostname:
        raise ValueError(f"잘못된 도메인: {target}")
    return ["https://" + target, "http://" + target]


class Colors:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, value: str, code: str) -> str:
        return f"\033[{code}m{value}\033[0m" if self.enabled else value


def format_cli_result(result: Result, colors: Colors | None = None) -> str:
    """Build the one-line result used by both stdout and the text report."""
    status = result.detection_status
    label = f"[{status}]"
    if colors is not None:
        label = colors.paint(label, STATUS_COLOR[status])
    return f"{label} {result.landing or result.target} :::> {inventory_summary(result, colors)}"


def _finding_value(entry: str) -> tuple[str, str]:
    """Return (category, value) from a rendered technology finding."""
    plain = entry.rsplit(" [", 1)[0]
    if ": " not in plain:
        return "", plain
    category, value = plain.split(": ", 1)
    return category, value


def _finding_location(entry: str) -> str:
    match = re.search(r"\[[^/\]]+/([^\]]+)\]", entry)
    return match.group(1) if match else ""


def _summary_module_visible(result: Result, key: str) -> bool:
    """Keep weak conflicting body clues in the report, not in the CLI summary."""
    if key in result.primary_modules:
        return True
    entries = result.technology_evidence.get(key, [])
    if any(_finding_location(entry) in {"path", "cookie", "header"} for entry in entries):
        return True
    if key == "nodejs":
        frontend = {"Next.js", "Nuxt", "Vue.js", "Remix", "SvelteKit"}
        return any(_finding_value(entry)[1] in frontend for entry in entries)
    return False


def framework_groups(result: Result) -> list[tuple[str, str, str]]:
    """Return module key, detailed file value, and compact CLI value."""
    groups: list[tuple[str, str, str]] = []
    useful_categories = {
        "런타임", "프레임워크", "CMS", "서블릿 컨테이너",
        "애플리케이션 서버", "제품", "인프라", "프런트엔드",
    }
    for key in result.selected_modules:
        if (key not in MODULES or not result.technology_evidence.get(key)
                or not _summary_module_visible(result, key)):
            continue
        details: list[str] = []
        for entry in result.technology_evidence[key]:
            category, value = _finding_value(entry)
            if (category in useful_categories and value != MODULES[key].label
                    and value not in details):
                details.append(value)
        label = MODULES[key].label
        if key == "nodejs":
            frontend_names = {"Next.js", "Nuxt", "Vue.js", "Remix", "SvelteKit"}
            frontend = [value for value in details if value in frontend_names]
            runtime_observed = any(
                _finding_value(entry)[0] in {"런타임", "세션"}
                or _finding_value(entry)[1] == "Express"
                for entry in result.technology_evidence[key]
            )
            if frontend and not runtime_observed:
                rendered = "; ".join(frontend)
                cli_value = rendered
            else:
                rendered = f"{label} ({'; '.join(details)})" if details else label
                cli_values = [label, *frontend]
                cli_value = "; ".join(dict.fromkeys(cli_values))
        else:
            rendered = f"{label} ({'; '.join(details)})" if details else label
            cli_value = label
        groups.append((key, rendered, cli_value))
    return groups


def csv_framework(result: Result) -> str:
    """Create a compact, color-free framework value for reports and CSV."""
    return "; ".join(value for _key, value, _cli in framework_groups(result))


def csv_server(result: Result) -> str:
    servers: list[str] = []
    for entry in result.server_info:
        match = re.search(r"\bServer:\s*([^\[]+)", entry, re.I)
        if match:
            value = match.group(1).strip()
            if value not in servers:
                servers.append(value)
    return "; ".join(servers)


def csv_versions(result: Result) -> str:
    """Collect version strings that were actually exposed in responses."""
    versions = list(result.versions)
    sources = result.server_info + [
        entry
        for entries in result.technology_evidence.values()
        for entry in entries
    ]
    for source in sources:
        without_url = re.sub(r"\s+\(https?://.*\)$", "", source)
        for match in re.finditer(r"(?<![\d.])v?(\d+\.\d+(?:\.\d+){0,2})(?![\d.])", without_url, re.I):
            version = match.group(1)
            if version not in versions:
                versions.append(version)
    return "; ".join(versions)


def inventory_summary(result: Result, colors: Colors | None = None) -> str:
    ip_value = ",".join(result.resolved_ips) or "-"
    if not result.detected:
        access = f"HTTP {result.status}" if result.landing else "HTTP 접속 실패"
        return f"IP={ip_value} | {access} | 서버/프레임워크 미확인"
    parts = [f"IP={ip_value}"]
    server = csv_server(result)
    framework_parts = framework_groups(result)
    version = csv_versions(result)
    if server:
        rendered_server = (
            colors.paint(server, SERVER_INFO_COLOR) if colors is not None else server
        )
        parts.append(f"Server={rendered_server}")
    if framework_parts:
        rendered_frameworks = []
        for key, _detail, value in framework_parts:
            rendered_frameworks.append(
                colors.paint(value, FRAMEWORK_COLOR.get(key, "1;36"))
                if colors is not None else value
            )
        parts.append(f"Framework={'; '.join(rendered_frameworks)}")
    if version:
        parts.append(f"Version={version}")
    if len(parts) == 1:
        parts.append(f"서버 헤더 {len(result.server_info)}개")
    return " | ".join(parts)


def write_csv(path: Path, results: list[Result]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow((
            "no", "status", "url", "domain", "ip",
            "server", "framework", "version", "remarks",
        ))
        for number, result in enumerate(results, 1):
            primary_ip = result.resolved_ips[0] if result.resolved_ips else ""
            additional_ips = result.resolved_ips[1:]
            remarks = (
                "추가 IP: " + "; ".join(additional_ips)
                if additional_ips else ""
            )
            writer.writerow((
                number,
                result.detection_status,
                result.landing or result.target,
                result.domain,
                primary_ip,
                csv_server(result),
                csv_framework(result),
                csv_versions(result),
                remarks,
            ))


def enable_windows_ansi() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
        handle = ctypes.windll.kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except (AttributeError, OSError):
        pass


def report(results: list[Result]) -> str:
    detected = sum(result.detected for result in results)
    lines = [
        "웹 서버 및 프레임워크 조사 결과",
        "=" * 72,
        "",
        "[전체 요약]",
        f"- 전체 대상: {len(results)}개",
        f"- 탐지: {detected}개",
        f"- 미탐: {len(results) - detected}개",
        "",
        "[판정 기준]",
        "- 탐지: HTTP 서버, 런타임, CMS 또는 프레임워크 단서를 하나 이상 확인",
        "- 미탐: DNS/IP만 확인됐거나 HTTP 응답에서 기술 정보를 식별하지 못함",
        "- 기술 식별 순서: URL 확장자/경로 > 세션 쿠키 > 응답 헤더 > HTML 본문",
        "- 복수 기술: 독립된 강한 증거와 프런트엔드 증거는 함께 표시",
        "- 충돌 증거: 더 강한 경로/쿠키/헤더와 충돌하는 본문 단서는 상세 항목에만 기록",
        "- 버전은 응답에 실제 노출된 값만 기록하며 설치 패키지 버전을 보증하지 않음",
        "",
    ]
    for result in results:
        status = result.detection_status
        lines.extend([
            "=" * 72,
            f"[{status}] {result.landing or result.target}",
            "",
            "[핵심 정보]",
            f"- 입력 대상: {result.target}",
            f"- 도메인: {result.domain or '-'}",
            f"- IP: {', '.join(result.resolved_ips) or '-'}",
            f"- 최종 URL: {result.landing or '-'}",
            f"- HTTP 상태: {result.status if result.status is not None else '-'}",
            f"- 서버: {csv_server(result) or '-'}",
            f"- 프레임워크: {csv_framework(result) or '-'}",
            f"- 노출 버전: {csv_versions(result) or '-'}",
            "- 선택 모듈: " + ", ".join(
                MODULES[key].label for key in result.selected_modules if key in MODULES
            ),
            "- 우선 식별 모듈: " + (
                ", ".join(MODULES[key].label for key in result.primary_modules if key in MODULES)
                or "없음"
            ),
            "- 식별 우선 근거: " + DETECTION_SOURCE.get(result.technology_source, "없음"),
            "",
            "[스캔 유형별 결과]",
        ])
        lines.extend(f"- {name}: {outcome}" for name, outcome in result.scan_type_summary())
        lines.extend(["", "[서버 정보]"])
        lines.extend(f"- {item}" for item in result.server_info)
        if not result.server_info:
            lines.append("- 없음")
        lines.extend(["", "[기술 및 프레임워크 증거]"])
        for key in result.selected_modules:
            if key not in MODULES:
                continue
            lines.append(f"- {MODULES[key].label}:")
            lines.extend(f"    · {item}" for item in result.technology_evidence.get(key, []))
            if not result.technology_evidence.get(key):
                lines.append("    · 없음")
        if result.sapi_hints:
            lines.extend(["", "[SAPI/스택 단서]"])
            lines.extend(f"- {item}" for item in result.sapi_hints)
        if "php" in result.selected_modules:
            lines.extend(["", "[PHP 추가 증거]"])
            for key, label in (
                ("headers", "HTTP 헤더"),
                ("client", "HTML/JS"),
                ("info_pages", "정보 페이지"),
                ("php_paths", "PHP 경로"),
                ("wordpress", "WordPress"),
            ):
                lines.append(f"- {label}:")
                lines.extend(f"    · {item}" for item in result.evidence[key])
                if not result.evidence[key]:
                    lines.append("    · 없음")
        lines.extend([
            "",
            "[실제 요청한 추가 경로]",
            "- 정보 페이지: " + (", ".join(result.checked_info) or "없음"),
            "- JavaScript: " + (", ".join(result.checked_js) or "없음"),
            "- 백엔드 URL: " + (", ".join(result.checked_backend_urls) or "없음"),
            "- WordPress 경로: " + (", ".join(result.checked_wordpress) or "없음"),
        ])
        if result.errors:
            lines.extend(["", "[오류]"])
            lines.extend(f"- {error}" for error in result.errors)
        lines.append("")
    lines.extend([
        "=" * 72,
        "[CLI 결과]",
        *[format_cli_result(result) for result in results],
    ])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    if os.name == "nt":
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(
        description="허가된 웹 자산의 서버 정보와 PHP/JSP/ASP/Node.js 기술 단서를 확인합니다."
    )
    parser.add_argument("targets", nargs="*", metavar="TARGET", help="URL 또는 도메인")
    parser.add_argument("-f", "--file", type=Path, metavar="FILE", help="대상 목록 파일 (한 줄에 하나)")
    parser.add_argument("-o", "--output", type=Path, metavar="FILE", help="상세 결과 저장 경로")
    parser.add_argument("--csv", type=Path, metavar="FILE",
                        help="URL·도메인·IP·서버·프레임워크·버전 CSV 저장 경로")
    parser.add_argument(
        "-e", "--extension", "--technology", dest="extensions", action="append", metavar="TYPE",
        help="탐지 모듈: php, jsp, asp, nodejs, all (반복/쉼표 지정 가능, 기본 all)",
    )
    parser.add_argument("--list-modules", action="store_true", help="사용 가능한 탐지 모듈을 출력하고 종료")
    parser.add_argument("--timeout", type=float, default=5, metavar="SEC", help="요청별 제한 시간 (기본 5초)")
    parser.add_argument("--max-js", type=int, default=3, metavar="N", help="대상별 읽을 동일 호스트 JS 수 (기본 3)")
    parser.add_argument("--max-backend-links", "--max-php-links", dest="max_php_links",
                        type=int, default=5, metavar="N",
                        help="HTML/JS에서 발견한 백엔드 URL을 추가로 GET (기본 5, 0이면 비활성)")
    parser.add_argument("--probe-wordpress", dest="wordpress_probe", action="store_const", const="force",
                        help="WordPress 흔적이 없어도 wp-login 등 경로를 탐색")
    parser.add_argument("--no-probe-wordpress", dest="wordpress_probe", action="store_const", const="off",
                        help="WordPress 경로 탐색 비활성")
    parser.set_defaults(wordpress_probe="auto")
    parser.add_argument("--insecure", action="store_true", help="내부 자체 서명 인증서 허용")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                        help="ANSI 색상 (기본 auto)")
    parser.add_argument("--no-color", dest="color", action="store_const", const="never",
                        help="--color never와 동일")
    args = parser.parse_args(argv)
    if args.list_modules:
        print("사용 가능: all, php, jsp(java/servlet), asp(aspx/dotnet), nodejs(node)")
        return 0
    try:
        selected_modules = resolve_modules(args.extensions)
    except ValueError as exc:
        parser.error(str(exc))
    if args.timeout <= 0 or args.max_js < 0 or args.max_php_links < 0:
        parser.error("--timeout은 0보다 크고 --max-js, --max-php-links는 0 이상이어야 합니다")

    targets = list(args.targets)
    if args.file:
        try:
            targets.extend(line.strip() for line in args.file.read_text(encoding="utf-8-sig").splitlines()
                           if line.strip() and not line.lstrip().startswith("#"))
        except OSError as exc:
            parser.error(f"대상 파일 읽기 실패: {exc}")
    targets = list(dict.fromkeys(targets))
    if not targets:
        parser.error("TARGET 또는 -f FILE이 필요합니다")

    enable_windows_ansi()
    colors = Colors(args.color == "always" or (args.color == "auto" and sys.stdout.isatty()
                    and "NO_COLOR" not in os.environ))
    banner_separator = "=" * max(len(line) for line in BANNER.splitlines())
    print(colors.paint(f"{banner_separator}\n{BANNER}\n{banner_separator}", "1;36"))
    scanner = Scanner(
        args.timeout,
        args.max_js,
        args.insecure,
        args.max_php_links,
        args.wordpress_probe,
        selected_modules,
    )
    results: list[Result] = []
    started = time.monotonic()
    for target in targets:
        try:
            result = scanner.scan(target)
        except ValueError as exc:
            result = Result(target=target, selected_modules=[module.key for module in selected_modules])
            result.errors.append(str(exc))
            finalize_result(result)
        results.append(result)
        print(format_cli_result(result, colors))

    detected = sum(result.detected for result in results)
    summary = " | ".join((
        colors.paint(f"탐지 {detected}개", STATUS_COLOR[STATUS_DETECTED]),
        colors.paint(f"미탐 {len(results) - detected}개", STATUS_COLOR[STATUS_NOT_DETECTED]),
    ))
    print(colors.paint(f"\n[*] 완료: 전체 {len(results)}개", "1;36")
          + f" :::>> {summary} | {time.monotonic()-started:.1f}초")
    if args.output:
        try:
            args.output.write_text(report(results), encoding="utf-8")
        except OSError as exc:
            print(colors.paint(f"결과 저장 실패: {exc}", "31"), file=sys.stderr)
            return 1
        print(f"상세 결과: {args.output.resolve()}")
    if args.csv:
        try:
            write_csv(args.csv, results)
        except OSError as exc:
            print(colors.paint(f"CSV 저장 실패: {exc}", "31"), file=sys.stderr)
            return 1
        print(f"CSV 결과: {args.csv.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
