"""Generic HTTP server and intermediary information collection."""

from __future__ import annotations

from .base import Finding, ResponseView


SERVER_HEADERS = {
    "server": "웹 서버",
    "via": "프록시/Via",
    "x-powered-by": "런타임",
    "x-generator": "생성기",
    "x-aspnet-version": "ASP.NET 버전",
    "x-aspnetmvc-version": "ASP.NET MVC 버전",
    "x-runtime": "런타임 정보",
    "x-served-by": "처리 서버",
    "x-backend-server": "백엔드 서버",
}


def inspect_server(response: ResponseView) -> list[Finding]:
    findings: list[Finding] = []
    for name, value in response.headers.items():
        category = SERVER_HEADERS.get(name.lower())
        if category and value.strip():
            findings.append(Finding(
                module="server",
                category=category,
                value=f"{name}: {value[:240]}",
                source=response.url,
                location="header",
                confidence="observed",
            ))
    return findings
