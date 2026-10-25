"""Shared types for declarative server-side technology fingerprints."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ResponseView:
    url: str
    status: int
    headers: dict[str, str]
    text: str
    content_type: str


@dataclass(frozen=True)
class Finding:
    module: str
    category: str
    value: str
    source: str
    location: str
    confidence: str = "medium"

    def render(self) -> str:
        return (
            f"{self.category}: {self.value} "
            f"[{self.confidence}/{self.location}] ({self.source})"
        )


@dataclass(frozen=True)
class Signature:
    location: str
    pattern: re.Pattern[str]
    category: str
    value: str
    confidence: str = "medium"
    header: str = ""


class TechnologyModule:
    """Base class used by PHP/JSP/ASP/Node.js fingerprint modules."""

    key = ""
    label = ""
    aliases: tuple[str, ...] = ()
    route_suffixes: tuple[str, ...] = ()
    signatures: tuple[Signature, ...] = ()

    def inspect(self, response: ResponseView) -> list[Finding]:
        findings: list[Finding] = []
        header_map = {name.lower(): value for name, value in response.headers.items()}
        for signature in self.signatures:
            if signature.location == "body":
                haystacks = (response.text,)
            elif signature.location == "path":
                haystacks = (urlsplit(response.url).path,)
            elif signature.location == "header":
                if signature.header:
                    haystacks = (header_map.get(signature.header.lower(), ""),)
                else:
                    haystacks = tuple(
                        f"{name}: {value}" for name, value in response.headers.items()
                    )
            else:
                continue
            if any(signature.pattern.search(value) for value in haystacks if value):
                findings.append(Finding(
                    module=self.key,
                    category=signature.category,
                    value=signature.value,
                    source=response.url,
                    location=(
                        "cookie"
                        if (signature.header.lower() == "set-cookie"
                            and signature.category in {"세션", "프레임워크"})
                        else signature.location
                    ),
                    confidence=signature.confidence,
                ))
        if self.matches_path(response.url):
            findings.append(Finding(
                module=self.key,
                category="경로",
                value=urlsplit(response.url).path,
                source=response.url,
                location="path",
                confidence="high",
            ))
        unique: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        for finding in findings:
            marker = (finding.category, finding.value, finding.source)
            if marker not in seen:
                seen.add(marker)
                unique.append(finding)
        return unique

    def matches_path(self, url: str) -> bool:
        path = urlsplit(url).path.lower()
        return any(path.endswith(suffix) or f"{suffix}/" in path for suffix in self.route_suffixes)


def regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.I)
