"""Technology module registry used by surface_scan.py."""

from __future__ import annotations

from .asp import MODULE as ASP
from .base import Finding, ResponseView, TechnologyModule
from .jsp import MODULE as JSP
from .nodejs import MODULE as NODEJS
from .php import MODULE as PHP
from .server import inspect_server


MODULES: dict[str, TechnologyModule] = {
    module.key: module for module in (PHP, JSP, ASP, NODEJS)
}

ALIASES = {
    alias.lower(): module.key
    for module in MODULES.values()
    for alias in module.aliases
}
ALIASES["all"] = "all"


def resolve_modules(values: list[str] | None) -> tuple[TechnologyModule, ...]:
    if not values:
        return tuple(MODULES.values())
    requested: list[str] = []
    for raw in values:
        for value in raw.split(","):
            normalized = value.strip().lower()
            if not normalized:
                continue
            key = ALIASES.get(normalized)
            if key is None:
                choices = ", ".join(("all", *MODULES))
                raise ValueError(f"지원하지 않는 탐지 모듈: {value} (사용 가능: {choices})")
            if key == "all":
                return tuple(MODULES.values())
            if key not in requested:
                requested.append(key)
    if not requested:
        raise ValueError("탐지 모듈을 하나 이상 지정해야 합니다")
    return tuple(MODULES[key] for key in requested)


__all__ = [
    "Finding", "MODULES", "ResponseView", "TechnologyModule",
    "inspect_server", "resolve_modules",
]
