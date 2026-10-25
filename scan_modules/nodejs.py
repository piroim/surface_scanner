"""Node.js server runtime and server-side JavaScript framework fingerprints."""

from __future__ import annotations

from .base import Signature, TechnologyModule, regex


class NodejsModule(TechnologyModule):
    key = "nodejs"
    label = "Node.js"
    aliases = ("node", "nodejs")
    # .js is intentionally excluded: browser JavaScript is not proof of Node.js.
    route_suffixes: tuple[str, ...] = ()
    signatures = (
        Signature("header", regex(r"\bExpress\b"), "프레임워크", "Express", "high", "x-powered-by"),
        Signature("header", regex(r"\bNuxt\b"), "프레임워크", "Nuxt", "high", "x-powered-by"),
        Signature("header", regex(r"\bNuxt\b"), "프런트엔드", "Vue.js", "high", "x-powered-by"),
        Signature("header", regex(r"\bNode(?:\.js)?\b"), "런타임", "Node.js", "high", "server"),
        Signature("header", regex(r"connect\.sid"), "세션", "Express/Connect session", "high", "set-cookie"),
        Signature("body", regex(r"<script[^>]+id=[\"']__NEXT_DATA__[\"']|/_next/static/"), "프레임워크", "Next.js", "high"),
        Signature("body", regex(r"/__nuxt/|/_nuxt/|__NUXT__"), "프레임워크", "Nuxt", "high"),
        Signature("body", regex(r"/__nuxt/|/_nuxt/|__NUXT__"), "프런트엔드", "Vue.js", "high"),
        Signature(
            "body",
            regex(r"data-v-app|data-v-[0-9a-f]{6,}|__VUE__|vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js"),
            "프런트엔드",
            "Vue.js",
            "high",
        ),
        Signature("body", regex(r"__remixContext|/build/_assets/"), "프레임워크", "Remix", "medium"),
        Signature("body", regex(r"data-sveltekit|__sveltekit"), "프레임워크", "SvelteKit", "medium"),
    )


MODULE = NodejsModule()
