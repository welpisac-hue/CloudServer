#!/usr/bin/env python3
"""
Production frontend build: minify public assets from frontend/ sources.
Vercel runs this via buildCommand before serving public/.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "frontend"
PUBLIC = ROOT / "public"


def _strip_js_comments(src: str) -> str:
    out = []
    i = 0
    n = len(src)
    in_squote = in_dquote = in_template = False
    escape = False
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        if in_squote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == "'":
                in_squote = False
            i += 1
            continue
        if in_dquote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_dquote = False
            i += 1
            continue
        if in_template:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == "`":
                in_template = False
            i += 1
            continue

        if ch == "'":
            in_squote = True
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            in_dquote = True
            out.append(ch)
            i += 1
            continue
        if ch == "`":
            in_template = True
            out.append(ch)
            i += 1
            continue

        if ch == "/" and nxt == "/":
            i += 2
            while i < n and src[i] not in "\r\n":
                i += 1
            continue
        if ch == "/" and nxt == "*":
            i += 2
            while i + 1 < n and not (src[i] == "*" and src[i + 1] == "/"):
                i += 1
            i = min(i + 2, n)
            continue

        out.append(ch)
        i += 1
    return "".join(out)


def minify_js(src: str) -> str:
    src = _strip_js_comments(src)
    src = re.sub(r"[ \t]+\n", "\n", src)
    src = re.sub(r"\n{3,}", "\n\n", src)
    src = re.sub(r"[ \t]{2,}", " ", src)
    banner = "/* Pulse Control Panel - production build (source in /frontend) */\n"
    return banner + src.strip() + "\n"


def minify_css(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"\s+", " ", src)
    src = re.sub(r"\s*([{}:;,>~+])\s*", r"\1", src)
    src = src.replace(";}", "}")
    return "/* Pulse Control Panel - production CSS */\n" + src.strip() + "\n"


def main() -> None:
    if not (SRC / "app.js").exists():
        raise SystemExit("frontend/app.js missing — edit sources under frontend/")

    PUBLIC.mkdir(parents=True, exist_ok=True)
    (PUBLIC / "downloads").mkdir(parents=True, exist_ok=True)

    # HTML copied as-is (login gate + structure)
    shutil.copy2(SRC / "index.html", PUBLIC / "index.html")
    (PUBLIC / "app.js").write_text(
        minify_js((SRC / "app.js").read_text(encoding="utf-8")),
        encoding="utf-8",
    )
    (PUBLIC / "style.css").write_text(
        minify_css((SRC / "style.css").read_text(encoding="utf-8")),
        encoding="utf-8",
    )
    print("Built minified frontend -> public/")


if __name__ == "__main__":
    main()
