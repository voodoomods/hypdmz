"""
Regenerate hypdmz.com's generated files:

    site/app/{hypgraph.js, hypgraph.css, vendor/}   the HypGraph UI, copied from the installed hypgraph package

and check that every page's href / src is relative (the site must work at / and under /hypdmz/ on github.io).

    python dev/build_site.py
"""
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

from hypgraph import __version__ as hypgraph_version
from hypgraph.ui import static_dir

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"


def main() -> None:
    ui = static_dir()
    app = SITE / "app"
    app.mkdir(parents=True, exist_ok=True)
    for f in ("hypgraph.js", "hypgraph.css"):
        shutil.copy2(ui / f, app / f)
    shutil.copytree(ui / "vendor", app / "vendor", dirs_exist_ok=True)
    print(f"  site/app/ from hypgraph {hypgraph_version}")
    bad = []
    for f in SITE.rglob("*.html"):
        if f.name == "404.html":
            continue
        bad += [f"{f.relative_to(SITE)}: {m}" for m in re.findall(r'(?:href|src)="/(?!/)[^"]*"', f.read_text(encoding="utf-8"))]
    if bad:
        sys.exit("root-absolute paths break the site under a prefix:\n  " + "\n  ".join(bad[:20]))
    print("  paths: all relative")


if __name__ == "__main__":
    main()
