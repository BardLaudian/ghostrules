#!/usr/bin/env python3
"""Build the playground site: ``web/`` plus the ghostrules wheel built from this checkout.

    python scripts/build_site.py [OUT_DIR]      # default: _site

The page loads the wheel from its own origin (``wheel.txt`` names it).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def build(out: Path) -> Path:
    """Write the site into ``out`` (replaced) and return the wheel path."""
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(ROOT / "web", out)
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            [sys.executable, "-m", "pip", "wheel", str(ROOT), "--no-deps", "-q", "-w", tmp],
            check=True,
        )
        wheels = list(Path(tmp).glob("ghostrules-*.whl"))
        if len(wheels) != 1:
            raise SystemExit(f"expected one wheel, found {len(wheels)}")
        wheel = out / wheels[0].name
        shutil.copy2(wheels[0], wheel)
    (out / "wheel.txt").write_text(wheel.name + "\n", encoding="utf-8")
    (out / ".nojekyll").write_text("", encoding="utf-8")
    return wheel


if __name__ == "__main__":
    print(build(Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "_site")))
