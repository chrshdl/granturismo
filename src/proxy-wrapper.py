#!/usr/bin/env python3
"""Entry point for the self-contained granturismo bundle.

Installed at the bundle root (e.g. ``/opt/granturismo/proxy-wrapper.py``).  It
puts the bundled package (and an optional ``vendor/`` directory of pure-Python
dependencies, if present) on ``sys.path`` and hands off to the real proxy at
``granturismo/proxy.py``.  This lets the appliance run the proxy with the stock
system ``python3`` and no installed packages.
"""

from __future__ import annotations

import os
import runpy
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
proxy = root / "granturismo" / "proxy.py"

if not proxy.exists():
    sys.stderr.write(f"proxy-wrapper.py: could not find {proxy}\n")
    raise SystemExit(1)

# Make `import granturismo` work, and pick up vendored deps if the bundle ships any.
vendor = root / "vendor"
if vendor.is_dir():
    sys.path.insert(0, str(vendor))
sys.path.insert(0, str(root))

os.chdir(root)
sys.argv = ["proxy.py"] + sys.argv[1:]
runpy.run_path(str(proxy), run_name="__main__")
