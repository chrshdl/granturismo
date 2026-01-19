#!/usr/bin/env python3
import os
import runpy
import sys
from pathlib import Path

# This script lives at the root of the bundle (/opt/granturismo/proxy-wrapper.py)
install_dir = Path(__file__).resolve().parent
vendor = install_dir / "vendor"

# add vendor dependencies to sys.path
if vendor.exists():
    sys.path.insert(0, str(vendor))

# add the install dir itself so 'import granturismo' works
sys.path.insert(0, str(install_dir))

# locate the actual proxy script
# build_tarball.py places it at: ./granturismo/proxy.py
target = install_dir / "granturismo" / "proxy.py"

if not target.exists():
    sys.stderr.write(f"proxy-wrapper.py: Critical error. Could not find {target}\n")
    sys.exit(1)

# handover execution
os.chdir(str(install_dir))
sys.argv = ["proxy.py"] + sys.argv[1:]
runpy.run_path(str(target), run_name="__main__")
