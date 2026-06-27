#!/usr/bin/env python3
"""Build the self-contained granturismo bundle.

The library is pure standard-library Python with no third-party runtime
dependencies, so the bundle is just the package plus a small launcher.  Layout
of the produced tarball::

    proxy-wrapper.py          # launcher run by systemd / the installer
    granturismo/              # the library package
    granturismo/proxy.py      # the UDP -> NDJSON proxy
    VERSION.txt
    README-BUNDLE.md

The version is taken from ``git describe`` (the ``v`` prefix is stripped).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def detect_version(lib_root: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(lib_root), "describe", "--tags", "--always"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        return out[1:] if out.startswith("v") else out
    except Exception:
        return "0.0.0+" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")


def stage_bundle(lib_root: Path, stage: Path, version: str) -> None:
    package = lib_root / "src" / "granturismo"
    proxy = lib_root / "src" / "proxy.py"
    wrapper = lib_root / "src" / "proxy-wrapper.py"
    for required in (package, proxy, wrapper):
        if not required.exists():
            raise SystemExit(f"missing {required}")

    shutil.copytree(package, stage / "granturismo")
    shutil.copy2(proxy, stage / "granturismo" / "proxy.py")
    shutil.copy2(wrapper, stage / "proxy-wrapper.py")
    (stage / "proxy-wrapper.py").chmod(0o755)

    # Drop bytecode caches so the artifact is reproducible.
    for cache in stage.rglob("__pycache__"):
        shutil.rmtree(cache, ignore_errors=True)

    (stage / "VERSION.txt").write_text(version + "\n", encoding="utf-8")
    (stage / "README-BUNDLE.md").write_text(
        f"granturismo self-contained bundle\n"
        f"version: {version}\n\n"
        f"Run:\n"
        f"  python3 proxy-wrapper.py --ps-ip 192.168.x.y "
        f"--jsonl-output udp://127.0.0.1:5600\n",
        encoding="utf-8",
    )


def make_tarball(stage: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w:gz") as tar:
        for child in sorted(stage.iterdir()):
            tar.add(child, arcname=child.name)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the granturismo bundle")
    parser.add_argument("--lib-root", required=True,
                        help="path to the repo (contains src/granturismo)")
    parser.add_argument("--output", required=True, help="output .tar.gz path")
    args = parser.parse_args()

    lib_root = Path(args.lib_root).resolve()
    output = Path(args.output).resolve()
    version = detect_version(lib_root)

    stage = Path(tempfile.mkdtemp(prefix="gt7-bundle-"))
    try:
        stage_bundle(lib_root, stage, version)
        make_tarball(stage, output)
        print(f"wrote {output} (version {version})")
    finally:
        shutil.rmtree(stage, ignore_errors=True)


if __name__ == "__main__":
    main()
