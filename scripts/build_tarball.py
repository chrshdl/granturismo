#!/usr/bin/env python3
"""
Build a self-contained granturismo tarball using **uv**, with a pure-Python Salsa20.

Changes vs earlier version:
- Vendors **pure-salsa20** instead of salsa20 (which ships a C extension).
- Writes a small compatibility shim at `vendor/salsa20/__init__.py` that exposes
  `Salsa20_xor` and `XSalsa20_xor` API expected by older code, delegating to
  `pure_salsa20.salsa20_xor` / `pure_salsa20.xsalsa20_xor`.

Result stays architecture-independent (no .so files).
"""

import argparse
import shutil
import subprocess
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path

DEFAULT_VENDOR_DEPS = [
    "marshmallow==3.21.2",
    "marshmallow-dataclass==8.6.0",
    "typing-inspect==0.9.0",
    "typeguard==4.3.0",
    "pure-salsa20==0.1.0",
    "mypy-extensions>=1.1.0",
    "packaging>=25.0",
    "typing-extensions>=4.15.0",
]


def run(cmd, **kw):
    print("+", " ".join(map(str, cmd)))
    return subprocess.run(cmd, check=True, text=True, **kw)


def ensure_cmd_exists(cmd_name: str):
    try:
        subprocess.run([cmd_name, "--version"], check=True, capture_output=True)
    except Exception:
        raise SystemExit(
            f"Required tool '{cmd_name}' not found. Install uv:\n"
            f"  curl -LsSf https://astral.sh/uv/install.sh | sh\n"
            f"or on CI use: astral-sh/setup-uv\n"
        )


def ensure_pure_python(dir_path: Path):
    bad = []
    for p in dir_path.rglob("*"):
        if p.suffix in {".so", ".pyd", ".dylib"}:
            bad.append(p)
    if bad:
        raise SystemExit(f"ERROR: Non-pure-Python artifacts found in vendor/: {bad}")


def copy_lib(lib_root: Path, dest: Path):
    src_pkg = lib_root / "src" / "granturismo"
    if not src_pkg.exists():
        raise SystemExit(
            f"Could not find {src_pkg}. Provide --lib-root pointing to the library checkout."
        )
    shutil.copytree(src_pkg, dest / "granturismo", dirs_exist_ok=True)


def write_version(dest: Path, lib_root: Path):
    ver = None
    try:
        cp = subprocess.run(
            ["git", "-C", str(lib_root), "describe", "--tags", "--always"],
            check=True,
            capture_output=True,
            text=True,
        )
        ver = cp.stdout.strip()
    except Exception:
        ver = "0.0.0+" + datetime.utcnow().strftime("%Y%m%d%H%M%S")
    (dest / "VERSION.txt").write_text(ver + "\n", encoding="utf-8")
    return ver


def write_bundle_readme(dest: Path, version: str):
    (dest / "README-BUNDLE.md").write_text(
        f"""\
granturismo self-contained bundle
version: {version}

Contents:
  - granturismo/ (library package)
  - granturismo/proxy.py (UDP->JSONL proxy)
  - vendor/ (pure-Python dependencies; shimmed salsa20)

Run (manually):
  python3 granturismo/proxy.py --ps-ip 192.168.x.y --jsonl-output udp://127.0.0.1:5600
""",
        encoding="utf-8",
    )


def vendor_deps_with_uv(dest: Path, deps: list[str]):
    ensure_cmd_exists("uv")
    vendor = dest / "vendor"
    vendor.mkdir(parents=True, exist_ok=True)
    cmd = ["uv", "pip", "install", "--no-deps", "--target", str(vendor)] + deps
    run(cmd)
    ensure_pure_python(vendor)
    # Add salsa20 compat shim
    shim_dir = vendor / "salsa20"
    shim_dir.mkdir(parents=True, exist_ok=True)
    shim = shim_dir / "__init__.py"
    shim.write_text(
        "from __future__ import annotations\n"
        "import pure_salsa20 as _p\n"
        "def Salsa20_xor(message: bytes, nonce: bytes, key: bytes) -> bytes:\n"
        "    # pure_salsa20 takes (key, nonce, plaintext)\n"
        "    return _p.salsa20_xor(key, nonce, message)\n"
        "def XSalsa20_xor(message: bytes, nonce: bytes, key: bytes) -> bytes:\n"
        "    return _p.xsalsa20_xor(key, nonce, message)\n",
        encoding="utf-8",
    )


def stage_proxy(dest: Path, kit_root: Path | None = None):
    # Expect proxy.py adjacent to this script under ../src/proxy.py when used from the kit;
    # if not found, try ./src/proxy.py relative to CWD.
    candidates = []
    if kit_root:
        candidates.append(kit_root / "src" / "proxy.py")
    candidates.append(Path(__file__).resolve().parent.parent / "src" / "proxy.py")
    candidates.append(Path.cwd() / "src" / "proxy.py")
    for c in candidates:
        if c.exists():
            proxy_src = c
            break
    else:
        raise SystemExit("Missing src/proxy.py (the UDP->JSONL proxy script).")
    shutil.copy2(proxy_src, dest / "granturismo" / "proxy.py")


def make_tarball(stage: Path, output: Path):
    with tarfile.open(output, "w:gz") as tf:
        for child in stage.iterdir():
            tf.add(child, arcname=child.name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--lib-root",
        required=True,
        help="Path to the granturismo repo (contains src/granturismo)",
    )
    ap.add_argument("--output", required=True, help="Output .tar.gz path")
    ap.add_argument(
        "--deps", nargs="*", default=DEFAULT_VENDOR_DEPS, help="Deps to vendor with uv"
    )
    ap.add_argument(
        "--kit-root",
        default=None,
        help="(Optional) path to kit root if running from elsewhere",
    )
    args = ap.parse_args()

    lib_root = Path(args.lib_root).resolve()
    out = Path(args.output).resolve()
    kit_root = Path(args.kit_root).resolve() if args.kit_root else None

    stage = Path(tempfile.mkdtemp(prefix="gt7-bundle-"))
    try:
        print(f"Staging at {stage}")
        copy_lib(lib_root, stage)
        stage_proxy(stage, kit_root=kit_root)
        vendor_deps_with_uv(stage, args.deps)
        version = write_version(stage, lib_root)
        write_bundle_readme(stage, version)
        out.parent.mkdir(parents=True, exist_ok=True)
        make_tarball(stage, out)
        print(f"Wrote bundle: {out}")
    finally:
        import shutil

        shutil.rmtree(stage, ignore_errors=True)


if __name__ == "__main__":
    main()

