#!/usr/bin/env python3
"""Sign a release artifact with an Ed25519 private key.

Reads a PEM-encoded Ed25519 private key from the ``GT_SIGNING_KEY`` environment
variable, signs the raw bytes of the given file, and writes a 64-byte Ed25519
signature next to it as ``<artifact>.sig``.

The instrument-cluster installer verifies this signature in-process with the
matching public key (baked into the installer), using the same ``cryptography``
library that ships on the appliance.
"""

from __future__ import annotations

import os
import sys

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: sign_artifact.py <artifact>\n")
        return 2
    artifact = argv[1]

    pem = os.environ.get("GT_SIGNING_KEY")
    if not pem:
        sys.stderr.write("GT_SIGNING_KEY is not set\n")
        return 2

    key = load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        sys.stderr.write("GT_SIGNING_KEY is not an Ed25519 private key\n")
        return 2

    with open(artifact, "rb") as f:
        data = f.read()
    signature = key.sign(data)

    out = artifact + ".sig"
    with open(out, "wb") as f:
        f.write(signature)
    print(f"wrote {out} ({len(signature)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
