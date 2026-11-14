#!/usr/bin/env python3
"""Emit the build-pinned SHA-256 digest for the trusted ZAOD init ELF."""

import hashlib
import os
import sys


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"Usage: {sys.argv[0]} INIT_ELF OUTPUT_HEADER")
    with open(sys.argv[1], "rb") as source:
        digest = hashlib.sha256(source.read()).digest()
    values = ", ".join(f"0x{value:02x}" for value in digest)
    output = (
        "#ifndef ZAOD_TRUSTED_INIT_HASH_H\n"
        "#define ZAOD_TRUSTED_INIT_HASH_H\n"
        f"#define ZAOD_TRUSTED_INIT_SHA256 {{{values}}}\n"
        "#endif\n"
    )
    os.makedirs(os.path.dirname(sys.argv[2]), exist_ok=True)
    with open(sys.argv[2], "w", encoding="ascii") as destination:
        destination.write(output)


if __name__ == "__main__":
    main()
