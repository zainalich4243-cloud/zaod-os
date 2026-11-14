#!/usr/bin/env python3
"""Verify signed Z-Shield definitions and emit a kernel hash table."""

import argparse
import os
from pathlib import Path

from z_shield import load_definitions

MAX_KERNEL_DEFINITIONS = 4096


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--definitions", default=os.environ.get(
        "ZAOD_ZSHIELD_DEFINITIONS", ""))
    parser.add_argument("--signature", default=os.environ.get(
        "ZAOD_ZSHIELD_SIGNATURE", ""))
    parser.add_argument("--public-key", default=os.environ.get(
        "ZAOD_ZSHIELD_PUBLIC_KEY", ""))
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    provided = [bool(args.definitions), bool(args.signature),
                bool(args.public_key)]
    if any(provided) and not all(provided):
        parser.error("definitions, signature, and public key must be supplied together")

    definitions = {}
    if all(provided):
        definitions = load_definitions(
            Path(args.definitions), Path(args.signature), Path(args.public_key))
        if len(definitions) > MAX_KERNEL_DEFINITIONS:
            parser.error(
                f"kernel catalog exceeds {MAX_KERNEL_DEFINITIONS} hash entries")

    rows = []
    for digest, label in sorted(definitions.items()):
        raw_digest = bytes.fromhex(digest)
        bytes_text = ", ".join(f"0x{value:02x}" for value in raw_digest)
        rows.append(f'    {{{{{bytes_text}}}, "{label}"}},')
    if not rows:
        rows.append('    {{0}, ""},')
    output = (
        "#ifndef ZAOD_ZSHIELD_HASHES_H\n"
        "#define ZAOD_ZSHIELD_HASHES_H\n"
        f"#define ZAOD_ZSHIELD_CATALOG_AUTHENTICATED {int(all(provided))}\n"
        f"#define ZAOD_ZSHIELD_DEFINITION_COUNT {len(definitions)}u\n"
        "#define ZAOD_ZSHIELD_DEFINITION_INITIALIZERS { \\\n"
        + " \\\n".join(rows)
        + " \\\n}\n"
        "#endif\n"
    )
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(output, encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
