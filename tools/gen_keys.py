#!/usr/bin/env python3
"""Provision a local ZAOD Ed25519 signing key and kernel trust header."""

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PRIVATE_KEY = (
    Path.home() / ".config" / "zaod" / "keys" / "zaod_release_private.key"
)
DEFAULT_PUBLIC_HEADER = ROOT / "kernel" / "crypto" / "zaod_keys.h"


class KeyProvisionError(Exception):
    pass


def run_openssl(*arguments: str) -> bytes:
    try:
        result = subprocess.run(
            ["openssl", *arguments],
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise KeyProvisionError(f"OpenSSL invocation failed: {error}") from error
    if result.returncode:
        raise KeyProvisionError(
            result.stderr.decode("utf-8", "replace").strip()
            or "OpenSSL operation failed"
        )
    return result.stdout


def provision(private_key: Path, public_header: Path, replace: bool) -> None:
    private_key = private_key.expanduser().absolute()
    public_header = public_header.expanduser().absolute()
    private_key.parent.mkdir(parents=True, exist_ok=True)
    if private_key.parent.is_symlink():
        raise KeyProvisionError("private-key directory may not be a symlink")
    private_key.parent.chmod(0o700)
    public_header.parent.mkdir(parents=True, exist_ok=True)

    if private_key.exists():
        if not private_key.is_file() or private_key.is_symlink():
            raise KeyProvisionError("private-key destination must be a regular file")
        if not replace:
            raise KeyProvisionError(
                f"private key already exists: {private_key}; use --replace to rotate it"
            )
        private_key.unlink()

    if public_header.exists() and not replace:
        try:
            current_header = public_header.read_text(encoding="ascii")
        except (OSError, UnicodeError) as error:
            raise KeyProvisionError(
                f"could not inspect public header: {error}"
            ) from error
        if "#define ZAOD_ROOT_PUBLIC_KEY_CONFIGURED 0" not in current_header:
            raise KeyProvisionError(
                f"public header is already provisioned: {public_header}; "
                "use --replace to rotate"
            )
    elif replace and not public_header.exists():
        raise KeyProvisionError("--replace requires an existing public header")

    encoded_private_key = run_openssl(
        "genpkey", "-algorithm", "ED25519", "-outform", "PEM"
    )
    private_key.write_bytes(encoded_private_key)
    private_key.chmod(0o600)
    try:
        public_der = run_openssl(
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-outform",
            "DER",
        )
        if len(public_der) < 32:
            raise KeyProvisionError("OpenSSL returned a truncated Ed25519 public key")
        public_key = public_der[-32:]
        byte_rows = []
        for offset in range(0, len(public_key), 8):
            values = ", ".join(
                f"0x{value:02x}" for value in public_key[offset:offset + 8]
            )
            byte_rows.append(f"    {values},")
        header = (
            "#ifndef ZAOD_KEYS_H\n"
            "#define ZAOD_KEYS_H\n\n"
            '#include "ed25519.h"\n\n'
            "/* Locally generated development root. Replace through a reviewed "
            "release-key ceremony. */\n"
            "#define ZAOD_ROOT_PUBLIC_KEY_CONFIGURED 1\n"
            "static const zaod_u8 ZAOD_ROOT_PUBLIC_KEY"
            "[ZAOD_ED25519_PUBLIC_KEY_SIZE] = {\n"
            + "\n".join(byte_rows)
            + "\n};\n\n"
            "#endif\n"
        )
        public_header.write_text(header, encoding="ascii")
        public_header.chmod(0o644)
    except (KeyProvisionError, OSError):
        private_key.unlink(missing_ok=True)
        raise

    print(f"Generated local signing key: {private_key}")
    print(f"Embedded public key in: {public_header}")
    print("Keep the private key offline; this is not a production key ceremony.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-key", type=Path, default=DEFAULT_PRIVATE_KEY)
    parser.add_argument("--public-header", type=Path, default=DEFAULT_PUBLIC_HEADER)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    try:
        provision(args.private_key, args.public_header, args.replace)
    except (KeyProvisionError, OSError) as error:
        print(f"gen_keys.py: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
