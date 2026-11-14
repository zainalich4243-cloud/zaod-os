#!/usr/bin/env python3
"""Fail-closed local hash scanner used by the ZAOD package installer."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

import zpkg


DEFINITIONS_DOMAIN = b"ZAOD-ZSHIELD-DEFINITIONS-V1\0"
DEFAULT_ROOT = Path("/etc/zaod/zshield")
MAX_SCAN_BYTES = 128 * 1024 * 1024
LABEL_RE = re.compile(r"^[A-Za-z0-9._ -]{1,96}$")


def load_definitions(
    definitions_path: Path, signature_path: Path, public_key_path: Path
) -> dict[str, Any]:
    try:
        definitions_bytes = zpkg.read_bounded_file(
            definitions_path, 8 * 1024 * 1024, "Z-Shield definitions"
        )
        signature = zpkg.read_bounded_file(signature_path, 64, "Z-Shield signature")
        if len(signature) != 64:
            zpkg.fail("Z-Shield definitions signature must be 64 bytes")
        definitions = zpkg.parse_json(definitions_bytes, "Z-Shield definitions")
        zpkg.verify_signature(
            public_key_path,
            DEFINITIONS_DOMAIN + definitions_bytes,
            signature,
        )
    except OSError as error:
        zpkg.fail(f"could not read trusted Z-Shield definitions: {error}")

    if set(definitions) != {"schema_version", "entries"}:
        zpkg.fail("Z-Shield definitions must contain schema_version and entries")
    if type(definitions["schema_version"]) is not int or definitions["schema_version"] != 1:
        zpkg.fail("unsupported Z-Shield definitions schema")
    entries = definitions["entries"]
    if not isinstance(entries, list) or len(entries) > 100_000:
        zpkg.fail("Z-Shield definitions entries must be a bounded list")

    hashes: dict[str, str] = {}
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"sha256", "label"}
            or not isinstance(entry["sha256"], str)
            or not zpkg.HASH_RE.fullmatch(entry["sha256"])
            or not isinstance(entry["label"], str)
            or not LABEL_RE.fullmatch(entry["label"])
        ):
            zpkg.fail("invalid Z-Shield hash definition entry")
        if entry["sha256"] in hashes:
            zpkg.fail("duplicate hash in Z-Shield definitions")
        hashes[entry["sha256"]] = entry["label"]
    return hashes


def hash_regular_file(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        zpkg.fail(f"cannot safely open file for scanning: {error}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            zpkg.fail(f"scanner only accepts regular files: {path}")
        if before.st_size > MAX_SCAN_BYTES:
            zpkg.fail(f"file exceeds the Z-Shield scan size limit: {path}")
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > MAX_SCAN_BYTES:
                zpkg.fail(f"file exceeds the Z-Shield scan size limit: {path}")
            digest.update(block)
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            zpkg.fail(f"file changed while Z-Shield scanned it: {path}")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def scan_file(
    path: Path,
    definitions_path: Path,
    signature_path: Path,
    public_key_path: Path,
) -> None:
    hashes = load_definitions(definitions_path, signature_path, public_key_path)
    digest = hash_regular_file(path)
    label = hashes.get(digest)
    if label is not None:
        zpkg.fail(f"Z-Shield detected a known threat ({label}): {path}")


def install_file(path: Path, data: bytes, mode: int = 0o644) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=".zshield-", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
        temporary_path.chmod(mode)
        os.replace(temporary_path, path)
    except OSError:
        temporary_path.unlink(missing_ok=True)
        raise


def sync_definitions(repo: str, public_key_path: Path, root: Path) -> None:
    if not zpkg.REPO_RE.fullmatch(repo):
        zpkg.fail("repository must be in owner/name form")
    if root.is_symlink():
        zpkg.fail(f"Z-Shield definitions directory may not be a symlink: {root}")
    root.mkdir(parents=True, exist_ok=True, mode=0o755)
    root = root.resolve(strict=True)
    owner, repository = repo.split("/", 1)
    base = f"https://github.com/{owner}/{repository}/releases/latest/download"
    definitions = zpkg.fetch_https(
        f"{base}/zshield-definitions.json", 8 * 1024 * 1024
    )
    signature = zpkg.fetch_https(f"{base}/zshield-definitions.sig", 64)

    with tempfile.TemporaryDirectory(prefix="zshield-verify-") as directory:
        definitions_path = Path(directory) / "definitions.json"
        signature_path = Path(directory) / "definitions.sig"
        definitions_path.write_bytes(definitions)
        signature_path.write_bytes(signature)
        load_definitions(definitions_path, signature_path, public_key_path)

    install_file(root / "definitions.json", definitions, 0o444)
    install_file(root / "definitions.sig", signature, 0o444)
    public_key = zpkg.read_bounded_file(public_key_path, 1024 * 1024, "public key")
    install_file(root / "definitions.pub", public_key, 0o444)
    print(f"Installed verified Z-Shield definitions in {root}")


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="z-shield")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan one regular file by SHA-256")
    scan.add_argument("path")
    scan.add_argument(
        "--definitions",
        default=os.environ.get(
            "ZAOD_ZSHIELD_DEFINITIONS", str(DEFAULT_ROOT / "definitions.json")
        ),
    )
    scan.add_argument(
        "--signature",
        default=os.environ.get(
            "ZAOD_ZSHIELD_SIGNATURE", str(DEFAULT_ROOT / "definitions.sig")
        ),
    )
    scan.add_argument(
        "--public-key",
        default=os.environ.get(
            "ZAOD_ZSHIELD_PUBLIC_KEY", str(DEFAULT_ROOT / "definitions.pub")
        ),
    )

    sync = commands.add_parser("sync", help="fetch and verify signed GitHub definitions")
    sync.add_argument("--repo", required=True)
    sync.add_argument("--public-key", required=True)
    sync.add_argument("--root", default=str(DEFAULT_ROOT))
    return parser


def main() -> int:
    parser = create_parser()
    arguments = sys.argv[1:]
    if arguments and arguments[0] == "--scan":
        arguments = ["scan", *arguments[1:]]
    args = parser.parse_args(arguments)
    try:
        if args.command == "scan":
            scan_file(
                Path(args.path),
                Path(args.definitions),
                Path(args.signature),
                Path(args.public_key),
            )
            print(f"Z-Shield: no known hash match: {args.path}")
        else:
            sync_definitions(args.repo, Path(args.public_key), Path(args.root))
    except zpkg.PackageError as error:
        print(f"Z-Shield: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"Z-Shield: operation failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
