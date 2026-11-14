#!/usr/bin/env python3
"""Build freestanding x86_64 ZAOD apps and signed kernel-flat packages."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import struct
from pathlib import Path
from typing import Any

import zpkg


ROOT = Path(__file__).resolve().parents[1]
SDK_ROOT = ROOT / "sdk"
DEFAULT_ROOT_KEY_HEADER = ROOT / "kernel" / "crypto" / "zaod_keys.h"
FLAT_PACKAGE_DOMAIN = b"ZAOD-FLAT-PKG-V1\0"
FLAT_PACKAGE_HEADER = struct.Struct("<4sHHIIII")
FLAT_PACKAGE_HEADER_SIZE = FLAT_PACKAGE_HEADER.size + 64
FLAT_PACKAGE_MAX_SIZE = 2 * 1024 * 1024
FLAT_PACKAGE_MAX_MANIFEST_SIZE = 64 * 1024
DEFAULT_PERMISSIONS = {
    "camera": "deny",
    "microphone": "deny",
    "storage": "deny",
    "notifications": "deny",
    "network": "none",
    "background": False,
}
BASE_CFLAGS = [
    "-O2",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-m64",
    "-mno-red-zone",
    "-mno-sse",
    "-mno-sse2",
    "-mno-mmx",
    "-mno-avx",
    "-msoft-float",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-pic",
    "-fno-pie",
    "-fno-stack-protector",
    "-fno-asynchronous-unwind-tables",
    "-fno-unwind-tables",
]


class ZaodcError(Exception):
    """Raised for invalid projects or failed toolchain operations."""


def root_public_key_from_header(header_path: Path) -> bytes:
    try:
        content = header_path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise ZaodcError(f"could not read kernel root-key header: {error}") from error
    if "#define ZAOD_ROOT_PUBLIC_KEY_CONFIGURED 1" not in content:
        raise ZaodcError("kernel root public key is not configured")
    match = re.search(r"ZAOD_ROOT_PUBLIC_KEY[^=]*=\s*\{([^}]*)\}", content)
    if match is None:
        raise ZaodcError("kernel root public key array is missing")
    values = re.findall(r"0x([0-9a-fA-F]{2})", match.group(1))
    if len(values) != 32:
        raise ZaodcError("kernel root public key must contain exactly 32 bytes")
    return bytes(int(value, 16) for value in values)


def flat_signing_message(manifest: bytes, elf: bytes) -> bytes:
    return (
        FLAT_PACKAGE_DOMAIN
        + struct.pack("<II", len(manifest), len(elf))
        + hashlib.sha256(manifest).digest()
        + hashlib.sha256(elf).digest()
    )


def parse_flat_package(
    package: bytes, public_key_path: Path
) -> tuple[dict[str, Any], bytes]:
    if len(package) < FLAT_PACKAGE_HEADER_SIZE or len(package) > FLAT_PACKAGE_MAX_SIZE:
        raise ZaodcError("flat .zaod package size is outside kernel limits")
    magic, version, header_size, manifest_offset, manifest_size, elf_offset, elf_size = (
        FLAT_PACKAGE_HEADER.unpack_from(package)
    )
    if (
        magic != b"ZAOD"
        or version != 1
        or header_size != FLAT_PACKAGE_HEADER_SIZE
        or manifest_offset != FLAT_PACKAGE_HEADER_SIZE
        or manifest_size == 0
        or manifest_size > FLAT_PACKAGE_MAX_MANIFEST_SIZE
        or elf_offset != manifest_offset + manifest_size
        or elf_size < 64
        or elf_offset + elf_size != len(package)
    ):
        raise ZaodcError("invalid flat .zaod header or payload bounds")
    signature = package[FLAT_PACKAGE_HEADER.size:header_size]
    manifest_bytes = package[manifest_offset:elf_offset]
    elf = package[elf_offset:]
    manifest = zpkg.parse_json(manifest_bytes, "flat package manifest")
    zpkg.validate_manifest(manifest)
    entrypoint = manifest.get("entrypoint")
    files = manifest.get("files")
    if (
        manifest.get("schema_version") != 2
        or entrypoint != "bin/app"
        or not isinstance(files, dict)
        or set(files) != {"bin/app"}
        or not zpkg.elf_is_x86_64(elf)
        or hashlib.sha256(elf).hexdigest() != files["bin/app"]
    ):
        raise ZaodcError("flat package must contain a matching bin/app ELF")
    zpkg.openssl_signature(
        "-verify", public_key_path,
        flat_signing_message(manifest_bytes, elf), signature,
    )
    return manifest, elf


def create_flat_package(
    stage: Path, output: Path, private_key: Path,
    root_key_header: Path,
) -> None:
    try:
        public_der = subprocess.run(
            [
                "openssl", "pkey", "-in", str(private_key),
                "-pubout", "-outform", "DER",
            ],
            check=True, capture_output=True, timeout=15,
        ).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise ZaodcError(f"could not derive signing public key: {error}") from error
    if len(public_der) < 32 or public_der[-32:] != root_public_key_from_header(
        root_key_header
    ):
        raise ZaodcError(
            "signing key does not match the kernel's embedded ZAOD root public key"
        )

    manifest = zpkg.parse_json(
        (stage / "manifest.json").read_bytes(), "staged manifest"
    )
    binary = (stage / "bin" / "app").read_bytes()
    if not zpkg.elf_is_x86_64(binary):
        raise ZaodcError("flat packages require an x86_64 ELF entrypoint")
    manifest["files"] = {"bin/app": hashlib.sha256(binary).hexdigest()}
    manifest_bytes = zpkg.canonical_json(manifest)
    if len(manifest_bytes) > FLAT_PACKAGE_MAX_MANIFEST_SIZE:
        raise ZaodcError("manifest exceeds kernel flat-package limit")
    message = flat_signing_message(manifest_bytes, binary)
    signature = zpkg.openssl_signature("-sign", private_key, message)
    elf_offset = FLAT_PACKAGE_HEADER_SIZE + len(manifest_bytes)
    package = (
        FLAT_PACKAGE_HEADER.pack(
            b"ZAOD", 1, FLAT_PACKAGE_HEADER_SIZE,
            FLAT_PACKAGE_HEADER_SIZE, len(manifest_bytes),
            elf_offset, len(binary),
        )
        + signature
        + manifest_bytes
        + binary
    )
    if len(package) > FLAT_PACKAGE_MAX_SIZE:
        raise ZaodcError("flat package exceeds the kernel's 2 MiB file limit")
    output.write_bytes(package)

    with tempfile.TemporaryDirectory(prefix="zaodc-public-") as directory:
        public_key = Path(directory) / "public.pem"
        try:
            subprocess.run(
                [
                    "openssl", "pkey", "-in", str(private_key),
                    "-pubout", "-out", str(public_key),
                ],
                check=True, capture_output=True, timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as error:
            output.unlink(missing_ok=True)
            raise ZaodcError(f"could not export signing public key: {error}") from error
        try:
            parse_flat_package(package, public_key)
        except (OSError, ZaodcError, zpkg.PackageError):
            output.unlink(missing_ok=True)
            raise


def compiler_path(candidate: str | None, default: str) -> str:
    name = candidate or default
    result = shutil.which(name)
    if result is None:
        raise ZaodcError(f"required compiler was not found: {name}")
    return result


def run_command(command: list[str], cwd: Path | None = None) -> None:
    try:
        result = subprocess.run(
            command, cwd=cwd, check=False, timeout=120
        )
    except subprocess.TimeoutExpired as error:
        raise ZaodcError(f"toolchain command timed out: {command[0]}") from error
    except OSError as error:
        raise ZaodcError(f"could not start {command[0]}: {error}") from error
    if result.returncode != 0:
        raise ZaodcError(f"toolchain command failed ({result.returncode}): {command[0]}")


def read_project(project: Path) -> tuple[Path, dict[str, Any]]:
    if project.is_symlink() or not project.is_dir():
        raise ZaodcError("project path must be a real directory")
    root = project.resolve(strict=True)
    config_path = root / "zaod.json"
    if config_path.is_symlink() or not config_path.is_file():
        raise ZaodcError("project must contain a regular zaod.json")
    try:
        config = zpkg.parse_json(config_path.read_bytes(), "zaod.json")
    except (OSError, zpkg.PackageError) as error:
        raise ZaodcError(str(error)) from error
    if set(config) != {"app_id", "version", "author", "permissions"}:
        raise ZaodcError(
            "zaod.json must contain exactly app_id, version, author, and permissions"
        )
    manifest: dict[str, Any] = {
        "schema_version": 2,
        "app_id": config["app_id"],
        "version": config["version"],
        "author": config["author"],
        "entrypoint": "bin/app",
        "permissions": config["permissions"],
        "files": {"bin/app": "0" * 64},
    }
    try:
        zpkg.validate_manifest(manifest)
    except zpkg.PackageError as error:
        raise ZaodcError(f"invalid project manifest: {error}") from error
    return root, manifest


def collect_sources(source_root: Path) -> list[Path]:
    if source_root.is_symlink() or not source_root.is_dir():
        raise ZaodcError("project must contain a real src/ directory")
    sources: list[Path] = []
    for current, directories, filenames in os.walk(source_root, followlinks=False):
        current_path = Path(current)
        for directory in directories:
            if (current_path / directory).is_symlink():
                raise ZaodcError("source tree may not contain symbolic links")
        for filename in filenames:
            path = current_path / filename
            if path.is_symlink() or not path.is_file():
                raise ZaodcError(f"unsupported source entry: {path}")
            if path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx"}:
                sources.append(path)
    if not sources:
        raise ZaodcError("project src/ tree contains no C or C++ source files")
    return sorted(sources)


def copy_assets(project: Path, stage: Path) -> None:
    assets = project / "assets"
    if not assets.exists():
        return
    if assets.is_symlink() or not assets.is_dir():
        raise ZaodcError("assets/ must be a real directory")
    for current, directories, filenames in os.walk(assets, followlinks=False):
        current_path = Path(current)
        for directory in directories:
            if (current_path / directory).is_symlink():
                raise ZaodcError("asset tree may not contain symbolic links")
        for filename in filenames:
            source = current_path / filename
            if source.is_symlink() or not source.is_file():
                raise ZaodcError(f"unsupported asset entry: {source}")
            relative = source.relative_to(assets)
            destination = stage / "assets" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)


def build_elf(project: Path, stage: Path, args: argparse.Namespace) -> None:
    sources = collect_sources(project / "src")
    cc = compiler_path(args.cc, os.environ.get("ZAOD_CC", "cc"))
    cxx = compiler_path(args.cxx, os.environ.get("ZAOD_CXX", "c++"))
    stage.mkdir(parents=True, exist_ok=False)
    (stage / "bin").mkdir()
    (stage / "assets").mkdir()
    include_flags = ["-I", str(SDK_ROOT)]
    project_include = project / "include"
    if project_include.exists():
        if project_include.is_symlink() or not project_include.is_dir():
            raise ZaodcError("include/ must be a real directory")
        include_flags.extend(["-I", str(project_include)])

    with tempfile.TemporaryDirectory(prefix="zaodc-obj-") as object_directory:
        object_root = Path(object_directory)
        objects: list[str] = []
        used_cxx = False
        for index, source in enumerate(sources):
            is_cxx = source.suffix.lower() in {".cc", ".cpp", ".cxx"}
            compiler = cxx if is_cxx else cc
            used_cxx = used_cxx or is_cxx
            object_path = object_root / f"source-{index}.o"
            standard = ["-std=c++17", "-fno-exceptions", "-fno-rtti"] if is_cxx else ["-std=c11"]
            run_command(
                [
                    compiler,
                    *standard,
                    *BASE_CFLAGS,
                    *include_flags,
                    "-c",
                    str(source),
                    "-o",
                    str(object_path),
                ],
                cwd=project,
            )
            objects.append(str(object_path))

        sdk_object = object_root / "libzaod.o"
        run_command(
            [
                cc,
                "-std=c11",
                *BASE_CFLAGS,
                "-I",
                str(SDK_ROOT),
                "-c",
                str(SDK_ROOT / "libzaod.c"),
                "-o",
                str(sdk_object),
            ]
        )
        objects.append(str(sdk_object))
        linker = cxx if used_cxx else cc
        run_command(
            [
                linker,
                "-nostdlib",
                "-static",
                "-no-pie",
                "-Wl,--build-id=none",
                f"-Wl,-T,{SDK_ROOT / 'zaod-app.ld'}",
                "-o",
                str(stage / "bin" / "app"),
                *objects,
            ]
        )
    copy_assets(project, stage)


def finalize_stage(stage: Path, manifest: dict[str, Any]) -> None:
    files: dict[str, str] = {}
    for top_level in ("bin", "assets"):
        directory = stage / top_level
        for current, directories, filenames in os.walk(directory, followlinks=False):
            current_path = Path(current)
            for name in directories:
                if (current_path / name).is_symlink():
                    raise ZaodcError("package staging tree may not contain symbolic links")
            for name in filenames:
                path = current_path / name
                if path.is_symlink() or not path.is_file():
                    raise ZaodcError(f"unsupported staged file: {path}")
                relative = path.relative_to(stage).as_posix()
                try:
                    zpkg.validate_relpath(relative)
                except zpkg.PackageError as error:
                    raise ZaodcError(str(error)) from error
                if path.stat().st_size > zpkg.MAX_FILE_BYTES:
                    raise ZaodcError(f"staged file exceeds the package size limit: {relative}")
                if len(files) >= zpkg.MAX_FILES:
                    raise ZaodcError("package contains too many payload files")
                files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest["files"] = dict(sorted(files.items()))
    try:
        zpkg.validate_manifest(manifest)
    except zpkg.PackageError as error:
        raise ZaodcError(f"generated v2 manifest is invalid: {error}") from error
    (stage / "manifest.json").write_bytes(zpkg.canonical_json(manifest) + b"\n")


def create_project(args: argparse.Namespace) -> None:
    destination = Path(args.project).expanduser()
    if os.path.lexists(destination):
        raise ZaodcError(f"project destination already exists: {destination}")
    permissions = dict(DEFAULT_PERMISSIONS)
    config = {
        "app_id": args.app_id,
        "version": args.version,
        "author": args.author,
        "permissions": permissions,
    }
    try:
        zpkg.validate_manifest(
            {
                "schema_version": 2,
                "app_id": config["app_id"],
                "version": config["version"],
                "author": config["author"],
                "entrypoint": "bin/app",
                "permissions": config["permissions"],
                "files": {"bin/app": "0" * 64},
            }
        )
    except zpkg.PackageError as error:
        raise ZaodcError(f"invalid project metadata: {error}") from error
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir()
    (destination / "zaod.json").write_text(
        json.dumps(config, indent=2) + "\n", encoding="utf-8"
    )
    (destination / "src").mkdir()
    (destination / "assets").mkdir()
    (destination / "src" / "main.c").write_text(
        '#include "libzaod.h"\n\n'
        "__attribute__((noreturn)) void _start(void)\n"
        "{\n"
        "    (void)zaod_exit();\n"
        "    for (;;) {\n"
        '        __asm__ volatile ("pause");\n'
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    print(f"Created ZAOD project in {destination}")


def build_project(args: argparse.Namespace) -> None:
    project, manifest = read_project(Path(args.project).expanduser())
    output = Path(args.output).expanduser().absolute()
    if os.path.lexists(output):
        raise ZaodcError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix=".zaodc-stage-", dir=output.parent) as temp:
        stage = Path(temp) / "package"
        build_elf(project, stage, args)
        finalize_stage(stage, manifest)
        if args.private_key:
            if output.suffix != ".zaod":
                raise ZaodcError("signed build output must use the .zaod extension")
            try:
                create_flat_package(
                    stage,
                    output,
                    Path(args.private_key).expanduser(),
                    args.root_key_header.expanduser(),
                )
            except (OSError, ZaodcError, zpkg.PackageError) as error:
                output.unlink(missing_ok=True)
                raise ZaodcError(f"could not create signed package: {error}") from error
            print(f"Created and verified kernel-flat signed package {output}")
        else:
            if output.suffix == ".zaod":
                raise ZaodcError(
                    "a valid .zaod needs a signing key; omit .zaod to emit a "
                    "signing-ready directory"
                )
            os.replace(stage, output)
            print(f"Prepared signing-ready package directory {output}")


def reject_run(args: argparse.Namespace) -> None:
    del args
    raise ZaodcError(
        "ZAOD app execution is unavailable: there is no user-facing package "
        "installer or host runner. The kernel package gate is system-task-only "
        "and requires a configured signed Z-Shield catalog. No host execution "
        "fallback is used."
    )


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zaodc")
    commands = parser.add_subparsers(dest="command", required=True)

    new = commands.add_parser("new", help="create a starter ZAOD app project")
    new.add_argument("project")
    new.add_argument("--app-id", required=True)
    new.add_argument("--version", default="0.1.0")
    new.add_argument("--author", default="ZAOD App Developer")
    new.set_defaults(handler=create_project)

    build = commands.add_parser("build", help="compile and validate a v2 ZAOD app")
    build.add_argument("project")
    build.add_argument("--output", required=True)
    build.add_argument("--private-key")
    build.add_argument(
        "--root-key-header",
        type=Path,
        default=DEFAULT_ROOT_KEY_HEADER,
        help="kernel public-key header that must match --private-key",
    )
    build.add_argument("--cc")
    build.add_argument("--cxx")
    build.set_defaults(handler=build_project)

    run = commands.add_parser("run", help="run a package in the kernel sandbox")
    run.add_argument("package")
    run.set_defaults(handler=reject_run)
    return parser


def main() -> int:
    args = create_parser().parse_args()
    try:
        args.handler(args)
    except (ZaodcError, OSError, zpkg.PackageError) as error:
        print(f"zaodc: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
