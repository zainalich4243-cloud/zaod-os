#!/usr/bin/env python3
"""ZAOD signed package packer and installer."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import io
import json
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


MAX_PACKAGE_BYTES = 128 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_FILES = 4096
MAX_PATH_BYTES = 100
SCHEMA_VERSION = 2
APP_ID_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,63}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SIGNING_DOMAIN = b"ZAOD-PACKAGE-V1\0"
CATALOG_DOMAIN = b"ZAOD-CATALOG-V1\0"


class PackageError(Exception):
    """Raised when a package, signature, or install operation is invalid."""


def fail(message: str) -> None:
    raise PackageError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(data: bytes, source: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{source} is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{source} must contain a JSON object")
    return value


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def get_zstd():
    library_name = ctypes.util.find_library("zstd")
    if library_name is None:
        fail("libzstd is required to read/write .zaod packages")
    library = ctypes.CDLL(library_name)
    library.ZSTD_getFrameContentSize.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    library.ZSTD_getFrameContentSize.restype = ctypes.c_ulonglong
    library.ZSTD_findFrameCompressedSize.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    library.ZSTD_findFrameCompressedSize.restype = ctypes.c_size_t
    library.ZSTD_decompress.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    library.ZSTD_decompress.restype = ctypes.c_size_t
    library.ZSTD_compressBound.argtypes = [ctypes.c_size_t]
    library.ZSTD_compressBound.restype = ctypes.c_size_t
    library.ZSTD_compress.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
    ]
    library.ZSTD_compress.restype = ctypes.c_size_t
    library.ZSTD_isError.argtypes = [ctypes.c_size_t]
    library.ZSTD_isError.restype = ctypes.c_uint
    library.ZSTD_getErrorName.argtypes = [ctypes.c_size_t]
    library.ZSTD_getErrorName.restype = ctypes.c_char_p
    return library


def zstd_error(library, result: int, context: str) -> None:
    if library.ZSTD_isError(result):
        detail = library.ZSTD_getErrorName(result).decode("ascii", "replace")
        fail(f"{context}: {detail}")


def zstd_decompress(data: bytes) -> bytes:
    if not data or len(data) > MAX_PACKAGE_BYTES:
        fail("compressed package is empty or exceeds the size limit")
    library = get_zstd()
    source = ctypes.create_string_buffer(data)
    frame_size = library.ZSTD_findFrameCompressedSize(source, len(data))
    zstd_error(library, frame_size, "invalid Zstandard frame")
    if frame_size != len(data):
        fail(".zaod must contain exactly one Zstandard frame")
    size = library.ZSTD_getFrameContentSize(source, len(data))
    if size in (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE):
        fail("zstd frame must declare its uncompressed size")
    if size == 0 or size > MAX_UNCOMPRESSED_BYTES:
        fail("uncompressed package exceeds the size limit")
    destination = ctypes.create_string_buffer(size)
    result = library.ZSTD_decompress(destination, size, source, len(data))
    zstd_error(library, result, "could not decompress .zaod")
    if result != size:
        fail("zstd frame size did not match its declared size")
    return destination.raw[:result]


def zstd_compress(data: bytes) -> bytes:
    if len(data) > MAX_UNCOMPRESSED_BYTES:
        fail("package contents exceed the size limit")
    library = get_zstd()
    source = ctypes.create_string_buffer(data)
    capacity = library.ZSTD_compressBound(len(data))
    destination = ctypes.create_string_buffer(capacity)
    result = library.ZSTD_compress(destination, capacity, source, len(data), 10)
    zstd_error(library, result, "could not compress .zaod")
    return destination.raw[:result]


def validate_relpath(path: str) -> str:
    if (
        not path
        or len(path.encode("utf-8")) > MAX_PATH_BYTES
        or not SAFE_PATH_RE.fullmatch(path)
        or path.startswith("/")
        or "\\" in path
    ):
        fail(f"invalid package path: {path!r}")
    normalized = posixpath.normpath(path)
    if normalized != path or normalized in (".", ".."):
        fail(f"non-canonical package path: {path!r}")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        fail(f"unsafe package path: {path!r}")
    if parts[0] not in ("bin", "assets"):
        fail(f"payload must be under bin/ or assets/: {path!r}")
    return path


def validate_manifest(manifest: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "app_id",
        "version",
        "author",
        "entrypoint",
        "permissions",
        "files",
    }
    if set(manifest) != required:
        fail("manifest must contain exactly: " + ", ".join(sorted(required)))
    version = manifest["schema_version"]
    if type(version) is not int or version not in (1, SCHEMA_VERSION):
        fail(f"unsupported manifest schema_version; expected 1 or {SCHEMA_VERSION}")
    if not isinstance(manifest["app_id"], str) or not APP_ID_RE.fullmatch(manifest["app_id"]):
        fail("manifest app_id is invalid")
    if not isinstance(manifest["version"], str) or not VERSION_RE.fullmatch(manifest["version"]):
        fail("manifest version must be semantic version MAJOR.MINOR.PATCH")
    if (
        not isinstance(manifest["author"], str)
        or not manifest["author"].strip()
        or len(manifest["author"]) > 128
    ):
        fail("manifest author must be a non-empty string of at most 128 characters")

    permissions = manifest["permissions"]
    if not isinstance(permissions, dict):
        fail("permissions must be an object")
    if version == 1:
        if set(permissions) != {"camera", "microphone", "network", "background"}:
            fail("schema v1 permissions must define camera, microphone, network, and background")
        for permission in ("camera", "microphone"):
            if permissions[permission] not in ("deny", "one-time"):
                fail(f"{permission} permission must be 'deny' or 'one-time'")
    else:
        if set(permissions) != {
            "camera",
            "microphone",
            "storage",
            "notifications",
            "network",
            "background",
        }:
            fail("schema v2 permissions must define camera, microphone, storage, notifications, network, and background")
        for permission in ("camera", "microphone", "storage", "notifications"):
            if permissions[permission] not in ("deny", "one-time", "while-using"):
                fail(f"{permission} permission must be 'deny', 'one-time', or 'while-using'")
    if permissions["network"] not in ("none", "foreground"):
        fail("network permission must be 'none' or 'foreground'")
    if permissions["background"] is not False:
        fail("24/7 background access is not allowed")

    entrypoint = manifest["entrypoint"]
    if not isinstance(entrypoint, str) or not entrypoint.startswith("bin/"):
        fail("entrypoint must name a binary under bin/")
    validate_relpath(entrypoint)
    files = manifest["files"]
    if not isinstance(files, dict) or not files:
        fail("manifest files must be a non-empty path-to-SHA256 map")
    if len(files) > MAX_FILES:
        fail(f"manifest may contain at most {MAX_FILES} payload files")
    for name, digest in files.items():
        validate_relpath(name)
        if not isinstance(digest, str) or not HASH_RE.fullmatch(digest):
            fail(f"invalid SHA-256 digest for {name!r}")
    if entrypoint not in files:
        fail("manifest entrypoint is not listed in files")


def signing_payload(manifest_bytes: bytes, files: dict[str, str]) -> bytes:
    return SIGNING_DOMAIN + manifest_bytes + b"\0" + canonical_json(files)


def openssl_signature(mode: str, key_path: Path, payload: bytes, signature: bytes | None = None) -> bytes:
    with tempfile.TemporaryDirectory(prefix="zpkg-sign-") as directory:
        input_path = Path(directory) / "payload"
        signature_path = Path(directory) / "signature"
        input_path.write_bytes(payload)
        command = ["openssl", "pkeyutl", mode, "-rawin", "-inkey", str(key_path)]
        if mode == "-verify":
            command.extend(["-pubin", "-sigfile", str(signature_path)])
            signature_path.write_bytes(signature or b"")
        else:
            command.extend(["-out", str(signature_path)])
        command.extend(["-in", str(input_path)])
        try:
            result = subprocess.run(command, capture_output=True, check=False, timeout=15)
        except FileNotFoundError:
            fail("OpenSSL is required for Ed25519 package signatures")
        except subprocess.TimeoutExpired:
            fail("OpenSSL signature operation timed out")
        if mode == "-sign":
            if result.returncode != 0:
                fail("package signing failed: " + result.stderr.decode("utf-8", "replace").strip())
            return signature_path.read_bytes()
        if result.returncode != 0:
            fail("package signature verification failed")
        return b""


def verify_signature(key_path: Path, payload: bytes, signature: bytes) -> None:
    if len(signature) != 64:
        fail("Ed25519 signature.sig must be exactly 64 bytes")
    openssl_signature("-verify", key_path, payload, signature)


def elf_is_x86_64(data: bytes) -> bool:
    return (
        len(data) >= 20
        and data[:4] == b"\x7fELF"
        and data[4] == 2
        and data[5] == 1
        and int.from_bytes(data[16:18], "little") in (2, 3)
        and int.from_bytes(data[18:20], "little") == 62
    )


def parse_package(package_bytes: bytes, public_key: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    archive_bytes = zstd_decompress(package_bytes)
    payload: dict[str, bytes] = {}
    directories: set[str] = set()
    seen_paths: set[str] = set()
    manifest_bytes: bytes | None = None
    signature: bytes | None = None
    total_file_bytes = 0

    try:
        archive = tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:")
    except tarfile.TarError as error:
        fail(f"invalid tar payload: {error}")

    with archive:
        members = archive.getmembers()
        if len(members) > MAX_FILES + 128:
            fail("package contains too many archive entries")
        for member in members:
            name = member.name
            if member.isdir():
                directory_name = name[:-1] if name.endswith("/") else name
                if directory_name in seen_paths:
                    fail(f"duplicate archive path: {name!r}")
                if directory_name not in ("bin", "assets"):
                    validate_relpath(directory_name + "/placeholder")
                if directory_name in directories or directory_name in payload:
                    fail(f"duplicate archive path: {name!r}")
                seen_paths.add(directory_name)
                directories.add(directory_name)
                continue
            if not member.isreg() or member.size > MAX_FILE_BYTES:
                fail(f"unsupported or oversized archive entry: {name!r}")
            if member.pax_headers:
                fail(f"PAX metadata is not allowed: {name!r}")
            if name in seen_paths:
                fail(f"duplicate archive path: {name!r}")
            seen_paths.add(name)
            if name not in ("manifest.json", "signature.sig"):
                validate_relpath(name)
                if name in directories:
                    fail(f"file conflicts with archive directory: {name!r}")
            total_file_bytes += member.size
            if total_file_bytes > MAX_UNCOMPRESSED_BYTES:
                fail("package payload exceeds the size limit")
            stream = archive.extractfile(member)
            if stream is None:
                fail(f"could not read archive entry: {name!r}")
            data = stream.read(member.size + 1)
            if len(data) != member.size:
                fail(f"truncated archive entry: {name!r}")
            if name == "manifest.json":
                manifest_bytes = data
            elif name == "signature.sig":
                signature = data
            else:
                payload[name] = data

    if manifest_bytes is None or signature is None:
        fail("package must contain manifest.json and signature.sig")
    manifest = parse_json(manifest_bytes, "manifest.json")
    validate_manifest(manifest)
    expected_files = manifest["files"]
    if set(payload) != set(expected_files):
        fail("archive payload paths do not exactly match manifest files")
    for name, data in payload.items():
        actual_hash = hashlib.sha256(data).hexdigest()
        if actual_hash != expected_files[name]:
            fail(f"SHA-256 mismatch for {name!r}")
        if name.startswith("bin/") and not elf_is_x86_64(data):
            fail(f"binary payload must be an x86_64 ELF executable: {name!r}")
    verify_signature(
        public_key,
        signing_payload(manifest_bytes, expected_files),
        signature,
    )
    return manifest, payload


def archive_members(manifest_bytes: bytes, signature: bytes, files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:", format=tarfile.USTAR_FORMAT) as archive:
        entries = [("manifest.json", manifest_bytes), ("signature.sig", signature)]
        entries.extend(sorted(files.items()))
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


def collect_source(source: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    if source.is_symlink() or not source.is_dir():
        fail("package source must be a real directory")
    manifest_path = source / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        fail("package source must contain manifest.json")
    manifest = parse_json(
        read_bounded_file(manifest_path, 2 * 1024 * 1024, "manifest.json"),
        "manifest.json",
    )
    if not isinstance(manifest, dict):
        fail("manifest.json must contain a JSON object")
    files: dict[str, bytes] = {}
    total_file_bytes = 0
    for top_level in source.iterdir():
        if top_level.name not in ("manifest.json", "bin", "assets"):
            fail(f"unexpected package source entry: {top_level.name!r}")
        if top_level.name == "manifest.json":
            continue
        if top_level.is_symlink() or not top_level.is_dir():
            fail(f"package source directory is invalid: {top_level.name!r}")
        for current, dirs, filenames in os.walk(top_level, followlinks=False):
            for directory in dirs:
                if (Path(current) / directory).is_symlink():
                    fail("package source may not contain symbolic links")
            for filename in filenames:
                path = Path(current) / filename
                if path.is_symlink() or not path.is_file():
                    fail(f"package source contains an unsupported file: {path}")
                relative = path.relative_to(source).as_posix()
                validate_relpath(relative)
                if len(files) >= MAX_FILES:
                    fail(f"package may contain at most {MAX_FILES} payload files")
                if path.stat().st_size > MAX_FILE_BYTES:
                    fail(f"package file is too large: {relative}")
                data = path.read_bytes()
                total_file_bytes += len(data)
                if total_file_bytes > MAX_UNCOMPRESSED_BYTES:
                    fail("package contents exceed the size limit")
                files[relative] = data

    manifest["files"] = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}
    validate_manifest(manifest)
    for name in files:
        if name.startswith("bin/") and not elf_is_x86_64(files[name]):
            fail(f"binary payload must be a 64-bit little-endian x86_64 ELF: {name!r}")
    return manifest, files


def command_pack(args: argparse.Namespace) -> None:
    manifest, files = collect_source(Path(args.source))
    manifest_bytes = canonical_json(manifest) + b"\n"
    signature = openssl_signature(
        "-sign",
        Path(args.private_key),
        signing_payload(manifest_bytes, manifest["files"]),
    )
    tar_bytes = archive_members(manifest_bytes, signature, files)
    package_bytes = zstd_compress(tar_bytes)
    if len(package_bytes) > MAX_PACKAGE_BYTES:
        fail("compressed package exceeds the size limit")
    Path(args.output).write_bytes(package_bytes)
    print(f"Created {args.output} ({len(package_bytes)} bytes)")


def extract_to_stage(stage: Path, manifest: dict[str, Any], files: dict[str, bytes]) -> list[Path]:
    manifest_path = stage / "manifest.json"
    manifest_path.write_bytes(canonical_json(manifest) + b"\n")
    manifest_path.chmod(0o644)
    installed = [manifest_path]
    policy_path = stage / ".zaod-policy.json"
    policy_path.write_bytes(canonical_json(policy_sidecar(manifest)) + b"\n")
    policy_path.chmod(0o444)
    installed.append(policy_path)
    for name, data in files.items():
        destination = stage.joinpath(*name.split("/"))
        parent = posixpath.dirname(name)
        parents: list[str] = []
        while parent:
            parents.append(parent)
            parent = posixpath.dirname(parent)
        for directory in reversed(parents):
            directory_path = stage.joinpath(*directory.split("/"))
            directory_path.mkdir(exist_ok=True, mode=0o755)
            directory_path.chmod(0o755)
        destination.write_bytes(data)
        destination.chmod(0o755 if name == manifest["entrypoint"] else 0o644)
        installed.append(destination)
    return installed


def policy_sidecar(manifest: dict[str, Any]) -> dict[str, Any]:
    permissions = manifest["permissions"]
    return {
        "schema_version": 1,
        "app_id": manifest["app_id"],
        "background_access": False,
        "resources": {
            "camera": permissions.get("camera", "deny"),
            "microphone": permissions.get("microphone", "deny"),
            "storage": permissions.get("storage", "deny"),
            "notifications": permissions.get("notifications", "deny"),
            "network": "while-using" if permissions["network"] == "foreground" else "deny",
        },
    }


def verify_stage(stage: Path, manifest: dict[str, Any], files: dict[str, bytes]) -> None:
    if stat.S_IMODE(stage.stat().st_mode) != 0o700:
        fail("Z-Shield scanner changed staging root permissions")
    expected_names = {"manifest.json", ".zaod-policy.json", *files.keys()}
    actual_names: set[str] = set()
    expected_directories: set[str] = set()
    for name in expected_names:
        parent = posixpath.dirname(name)
        while parent:
            expected_directories.add(parent)
            parent = posixpath.dirname(parent)
    actual_directories: set[str] = set()
    for current, dirs, filenames in os.walk(stage, followlinks=False):
        current_path = Path(current)
        for directory in dirs:
            path = current_path / directory
            if path.is_symlink() or not path.is_dir():
                fail("Z-Shield scanner created a symbolic link in staging")
            actual_directories.add(path.relative_to(stage).as_posix())
            if stat.S_IMODE(path.stat().st_mode) != 0o755:
                fail("Z-Shield scanner changed staging directory permissions")
        for filename in filenames:
            path = current_path / filename
            if path.is_symlink() or not path.is_file():
                fail("Z-Shield scanner created an unsupported staging entry")
            name = path.relative_to(stage).as_posix()
            actual_names.add(name)
            expected_mode = 0o644
            if name == ".zaod-policy.json":
                expected_mode = 0o444
            if name in files and name == manifest["entrypoint"]:
                expected_mode = 0o755
            if stat.S_IMODE(path.stat().st_mode) != expected_mode:
                fail(f"Z-Shield scanner changed file permissions: {name}")
    if actual_names != expected_names or actual_directories != expected_directories:
        fail("staging contents changed during Z-Shield scanning")

    installed_manifest = parse_json((stage / "manifest.json").read_bytes(), "staged manifest")
    if installed_manifest != manifest:
        fail("staged manifest changed during Z-Shield scanning")
    installed_policy = parse_json(
        (stage / ".zaod-policy.json").read_bytes(), "staged permission policy"
    )
    if installed_policy != policy_sidecar(manifest):
        fail("staged permission policy changed during Z-Shield scanning")
    for name, data in files.items():
        if hashlib.sha256((stage / name).read_bytes()).digest() != hashlib.sha256(data).digest():
            fail(f"staged payload changed during Z-Shield scanning: {name}")


def run_scanner(scanner: Path, files: list[Path]) -> None:
    if scanner.is_symlink() or not scanner.is_file() or not os.access(scanner, os.X_OK):
        fail(f"Z-Shield scanner is missing or not executable: {scanner}")
    scanner = scanner.resolve(strict=True)
    for path in files:
        try:
            result = subprocess.run(
                [str(scanner), "--scan", str(path)],
                capture_output=True,
                check=False,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            fail(f"Z-Shield scan timed out: {path.name}")
        except OSError as error:
            fail(f"could not start Z-Shield scanner: {error}")
        if result.stdout:
            sys.stdout.buffer.write(result.stdout)
        if result.stderr:
            sys.stderr.buffer.write(result.stderr)
        if result.returncode != 0:
            fail(f"Z-Shield rejected package content: {path.name}")


def safe_apps_root(root: Path) -> Path:
    if root.is_symlink():
        fail(f"application root may not be a symlink: {root}")
    root.mkdir(parents=True, exist_ok=True, mode=0o755)
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        fail(f"application root is not a directory: {resolved}")
    return resolved


def read_bounded_file(path: Path, limit: int, description: str) -> bytes:
    if path.stat().st_size > limit:
        fail(f"{description} exceeds the size limit")
    with path.open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        fail(f"{description} exceeds the size limit")
    return data


def install_package(
    package_bytes: bytes,
    public_key: Path,
    scanner: Path,
    apps_root: Path,
) -> None:
    manifest, files = parse_package(package_bytes, public_key)
    root = safe_apps_root(apps_root)
    app_id = manifest["app_id"]
    destination = root / app_id
    if os.path.lexists(destination):
        fail(f"application is already installed: {app_id}")

    stage = Path(tempfile.mkdtemp(prefix=f".zpkg-{app_id}-", dir=root))
    try:
        scanned_files = extract_to_stage(stage, manifest, files)
        run_scanner(scanner, scanned_files)
        verify_stage(stage, manifest, files)
        receipt = {
            "app_id": app_id,
            "version": manifest["version"],
            "files": sorted(["manifest.json", *files.keys()]),
        }
        receipt_path = stage / ".zaod-install.json"
        receipt_path.write_bytes(canonical_json(receipt) + b"\n")
        receipt_path.chmod(0o600)
        stage.chmod(0o755)
        os.replace(stage, destination)
    except (PackageError, OSError) as error:
        if stage.exists():
            try:
                shutil.rmtree(stage)
            except OSError as cleanup_error:
                fail(f"{error}; staging cleanup also failed: {cleanup_error}")
        raise
    print(f"Installed {app_id} {manifest['version']} to {destination}")


def command_verify(args: argparse.Namespace) -> None:
    package = read_bounded_file(Path(args.package), MAX_PACKAGE_BYTES, "package")
    manifest, files = parse_package(package, Path(args.public_key))
    print(f"Valid package: {manifest['app_id']} {manifest['version']}")
    print(f"Verified payload files: {len(files)}")


def command_install(args: argparse.Namespace) -> None:
    install_package(
        read_bounded_file(Path(args.package), MAX_PACKAGE_BYTES, "package"),
        Path(args.public_key),
        Path(args.scanner),
        Path(args.root),
    )


def fetch_https(url: str, limit: int) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "ZAOD-zpkg/1", "Accept": "application/octet-stream"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            final_url = urllib.parse.urlparse(response.geturl())
            if final_url.scheme != "https" or not final_url.hostname:
                fail("GitHub redirected to a non-HTTPS URL")
            if final_url.hostname not in {
                "github.com",
                "release-assets.githubusercontent.com",
                "objects.githubusercontent.com",
            }:
                fail(f"unexpected GitHub download host: {final_url.hostname}")
            content_length = response.headers.get("Content-Length")
            if content_length is not None and int(content_length) > limit:
                fail("download exceeds the size limit")
            data = response.read(limit + 1)
    except urllib.error.URLError as error:
        fail(f"GitHub download failed: {error}")
    if len(data) > limit:
        fail("download exceeds the size limit")
    return data


def verify_catalog(catalog_bytes: bytes, signature: bytes, public_key: Path) -> dict[str, Any]:
    verify_signature(public_key, CATALOG_DOMAIN + catalog_bytes, signature)
    catalog = parse_json(catalog_bytes, "catalog.json")
    if set(catalog) != {"schema_version", "packages"}:
        fail("catalog must contain exactly schema_version and packages")
    if type(catalog["schema_version"]) is not int or catalog["schema_version"] != 1:
        fail("unsupported package catalog schema")
    if not isinstance(catalog["packages"], list):
        fail("catalog packages must be a list")
    return catalog


def command_fetch(args: argparse.Namespace) -> None:
    if not REPO_RE.fullmatch(args.repo):
        fail("repository must be in owner/name form")
    if not APP_ID_RE.fullmatch(args.app_id) or not VERSION_RE.fullmatch(args.version):
        fail("invalid app ID or version")
    owner, repository = args.repo.split("/", 1)
    base = f"https://github.com/{owner}/{repository}/releases"
    catalog_bytes = fetch_https(f"{base}/latest/download/catalog.json", 2 * 1024 * 1024)
    catalog_signature = fetch_https(f"{base}/latest/download/catalog.sig", 64)
    catalog = verify_catalog(catalog_bytes, catalog_signature, Path(args.public_key))

    matches = [
        item
        for item in catalog["packages"]
        if isinstance(item, dict)
        and item.get("app_id") == args.app_id
        and item.get("version") == args.version
    ]
    if len(matches) != 1:
        fail("signed catalog must contain exactly one matching package")
    entry = matches[0]
    if set(entry) != {"app_id", "version", "release_tag", "asset", "sha256"}:
        fail("catalog entry has an invalid shape")
    release_tag = entry["release_tag"]
    asset = entry["asset"]
    digest = entry["sha256"]
    if (
        not isinstance(release_tag, str)
        or not re.fullmatch(r"v?[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", release_tag)
        or not isinstance(asset, str)
        or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}\.zaod", asset)
        or not isinstance(digest, str)
        or not HASH_RE.fullmatch(digest)
    ):
        fail("catalog release tag, asset name, or SHA-256 digest is invalid")

    quoted_tag = urllib.parse.quote(release_tag, safe="")
    package_url = f"{base}/download/{quoted_tag}/{urllib.parse.quote(asset, safe='')}"
    package = fetch_https(package_url, MAX_PACKAGE_BYTES)
    if hashlib.sha256(package).hexdigest() != digest:
        fail("downloaded package hash does not match the signed catalog")
    manifest, _ = parse_package(package, Path(args.public_key))
    if manifest["app_id"] != args.app_id or manifest["version"] != args.version:
        fail("downloaded package identity does not match the signed catalog entry")
    install_package(
        package,
        Path(args.public_key),
        Path(args.scanner),
        Path(args.root),
    )


def command_remove(args: argparse.Namespace) -> None:
    if not APP_ID_RE.fullmatch(args.app_id):
        fail("invalid app ID")
    root = safe_apps_root(Path(args.root))
    destination = root / args.app_id
    if destination.is_symlink() or not destination.is_dir():
        fail(f"application is not installed or is not a real directory: {args.app_id}")
    receipt = destination / ".zaod-install.json"
    if receipt.is_symlink() or not receipt.is_file():
        fail("refusing to remove a directory without a ZAOD install receipt")
    metadata = parse_json(receipt.read_bytes(), "install receipt")
    if metadata.get("app_id") != args.app_id:
        fail("install receipt app_id does not match target directory")
    shutil.rmtree(destination)
    print(f"Removed {args.app_id} from {destination}")


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zpkg", description="ZAOD signed package manager")
    subparsers = parser.add_subparsers(dest="command", required=True)

    pack = subparsers.add_parser("pack", help="create a signed .zaod package")
    pack.add_argument("source")
    pack.add_argument("output")
    pack.add_argument("--private-key", required=True)
    pack.set_defaults(handler=command_pack)

    verify = subparsers.add_parser("verify", help="verify a .zaod package signature")
    verify.add_argument("package")
    verify.add_argument("--public-key", required=True)
    verify.set_defaults(handler=command_verify)

    install = subparsers.add_parser("install", help="scan and install a local package")
    install.add_argument("package")
    install.add_argument("--public-key", required=True)
    install.add_argument("--scanner", required=True, help="trusted Z-Shield scanner executable")
    install.add_argument("--root", default="/opt/zaod/apps")
    install.set_defaults(handler=command_install)

    fetch = subparsers.add_parser("fetch", help="fetch a signed release package from GitHub")
    fetch.add_argument("app_id")
    fetch.add_argument("version")
    fetch.add_argument("--repo", required=True, help="GitHub owner/repository")
    fetch.add_argument("--public-key", required=True)
    fetch.add_argument("--scanner", required=True, help="trusted Z-Shield scanner executable")
    fetch.add_argument("--root", default="/opt/zaod/apps")
    fetch.set_defaults(handler=command_fetch)

    remove = subparsers.add_parser("remove", help="remove one installed package")
    remove.add_argument("app_id")
    remove.add_argument("--root", default="/opt/zaod/apps")
    remove.set_defaults(handler=command_remove)
    return parser


def main() -> int:
    parser = create_parser()
    args = parser.parse_args()
    try:
        args.handler(args)
    except (PackageError, OSError, tarfile.TarError, json.JSONDecodeError, ValueError) as error:
        print(f"zpkg: error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
