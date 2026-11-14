#!/usr/bin/env python3

import sys
from pathlib import Path


def parse_newc(path: Path) -> dict[str, tuple[int, bytes]]:
    data = path.read_bytes()
    files: dict[str, tuple[int, bytes]] = {}
    offset = 0
    while offset + 110 <= len(data):
        header = data[offset : offset + 110]
        if header[:6] != b"070701":
            raise AssertionError(f"invalid newc header at offset {offset}")
        mode = int(header[14:22], 16)
        size = int(header[54:62], 16)
        name_size = int(header[94:102], 16)
        offset += 110
        if name_size == 0 or offset + name_size > len(data):
            raise AssertionError("invalid CPIO name size")
        name_data = data[offset : offset + name_size]
        if name_data[-1] != 0 or b"\0" in name_data[:-1]:
            raise AssertionError("invalid CPIO name")
        name = name_data[:-1].decode("ascii")
        offset = (offset + name_size + 3) & ~3
        if offset + size > len(data):
            raise AssertionError("invalid CPIO file size")
        content = data[offset : offset + size]
        offset = (offset + size + 3) & ~3
        if name == "TRAILER!!!":
            if size != 0 or any(data[offset:]):
                raise AssertionError("invalid CPIO trailer")
            return files
        if name in files:
            raise AssertionError(f"duplicate CPIO entry: {name}")
        files[name] = (mode, content)
    raise AssertionError("missing CPIO trailer")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"Usage: {sys.argv[0]} INITRAMFS")
    entries = parse_newc(Path(sys.argv[1]))
    if "sbin/init.elf" not in entries:
        raise AssertionError("init.elf is missing from initramfs")
    mode, executable = entries["sbin/init.elf"]
    if mode & 0o111 == 0:
        raise AssertionError("init.elf is not executable in the archive")
    if (
        len(executable) < 20
        or executable[:4] != b"\x7fELF"
        or executable[4] != 2
        or int.from_bytes(executable[18:20], "little") != 62
    ):
        raise AssertionError("init.elf is not an x86_64 ELF64 image")
    if "etc/zaod-release" not in entries:
        raise AssertionError("release metadata is missing from initramfs")
    print("initramfs contents and init.elf verified")


if __name__ == "__main__":
    main()
