#!/usr/bin/env python3
import os
import stat
import sys
import time


def align4(value):
    return (value + 3) & ~3


def add_entry(output, name, data, mode, inode, mtime):
    encoded_name = name.encode("ascii") + b"\0"
    fields = (
        inode,
        mode,
        0,
        0,
        1,
        mtime,
        len(data),
        0,
        0,
        0,
        0,
        len(encoded_name),
        0,
    )
    header = b"070701" + b"".join(f"{field:08x}".encode("ascii") for field in fields)
    output.extend(header)
    output.extend(encoded_name)
    output.extend(b"\0" * (align4(len(output)) - len(output)))
    output.extend(data)
    output.extend(b"\0" * (align4(len(output)) - len(output)))


def main():
    if len(sys.argv) != 3:
        raise SystemExit(f"Usage: {sys.argv[0]} OUTPUT INIT_ELF")

    output_path = sys.argv[1]
    init_path = sys.argv[2]
    timestamp = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
    archive = bytearray()
    with open(init_path, "rb") as source:
        init_elf = source.read()
    if len(init_elf) < 20 or init_elf[:4] != b"\x7fELF" or init_elf[4] != 2:
        raise SystemExit(f"error: {init_path} is not a 64-bit ELF executable")
    files = (
        (
            "etc/zaod-release",
            b"NAME=ZAOD\nVERSION=0.1-kernel-bringup\n",
            stat.S_IFREG | 0o644,
        ),
        (
            "README",
            b"ZAOD initramfs prototype. init.elf is packaged but not launched by this kernel yet.\n",
            stat.S_IFREG | 0o644,
        ),
        ("sbin/init.elf", init_elf, stat.S_IFREG | 0o755),
    )

    add_entry(archive, "etc", b"", stat.S_IFDIR | 0o755, 1, timestamp)
    add_entry(archive, "sbin", b"", stat.S_IFDIR | 0o755, 2, timestamp)
    for inode, (name, data, mode) in enumerate(files, start=3):
        add_entry(archive, name, data, mode, inode, timestamp)
    add_entry(archive, "TRAILER!!!", b"", 0, len(files) + 3, timestamp)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as image:
        image.write(archive)


if __name__ == "__main__":
    main()
