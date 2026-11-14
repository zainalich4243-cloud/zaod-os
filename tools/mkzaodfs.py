#!/usr/bin/env python3
"""Format an existing regular disk-image file with the minimal ZAODFS layout."""

import argparse
import os
import struct
import zlib

SECTOR_SIZE = 512
SLOT_COUNT = 16
DATA_SECTORS = 4096
DATA_START = 1 + SLOT_COUNT
REQUIRED_SECTORS = DATA_START + SLOT_COUNT * DATA_SECTORS
VOLUME_MAGIC = b"ZAODFS01"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    format_parser = subparsers.add_parser(
        "format", help="explicitly format an existing regular disk image"
    )
    format_parser.add_argument("image")
    args = parser.parse_args()

    if not os.path.isfile(args.image):
        parser.error("target must be an existing regular disk-image file")
    if os.path.getsize(args.image) < REQUIRED_SECTORS * SECTOR_SIZE:
        parser.error(
            f"image must be at least {REQUIRED_SECTORS * SECTOR_SIZE} bytes"
        )

    volume = bytearray(SECTOR_SIZE)
    struct.pack_into(
        "<8sIIII",
        volume,
        0,
        VOLUME_MAGIC,
        1,
        SLOT_COUNT,
        DATA_SECTORS,
        DATA_START,
    )
    struct.pack_into("<I", volume, 508, zlib.crc32(volume) & 0xFFFFFFFF)
    with open(args.image, "r+b", buffering=0) as image:
        image.seek(0)
        image.write(volume)
        image.write(bytes(SLOT_COUNT * SECTOR_SIZE))
        image.flush()
        os.fsync(image.fileno())
    print(f"Formatted ZAODFS image: {args.image}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
