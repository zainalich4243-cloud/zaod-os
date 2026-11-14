#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
iso_root="$root_dir/iso_root"
build_dir="$root_dir/build"
output_iso="$root_dir/zaod-os-production.iso"
limine_tool_source="$root_dir/tools/limine/limine.c"
limine_tool="$build_dir/limine"

make -C "$root_dir/kernel" all

required_files=(
    "$iso_root/boot/limine.cfg"
    "$iso_root/boot/limine/limine.conf"
    "$iso_root/boot/limine/limine-bios.sys"
    "$iso_root/boot/limine/limine-bios-cd.bin"
    "$iso_root/boot/limine/limine-uefi-cd.bin"
    "$iso_root/EFI/BOOT/BOOTX64.EFI"
    "$iso_root/kernel/zaod_kernel.elf"
    "$iso_root/boot/initramfs.img"
    "$limine_tool_source"
)

for file in "${required_files[@]}"; do
    if [[ ! -f "$file" ]]; then
        printf 'error: required file is missing: %s\n' "${file#"$root_dir"/}" >&2
        exit 1
    fi
done

for tool in cc xorriso; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'error: required command is not installed: %s\n' "$tool" >&2
        exit 1
    fi
done

mkdir -p "$build_dir"
cc -std=c99 -D_FILE_OFFSET_BITS=64 "$limine_tool_source" -o "$limine_tool"

xorriso -as mkisofs \
    -b boot/limine/limine-bios-cd.bin \
    -no-emul-boot \
    -boot-load-size 4 \
    -boot-info-table \
    --efi-boot boot/limine/limine-uefi-cd.bin \
    -efi-boot-part \
    --efi-boot-image \
    --protective-msdos-label \
    "$iso_root" \
    -o "$output_iso"

"$limine_tool" bios-install "$output_iso"
printf 'Created bootable ISO: %s\n' "$output_iso"
