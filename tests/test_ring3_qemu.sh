#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${ZAOD_ISO_PATH:-}" ]]; then
    iso_path="$(realpath -- "$ZAOD_ISO_PATH")"
    use_existing_iso=1
else
    iso_path="$root_dir/zaod-os-production.iso"
    use_existing_iso=0
fi

qemu="$(command -v qemu-system-x86_64 || true)"
socat="$(command -v socat || true)"
ovmf=""
qemu_memory="${ZAOD_QEMU_MEMORY:-512M}"
persistent_disk_size="${ZAOD_QEMU_DISK_SIZE:-34M}"
if [[ ! "$qemu_memory" =~ ^[0-9]+[KMG]$ ]]; then
    printf 'Invalid ZAOD_QEMU_MEMORY: expected a size such as 512M or 2G.\n' >&2
    exit 2
fi
if [[ ! "$persistent_disk_size" =~ ^[0-9]+[KMG]$ ]]; then
    printf 'Invalid ZAOD_QEMU_DISK_SIZE: expected a size such as 34M or 8G.\n' >&2
    exit 2
fi
for candidate in /usr/share/qemu/OVMF.fd \
                /usr/share/OVMF/OVMF_CODE.fd \
                /usr/share/edk2/x64/OVMF_CODE.fd; do
    if [[ -f "$candidate" ]]; then
        ovmf="$candidate"
        break
    fi
done

if [[ -z "$qemu" || -z "$socat" || -z "$ovmf" ]]; then
    printf 'Ring-3 QEMU integration test skipped (QEMU, socat, or OVMF missing).\n'
    exit 0
fi
if [[ "$use_existing_iso" == 0 && -e "$iso_path" ]]; then
    printf 'Ring-3 QEMU integration test skipped (refusing to overwrite existing ISO).\n'
    exit 0
fi
if [[ "$use_existing_iso" == 1 && ! -f "$iso_path" ]]; then
    printf 'Ring-3 QEMU integration test failed (requested ISO does not exist).\n' >&2
    exit 1
fi

temporary_dir="$(mktemp -d)"
qemu_pid=""
owns_iso=0
cleanup()
{
    if [[ -n "$qemu_pid" ]]; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    if [[ "$owns_iso" == 1 ]]; then
        rm -f -- "$iso_path"
    fi
    rm -f -- "$temporary_dir/build.log" \
        "$temporary_dir/serial.log" "$temporary_dir/monitor.sock" \
        "$temporary_dir/persistent.img"
    rmdir "$temporary_dir"
}
trap cleanup EXIT

if [[ "$use_existing_iso" == 0 ]]; then
    "$root_dir/build.sh" >"$temporary_dir/build.log" 2>&1
    owns_iso=1
fi
truncate -s "$persistent_disk_size" "$temporary_dir/persistent.img"
python3 "$root_dir/tools/mkzaodfs.py" format \
    "$temporary_dir/persistent.img" >/dev/null
"$qemu" -m "$qemu_memory" -bios "$ovmf" -cdrom "$iso_path" -boot d \
    -drive "file=$temporary_dir/persistent.img,format=raw,if=ide,index=0" \
    -display none -serial "file:$temporary_dir/serial.log" \
    -monitor "unix:$temporary_dir/monitor.sock,server=on,wait=off" \
    -no-reboot -no-shutdown >/dev/null 2>&1 &
qemu_pid=$!

sleep 10
printf 'sendkey ret\n' | "$socat" -T 2 - \
    "UNIX-CONNECT:$temporary_dir/monitor.sock" >/dev/null
sleep 5
printf 'sendkey e\n' | "$socat" -T 2 - \
    "UNIX-CONNECT:$temporary_dir/monitor.sock" >/dev/null
sleep 1
kill "$qemu_pid" 2>/dev/null || true
wait "$qemu_pid" 2>/dev/null || true
qemu_pid=""

if ! grep -aFq -- 'Trusted init.elf loaded as ring-3 task' \
    "$temporary_dir/serial.log"; then
    printf 'Ring-3 QEMU test failed to launch init.elf.\n' >&2
    cat "$temporary_dir/serial.log" >&2
    exit 1
fi

if ! grep -aFq -- 'Trusted init SHA-256 integrity check passed' \
    "$temporary_dir/serial.log"; then
    printf 'Ring-3 QEMU test failed the trusted init integrity check.\n' >&2
    cat "$temporary_dir/serial.log" >&2
    exit 1
fi

if ! grep -aFq -- 'Persistent ZAODFS volume: mounted' \
    "$temporary_dir/serial.log"; then
    printf 'Ring-3 QEMU test failed to mount the persistent test volume.\n' >&2
    cat "$temporary_dir/serial.log" >&2
    exit 1
fi

if grep -Eq 'FATAL kernel CPU exception|User CPU exception' \
    "$temporary_dir/serial.log"; then
    printf 'Ring-3 QEMU test observed a CPU exception.\n' >&2
    cat "$temporary_dir/serial.log" >&2
    exit 1
fi

printf 'Ring-3 QEMU integration test passed.\n'
