#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
suite="${ZAOD_DEBIAN_SUITE:-trixie}"
mirror="${ZAOD_DEBIAN_MIRROR:-http://deb.debian.org/debian}"
work_dir="/tmp/zaod-live-$(id -u)"
rootfs="$work_dir/rootfs"
iso_root="$work_dir/iso"
output_iso="${ZAOD_LIVE_OUTPUT:-$root_dir/zaod-os-live.iso}"

for tool in debootstrap mksquashfs grub-mkrescue xorriso; do
    command -v "$tool" >/dev/null || {
        printf 'Missing required build tool: %s\n' "$tool" >&2
        exit 1
    }
done
[[ "$(dpkg --print-architecture)" == amd64 ]] || {
    echo "The live image builder requires an amd64 host." >&2
    exit 1
}
sudo -n true || {
    echo "Passwordless sudo is required for debootstrap and chroot setup." >&2
    exit 1
}

mounted=()
cleanup()
{
    status=$?
    for ((i=${#mounted[@]} - 1; i >= 0; --i)); do
        sudo umount "${mounted[i]}" 2>/dev/null || true
    done
    if [[ $status -eq 0 ]]; then
        sudo rm -rf -- "$work_dir"
    else
        printf 'Build failed; resumable root filesystem retained at %s\n' "$rootfs" >&2
    fi
}
trap cleanup EXIT

sudo install -d -m 0755 "$rootfs" "$iso_root/live" "$iso_root/boot/grub"
if ! sudo test -x "$rootfs/usr/bin/apt-get"; then
    sudo debootstrap --arch=amd64 --variant=minbase \
        --include=ca-certificates,gnupg "$suite" "$rootfs" "$mirror"
fi

sudo tee "$rootfs/etc/apt/sources.list" >/dev/null <<EOF
deb $mirror $suite main contrib non-free non-free-firmware
deb $mirror ${suite}-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security ${suite}-security main contrib non-free non-free-firmware
EOF
sudo rm -f "$rootfs/etc/resolv.conf"
sudo install -m 0644 /etc/resolv.conf "$rootfs/etc/resolv.conf"
for path in dev proc sys run; do
    if sudo mountpoint -q "$rootfs/$path"; then
        mounted+=("$rootfs/$path")
    else
        sudo mount --bind "/$path" "$rootfs/$path"
        mounted+=("$rootfs/$path")
    fi
done
if sudo mountpoint -q "$rootfs/dev/pts"; then
    mounted+=("$rootfs/dev/pts")
else
    sudo mount --bind /dev/pts "$rootfs/dev/pts"
    mounted+=("$rootfs/dev/pts")
fi

sudo chroot "$rootfs" /usr/bin/dpkg --configure -a
sudo chroot "$rootfs" /usr/bin/env DEBIAN_FRONTEND=noninteractive \
    /usr/bin/apt-get update
sudo chroot "$rootfs" /usr/bin/env DEBIAN_FRONTEND=noninteractive \
    /usr/bin/apt-get install -y --no-install-recommends \
    ca-certificates dbus-x11 firefox-esr firmware-amd-graphics \
    firmware-iwlwifi firmware-linux-free firmware-misc-nonfree \
    firmware-realtek lightdm locales live-boot live-config \
    live-config-systemd linux-image-amd64 mesa-va-drivers \
    mesa-vulkan-drivers network-manager network-manager-gnome \
    pipewire-audio sudo systemd-sysv thunar xfce4 xfce4-goodies \
    xfce4-taskmanager xfce4-terminal xserver-xorg zram-tools

for group in audio video plugdev netdev sudo; do
    sudo chroot "$rootfs" /usr/sbin/groupadd -f "$group"
done
if ! sudo chroot "$rootfs" /usr/bin/id zaod >/dev/null 2>&1; then
    sudo chroot "$rootfs" /usr/sbin/useradd --create-home \
        --shell /bin/bash --groups audio,video,plugdev,netdev,sudo zaod
fi
sudo chroot "$rootfs" /usr/bin/passwd --lock root
sudo tee "$rootfs/etc/sudoers.d/zaod-live" >/dev/null <<'EOF'
zaod ALL=(ALL) NOPASSWD: ALL
EOF
sudo chmod 0440 "$rootfs/etc/sudoers.d/zaod-live"
sudo install -d -m 0755 "$rootfs/etc/lightdm/lightdm.conf.d"
sudo tee "$rootfs/etc/lightdm/lightdm.conf.d/50-zaod-live.conf" >/dev/null <<'EOF'
[Seat:*]
autologin-user=zaod
autologin-user-timeout=0
user-session=xfce
EOF
sudo tee "$rootfs/etc/zaod-release" >/dev/null <<EOF
NAME="ZAOD OS Live Desktop"
BASE="Debian $suite"
EDITION="XFCE Live"
EOF
sudo tee "$rootfs/etc/issue" >/dev/null <<'EOF'
ZAOD OS Live Desktop
Debian-based community prototype. Live-session changes are temporary.
EOF
sudo tee "$rootfs/etc/default/zramswap" >/dev/null <<'EOF'
ALGO=lz4
PERCENT=50
PRIORITY=100
EOF
sudo sed -i '/^[[:space:]]*#\?en_US.UTF-8 UTF-8$/d' "$rootfs/etc/locale.gen"
printf 'en_US.UTF-8 UTF-8\n' | sudo tee -a "$rootfs/etc/locale.gen" >/dev/null
sudo chroot "$rootfs" /usr/bin/env DEBIAN_FRONTEND=noninteractive \
    /usr/sbin/locale-gen en_US.UTF-8
sudo chroot "$rootfs" /usr/sbin/update-initramfs -u -k all
sudo chroot "$rootfs" /usr/bin/apt-get clean
sudo rm -f "$rootfs/etc/resolv.conf"
sudo ln -s /run/NetworkManager/resolv.conf "$rootfs/etc/resolv.conf"

kernel="$(sudo find "$rootfs/boot" -maxdepth 1 -type f -name 'vmlinuz-*' -printf '%f\n' | sort -V | tail -n 1)"
initrd="$(sudo find "$rootfs/boot" -maxdepth 1 -type f -name 'initrd.img-*' -printf '%f\n' | sort -V | tail -n 1)"
[[ -n "$kernel" && -n "$initrd" ]] || {
    echo "Debian kernel or initramfs is missing." >&2
    exit 1
}
sudo cp -L "$rootfs/boot/$kernel" "$iso_root/live/vmlinuz"
sudo cp -L "$rootfs/boot/$initrd" "$iso_root/live/initrd.img"
sudo install -m 0644 "$root_dir/live/grub.cfg" "$iso_root/boot/grub/grub.cfg"
sudo install -d -m 0755 "$iso_root/.disk"
printf 'ZAOD Debian %s XFCE Live\n' "$suite" |
    sudo tee "$iso_root/.disk/info" >/dev/null
sudo mksquashfs "$rootfs" "$iso_root/live/filesystem.squashfs" \
    -comp xz -b 1M -noappend -e boot
sudo chown -R "$(id -u):$(id -g)" "$iso_root"
grub-mkrescue -o "$output_iso" "$iso_root"
printf 'Created Debian-based ZAOD live desktop: %s\n' "$output_iso"
