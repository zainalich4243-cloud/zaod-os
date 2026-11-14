# zaod-os

## Building the bootable ISO

The workspace includes the Limine v12.10.0 BIOS/UEFI boot files, a UEFI
fallback loader, and its `bios-install` utility source. Build tools can be
installed on Ubuntu with:

```sh
sudo apt-get update
sudo apt-get install build-essential nasm xorriso mtools grub-pc-bin wget
```

Run the build script to compile the freestanding kernel and initramfs, then
bundle both with Limine:

```sh
./build.sh
```

To compile only the kernel without producing an ISO, run:

```sh
make -C kernel kernel
```

This writes `iso_root/kernel/zaod_kernel.elf`.
The script writes `zaod-os-production.iso` in the repository root. Kernel build flags
and optimization are configured in [kernel/.config](./kernel/.config); the
custom Makefile uses `-O3`. The Limine menu waits indefinitely for a selection.
The image is currently a bootable kernel prototype, not a production OS
release: optional drivers, encrypted user storage, graphical session manager,
and bundled native desktop applications are not implemented.
Limine loads its recognized configuration from
[`iso_root/boot/limine/limine.conf`](./iso_root/boot/limine/limine.conf);
[`iso_root/boot/limine.cfg`](./iso_root/boot/limine.cfg) is retained as a
compatibility copy for the requested project layout.
The two entries pass `zaod.mode=live ram` and `zaod.mode=install` and load
`initramfs.img` as a module. The kernel initializes COM1 diagnostics, reads
Limine boot/memory-map data, installs CPU exception handlers, tests its
HHDM-backed page allocator, then starts the serial monitor task (`help`,
`info`, `mem`, `page`, `panic`, `halt`) alongside the CPL3 framebuffer
launcher.

## Early-boot memory and hardware policies

The SysV-style scripts in `iso_root/etc/init.d/` are called at boot by the
included `iso_root/etc/rcS.d/` hooks on a SysV-compatible system. Other init
systems should register the same scripts as root. To run them manually:

```sh
/etc/init.d/zram-init start
/etc/init.d/zaod-scale start
```

`zram-init` enables an LZ4 (or ZSTD fallback) swap device using half of physical
RAM when total RAM is at most 3 GiB. `zaod-scale.sh` writes the selected `lite`
or `pro` mode to `/run/zaod-scale/mode`, applies available CPU governors and
`mq-deadline`, and can toggle Hyprland animations/blur when run in an active
Hyprland session. Lite mode is selected for RAM below 3 GiB or a Celeron; Pro
mode requires at least 4 GiB and two or more cores. Other hardware falls back
to Lite. Generic GPU acceleration cannot be enabled by a shell script; it
depends on the kernel's DRM driver and compositor. The target init system
should invoke the scripts as root, and a desktop-session hook is needed to
apply compositor settings outside Hyprland.

## Kernel security policy bring-up

The kernel contains a policy API in
[kernel/src/security.c](./kernel/src/security.c): unprivileged module loads
and unverified executable launches are denied, and writes to protected system
paths are denied. Path checks reject relative, traversal,
repeated-separator, and overlong paths. Decisions enter a bounded in-memory
event ring and are printed to the serial console. A fixed-capacity permission
broker additionally denies third-party background execution, prompts for
registered camera, microphone, storage, notifications, and network policies,
and revokes grants when foreground focus is lost or the process exits. The
kernel scheduler suspends non-system tasks when its system-controlled focus
hook backgrounds them; only a system task can resume them. The monitor's
`perm` command demonstrates the serial prompt. Run
`make -C kernel test` for host-side policy and permission tests.

The kernel has a kernel-thread scheduler, a `newc` CPIO read-only VFS, RAM
app-scoped settings, and an `int 0x80` syscall dispatcher. The gate is
user-callable; bounded syscall arguments are copied through validated user
mappings. Each user task receives a private lower-half page-table root while
kernel mappings remain supervisor-only. A W^X ELF64 loader now launches the
trusted initramfs `/sbin/init.elf` in CPL3; the TSS kernel stack is switched on
task selection, and user faults terminate the task instead of halting the
kernel. The monitor's subject records are test inputs, not an authentication
system. The system-task `sys_exec` route now validates flat `.zaod` package
signatures, manifest permissions, the ELF SHA-256, configured Z-Shield
blocklist, and W^X mappings before spawning an app. Launch fails closed unless
a signed Z-Shield catalog is configured. Only the system task can launch
packages and only one third-party task may be active at a time; a graphical
session manager and package installer are still absent.
A host-side Z-Shield scanner in
[tools/z_shield.py](./tools/z_shield.py) verifies signed local SHA-256 threat
definitions and is compatible with the package install scan hook. It fails
closed when trusted definitions are missing or invalid; it only recognizes
listed hashes and cannot detect unknown threats. To compile those definitions
into the kernel, pass all three trusted inputs to the build:

```sh
make -C kernel kernel \
  ZAOD_ZSHIELD_DEFINITIONS=/path/to/definitions.json \
  ZAOD_ZSHIELD_SIGNATURE=/path/to/definitions.sig \
  ZAOD_ZSHIELD_PUBLIC_KEY=/path/to/definitions.pub
```

The host build verifies the definitions signature before emitting the bounded
kernel hash table; a partial or invalid configuration fails the build. With no
catalog supplied, kernel VFS writes fail closed. With a catalog, writes are
hashed as complete candidate files; known matches are denied and recorded in
the in-memory security event ring. The ELF loader also SHA-256-pins the trusted
init image at build time and rejects other images. Signature verification
occurs during the trusted build, not in the kernel; this is not a kernel
daemon, unknown threats remain undetected, and there is no persistent
encrypted log.

The kernel flat-package parser uses an Ed25519 trust root. Run
`python3 tools/gen_keys.py` to store a local signing key outside the repository at
`~/.config/zaod/keys/zaod_release_private.key` (mode 0600) and writes the
public key into `kernel/crypto/zaod_keys.h`. A locally generated key is still
only a development trust anchor, not an official ZAOD release key; production
release keys need independent custody and a reviewed signing ceremony.
The loader uses the generated root public key, currently a local development
trust anchor rather than an official release key. Package installation still
runs the explicitly configured host scanner before committing staged content.
Permanent auto-deletion is not enabled; suspicious content is denied, and a
future response should use reversible quarantine.

## Native packages

The host `zpkg` archive format and kernel flat runtime format are documented in
[docs/zaod-package-format.md](./docs/zaod-package-format.md). The executable
wrapper is [tools/zpkg](./tools/zpkg); its packer, verifier, GitHub catalog
fetcher, and installer are implemented in [tools/zpkg.py](./tools/zpkg.py).
The host-side scanner is available as [tools/z-shield](./tools/z-shield).
Package installation requires a trusted Ed25519 package key, the scanner
executable, and valid signed Z-Shield definitions; it fails closed if any
verification fails.
`make -C kernel test` also runs package signature, manifest, scanner, install,
and removal tests.

## ZAOD SDK and Studio

The freestanding C SDK is in [sdk/](./sdk/). It wraps the current syscall
numbers for file access, exit, execution requests, permission prompts, input,
and the system-only onboarding draw call. Compile project templates with
[tools/zaodc](./tools/zaodc); it emits a schema-v2 manifest with background
access disabled and a signing-ready package directory, or a kernel-flat signed
`.zaod` when given the matching Ed25519 private key. Use
[docs/zaod-sdk.md](./docs/zaod-sdk.md) for the commands and current ABI.

[ZAOD Studio](./apps/zaod-studio/) is a lightweight host-side Tk editor with
project templates, line numbers, basic C highlighting, build, and package
export. Its “Build & Run in Sandbox” action builds and then reports the
runtime limitation instead of executing untrusted code on the host. Although
the kernel now has a signature-gated package execution path, no flat-package
installer, desktop manager, broad app-data isolation, or native window API is
available yet. Consequently Studio cannot yet be shipped as a functional
native `.zaod` app, and `zaodc run` fails closed.

ZAOD remains a custom Limine-protocol kernel bring-up, not a Linux kernel or
POSIX-compliant OS. It can parse the read-only CPIO initramfs and launch the
trusted init ELF in user mode; the signed-app launch path is wired but gated on
storage, trusted scanner catalog, and a system-managed package workflow.
The freestanding ChaCha20-Poly1305 primitive in
[kernel/crypto/chacha20.c](./kernel/crypto/chacha20.c) passes the RFC 8439
known-answer and tamper tests, but it is not yet integrated with ZAODFS; there
is no Argon2id password derivation, persistent nonce design, or volume-key
lifecycle, so user data is not encrypted at rest.
An optional primary-master ATA LBA28 disk can be mounted as a minimal fixed-slot
ZAODFS volume for `/home/` and `/opt/zaod/apps/`; it is not a general-purpose
filesystem, and the kernel never formats disks automatically. The kernel
enforces build-authenticated known-hash checks on VFS writes when a catalog is
configured and pins the trusted init image, but it does not verify catalog
signatures at runtime or run a Z-Shield daemon. The full scanner remains a
host-side package tool.
