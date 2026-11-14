# ZAOD SDK and toolchain

## Create and build a project

```sh
tools/zaodc new hello --app-id example.hello --author "Example"
tools/zaodc build hello --output build/hello
tools/zaodc build hello --output build/hello.zaod \
    --private-key /secure/path/zaod_release_private.key
```

The first build output is a directory containing `manifest.json`, `bin/app`,
and any copied project assets. It is intentionally unsigned and can be
reviewed before signing. Supplying `--private-key KEY` directly to `zaodc
build` writes and verifies a kernel-flat signed `.zaod`; the output must end
in `.zaod`, and the key must match `kernel/crypto/zaod_keys.h` or the selected
`--root-key-header`. The flat runtime format carries only `bin/app`; project
assets remain in the staging directory. `tools/zpkg` produces a separate
compressed host distribution format that the kernel does not load.

Projects contain a `zaod.json` with exactly these fields:

```json
{
  "app_id": "example.hello",
  "version": "0.1.0",
  "author": "Example",
  "permissions": {
    "camera": "deny",
    "microphone": "deny",
    "storage": "deny",
    "notifications": "deny",
    "network": "none",
    "background": false
  }
}
```

C and freestanding C++ sources under `src/` are compiled for x86_64. The
application entry point is `_start`; no hosted C or C++ runtime is linked.
Assets under `assets/` are copied into the unsigned staging directory.
`zaodc` checks the v2 manifest and ELF architecture. The host package manager
separately verifies archive signatures and payload hashes, and `zpkg install`
invokes the configured trusted Z-Shield scanner before committing installation.

## SDK interface

`sdk/libzaod.h` and `sdk/libzaod.c` define:

- `zaod_open`, `zaod_read`, `zaod_write`, `zaod_exec`, and `zaod_exit`
- `zaod_request_perm`, with the kernel broker as the authority for the
  `Only This Time` / `While Using App` prompt choices
- `zaod_input_read` and `zaod_ui_draw_onboarding`

Results use the kernel's signed return convention: non-negative values are
success and negative values are error numbers. The current kernel only allows
input, onboarding, and launcher drawing calls for system tasks. It has no
general third-party framebuffer/window syscall. Permission requests are dispatched
through the fixed-table broker and currently prompt on the serial console.
The kernel focus hook revokes grants and suspends non-system tasks when
backgrounded, but no desktop session manager currently drives focus changes.
The trusted CPL3 init now draws a small system-only framebuffer launcher and
can request the three known `.zaod` package paths through `sys_exec`. The
launcher reports missing or denied packages; those core packages are not
bundled or installed yet, and its settings entry is explicitly unfinished.

## Studio and execution boundary

Run the host-side editor with `apps/zaod-studio/run.sh`. It uses Tkinter from
the host Python installation; it is not itself a native ZAOD app. Its build
action compiles the project. Its sandbox action deliberately refuses to run
the resulting ELF. The system-task `sys_exec` path validates flat-package
signatures, manifest policy, binary digest, configured Z-Shield block hashes,
and W^X ELF segments before creating a CPL3 task. The system task is currently
the only package launcher; no flat-package installer or graphical session
manager is present. `zaodc run` remains fail-closed and never falls back to
executing package code on the host.

The scheduler and VFS currently operate on kernel tasks. The VFS provides
read-only files from the CPIO initramfs, per-app volatile RAM storage, and
`/home/` plus `/opt/zaod/apps/` paths on an optional primary-master ATA LBA28
disk formatted with the fixed-slot ZAODFS. ZAODFS holds 16 files, up to 2 MiB
each; it is not a general-purpose filesystem and has no partition/ATA driver
selection. `tools/mkzaodfs.py format IMAGE` formats only an existing regular
disk-image file and must not be used on a device containing needed data.
The kernel never formats storage automatically. VFS writes fail closed unless
a signed definitions catalog is supplied to the kernel build. Z-Shield is a
host-side signed-hash scanner wired into package installation, not an
always-running kernel daemon. The host build verifies an optional signed
catalog and compiles it into the kernel; VFS writes are then hash-checked
before commit. The kernel does not verify that catalog signature itself.
