# ZAOD App Developer Guide

This guide covers the current x86_64 freestanding C SDK and the kernel-flat
`.zaod` package format. The runtime is experimental; read the limitations below
before designing an app for release.

## Requirements

On Ubuntu/Debian, install the host compiler and signing tools:

```sh
sudo apt-get install build-essential openssl python3
```

The repository tools are `tools/zaodc`, `tools/zpkg`, and the headers/library
in `sdk/`. No hosted C library is linked into a native app.

## Create an app

```sh
tools/zaodc new hello \
  --app-id org.example.hello \
  --version 0.1.0 \
  --author "Example Developer"
```

This creates:

```text
hello/
├── zaod.json
├── src/
│   └── main.c
└── assets/
```

`zaod.json` has exactly four fields: `app_id`, `version`, `author`, and
`permissions`. App IDs use lowercase letters, digits, dots, and hyphens; use a
reverse-domain name you control.

The default entry point is `_start`. A minimal app exits without a hosted
runtime:

```c
#include "libzaod.h"

__attribute__((noreturn))
void _start(void)
{
    (void)zaod_exit();
    for (;;) {
        __asm__ volatile ("pause");
    }
}
```

Add C files under `src/`, project headers under `include/`, and static files
under `assets/`. Sources are compiled as freestanding x86_64. C++ is accepted
with exceptions and RTTI disabled. Do not assume libc, a POSIX process model,
or a general graphical API.

## Permissions

The manifest must declare all six policy fields. The defaults deny access:

```json
{
  "camera": "deny",
  "microphone": "deny",
  "storage": "deny",
  "notifications": "deny",
  "network": "none",
  "background": false
}
```

Camera, microphone, storage, and notifications accept `deny`, `one-time`, or
`while-using`. Network accepts `none` or `foreground`. Background execution
must remain `false`; third-party background persistence is not supported.
Request only permissions the app actually needs. A broker grant does not imply
that a hardware driver or service exists.

The SDK API is declared in [`../sdk/libzaod.h`](../sdk/libzaod.h):

- `zaod_open`, `zaod_read`, and `zaod_write` for bounded file access.
- `zaod_request_perm` for a broker-mediated resource request.
- `zaod_exit` to terminate the current task.
- `zaod_exec`, input, and UI functions are currently system-task-only or
  otherwise restricted; third-party apps do not have a general window,
  framebuffer, keyboard, or child-process API.

Syscall results are signed: non-negative results indicate success and negative
values indicate errors. Check every result; do not treat a denied permission or
failed write as success.

## Build and inspect

Build an unsigned staging directory first:

```sh
tools/zaodc build hello --output build/hello
find build/hello -maxdepth 3 -type f -print
```

The output contains `manifest.json`, `bin/app`, and staged assets. The tool
hashes the files and validates the manifest and x86_64 ELF. Assets are retained
in the staging directory; the current signed kernel-flat format includes only
`bin/app`, so the kernel runtime cannot yet load app assets.

Run the host-side regression suite before sharing a project:

```sh
make -C kernel test
```

## Sign a kernel-flat package

Signing keys are not interchangeable with package files. Never commit or
publish a private key. The repository's embedded root is a local development
trust anchor, not a production release key. Do not replace it in a release
build.

For isolated development, provision a separate test key and header:

```sh
python3 tools/gen_keys.py \
  --private-key "$HOME/.config/zaod/keys/dev-test.key" \
  --public-header build/dev_zaod_keys.h
```

Build a flat package against that header:

```sh
tools/zaodc build hello \
  --output build/hello.zaod \
  --private-key "$HOME/.config/zaod/keys/dev-test.key" \
  --root-key-header build/dev_zaod_keys.h
```

`zaodc` verifies that the private key matches the selected header and verifies
the resulting Ed25519 signature. A kernel accepts this package only if it was
built with the same public key. Keep test keys and headers out of release
builds.

## Package formats are different

There are two formats with the `.zaod` suffix:

1. `tools/zaodc build ... --private-key ...` produces the uncompressed,
   kernel-flat signed package documented in
   [`zaod-package-format.md`](./zaod-package-format.md).
2. `tools/zpkg pack` produces a compressed host distribution archive for the
   host-side installer/scanner. The kernel loader cannot execute that archive.

Do not pass a `zpkg` archive to the kernel loader or treat it as a kernel-flat
package.

## Current runtime and publishing limits

The kernel has a signed-package execution gate, but it is not yet a complete
app platform:

- The kernel requires a configured signed Z-Shield catalog and fails closed
  without one. A catalog containing no threat entries provides no malware
  coverage.
- There is no flat-package installer in the OS. Packages must be placed at
  `/opt/zaod/apps/<app-id>/package.zaod` by a trusted system workflow.
- The optional ATA-backed filesystem has 16 fixed slots and a 2 MiB maximum
  file size; a package must fit both limits.
- No general third-party graphics/input/window API, app store, update system,
  or third-party process lifecycle UI exists.
- `tools/zaodc run` intentionally does not execute app code on the host. A
  CPL3 package integration test and a supported user-facing install workflow
  are still required before publishing native apps.

Consequently, a valid signature proves package integrity and signer identity
relative to the selected test root; it does not make an app safe, provide
missing kernel services, or make this prototype production-ready.
