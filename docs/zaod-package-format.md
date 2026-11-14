# ZAOD Package Formats

The host `zpkg` distribution format is one Zstandard frame containing a POSIX
USTAR archive. The archive contains exactly one root `manifest.json`, one raw
64-byte Ed25519 `signature.sig`, and the payload files declared by the
manifest. Payload paths must be beneath `bin/` or `assets/`. Links, devices,
sparse files, PAX extensions, duplicate names, traversal paths, and undeclared
files are rejected.

The current package manager bounds a compressed package to 128 MiB, an
uncompressed archive to 128 MiB, a payload file to 32 MiB, and the package to
4,096 payload files. Binary payloads are currently restricted to ELF64,
little-endian x86_64.

## Kernel flat runtime package format

The kernel parser and `zaodc build --private-key ... --output APP.zaod` use a
separate uncompressed `ZAOD` flat format (version 1), not the host `zpkg`
Zstandard/USTAR container above. Its 88-byte
little-endian header is laid out as: magic[4], version u16, header size u16,
manifest offset u32, manifest size u32, ELF offset u32, ELF size u32, and raw
Ed25519 signature[64]. The manifest starts at byte 88; the ELF follows it
immediately, and the ELF end must equal the package end. The parser bounds
manifest data to 64 KiB and ELF data to 16 MiB, checks the ELF64 x86_64
identity fields, and hashes both sections with SHA-256.

The signature covers this exact message:

```text
"ZAOD-FLAT-PKG-V1\0" || LE32(manifest_size) || LE32(elf_size) ||
SHA256(manifest) || SHA256(elf)
```

Ed25519 verification is freestanding and uses fixed-size stack storage. The
generic parser accepts a caller-supplied public key for testability. The
root-key wrapper checks `kernel/crypto/zaod_keys.h`. The package
manifest must be schema v2 with `entrypoint: "bin/app"`, disabled background
access, known permission fields, and a matching SHA-256 digest for `bin/app`.
The flat format carries only that entrypoint ELF; other staged assets are not
included in a signed flat package. `zaodc` checks that the signing key matches
the public key in the selected kernel header.

`sys_exec` now routes system-task package requests through flat-header,
signature, manifest, ELF digest, Z-Shield catalog, permission-policy, and
verified ELF checks before spawning a CPL3 task. The package must be under
`/opt/zaod/apps/<app-id>/` and the kernel requires a configured signed
Z-Shield catalog; without it execution fails closed. Only the system task may
launch packages, and at most one third-party task may be active at a time.
The kernel does not yet include a graphical session manager or a flat-package
installer, so this gate is not a complete end-user application workflow.

## Manifest schema v2

The manifest is UTF-8 JSON with duplicate keys rejected. Both schema versions
use exactly these top-level fields; new packages use manifest schema version 2:

```json
{
  "schema_version": 2,
  "app_id": "example.hello",
  "version": "1.2.3",
  "author": "ZAOD App Team",
  "entrypoint": "bin/hello",
  "permissions": {
    "camera": "one-time",
    "microphone": "deny",
    "storage": "while-using",
    "notifications": "deny",
    "network": "foreground",
    "background": false
  },
  "files": {
    "assets/icon.png": "<64 lowercase hexadecimal SHA-256 characters>",
    "bin/hello": "<64 lowercase hexadecimal SHA-256 characters>"
  }
}
```

`files` lists every payload file and its SHA-256 digest; it excludes
`manifest.json` and `signature.sig`. `camera` and `microphone` accept only
`deny`, `one-time`, or `while-using`; `storage` and `notifications` accept the
same values. Network accepts `none` or `foreground`; background must be the
JSON boolean `false`. Schema v1 packages remain readable; their storage and
notification permissions default to `deny`.

During installation, `zpkg` creates a read-only `.zaod-policy.json` alongside
the app files. It contains the validated resource policies, maps network
`foreground` to `while-using`, and denies resources absent from a legacy v1
manifest. Z-Shield scans this generated policy as well as the manifest and
payload before installation. This sidecar is installer metadata, not a
kernel-enforced permission record yet. The kernel permission broker treats
`Only This Time` as authorization for that permission request only; it does
not retain a grant. `While Using` is retained only while the process remains
foreground and is revoked on focus loss or process exit. Because the kernel
does not yet expose camera, microphone, or network device operations, this
broker behavior does not itself provide those resource drivers or a graphical
permission prompt.

## Signature

For package signing, the Ed25519 message is:

```text
"ZAOD-PACKAGE-V1\0" || exact_manifest_bytes || "\0" ||
canonical_json(manifest.files)
```

Canonical JSON uses UTF-8, sorted keys, no insignificant whitespace, and no
ASCII escaping of non-ASCII characters. `signature.sig` is the raw Ed25519
signature. The package manager receives the trusted public key out-of-band;
there is no built-in ZAOD release key.

The release catalog is a signed JSON object with `schema_version: 1` and a
`packages` array. Each entry has exactly `app_id`, `version`, `release_tag`,
`asset`, and `sha256`. Its signature is over
`"ZAOD-CATALOG-V1\0" || exact_catalog_bytes`. The package SHA-256 in this
catalog is checked before the package's own signature and payload digests.
`zpkg fetch` reads `catalog.json` and `catalog.sig` from the repository's
latest GitHub release, then fetches the named asset from its signed release
tag. All fetches use HTTPS and enforce download size limits.

## CLI

```text
tools/zpkg pack SOURCE OUTPUT.zaod --private-key SIGNING_PRIVATE.pem
tools/zpkg verify PACKAGE.zaod --public-key ZAOD_PACKAGE_PUBLIC.pem
tools/zpkg install PACKAGE.zaod --public-key ZAOD_PACKAGE_PUBLIC.pem \
    --scanner /trusted/path/to/z-shield --root /opt/zaod/apps
tools/zpkg fetch APP_ID VERSION --repo OWNER/REPOSITORY \
    --public-key ZAOD_PACKAGE_PUBLIC.pem --scanner /trusted/path/to/z-shield
tools/zpkg remove APP_ID --root /opt/zaod/apps
```

Install and fetch require an explicit scanner executable. Before publication,
the scanner is invoked as `SCANNER --scan PATH` for the manifest and every
payload file. A nonzero exit or scanner failure aborts installation and removes
the staging directory. The scanner executable must be supplied by a trusted
system installation, not by the package.

The host-side hash scanner is available as `tools/z-shield`. It verifies
Ed25519-signed `zshield-definitions.json` and `zshield-definitions.sig` files,
then compares each scanned file's SHA-256 digest to the trusted definitions.
Provision the trust public key out-of-band at
`/etc/zaod/zshield/definitions.pub`, then update definitions from a GitHub
release with:

```sh
tools/z-shield sync --repo OWNER/REPOSITORY \
    --public-key /path/to/trusted-definitions.pub
tools/zpkg install PACKAGE.zaod --public-key ZAOD_PACKAGE_PUBLIC.pem \
    --scanner /path/to/tools/z-shield
```

The signed definitions JSON has `schema_version: 1` and an `entries` array;
each entry has exactly a lowercase SHA-256 `sha256` and a short `label`.
Sign the exact JSON bytes with the Ed25519 message prefix
`"ZAOD-ZSHIELD-DEFINITIONS-V1\0"`. Missing, malformed, or invalidly signed
definitions cause scans to fail closed. Hash matching detects only listed
known files; it is not heuristic analysis and cannot detect unknown threats.
The scanner is a host-side package gate, not a running kernel daemon.

Installation is staged beneath the app root and atomically renamed into
`APP_ROOT/APP_ID`; packages cannot choose installation paths or set ownership.
Removal requires the app ID and a ZAOD install receipt and removes only that
app's isolated directory.

## Current implementation boundary

The kernel has a fixed-capacity permission broker, a kernel-thread scheduler,
a CPIO-backed read-only VFS, and syscall routing through the security and
permission APIs. Writable per-app settings are bounded, volatile RAM files.
System-managed `/home/` and `/opt/zaod/apps/` paths can use the optional,
primary-master ATA-backed fixed-slot ZAODFS volume described in
[`zaod-sdk.md`](./zaod-sdk.md); the root filesystem remains read-only. The
`int 0x80` gate is DPL3, with validated copies for user syscall buffers. A
trusted init ELF runs in CPL3 with separate lower-half page tables, a TSS
kernel stack, and W^X segment mappings. Host tests cover policy registration,
background denial, prompt choices, VFS access checks, syscall denial, address
space permissions, storage revocation, package manifest policy, and flat
package signatures. Linux namespaces and seccomp are not part of this custom
kernel.

`zpkg` does not execute packages and its compressed distribution container is
not the kernel flat runtime format. Installation still requires an explicitly
configured trusted scanner and fails closed if it is missing or rejects a
file. No generic scanner can reliably identify unknown malware. The Python
package manager and hash scanner are host-side tools; the kernel cannot run
them. The kernel's ELF loader still SHA-256-pins the trusted init image at
build time. When signed Z-Shield definitions are supplied to the kernel build,
the host build verifies their Ed25519 signature and compiles the bounded hash
list into the kernel; VFS writes are checked against it before commit, and
matches are denied and recorded in the in-memory security event ring. The
package execution path also fails closed without this catalog and rejects
known blocked ELF hashes. The kernel does not verify the catalog signature at
runtime, unknown threats remain undetected, and this does not provide an
autonomous scanner daemon or persistent security log.

`zaodc` and `libzaod` are in `tools/` and `sdk/`. The compiler creates an
x86_64 ELF and a v2 manifest with background access disabled. Without a
private key it emits a signing-ready directory; with a matching private key
and kernel root header it emits and verifies a kernel-flat signed `.zaod`.
The flat runtime package currently includes only `bin/app`, not project
assets. The host-side ZAOD Studio can edit projects and build packages, but
cannot run them in a kernel sandbox. The kernel gate currently lacks a flat
package installer, graphical session manager, general app-data isolation, and
runtime window/framebuffer APIs. The persistent volume is not a
general-purpose filesystem.
