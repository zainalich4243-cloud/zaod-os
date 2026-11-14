import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import zpkg
import z_shield

ZPKG = Path(__file__).resolve().parents[1] / "tools" / "zpkg"
Z_SHIELD = Path(__file__).resolve().parents[1] / "tools" / "z-shield"
GEN_ZSHIELD_HASHES = (
    Path(__file__).resolve().parents[1] / "tools" / "gen_zshield_hashes.py"
)


def minimal_elf() -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[6] = 1
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = (62).to_bytes(2, "little")
    return bytes(header)


class ZpkgTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zpkg-test-")
        self.root = Path(self.temp.name)
        self.private_key = self.root / "private.pem"
        self.public_key = self.root / "public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.private_key)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(self.private_key),
                "-pubout",
                "-out",
                str(self.public_key),
            ],
            check=True,
            capture_output=True,
        )
        self.source = self.root / "source"
        (self.source / "bin").mkdir(parents=True)
        (self.source / "assets").mkdir()
        (self.source / "bin" / "sample").write_bytes(minimal_elf())
        (self.source / "assets" / "icon.dat").write_bytes(b"icon")
        (self.source / "manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "app_id": "sample.app",
                    "version": "1.2.3",
                    "author": "ZAOD tests",
                    "entrypoint": "bin/sample",
                    "permissions": {
                        "camera": "one-time",
                        "microphone": "deny",
                        "storage": "while-using",
                        "notifications": "deny",
                        "network": "foreground",
                        "background": False,
                    },
                    "files": {},
                }
            ),
            encoding="utf-8",
        )
        self.package = self.root / "sample.zaod"
        subprocess.run(
            [
                str(ZPKG),
                "pack",
                str(self.source),
                str(self.package),
                "--private-key",
                str(self.private_key),
            ],
            check=True,
            capture_output=True,
        )
        self.scanner = self.root / "scanner"
        self.scanner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.scanner.chmod(0o755)
        self.apps_root = self.root / "apps"

    def tearDown(self):
        self.temp.cleanup()

    def test_signed_package_round_trip_and_remove(self):
        manifest, payload = zpkg.parse_package(
            self.package.read_bytes(), self.public_key
        )
        self.assertEqual(manifest["app_id"], "sample.app")
        self.assertIn("bin/sample", payload)

        subprocess.run(
            [
                str(ZPKG),
                "verify",
                str(self.package),
                "--public-key",
                str(self.public_key),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                str(ZPKG),
                "install",
                str(self.package),
                "--public-key",
                str(self.public_key),
                "--scanner",
                str(self.scanner),
                "--root",
                str(self.apps_root),
            ],
            check=True,
        )
        app_dir = self.apps_root / "sample.app"
        self.assertTrue((app_dir / "bin/sample").exists())
        self.assertTrue(os.access(app_dir / "bin/sample", os.X_OK))
        policy = json.loads((app_dir / ".zaod-policy.json").read_text())
        self.assertEqual(policy["app_id"], "sample.app")
        self.assertFalse(policy["background_access"])
        self.assertEqual(policy["resources"]["camera"], "one-time")
        self.assertEqual(policy["resources"]["storage"], "while-using")
        self.assertEqual(policy["resources"]["network"], "while-using")
        self.assertEqual(
            (app_dir / ".zaod-policy.json").stat().st_mode & 0o777, 0o444
        )

        subprocess.run(
            [
                str(ZPKG),
                "remove",
                "sample.app",
                "--root",
                str(self.apps_root),
            ],
            check=True,
            capture_output=True,
        )
        self.assertFalse(app_dir.exists())

    def test_payload_tampering_is_rejected(self):
        manifest, payload = zpkg.parse_package(
            self.package.read_bytes(), self.public_key
        )
        payload["assets/icon.dat"] = b"changed"
        unsigned_tar = zpkg.archive_members(
            zpkg.canonical_json(manifest) + b"\n",
            b"\0" * 64,
            payload,
        )
        altered_package = zpkg.zstd_compress(unsigned_tar)
        with self.assertRaises(zpkg.PackageError):
            zpkg.parse_package(altered_package, self.public_key)

    def test_bad_signature_and_trailing_zstd_data_are_rejected(self):
        manifest, payload = zpkg.parse_package(
            self.package.read_bytes(), self.public_key
        )
        unsigned_tar = zpkg.archive_members(
            zpkg.canonical_json(manifest) + b"\n",
            b"\0" * 64,
            payload,
        )
        bad_signature_package = zpkg.zstd_compress(unsigned_tar)
        with self.assertRaises(zpkg.PackageError):
            zpkg.parse_package(bad_signature_package, self.public_key)
        with self.assertRaises(zpkg.PackageError):
            zpkg.parse_package(self.package.read_bytes() + b"trailing", self.public_key)

    def test_background_and_persistent_camera_are_rejected(self):
        manifest = json.loads((self.source / "manifest.json").read_text())
        manifest["permissions"]["background"] = True
        with self.assertRaises(zpkg.PackageError):
            zpkg.validate_manifest(manifest)

    def test_legacy_manifest_permissions_default_new_resources_to_deny(self):
        manifest = json.loads((self.source / "manifest.json").read_text())
        manifest["schema_version"] = 1
        manifest["permissions"] = {
            "camera": "one-time",
            "microphone": "deny",
            "network": "none",
            "background": False,
        }
        manifest["files"] = {"bin/sample": "0" * 64}
        zpkg.validate_manifest(manifest)
        sidecar = zpkg.policy_sidecar(manifest)
        self.assertEqual(sidecar["resources"]["storage"], "deny")
        self.assertEqual(sidecar["resources"]["notifications"], "deny")
        self.assertEqual(sidecar["resources"]["network"], "deny")

        manifest["permissions"]["background"] = False
        manifest["permissions"]["camera"] = "always"
        with self.assertRaises(zpkg.PackageError):
            zpkg.validate_manifest(manifest)

        manifest["permissions"]["camera"] = "deny"
        manifest["permissions"]["notifications"] = "always"
        with self.assertRaises(zpkg.PackageError):
            zpkg.validate_manifest(manifest)

        manifest["permissions"]["notifications"] = "deny"
        manifest["permissions"]["network"] = "always"
        with self.assertRaises(zpkg.PackageError):
            zpkg.validate_manifest(manifest)

    def test_signed_catalog_signature(self):
        catalog_bytes = zpkg.canonical_json(
            {"schema_version": 1, "packages": []}
        )
        signature = zpkg.openssl_signature(
            "-sign", self.private_key, zpkg.CATALOG_DOMAIN + catalog_bytes
        )
        verified = zpkg.verify_catalog(
            catalog_bytes, signature, self.public_key
        )
        self.assertEqual(verified["packages"], [])
        with self.assertRaises(zpkg.PackageError):
            zpkg.verify_catalog(
                catalog_bytes + b" ", signature, self.public_key
            )

    def test_scanner_rejection_does_not_install(self):
        self.scanner.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        with self.assertRaises(zpkg.PackageError):
            zpkg.install_package(
                self.package.read_bytes(),
                self.public_key,
                self.scanner,
                self.apps_root,
            )
        self.assertFalse((self.apps_root / "sample.app").exists())
        self.assertEqual(list(self.apps_root.iterdir()), [])

    def test_scanner_cannot_modify_staged_payload(self):
        self.scanner.write_text(
            "#!/bin/sh\ncase \"$2\" in */bin/sample) printf changed > \"$2\";; esac\nexit 0\n",
            encoding="utf-8",
        )
        with self.assertRaises(zpkg.PackageError):
            zpkg.install_package(
                self.package.read_bytes(),
                self.public_key,
                self.scanner,
                self.apps_root,
            )
        self.assertEqual(list(self.apps_root.iterdir()), [])

    def test_scanner_cannot_modify_permission_policy(self):
        self.scanner.write_text(
            "#!/bin/sh\ncase \"$2\" in */.zaod-policy.json) chmod u+w \"$2\"; printf changed > \"$2\";; esac\nexit 0\n",
            encoding="utf-8",
        )
        with self.assertRaises(zpkg.PackageError):
            zpkg.install_package(
                self.package.read_bytes(),
                self.public_key,
                self.scanner,
                self.apps_root,
            )
        self.assertEqual(list(self.apps_root.iterdir()), [])

    def test_z_shield_verifies_signed_hashes_and_scanner_cli(self):
        definitions = self.root / "definitions.json"
        signature = self.root / "definitions.sig"
        sample_path = self.source / "bin" / "sample"
        definitions_bytes = zpkg.canonical_json(
            {
                "schema_version": 1,
                "entries": [
                    {
                        "sha256": hashlib.sha256(sample_path.read_bytes()).hexdigest(),
                        "label": "test threat",
                    }
                ],
            }
        )
        definitions.write_bytes(definitions_bytes)
        signature.write_bytes(
            zpkg.openssl_signature(
                "-sign",
                self.private_key,
                z_shield.DEFINITIONS_DOMAIN + definitions_bytes,
            )
        )

        with self.assertRaises(zpkg.PackageError):
            z_shield.scan_file(
                sample_path, definitions, signature, self.public_key
            )
        cli_result = subprocess.run(
            [
                str(Z_SHIELD),
                "--scan",
                str(sample_path),
                "--definitions",
                str(definitions),
                "--signature",
                str(signature),
                "--public-key",
                str(self.public_key),
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(cli_result.returncode, 1)
        self.assertIn("test threat", cli_result.stderr)
        signature.write_bytes(b"\0" * 64)
        with self.assertRaises(zpkg.PackageError):
            z_shield.scan_file(
                sample_path, definitions, signature, self.public_key
            )

    def test_z_shield_fails_closed_without_trusted_definitions(self):
        with self.assertRaises(zpkg.PackageError):
            z_shield.scan_file(
                self.source / "bin" / "sample",
                self.root / "missing.json",
                self.root / "missing.sig",
                self.public_key,
            )

    def test_signed_z_shield_catalog_is_compiled_for_kernel(self):
        definitions = self.root / "definitions.json"
        signature = self.root / "definitions.sig"
        output = self.root / "zshield_hashes.h"
        digest = hashlib.sha256(b"kernel test threat").hexdigest()
        definitions_bytes = zpkg.canonical_json(
            {
                "schema_version": 1,
                "entries": [{"sha256": digest, "label": "kernel test"}],
            }
        )
        definitions.write_bytes(definitions_bytes)
        signature.write_bytes(
            zpkg.openssl_signature(
                "-sign",
                self.private_key,
                z_shield.DEFINITIONS_DOMAIN + definitions_bytes,
            )
        )
        environment = os.environ.copy()
        environment.update(
            {
                "ZAOD_ZSHIELD_DEFINITIONS": str(definitions),
                "ZAOD_ZSHIELD_SIGNATURE": str(signature),
                "ZAOD_ZSHIELD_PUBLIC_KEY": str(self.public_key),
            }
        )
        result = subprocess.run(
            [sys.executable, str(GEN_ZSHIELD_HASHES), "--output", str(output)],
            capture_output=True,
            check=False,
            text=True,
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        generated = output.read_text(encoding="ascii")
        self.assertIn("#define ZAOD_ZSHIELD_CATALOG_AUTHENTICATED 1", generated)
        self.assertIn("#define ZAOD_ZSHIELD_DEFINITION_COUNT 1u", generated)
        self.assertIn("kernel test", generated)
        expected_bytes = ", ".join(
            f"0x{value:02x}" for value in bytes.fromhex(digest)
        )
        self.assertIn(expected_bytes, generated)
        trusted_hash = self.root / "trusted_init_hash.h"
        trusted_hash.write_text(
            "#define ZAOD_TRUSTED_INIT_SHA256 {" +
            ", ".join(["0"] * 32) + "}\n",
            encoding="ascii",
        )
        kernel = Path(__file__).resolve().parents[1] / "kernel"
        compile_result = subprocess.run(
            [
                "cc",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(self.root),
                "-I",
                str(kernel / "include"),
                "-fsyntax-only",
                str(kernel / "src" / "zshield.c"),
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
        probe = self.root / "zshield_probe.c"
        probe.write_text(
            '#include <string.h>\n'
            '#include "zshield.h"\n'
            'int main(void) {\n'
            '  const char *label = 0;\n'
            '  return zshield_scan_bytes("kernel test threat", '
            '18, &label) && strcmp(label, "kernel test") == 0 ? 0 : 1;\n'
            '}\n',
            encoding="ascii",
        )
        probe_binary = self.root / "zshield_probe"
        compile_result = subprocess.run(
            [
                "cc",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(self.root),
                "-I",
                str(kernel / "include"),
                str(probe),
                str(kernel / "src" / "sha256.c"),
                str(kernel / "src" / "zshield.c"),
                "-o",
                str(probe_binary),
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
        self.assertEqual(subprocess.run([str(probe_binary)], check=False).returncode, 0)

        signature.write_bytes(b"\0" * 64)
        result = subprocess.run(
            [sys.executable, str(GEN_ZSHIELD_HASHES), "--output", str(output)],
            capture_output=True,
            check=False,
            text=True,
            env=environment,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_zpkg_installs_through_z_shield_with_signed_definitions(self):
        definitions = self.root / "definitions.json"
        signature = self.root / "definitions.sig"
        definitions_bytes = zpkg.canonical_json(
            {"schema_version": 1, "entries": []}
        )
        definitions.write_bytes(definitions_bytes)
        signature.write_bytes(
            zpkg.openssl_signature(
                "-sign",
                self.private_key,
                z_shield.DEFINITIONS_DOMAIN + definitions_bytes,
            )
        )
        with patch.dict(
            os.environ,
            {
                "ZAOD_ZSHIELD_DEFINITIONS": str(definitions),
                "ZAOD_ZSHIELD_SIGNATURE": str(signature),
                "ZAOD_ZSHIELD_PUBLIC_KEY": str(self.public_key),
            },
        ):
            zpkg.install_package(
                self.package.read_bytes(),
                self.public_key,
                Z_SHIELD,
                self.apps_root,
            )
        self.assertTrue((self.apps_root / "sample.app" / "bin/sample").exists())


if __name__ == "__main__":
    unittest.main()
