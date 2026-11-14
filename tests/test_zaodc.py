import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import zaodc
import zpkg


ZAODC = ROOT / "tools" / "zaodc"


class ZaodcTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zaodc-test-")
        self.root = Path(self.temp.name)
        self.project = self.root / "sample"
        subprocess.run(
            [
                str(ZAODC),
                "new",
                str(self.project),
                "--app-id",
                "sample.hello",
                "--author",
                "ZAOD tests",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        (self.project / "assets" / "icon.bin").write_bytes(b"sample icon")
        (self.project / "src" / "main.c").write_text(
            '#include "libzaod.h"\n'
            "__attribute__((noreturn)) void _start(void) {\n"
            "    char data[4] = {0};\n"
            '    int64_t fd = zaod_open("/var/lib/zaod/apps/sample.hello/state", '
            "ZAOD_OPEN_WRITE | ZAOD_OPEN_CREATE);\n"
            '    if (fd >= 0) (void)zaod_write(fd, "ok", 3);\n'
            "    (void)zaod_read(fd, data, sizeof(data));\n"
            "    (void)zaod_request_perm(ZAOD_PERMISSION_CAMERA);\n"
            "    (void)zaod_ui_draw_onboarding(0, 0);\n"
            "    (void)zaod_exit();\n"
            '    for (;;) __asm__ volatile ("pause");\n'
            "}\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_build_creates_valid_v2_signing_stage_and_signed_package(self):
        stage = self.root / "stage"
        subprocess.run(
            [str(ZAODC), "build", str(self.project), "--output", str(stage)],
            check=True,
            capture_output=True,
            text=True,
        )
        manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
        zpkg.validate_manifest(manifest)
        self.assertEqual(manifest["schema_version"], 2)
        self.assertFalse(manifest["permissions"]["background"])
        self.assertIn("bin/app", manifest["files"])
        self.assertIn("assets/icon.bin", manifest["files"])
        self.assertEqual((stage / "bin/app").read_bytes()[:4], b"\x7fELF")

        private_key = self.root / "signing.pem"
        public_key = self.root / "signing.pub"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(private_key),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_key),
            ],
            check=True,
            capture_output=True,
        )
        public_der = subprocess.run(
            ["openssl", "pkey", "-in", str(private_key), "-pubout", "-outform", "DER"],
            check=True,
            capture_output=True,
        ).stdout
        root_header = self.root / "zaod_keys.h"
        root_header.write_text(
            "#define ZAOD_ROOT_PUBLIC_KEY_CONFIGURED 1\n"
            "static const unsigned char ZAOD_ROOT_PUBLIC_KEY[32] = {\n"
            + ", ".join(f"0x{value:02x}" for value in public_der[-32:])
            + "\n};\n",
            encoding="ascii",
        )
        package = self.root / "sample.zaod"
        subprocess.run(
            [
                str(ZAODC),
                "build",
                str(self.project),
                "--output",
                str(package),
                "--private-key",
                str(private_key),
                "--root-key-header",
                str(root_header),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        signed_manifest, binary = zaodc.parse_flat_package(
            package.read_bytes(), public_key
        )
        self.assertEqual(signed_manifest["schema_version"], 2)
        self.assertEqual(set(signed_manifest["files"]), {"bin/app"})
        self.assertEqual(binary[:4], b"\x7fELF")
        self.assertTrue(package.read_bytes().startswith(b"ZAOD"))
        verifier = os.environ.get("ZAOD_KERNEL_PACKAGE_VERIFY")
        if verifier:
            public_raw = self.root / "public.raw"
            public_raw.write_bytes(public_der[-32:])
            subprocess.run(
                [verifier, str(package), str(public_raw)],
                check=True,
                capture_output=True,
            )
        tampered = bytearray(package.read_bytes())
        tampered[-1] ^= 1
        with self.assertRaises((zaodc.ZaodcError, zpkg.PackageError)):
            zaodc.parse_flat_package(bytes(tampered), public_key)

        mismatched_header = self.root / "mismatched-zaod_keys.h"
        mismatched_key = bytearray(public_der[-32:])
        mismatched_key[0] ^= 1
        mismatched_header.write_text(
            "#define ZAOD_ROOT_PUBLIC_KEY_CONFIGURED 1\n"
            "static const unsigned char ZAOD_ROOT_PUBLIC_KEY[32] = {\n"
            + ", ".join(f"0x{value:02x}" for value in mismatched_key)
            + "\n};\n",
            encoding="ascii",
        )
        mismatch = subprocess.run(
            [
                str(ZAODC), "build", str(self.project),
                "--output", str(self.root / "mismatch.zaod"),
                "--private-key", str(private_key),
                "--root-key-header", str(mismatched_header),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertIn("does not match", mismatch.stderr)

    def test_background_policy_is_rejected_and_run_fails_closed(self):
        config_path = self.project / "zaod.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["permissions"]["background"] = True
        config_path.write_text(json.dumps(config), encoding="utf-8")
        rejected = subprocess.run(
            [
                str(ZAODC),
                "build",
                str(self.project),
                "--output",
                str(self.root / "rejected"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("background", rejected.stderr)

        result = subprocess.run(
            [str(ZAODC), "run", str(self.root / "untrusted.zaod")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("system-task-only", result.stderr)


if __name__ == "__main__":
    unittest.main()
