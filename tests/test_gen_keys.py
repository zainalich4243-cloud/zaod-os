import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GEN_KEYS = ROOT / "tools" / "gen_keys.py"


class KeyProvisionTests(unittest.TestCase):
    def test_key_is_private_and_public_header_matches(self):
        with tempfile.TemporaryDirectory(prefix="zaod-key-test-") as directory:
            root = Path(directory)
            private_key = root / "keys" / "release.key"
            public_header = root / "zaod_keys.h"
            public_header.write_text(
                "#define ZAOD_ROOT_PUBLIC_KEY_CONFIGURED 0\n",
                encoding="ascii",
            )
            result = subprocess.run(
                [
                    "python3",
                    str(GEN_KEYS),
                    "--private-key",
                    str(private_key),
                    "--public-header",
                    str(public_header),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(private_key.stat().st_mode & 0o777, 0o600)
            self.assertEqual(private_key.parent.stat().st_mode & 0o777, 0o700)

            public_der = subprocess.run(
                [
                    "openssl",
                    "pkey",
                    "-in",
                    str(private_key),
                    "-pubout",
                    "-outform",
                    "DER",
                ],
                capture_output=True,
                check=True,
            ).stdout
            encoded = re.findall(
                r"0x([0-9a-f]{2})",
                public_header.read_text(encoding="ascii"),
            )
            self.assertEqual(bytes.fromhex("".join(encoded)), public_der[-32:])

            rejected = subprocess.run(
                [
                    "python3",
                    str(GEN_KEYS),
                    "--private-key",
                    str(private_key),
                    "--public-header",
                    str(public_header),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertTrue(private_key.is_file())


if __name__ == "__main__":
    unittest.main()
