import gzip
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("provenance", Path(__file__).with_name("release-provenance.py"))
provenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provenance)


class ReleaseProvenanceTest(unittest.TestCase):
    def test_archive_and_raw_core_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = b"test-core-bytes"
            with zipfile.ZipFile(root / "Xray-windows-64.zip", "w") as archive:
                archive.writestr("xray.exe", data)
                archive.writestr("geoip.dat", b"not-the-core")
            with tarfile.open(root / "clash-linux-amd64-v1.tar.gz", "w:gz") as archive:
                member = tarfile.TarInfo("clash")
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            with gzip.open(root / "mihomo-linux-amd64-v1.gz", "wb") as archive:
                archive.write(data)
            result = provenance.manifest(root, "a" * 40, "go1.27.0")
            self.assertEqual(len(result["artifacts"]), 3)
            for item in result["artifacts"].values():
                self.assertEqual(item["coreSha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(result["chitandaCommit"], "a" * 40)

    def test_invalid_commit_and_missing_core_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                provenance.manifest(directory, "not-a-commit", "go-test")
            with self.assertRaises(ValueError):
                provenance.manifest(directory, "a" * 40, "go-test")
