import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("patch_xnet", Path(__file__).with_name("patch_xnet.py"))
patch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch)


class H2SnapshotPatchTest(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory) / ".chitanda-xnet"
        (root / "http2").mkdir(parents=True)
        (root / "go.mod").write_text("module golang.org/x/net\n", encoding="utf-8")
        (root / "http2/transport_common.go").write_text(patch.PATCH_COMMON_TARGET, encoding="utf-8")
        (root / "http2/transport.go").write_text("transportDefaultStreamFlow = 4 << 20\n" + patch.PATCH_TRANSPORT_TARGET, encoding="utf-8")
        return root

    def test_snapshot_patch_is_complete_and_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            patch.patch_directory(root)
            before = (root / "http2/transport.go").read_text(encoding="utf-8")
            patch.patch_directory(root)
            self.assertEqual(before, (root / "http2/transport.go").read_text(encoding="utf-8"))
            self.assertIn("transportDefaultStreamFlow = 64 << 20", before)
            self.assertIn("WriteDataPadded", before)

    def test_missing_anchor_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            (root / "http2/transport.go").write_text("changed upstream", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                patch.patch_directory(root)

    def test_cannot_patch_an_arbitrary_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "isolated"):
                patch.patch_directory(directory)

    def test_mixed_patched_and_unpatched_anchor_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            patch.patch_directory(root)
            path = root / "http2/transport.go"
            path.write_text(path.read_text(encoding="utf-8") + "\n" + patch.PATCH_TRANSPORT_TARGET, encoding="utf-8")
            with self.assertRaises(RuntimeError):
                patch.patch_directory(root)
