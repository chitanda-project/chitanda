import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).parent))
spec = importlib.util.spec_from_file_location("prepare_mihomo_quic", Path(__file__).with_name("prepare-mihomo-quic.py"))
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class XnetModuleSnapshotTest(unittest.TestCase):
    def test_module_zip_and_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "net.zip", root / ".chitanda-xnet"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("golang.org/x/net@v0.56.0/go.mod", "module golang.org/x/net\n")
                archive.writestr("golang.org/x/net@v0.56.0/http2/transport.go", "original source")
            prepare.copy_xnet_zip(source, destination)
            self.assertEqual((destination / "http2/transport.go").read_text(), "original source")
            with self.assertRaises(FileExistsError):
                prepare.copy_xnet_zip(source, destination)

    def test_unsafe_zip_member_rejected_before_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "net.zip", root / ".chitanda-xnet"
            for member in ("another-module/file", "golang.org/x/net@v0.56.0/../escaped", "golang.org/x/net@v0.56.0/C:/bad"):
                with zipfile.ZipFile(source, "w") as archive:
                    archive.writestr(member, "bad")
                with self.assertRaises(RuntimeError):
                    prepare.copy_xnet_zip(source, destination)
                self.assertFalse(destination.exists())
