import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("inject-mihomo.py")
spec = importlib.util.spec_from_file_location("inject_mihomo", SCRIPT)
inject_mihomo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inject_mihomo)


class PatchUDPSenderCapacityTest(unittest.TestCase):
    def test_patches_once_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as root:
            tunnel = Path(root) / "tunnel" / "tunnel.go"
            tunnel.parent.mkdir()
            tunnel.write_text("\tsenderCapacity = 128 // chan capacity of PacketSender\n", encoding="utf-8")
            inject_mihomo.patch_udp_sender_capacity(root)
            inject_mihomo.patch_udp_sender_capacity(root)
            self.assertEqual(tunnel.read_text(encoding="utf-8"), "\tsenderCapacity = 4096 // chan capacity of PacketSender\n")

    def test_rejects_changed_upstream_capacity(self):
        with tempfile.TemporaryDirectory() as root:
            tunnel = Path(root) / "tunnel" / "tunnel.go"
            tunnel.parent.mkdir()
            tunnel.write_text("\tsenderCapacity = 256 // chan capacity of PacketSender\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "unexpected Mihomo UDP sender capacity"):
                inject_mihomo.patch_udp_sender_capacity(root)


if __name__ == "__main__":
    unittest.main()
