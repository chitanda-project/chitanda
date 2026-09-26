"""Fail-closed checks for Xray source injection anchors."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("inject_xray", Path(__file__).with_name("inject-xray.py"))
inject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inject)


class InjectionAnchorTests(unittest.TestCase):
    def test_udp_pipe_burst_budget_covers_proxy_frontends(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            hub = root / "transport" / "internet" / "udp" / "hub.go"
            worker = root / "app" / "proxyman" / "inbound" / "worker.go"
            hub.parent.mkdir(parents=True)
            worker.parent.mkdir(parents=True)
            hub.write_text("type Hub struct {\n\toobBytes := make([]byte, 256)\n\t\trawBytes := buffer.Extend(buf.Size)\n\t\tbuffer.Resize(0, int32(n))", encoding="utf-8")
            worker.write_text("h, err := udp.ListenUDP(ctx, w.address, w.port, w.stream, udp.HubCapacity(256))\n\t\tpReader, pWriter := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(16*1024))", encoding="utf-8")
            inject.inject_udp_packet_size(root)
            result = worker.read_text(encoding="utf-8")
            self.assertIn("pipe.WithSizeLimit(4*1024*1024)", result)
            self.assertNotIn("pipe.WithSizeLimit(16*1024)", result)
            inject.inject_udp_packet_size(root)
            self.assertEqual(worker.read_text(encoding="utf-8"), result)

    def test_unique_anchor_and_idempotence(self):
        original = "before\nanchor\nafter\n"
        patched = inject.replace_unique(original, "anchor", "registered\nanchor", "test")
        self.assertEqual(patched, "before\nregistered\nanchor\nafter\n")
        self.assertEqual(inject.replace_unique(patched, "anchor", "registered\nanchor", "test"), patched)

    def test_missing_and_duplicate_anchors_fail(self):
        with self.assertRaises(RuntimeError):
            inject.replace_unique("no anchor", "expected", "registered\nexpected", "test")
        with self.assertRaises(RuntimeError):
            inject.replace_unique("anchor\nanchor", "anchor", "registered\nanchor", "test")
        with self.assertRaises(RuntimeError):
            inject.replace_unique("registered\nanchor\nregistered\nanchor", "anchor", "registered\nanchor", "test")
        with self.assertRaises(RuntimeError):
            inject.replace_unique("registered\nanchor\nanchor", "anchor", "registered\nanchor", "test")

    def test_partial_previous_udp_patch_fails(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "hub.go"
            path.write_text("func HubPacketSize()\nfirst", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                inject.patch_once(path, "func HubPacketSize()", [("first", "second")])


if __name__ == "__main__":
    unittest.main()
