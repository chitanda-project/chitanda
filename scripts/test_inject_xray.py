"""Fail-closed checks for Xray source injection anchors."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("inject_xray", Path(__file__).with_name("inject-xray.py"))
inject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inject)


class InjectionAnchorTests(unittest.TestCase):
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
