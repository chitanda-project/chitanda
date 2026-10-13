import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("udp_probe", Path(__file__).with_name("udp_probe.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class UDPProbeTests(unittest.TestCase):
    def test_config_is_private_exclusive_and_preserves_identity(self):
        with tempfile.TemporaryDirectory() as root:
            client = Path(root) / "client.json"
            client.write_text(json.dumps({"outbounds": [{"settings": {
                "server": "127.0.0.1:12345", "psk": "test-key", "path": "/test", "server_id": "node-id"
            }}]}), encoding="utf-8")
            output = Path(root) / "client.yaml"
            args = SimpleNamespace(xray_client=str(client), output=str(output), socks_port=19090)
            probe.config(args)
            result = output.read_text(encoding="utf-8")
            self.assertIn('server-id: "node-id"', result)
            self.assertIn('bind-address: 127.0.0.1', result)
            self.assertNotIn('\\n', result)
            with self.assertRaises(SystemExit):
                probe.config(args)

    def test_socks_greeting_and_udp_association_are_real_bytes(self):
        class Control:
            sent = []
            reply = bytearray(b'\x05\x00\x05\x00\x00\x01\x7f\x00\x00\x01\x12\x34')
            def settimeout(self, _): pass
            def sendall(self, data): self.sent.append(data)
            def recv(self, count):
                result = bytes(self.reply[:count]); del self.reply[:count]; return result
        control = Control()
        with patch.object(probe.socket, 'create_connection', return_value=control):
            _, relay = probe.socks_relay(19090)
        self.assertEqual(control.sent, [bytes([5, 1, 0]), bytes([5, 3, 0, 1, 0, 0, 0, 0, 0, 0])])
        self.assertEqual(relay, ('127.0.0.1', 0x1234))

    def test_non_positive_rate_rejected(self):
        with self.assertRaises(ValueError):
            probe.send(SimpleNamespace(rate_mbps=0, seconds=1))


if __name__ == '__main__':
    unittest.main()
