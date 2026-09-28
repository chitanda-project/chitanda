import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("inject-mihomo.py")
spec = importlib.util.spec_from_file_location("inject_mihomo", SCRIPT)
inject_mihomo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inject_mihomo)


class PatchUDPSenderQueueTest(unittest.TestCase):
    @staticmethod
    def write_upstream(root, capacity=128):
        tunnel_dir = Path(root) / "tunnel"
        tunnel_dir.mkdir()
        (tunnel_dir / "tunnel.go").write_text(
            f"\tsenderCapacity = {capacity} // chan capacity of PacketSender\n"
            "\tqueueCapacity  = 64  // chan capacity tcpQueue and udpQueue\n", encoding="utf-8"
        )
        (tunnel_dir / "connection.go").write_text(
            "\tch     chan C.PacketAdapter\n"
            "ch := make(chan C.PacketAdapter, senderCapacity)\n"
            "case packet := <-s.ch:\n"
            "\tfor {\n\t\tselect {\n\t\tcase data := <-s.ch:\n\t\t\tdata.Drop() // drop all data still in chan\n\t\tdefault:\n\t\t\treturn // no data, exit goroutine\n\t\t}\n\t}\n"
            "\tselect {\n\tcase s.ch <- packet:\n\t\t// put ok, so don't drop packet, will process by other side of chan\n\tcase <-s.ctx.Done():\n\t\tpacket.Drop() // sender closed when putting data to chan\n\tdefault:\n\t\tpacket.Drop() // chan is full\n\t}\n",
            encoding="utf-8",
        )

    def test_patches_once_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as root:
            self.write_upstream(root)
            inject_mihomo.patch_udp_sender_queue(root)
            inject_mihomo.patch_udp_sender_queue(root)
            self.assertIn("senderCapacity = 128", (Path(root) / "tunnel" / "tunnel.go").read_text(encoding="utf-8"))
            self.assertIn("ch := newChitandaPacketQueue()", (Path(root) / "tunnel" / "connection.go").read_text(encoding="utf-8"))

    def test_rejects_changed_upstream_capacity(self):
        with tempfile.TemporaryDirectory() as root:
            self.write_upstream(root, capacity=256)
            with self.assertRaisesRegex(RuntimeError, "unexpected Mihomo UDP sender capacity"):
                inject_mihomo.patch_udp_sender_queue(root)

    def test_patches_full_process_loop_with_drain_batch(self):
        with tempfile.TemporaryDirectory() as root:
            tunnel_dir = Path(root) / "tunnel"
            tunnel_dir.mkdir()
            (tunnel_dir / "tunnel.go").write_text(
                "\tsenderCapacity = 128 // chan capacity of PacketSender\n"
                "\tqueueCapacity  = 64  // chan capacity tcpQueue and udpQueue\n",
                encoding="utf-8"
            )
            (tunnel_dir / "connection.go").write_text(
                "\tch     chan C.PacketAdapter\n"
                "ch := make(chan C.PacketAdapter, senderCapacity)\n"
                "case packet := <-s.ch:\n"
                "\t\t\tif proxy != nil {\n"
                "\t\t\t\tproxy.UpdateWriteBack(packet)\n"
                "\t\t\t}\n"
                "\t\t\ts.processPacket(pc, packet)\n"
                "\tfor {\n\t\tselect {\n\t\tcase data := <-s.ch:\n\t\t\tdata.Drop() // drop all data still in chan\n\t\tdefault:\n\t\t\treturn // no data, exit goroutine\n\t\t}\n\t}\n"
                "\tselect {\n\tcase s.ch <- packet:\n\t\t// put ok, so don't drop packet, will process by other side of chan\n\tcase <-s.ctx.Done():\n\t\tpacket.Drop() // sender closed when putting data to chan\n\tdefault:\n\t\tpacket.Drop() // chan is full\n\t}\n",
                encoding="utf-8",
            )
            inject_mihomo.patch_udp_sender_queue(root)
            inject_mihomo.patch_udp_sender_queue(root)
            self.assertIn("queueCapacity  = 2048", (tunnel_dir / "tunnel.go").read_text(encoding="utf-8"))
            conn_text = (tunnel_dir / "connection.go").read_text(encoding="utf-8")
            self.assertIn("s.drainBatch(pc, proxy)", conn_text)
            self.assertIn("ch := newChitandaPacketQueue()", conn_text)

    def test_rejects_changed_udp_ingress_capacity(self):
        with tempfile.TemporaryDirectory() as root:
            self.write_upstream(root)
            tunnel = Path(root) / "tunnel" / "tunnel.go"
            tunnel.write_text(tunnel.read_text(encoding="utf-8").replace("queueCapacity  = 64", "queueCapacity  = 128"), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "unexpected Mihomo UDP ingress queue capacity"):
                inject_mihomo.patch_udp_sender_queue(root)

    def test_tracker_batch_accounting_patch_is_idempotent(self):
        with tempfile.TemporaryDirectory() as root:
            tracker = Path(root) / "tunnel" / "statistic" / "tracker.go"
            tracker.parent.mkdir(parents=True)
            tracker.write_text("func (ut *udpTracker) Close() error {\n", encoding="utf-8")
            inject_mihomo.patch_udp_tracker_batch_accounting(root)
            inject_mihomo.patch_udp_tracker_batch_accounting(root)
            self.assertEqual(tracker.read_text(encoding="utf-8").count("func (ut *udpTracker) RecordChitandaBatchUpload"), 1)

    def test_rejects_changed_tracker_batch_accounting(self):
        with tempfile.TemporaryDirectory() as root:
            tracker = Path(root) / "tunnel" / "statistic" / "tracker.go"
            tracker.parent.mkdir(parents=True)
            tracker.write_text("func (ut *udpTracker) RecordChitandaBatchUpload(n int) {}\nfunc (ut *udpTracker) Close() error {\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "unexpected Mihomo UDP tracker implementation"):
                inject_mihomo.patch_udp_tracker_batch_accounting(root)

    def test_tun_icmp_route_patch_is_idempotent(self):
        with tempfile.TemporaryDirectory() as root:
            prepare = Path(root) / "listener" / "sing_tun" / "prepare.go"
            prepare.parent.mkdir(parents=True)
            prepare.write_text('\t\tlog.Infoln("[ICMP] %s %s --> %s using DIRECT", network, source, destination)\n', encoding="utf-8")
            inject_mihomo.patch_tun_icmp_route(root)
            inject_mihomo.patch_tun_icmp_route(root)
            self.assertIn("h.prepareChitandaICMP", prepare.read_text(encoding="utf-8"))

    def test_tun_icmp_rule_selection_keeps_disabled_proxy_visible(self):
        with tempfile.TemporaryDirectory() as root:
            tunnel = Path(root) / "tunnel" / "tunnel.go"
            tunnel.parent.mkdir(parents=True)
            tunnel.write_text("if metadata.NetWork == C.UDP && !adapter.SupportUDP() {\n", encoding="utf-8")
            inject_mihomo.patch_tun_icmp_rule_selection(root)
            inject_mihomo.patch_tun_icmp_rule_selection(root)
            content = tunnel.read_text(encoding="utf-8")
            self.assertIn("metadata.Type == C.TUN && metadata.SrcPort == 0 && metadata.DstPort == 0", content)


if __name__ == "__main__":
    unittest.main()
