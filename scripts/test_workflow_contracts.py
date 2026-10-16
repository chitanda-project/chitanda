"""Guard authenticated upstream discovery and non-empty vendor test gates."""
from pathlib import Path
import re
import unittest


WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


class WorkflowContractsTest(unittest.TestCase):
    def test_buffer_lifecycle_gates_restore_and_repeat_real_tests(self):
        for name in ("audit-multi-user.yml", "build-xray.yml"):
            source = (WORKFLOWS / name).read_text(encoding="utf-8")
            for package, filename, test in (
                ("pkg/server", "plain_udp_shutdown_test.go", "'^TestPlainUDP(ShutdownDrains|QueueMemory|TaskMemory)'"),
                ("internal/frame", "stream_writer_test.go", "StreamWriterPooled"),
                ("pkg/server", "stream_shutdown_test.go", "StreamShutdown"),
                ("internal/rawstream", "buffer_allocation_test.go", "RawBufferLazy"),
            ):
                restore = f'cp "$GITHUB_WORKSPACE"/{package}/{filename} vendor/github.com/violetaini/chitanda/{package}/'
                run = f"go test -mod=vendor -race github.com/violetaini/chitanda/{package} -run {test} -count=30"
                with self.subTest(workflow=name, package=package):
                    self.assertIn(restore, source)
                    self.assertIn(run, source)
                    self.assertLess(source.index(restore), source.index(run))
            self.assertIn("go test -mod=vendor -race ./proxy/chitanda -run PacketReadLease -count=30", source)

    def test_upstream_api_queries_use_workflow_token(self):
        queries = 0
        for name in ("audit-multi-user.yml", "build-xray.yml", "build-mihomo-stable.yml", "build-mihomo-alpha.yml"):
            source = (WORKFLOWS / name).read_text(encoding="utf-8")
            for step in re.split(r"(?m)^      - ", source):
                if not re.search(r"https://api\.github\.com/repos/(?:XTLS/Xray-core|MetaCubeX/mihomo)/", step):
                    continue
                with self.subTest(workflow=name, step=step.splitlines()[0]):
                    self.assertIn("GH_TOKEN: ${{ github.token }}", step)
                    self.assertIn('-H "Authorization: Bearer $GH_TOKEN"', step)
                    queries += 1
        self.assertEqual(queries, 5)

    def test_new_vendor_regressions_are_restored_before_execution(self):
        for name in ("audit-multi-user.yml", "build-xray.yml"):
            source = (WORKFLOWS / name).read_text(encoding="utf-8")
            for package, source_glob, test in (
                ("connio", "*_test.go", "WriterShutdown"),
                ("server", "stream_admission_test.go", "StreamAdmission"),
            ):
                with self.subTest(workflow=name, package=package):
                    restore = f'cp "$GITHUB_WORKSPACE"/pkg/{package}/{source_glob} vendor/github.com/violetaini/chitanda/pkg/{package}/'
                    run = f"go test -mod=vendor -race github.com/violetaini/chitanda/pkg/{package} -run {test} -count=30"
                    self.assertIn(restore, source)
                    self.assertIn(run, source)
                    self.assertLess(source.index(restore), source.index(run))
