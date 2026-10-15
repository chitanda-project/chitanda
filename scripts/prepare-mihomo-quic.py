#!/usr/bin/env python3
"""Use the verified Chitanda quic-go snapshot in an injected Mihomo module."""

import json
import shutil
import subprocess
import sys
from pathlib import Path
import zipfile

from patch_xnet import patch_directory


MODULE = "github.com/quic-go/quic-go"
VERSION = "v0.61.0"


def run(cwd: Path, *args: str) -> str:
    result = subprocess.run(args, cwd=cwd, check=True, text=True, capture_output=True)
    return result.stdout.strip()

def prepare_xnet(mihomo_dir: Path) -> None:
    module = json.loads(run(mihomo_dir, "go", "list", "-m", "-json", "golang.org/x/net"))
    if module["Version"] != "v0.56.0" or module.get("Replace"):
        raise RuntimeError(f"unsupported x/net resolution: {module}")
    destination = mihomo_dir / ".chitanda-xnet"
    if destination.exists():
        raise RuntimeError(f"refusing to overwrite existing path: {destination}")
    # Previous releases modified expanded GOMODCACHE files. Start from the
    # checksum-managed module zip, not a possibly contaminated expanded tree.
    download = json.loads(run(mihomo_dir, "go", "mod", "download", "-json", "golang.org/x/net@v0.56.0"))
    copy_xnet_zip(Path(download["Zip"]), destination)
    patch_directory(destination)
    run(mihomo_dir, "go", "mod", "edit", f"-replace=golang.org/x/net={destination.as_posix()}")
    run(mihomo_dir, "go", "mod", "tidy")
    resolved = Path(run(mihomo_dir, "go", "list", "-f", "{{.Dir}}", "golang.org/x/net/http2"))
    if resolved.resolve() != destination / "http2":
        raise RuntimeError(f"patched H2 snapshot not selected: {resolved}")


def copy_xnet_zip(source: Path, destination: Path) -> None:
    prefix = "golang.org/x/net@v0.56.0/"
    with zipfile.ZipFile(source) as archive:
        files = []
        for member in archive.infolist():
            if not member.filename.startswith(prefix):
                raise RuntimeError(f"unexpected x/net zip member: {member.filename}")
            relative = member.filename[len(prefix):]
            parts = relative.split("/")
            if any(part in ("", ".", "..") for part in parts) or "\\" in relative or ":" in relative:
                raise RuntimeError(f"unsafe x/net zip member: {member.filename}")
            files.append((member, parts))
        if not files:
            raise RuntimeError("empty x/net module zip")
        destination.mkdir()
        for member, parts in files:
            target = destination.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as reader, target.open("xb") as writer:
                shutil.copyfileobj(reader, writer)


def prepare(mihomo_dir: Path, core_dir: Path) -> None:
    mihomo_dir = mihomo_dir.resolve(strict=True)
    core_dir = core_dir.resolve(strict=True)
    source = core_dir / "vendor" / "github.com" / "quic-go" / "quic-go"
    destination = mihomo_dir / ".chitanda-quic-go"
    if not (source / "connection.go").is_file():
        raise RuntimeError(f"missing patched quic-go source: {source}")
    for relative, marker in (
        ("connection.go", "SendDatagramNoCopyContext"),
        ("datagram_queue.go", "AddBatchContext"),
        ("http3/stream.go", "SendDatagramsContext"),
        ("connection.go", "ReceiveQueueStats"),
        ("connection.go", "receivedPacketQueueClosed"),
        ("http3/state_tracking_stream.go", "DatagramReceiveStats"),
        ("http3/stream.go", "func (s *RequestStream) DatagramReceiveStats()"),
    ):
        if marker not in (source / relative).read_text(encoding="utf-8"):
            raise RuntimeError(f"missing deadline patch in {relative}")

    module = json.loads(run(mihomo_dir, "go", "list", "-m", "-json", MODULE))
    if module["Version"] != VERSION or module.get("Replace"):
        raise RuntimeError(f"unsupported {MODULE} resolution: {module}")
    original = Path(module["Dir"])
    if destination.exists():
        raise RuntimeError(f"refusing to overwrite existing path: {destination}")
    shutil.copytree(source, destination)
    shutil.copy2(original / "go.mod", destination / "go.mod")
    shutil.copy2(original / "go.sum", destination / "go.sum")
    for name, target in (
        ("receive_queue_test.go.txt", "receive_queue_test.go"),
        ("http3_state_tracking_stream_test.go.txt", "http3/state_tracking_stream_lazy_test.go"),
    ):
        shutil.copy2(core_dir / "scripts" / "vendor-tests" / name, destination / target)

    run(mihomo_dir, "go", "mod", "edit", f"-replace={MODULE}={destination.as_posix()}")
    run(mihomo_dir, "go", "mod", "tidy")
    resolved = Path(run(mihomo_dir, "go", "list", "-f", "{{.Dir}}", MODULE))
    if resolved.resolve() != destination:
        raise RuntimeError(f"patched {MODULE} was not selected: {resolved}")
    print(f"Mihomo uses patched {MODULE} {VERSION} from {destination}")
    prepare_xnet(mihomo_dir)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: prepare-mihomo-quic.py MIHOMO_DIR CHITANDA_DIR")
    prepare(Path(sys.argv[1]), Path(sys.argv[2]))
