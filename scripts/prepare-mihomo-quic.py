#!/usr/bin/env python3
"""Use the verified Chitanda quic-go snapshot in an injected Mihomo module."""

import json
import shutil
import subprocess
import sys
from pathlib import Path


MODULE = "github.com/quic-go/quic-go"
VERSION = "v0.61.0"


def run(cwd: Path, *args: str) -> str:
    result = subprocess.run(args, cwd=cwd, check=True, text=True, capture_output=True)
    return result.stdout.strip()


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

    run(mihomo_dir, "go", "mod", "edit", f"-replace={MODULE}={destination.as_posix()}")
    run(mihomo_dir, "go", "mod", "tidy")
    resolved = Path(run(mihomo_dir, "go", "list", "-f", "{{.Dir}}", MODULE))
    if resolved.resolve() != destination:
        raise RuntimeError(f"patched {MODULE} was not selected: {resolved}")
    print(f"Mihomo uses patched {MODULE} {VERSION} from {destination}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: prepare-mihomo-quic.py MIHOMO_DIR CHITANDA_DIR")
    prepare(Path(sys.argv[1]), Path(sys.argv[2]))
