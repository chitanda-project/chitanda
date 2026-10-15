#!/usr/bin/env python3
"""Record source commit and both archive/core hashes without extracting files."""
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import zipfile


def digest(stream):
    result = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1 << 20), b""):
        result.update(chunk)
    return result.hexdigest()


def manifest(directory, commit, go_version):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("expected a full Chitanda commit SHA")
    artifacts = {}
    cores = {"clash", "mihomo", "mihomo.exe", "xray", "xray.exe"}
    for path in sorted(Path(directory).iterdir()):
        if path.name.endswith(".zip"):
            with zipfile.ZipFile(path) as archive:
                names = [name for name in archive.namelist() if name in cores]
                if len(names) != 1:
                    raise ValueError(f"expected one core in {path.name}")
                core = names[0]
                with archive.open(core) as stream:
                    core_hash = digest(stream)
        elif path.name.endswith(".tar.gz"):
            with tarfile.open(path, "r:gz") as archive:
                member = archive.getmember("clash")
                if not member.isfile():
                    raise ValueError(f"expected a regular clash core in {path.name}")
                core = "clash"
                with archive.extractfile(member) as stream:
                    core_hash = digest(stream)
        elif path.name.startswith("mihomo-") and path.name.endswith(".gz"):
            core = "mihomo"
            with gzip.open(path, "rb") as stream:
                core_hash = digest(stream)
        else:
            continue
        with path.open("rb") as stream:
            archive_hash = digest(stream)
        artifacts[path.name] = {"sha256": archive_hash, "coreName": core, "coreSha256": core_hash}
    if not artifacts:
        raise ValueError("no release cores found")
    return {"schema": 1, "chitandaCommit": commit, "goVersion": go_version,
            "h2Implementation": "http2legacy", "artifacts": artifacts}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: release-provenance.py DIST_DIR CHITANDA_COMMIT")
    directory = Path(sys.argv[1]).resolve(strict=True)
    go_version = subprocess.run(["go", "env", "GOVERSION"], check=True, capture_output=True, text=True).stdout.strip()
    result = manifest(directory, sys.argv[2], go_version)
    (directory / "build-info.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
