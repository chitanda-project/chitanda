#!/usr/bin/env python3
import os
import sys
import stat
from pathlib import Path

PATCH_COMMON_TARGET = "\tCountError func(errType string)\n\n\t// Internal state, differs between wrapped and non-wrapped implementations."
PATCH_COMMON_REPLACE = "\tCountError func(errType string)\n\n\t// MaxDataPadding, if positive, enables pseudo-random padding on HTTP/2 DATA frames (RFC 7540).\n\t// Bounded in range [0, 255].\n\tMaxDataPadding int\n\n\t// Internal state, differs between wrapped and non-wrapped implementations."

PATCH_TRANSPORT_TARGET = """			allowed, err = cs.awaitFlowControl(len(remain))
			if err != nil {
				return err
			}
			cc.wmu.Lock()
			data := remain[:allowed]
			remain = remain[allowed:]
			sentEnd = sawEOF && len(remain) == 0 && !hasTrailers
			err = cc.fr.WriteData(cs.ID, sentEnd, data)"""

PATCH_TRANSPORT_REPLACE = """			targetPad := 0
			if cc.t.MaxDataPadding > 0 {
				maxPad := cc.t.MaxDataPadding
				if maxPad > 255 {
					maxPad = 255
				}
				minPad := 8
				if minPad > maxPad {
					minPad = maxPad
				}
				targetPad = minPad + int(time.Now().UnixNano()%(int64(maxPad-minPad+1)))
			}
			reqBytes := len(remain)
			if targetPad > 0 {
				reqBytes += targetPad + 1
			}
			allowed, err = cs.awaitFlowControl(reqBytes)
			if err != nil {
				return err
			}
			cc.wmu.Lock()
			var data, pad []byte
			if targetPad > 0 && allowed > int32(len(remain)+1) {
				data = remain
				remain = nil
				actualPad := int(allowed) - len(data) - 1
				if actualPad > targetPad {
					actualPad = targetPad
				}
				if actualPad > 255 {
					actualPad = 255
				}
				if actualPad > 0 {
					pad = make([]byte, actualPad)
				}
			} else {
				takeData := min(int(allowed), len(remain))
				data = remain[:takeData]
				remain = remain[takeData:]
			}
			actualUsed := len(data)
			if len(pad) > 0 {
				actualUsed += 1 + len(pad)
			}
			if unused := allowed - int32(actualUsed); unused > 0 {
				cc.mu.Lock()
				cs.flow.add(unused)
				if cs.flow.conn != nil {
					cs.flow.conn.add(unused)
				}
				cc.cond.Broadcast()
				cc.mu.Unlock()
			}
			sentEnd = sawEOF && len(remain) == 0 && !hasTrailers
			if len(pad) > 0 {
				err = cc.fr.WriteDataPadded(cs.ID, sentEnd, data, pad)
			} else {
				err = cc.fr.WriteData(cs.ID, sentEnd, data)
			}"""

def make_writable(filepath):
    mode = os.stat(filepath).st_mode
    os.chmod(filepath, mode | stat.S_IWUSR)

def patch_file(filepath, old, new):
    if not os.path.exists(filepath):
        raise RuntimeError(f"missing H2 source: {filepath}")
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    if content.count(new) == 1 and old not in content:
        print(f"  [=] Already patched: {filepath}")
        return True
    if content.count(old) != 1 or new in content:
        raise RuntimeError(f"ambiguous or missing H2 patch anchor: {filepath}")
    make_writable(filepath)
    content = content.replace(old, new, 1)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  [+] Successfully patched: {filepath}")
    return True

def patch_directory(directory):
    # Only a deliberately staged snapshot may be modified. Never walk or
    # patch GOMODCACHE: tests and builds must consume the same local module.
    directory = Path(directory).resolve(strict=True)
    if directory.name != ".chitanda-xnet":
        raise RuntimeError("H2 patch target must be an isolated .chitanda-xnet snapshot")
    if "module golang.org/x/net\n" not in (directory / "go.mod").read_text(encoding="utf-8"):
        raise RuntimeError("unexpected x/net module")
    patch_file(directory / "http2" / "transport_common.go", PATCH_COMMON_TARGET, PATCH_COMMON_REPLACE)
    patch_file(directory / "http2" / "transport.go", PATCH_TRANSPORT_TARGET, PATCH_TRANSPORT_REPLACE)
    patch_file(directory / "http2" / "transport.go", "transportDefaultStreamFlow = 4 << 20", "transportDefaultStreamFlow = 64 << 20")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: patch_xnet.py /path/to/.chitanda-xnet")
    patch_directory(sys.argv[1])
