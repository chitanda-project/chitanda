#!/usr/bin/env python3
\"\"\"Isolated SOCKS5 UDP and direct UDP packet-count probe.\"\"\"

import argparse
import json
import secrets
import socket
import struct
import time
from pathlib import Path


PAYLOAD_SIZE = 1200


def config(args):
    client = json.loads(Path(args.xray_client).read_text(encoding=\"utf-8\"))
    outbound = client[\"outbounds\"][0][\"settings\"]
    server, port = outbound[\"server\"].rsplit(\":\", 1)
    node = {
        \"name\": \"udp-retest\",
        \"server\": server,
        \"port\": int(port),
        \"psk\": outbound[\"psk\"],
        \"path\": outbound[\"path\"],
        \"transport\": \"h3\",
        \"sni\": \"localhost\",
        \"skip-cert-verify\": True,
        \"udp\": True,
        \"pool-size\": 1,
        \"udp-pool-size\": 1,
        \"auto-scale\": False,
    }
    lines = [
        f\"socks-port: {args.socks_port}\",
        \"allow-lan: false\",
        \"mode: rule\",
        \"log-level: warning\",
        \"proxies:\",
        \"  - name: udp-retest\",
        \"    type: chitanda\",
    ]
    for key, value in node.items():
        lines.append(f\"    {key}: {json.dumps(value)}\")
    lines += [
        \"proxy-groups:\",
        \"  - name: UDP-TEST\",
        \"    type: select\",
        \"    proxies: [udp-retest]\",
        \"rules:\",
        \"  - MATCH,UDP-TEST\",
    ]
    output = Path(args.output)
    if output.exists():
        raise SystemExit(f\"refusing to overwrite {output}\")
    output.write_text(\"\
    print(f\"wrote {output.name} (contains private test PSK)\")


def read_exact(sock, count):
    data = b\"\"
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise RuntimeError(\"SOCKS control connection closed\")
        data += chunk
    return data


def socks_relay(port):
    control = socket.create_connection((\"127.0.0.1\", port), timeout=10)
    control.settimeout(10)
    control.sendall(b\"\\x05\\x01\\x00\")
    if read_exact(control, 2) != b\"\\x05\\x00\":
        raise RuntimeError(\"SOCKS authentication failed\")
    control.sendall(b\"\\x05\\x03\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\")
    prefix = read_exact(control, 4)
    if prefix[:2] != b\"\\x05\\x00\":
        raise RuntimeError(f\"SOCKS UDP associate failed: {prefix.hex()}\")
    if prefix[3] == 1:
        host = socket.inet_ntoa(read_exact(control, 4))
    elif prefix[3] == 4:
        host = socket.inet_ntop(socket.AF_INET6, read_exact(control, 16))
    elif prefix[3] == 3:
        host = read_exact(control, read_exact(control, 1)[0]).decode(\"ascii\")
    else:
        raise RuntimeError(\"unsupported SOCKS relay address type\")
    relay_port = struct.unpack(\"!H\", read_exact(control, 2))[0]
    if host == \"0.0.0.0\":
        host = \"127.0.0.1\"
    return control, (host, relay_port)


def send(args):
    run_id = secrets.token_bytes(8)
    control = None
    target = (args.host, args.port)
    header = b\"\"
    if args.mode == \"socks\":
        control, target = socks_relay(args.socks_port)
        header = b\"\\x00\\x00\\x00\\x01\" + socket.inet_aton(args.host) + struct.pack(\"!H\", args.port)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    pad = bytes(PAYLOAD_SIZE - 16)
    interval = PAYLOAD_SIZE * 8 / (args.rate_mbps * 1_000_000)
    start = time.monotonic()
    end = start + args.seconds
    count = 0
    while True:
        planned = start + count * interval
        if planned >= end:
            break
        now = time.monotonic()
        remaining = planned - now
        if remaining > 0.0005:
            time.sleep(remaining - 0.0002)
        while time.monotonic() < planned:
            pass
        udp.sendto(header + run_id + struct.pack(\"!Q\", count) + pad, target)
        count += 1
    elapsed = time.monotonic() - start
    finish = header + b\"END!\" + run_id + struct.pack(\"!Q\", count)
    for _ in range(20):
        udp.sendto(finish, target)
        time.sleep(0.025)
    time.sleep(3)
    udp.close()
    if control:
        control.close()
    print(json.dumps({\"mode\": args.mode, \"run_id\": run_id.hex(), \"sent\": count,
                      \"seconds\": args.seconds, \"elapsed_s\": round(elapsed, 4),
                      \"payload_mbps\": round(count * PAYLOAD_SIZE * 8 / elapsed / 1_000_000, 3)}), flush=True)


def sink(args):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
    udp.bind((args.bind, args.port))
    udp.settimeout(0.5)
    seen = set()
    run_id = None
    expected = None
    duplicates = 0
    end_at = None
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        if end_at is not None and time.monotonic() >= end_at:
            break
        try:
            data, _ = udp.recvfrom(2048)
        except socket.timeout:
            continue
        if data.startswith(b\"END!\") and len(data) == 20:
            if run_id is None or data[4:12] == run_id:
                run_id = data[4:12]
                expected = struct.unpack(\"!Q\", data[12:20])[0]
                end_at = time.monotonic() + 3
            continue
        if len(data) != PAYLOAD_SIZE:
            continue
        if run_id is None:
            run_id = data[:8]
        if data[:8] != run_id:
            continue
        seq = struct.unpack(\"!Q\", data[8:16])[0]
        if seq in seen:
            duplicates += 1
        else:
            seen.add(seq)
    udp.close()
    print(json.dumps({\"run_id\": run_id.hex() if run_id else None,
                      \"expected\": expected, \"received\": len(seen), \"duplicates\": duplicates,
                      \"missing\": expected - len(seen) if expected is not None else None,
                      \"end_marker_seen\": expected is not None}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest=\"command\", required=True)
    cfg = sub.add_parser(\"config\")
    cfg.add_argument(\"--xray-client\", required=True)
    cfg.add_argument(\"--output\", required=True)
    cfg.add_argument(\"--socks-port\", type=int, required=True)
    sender = sub.add_parser(\"send\")
    sender.add_argument(\"--mode\", choices=(\"direct\", \"socks\"), required=True)
    sender.add_argument(\"--host\", required=True)
    sender.add_argument(\"--port\", type=int, required=True)
    sender.add_argument(\"--socks-port\", type=int, default=0)
    sender.add_argument(\"--rate-mbps\", type=float, required=True)
    sender.add_argument(\"--seconds\", type=float, default=10)
    receiver = sub.add_parser(\"sink\")
    receiver.add_argument(\"--bind\", default=\"0.0.0.0\")
    receiver.add_argument(\"--port\", type=int, required=True)
    receiver.add_argument(\"--timeout\", type=float, default=30)
    args = parser.parse_args()
    {\"config\": config, \"send\": send, \"sink\": sink}[args.command](args)


if __name__ == \"__main__\":
    main()