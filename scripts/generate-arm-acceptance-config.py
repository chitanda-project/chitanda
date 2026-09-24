#!/usr/bin/env python3
"""Generate isolated Xray configs for one-user versus 30-user ARM acceptance tests.

The output contains fresh temporary PSKs. Keep it outside Git and remove it
after the run. Server certificates are created separately in the server's
working directory as cert.pem and key.pem.
"""

import argparse
import json
import os
import secrets
from pathlib import Path


CASES = (("h2", 1), ("h2", 30), ("stream", 1), ("stream", 30),
         ("auto", 30), ("h3", 30), ("auto", 1), ("h3", 1))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outdir", type=Path, required=True)
    parser.add_argument("--server-host", required=True)
    parser.add_argument("--server-port", type=int, default=39100)
    parser.add_argument("--client-port", type=int, default=39200)
    parser.add_argument("--target-port", type=int, default=39110)
    parser.add_argument("--case", action="append", choices=[f"{mode}-{count}" for mode, count in CASES],
                        help="Generate only the named case (repeatable).")
    args = parser.parse_args()

    # POSIX modes do not map reliably to Windows ACLs. On Windows, keep this
    # output under a private workspace directory (such as .validation).
    if os.name != "nt":
        os.umask(0o077)
    args.outdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        args.outdir.chmod(0o700)
    server_inbounds = []
    client_inbounds = []
    client_outbounds = []
    rules = []
    manifest = []

    cases = [(mode, count) for mode, count in CASES
             if args.case is None or f"{mode}-{count}" in args.case]
    for index, (transport, count) in enumerate(cases):
        name = f"{transport}-{count}"
        server_port = args.server_port + index
        client_port = args.client_port + index
        selected_key = secrets.token_hex(32)
        settings = {"transport": transport, "path": "/arm-acceptance"}
        if count == 1:
            settings["psk"] = selected_key
        else:
            settings["users"] = [
                {"email": f"audit-{name}-{user_index}",
                 "psk": selected_key if user_index == count - 1 else secrets.token_hex(32)}
                for user_index in range(count)
            ]
        if transport == "stream":
            settings["server_id"] = "arm-acceptance-isolated"
        else:
            settings.update({"strict_sni": "localhost", "cert_file": "cert.pem", "key_file": "key.pem"})

        inbound = {
            "tag": f"in-{name}", "listen": "0.0.0.0", "port": server_port,
            "protocol": "chitanda", "settings": settings,
        }
        if transport != "stream":
            inbound["streamSettings"] = {
                "security": "tls",
                "tlsSettings": {
                    "certificates": [{"certificateFile": "cert.pem", "keyFile": "key.pem"}],
                    "alpn": ["h3"] if transport == "h3" else ["h2", "http/1.1"],
                },
            }
        server_inbounds.append(inbound)

        client_inbounds.append({
            "tag": f"local-{name}", "listen": "127.0.0.1", "port": client_port,
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1", "port": args.target_port, "network": "tcp,udp"},
        })
        outbound_settings = {
            "server": f"{args.server_host}:{server_port}", "psk": selected_key,
            "transport": transport, "path": "/arm-acceptance",
        }
        if transport == "stream":
            outbound_settings["server_id"] = "arm-acceptance-isolated"
        else:
            outbound_settings.update({"server_name": "localhost", "allow_insecure": True, "pool_size": 1})
        client_outbounds.append({
            "tag": f"out-{name}", "protocol": "chitanda", "settings": outbound_settings,
        })
        rules.append({"type": "field", "inboundTag": [f"local-{name}"], "outboundTag": f"out-{name}"})
        manifest.append({"name": name, "server_port": server_port, "client_port": client_port})

    server = {
        "log": {"loglevel": "warning"},
        "inbounds": server_inbounds,
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }
    client = {
        "log": {"loglevel": "warning"},
        "inbounds": client_inbounds,
        "outbounds": client_outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
    for name, value in (("server.json", server), ("client.json", client), ("manifest.json", manifest)):
        path = args.outdir / name
        # Refuse to overwrite an existing file (including a symlink): the
        # generated configs contain fresh private PSKs.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(json.dumps(value, indent=2) + "\n")
        if os.name != "nt":
            path.chmod(0o600)


if __name__ == "__main__":
    main()
