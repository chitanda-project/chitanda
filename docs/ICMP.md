# ICMP Echo relay

Chitanda relays ICMP Echo Request and Echo Reply (IPv4 and IPv6). It does not
relay arbitrary ICMP control messages. The server requires permission to open
raw ICMP sockets (for example, root or `CAP_NET_RAW` on Linux).

Targets are limited to public unicast addresses by default, matching the
existing TCP/UDP target policy. `-allow-private-targets` on the standalone
server additionally permits loopback/private targets for isolated testing;
do not use it for an Internet-facing deployment without assessing the access
it grants. Malformed requests, replies from a different source, and replies
for another association are discarded.

The standalone `chitanda-ping` tool requires `-server`, `-path`, and a PSK.
Use `-psk-file` with the same hex/base64url encoding accepted by the server.
TLS verification remains enabled unless `-insecure` is explicitly supplied.
The tool exits unsuccessfully if any requested Echo round fails.

Embedding cores use UDP destination port zero as the ICMP Echo convention:
the datagram payload must be a valid Echo Request and the destination must be
an IP address. Xray's Chitanda outbound and Mihomo's Chitanda packet adapter
translate this convention to the protocol's ICMP address. In Mihomo TUN mode,
ICMP follows the selected routing rule when it resolves to a Chitanda node;
unsupported proxy selections fail closed rather than silently using DIRECT.
If a rule selects a Chitanda node with `udp: false`, ICMP is dropped rather
than falling through to Mihomo's default DIRECT route or producing a local
fake Echo Reply.
If ICMP forwarding is disabled in Mihomo, its existing fake-ping behavior
still takes precedence.

For H2/auto clients, the ICMP datagram path uses the H3 UDP listener. The H3
listener must be reachable at the configured node address/port even when TCP
traffic uses H2. Stream and H1 use the plain-UDP listener.

For intermediate L4 forwarders (such as IEPL port-forwarding with realm),
ensure UDP forwarding is enabled alongside TCP for the node port so that
Chitanda datagrams (UDP and ICMP) are seamlessly relayed to the landing server.
