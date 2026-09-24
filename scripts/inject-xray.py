#!/usr/bin/env python3
import os
import sys
import shutil

def patch_once(path, marker, changes):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    if marker in content:
        if any(content.count(after) != 1 for _, after in changes):
            raise RuntimeError(f"Incomplete prior integration in {path}")
        return
    for before, after in changes:
        if content.count(before) != 1:
            raise RuntimeError(f"Upstream anchor changed in {path}; refusing a partial UDP integration")
        content = content.replace(before, after, 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def replace_unique(content, before, after, description):
    if after in content:
        if content.count(after) != 1 or content.count(before) != 1:
            raise RuntimeError(f"Duplicate {description} registration")
        return content
    if content.count(before) != 1:
        raise RuntimeError(f"Upstream {description} anchor changed; refusing incomplete integration")
    return content.replace(before, after, 1)

def inject_udp_packet_size(xray_dir):
    # Opt-in only: normal upstream protocols retain their existing allocation
    # strategy. Chitanda must receive the entire authenticated UDP record.
    hub = os.path.join(xray_dir, "transport", "internet", "udp", "hub.go")
    patch_once(hub, "func HubPacketSize(", [
        ("type Hub struct {", "func HubPacketSize(size int32) HubOption {\n\treturn func(h *Hub) { if size > buf.Size && size <= 65535 { h.packetSize = size } }\n}\n\ntype Hub struct {\n\tpacketSize int32"),
        ("\toobBytes := make([]byte, 256)", "\toobBytes := make([]byte, 256)\n\tvar largePacket []byte\n\tif h.packetSize > buf.Size { largePacket = make([]byte, h.packetSize) }"),
        ("\t\trawBytes := buffer.Extend(buf.Size)", "\t\trawBytes := buffer.Extend(buf.Size)\n\t\tif largePacket != nil { rawBytes = largePacket }"),
        ("\t\tbuffer.Resize(0, int32(n))", "\t\tif largePacket != nil {\n\t\t\tbuffer.Release()\n\t\t\tbuffer = buf.NewWithSize(int32(max(1, n)))\n\t\t\tcopy(buffer.Extend(int32(n)), rawBytes[:n])\n\t\t}\n\t\tbuffer.Resize(0, int32(n))"),
    ])
    worker = os.path.join(xray_dir, "app", "proxyman", "inbound", "worker.go")
    patch_once(worker, "UDPPacketBufferSize()", [
        ("h, err := udp.ListenUDP(ctx, w.address, w.port, w.stream, udp.HubCapacity(256))",
         "opts := []udp.HubOption{udp.HubCapacity(256)}\n\tif sized, ok := w.proxy.(interface{ UDPPacketBufferSize() int32 }); ok {\n\t\topts = append(opts, udp.HubPacketSize(sized.UDPPacketBufferSize()))\n\t}\n\th, err := udp.ListenUDP(ctx, w.address, w.port, w.stream, opts...)"),
        ("pReader, pWriter := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(16*1024))",
         "pReader, pWriter := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(4*1024*1024))"),
    ])


def inject_xray(xray_dir, chitanda_dir):
    print(f"[*] Injecting Chitanda protocol into Xray-core: {xray_dir}")
    inject_udp_packet_size(xray_dir)
    proxy_dir = os.path.join(xray_dir, "proxy", "chitanda")
    conf_dir = os.path.join(xray_dir, "infra", "conf")
    os.makedirs(proxy_dir, exist_ok=True)
    os.makedirs(conf_dir, exist_ok=True)
    
    # 1. Copy the adapter and its regression tests into proxy/chitanda/.
    src_integration = os.path.join(chitanda_dir, "integration", "xray")
    for fname in sorted(os.listdir(src_integration)):
        if fname.endswith(".go"):
            src = os.path.join(src_integration, fname)
            dst = os.path.join(proxy_dir, fname)
            shutil.copy2(src, dst)
            print(f"  [+] Copied {fname} -> proxy/chitanda/")
        
    # 2. Copy chitanda.go -> infra/conf/chitanda.go
    src_conf_dir = os.path.join(chitanda_dir, "integration", "xray_conf")
    for fname in sorted(os.listdir(src_conf_dir)):
        if fname.endswith(".go"):
            shutil.copy2(os.path.join(src_conf_dir, fname), os.path.join(conf_dir, fname))
    
    # 3. Patch infra/conf/xray.go
    xray_conf_go = os.path.join(conf_dir, "xray.go")
    if not os.path.isfile(xray_conf_go):
        raise RuntimeError(f"Missing Xray configuration registry: {xray_conf_go}")
    with open(xray_conf_go, "r", encoding="utf-8") as f:
        content = f.read()
    tls_anchor = '\tif dokodemoConfig, ok := rawConfig.(*DokodemoConfig); ok {'
    tls_registration = '\tif chitandaConfig, ok := rawConfig.(*ChitandaInboundConfig); ok {\n\t\tchitandaConfig.InheritTLS(c.StreamSetting)\n\t}\n'
    content = replace_unique(content, tls_anchor, tls_registration + tls_anchor, "Chitanda TLS inheritance")
    inbound_anchor = '"vless":         func() interface{} { return new(VLessInboundConfig) },'
    inbound_registration = '"chitanda":      func() interface{} { return new(ChitandaInboundConfig) },\n\t\t'
    content = replace_unique(content, inbound_anchor, inbound_registration + inbound_anchor, "Chitanda inbound JSON")
    outbound_anchor = '"vless":       func() interface{} { return new(VLessOutboundConfig) },'
    outbound_registration = '"chitanda":    func() interface{} { return new(ChitandaOutboundConfig) },\n\t\t'
    content = replace_unique(content, outbound_anchor, outbound_registration + outbound_anchor, "Chitanda outbound JSON")
    with open(xray_conf_go, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  [+] Verified {xray_conf_go} inbound/outbound JSON loaders")

    # 4. Patch main/distro/all/all.go
    all_go = os.path.join(xray_dir, "main", "distro", "all", "all.go")
    if not os.path.isfile(all_go):
        raise RuntimeError(f"Missing Xray distro registry: {all_go}")
    with open(all_go, "r", encoding="utf-8") as f:
        content = f.read()
    target_import = '_ "github.com/xtls/xray-core/proxy/vless/outbound"'
    new_import = '_ "github.com/xtls/xray-core/proxy/chitanda"\n\t' + target_import
    content = replace_unique(content, target_import, new_import, "Chitanda distro")
    with open(all_go, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  [+] Verified {all_go} Chitanda distro registration")

    # 5. Patch go.mod
    go_mod = os.path.join(xray_dir, "go.mod")
    if not os.path.isfile(go_mod):
        raise RuntimeError(f"Missing Xray module: {go_mod}")
    with open(go_mod, "r", encoding="utf-8") as f:
        content = f.read()
    module_name = 'github.com/violetaini/chitanda'
    abs_chitanda = os.path.abspath(chitanda_dir).replace('\\', '/')
    replacement = f"replace {module_name} => {abs_chitanda}"
    requirement = f"{module_name} v0.0.0-unpublished"
    if replacement not in content and module_name not in content:
        content += f"\n{replacement}\n"
        content += f"\nrequire (\n\t{requirement}\n\tgithub.com/quic-go/quic-go v0.59.0\n)\n"
    elif content.count(replacement) != 1 or content.count(requirement) != 1:
        raise RuntimeError("Incomplete or conflicting Chitanda go.mod integration")
    with open(go_mod, "w", encoding="utf-8") as f:
        f.write(content)

    print("[*] Injection into Xray-core completed successfully!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python inject-xray.py <path_to_xray_repo> [path_to_chitanda_repo]")
        sys.exit(1)
    xray_path = sys.argv[1]
    chitanda_path = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    inject_xray(xray_path, chitanda_path)
