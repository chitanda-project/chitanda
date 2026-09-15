#!/usr/bin/env python3
import os
import sys
import shutil

def patch_once(path, marker, changes):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    if marker in content:
        return
    for before, after in changes:
        if content.count(before) != 1:
            raise RuntimeError(f"Upstream anchor changed in {path}; refusing a partial UDP integration")
        content = content.replace(before, after, 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

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
    if os.path.exists(xray_conf_go):
        with open(xray_conf_go, "r", encoding="utf-8") as f:
            content = f.read()
        if 'chitandaConfig.InheritTLS(c.StreamSetting)' not in content:
            anchor = '\tif dokodemoConfig, ok := rawConfig.(*DokodemoConfig); ok {'
            if content.count(anchor) != 1:
                raise RuntimeError("Xray inbound build anchor changed; refusing incomplete integration")
            content = content.replace(anchor, '\tif chitandaConfig, ok := rawConfig.(*ChitandaInboundConfig); ok {\n\t\tchitandaConfig.InheritTLS(c.StreamSetting)\n\t}\n' + anchor, 1)
            with open(xray_conf_go, "w", encoding="utf-8") as f:
                f.write(content)
        if '"chitanda"' not in content:
            content = content.replace(
                '"vless":         func() interface{} { return new(VLessInboundConfig) },',
                '"chitanda":      func() interface{} { return new(ChitandaInboundConfig) },\n\t\t"vless":         func() interface{} { return new(VLessInboundConfig) },',
                1
            )
            content = content.replace(
                '"vless":       func() interface{} { return new(VLessOutboundConfig) },',
                '"chitanda":    func() interface{} { return new(ChitandaOutboundConfig) },\n\t\t"vless":       func() interface{} { return new(VLessOutboundConfig) },',
                1
            )
            with open(xray_conf_go, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  [+] Patched {xray_conf_go} with chitanda inbound/outbound JSON loaders")

    # 4. Patch main/distro/all/all.go
    all_go = os.path.join(xray_dir, "main", "distro", "all", "all.go")
    if os.path.exists(all_go):
        with open(all_go, "r", encoding="utf-8") as f:
            content = f.read()
        if 'proxy/chitanda' not in content:
            target_import = '_ "github.com/xtls/xray-core/proxy/vless/outbound"'
            new_import = '_ "github.com/xtls/xray-core/proxy/chitanda"\n\t' + target_import
            content = content.replace(target_import, new_import, 1)
            with open(all_go, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  [+] Patched {all_go} with proxy/chitanda registration")

    # 5. Patch go.mod
    go_mod = os.path.join(xray_dir, "go.mod")
    if os.path.exists(go_mod):
        with open(go_mod, "r", encoding="utf-8") as f:
            content = f.read()
        module_name = 'github.com/violetaini/chitanda'
        if module_name not in content:
            abs_chitanda = os.path.abspath(chitanda_dir).replace('\\', '/')
            content += f"\nreplace {module_name} => {abs_chitanda}\n"
            content += f"\nrequire (\n\t{module_name} v0.0.0-unpublished\n\tgithub.com/quic-go/quic-go v0.59.0\n)\n"
            with open(go_mod, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  [+] Patched {go_mod} with replace {module_name} => {abs_chitanda}")

    print("[*] Injection into Xray-core completed successfully!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python inject-xray.py <path_to_xray_repo> [path_to_chitanda_repo]")
        sys.exit(1)
    xray_path = sys.argv[1]
    chitanda_path = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    inject_xray(xray_path, chitanda_path)
