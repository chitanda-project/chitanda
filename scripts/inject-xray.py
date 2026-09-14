#!/usr/bin/env python3
import os
import sys
import shutil

def inject_xray(xray_dir, chitanda_dir):
    print(f"[*] Injecting Chitanda protocol into Xray-core: {xray_dir}")
    proxy_dir = os.path.join(xray_dir, "proxy", "chitanda")
    conf_dir = os.path.join(xray_dir, "infra", "conf")
    os.makedirs(proxy_dir, exist_ok=True)
    os.makedirs(conf_dir, exist_ok=True)
    
    # 1. Copy the adapter and its regression tests into proxy/chitanda/.
    src_integration = os.path.join(chitanda_dir, "integration", "xray")
    for fname in ["config.pb.go", "outbound.go", "inbound.go", "config_test.go", "pipe_conn_test.go"]:
        src = os.path.join(src_integration, fname)
        dst = os.path.join(proxy_dir, fname)
        shutil.copy2(src, dst)
        print(f"  [+] Copied {fname} -> proxy/chitanda/")
        
    # 2. Copy chitanda.go -> infra/conf/chitanda.go
    src_conf = os.path.join(chitanda_dir, "integration", "xray_conf", "chitanda.go")
    dst_conf = os.path.join(conf_dir, "chitanda.go")
    shutil.copy2(src_conf, dst_conf)
    print(f"  [+] Copied {src_conf} -> infra/conf/chitanda.go")
    
    # 3. Patch infra/conf/xray.go
    xray_conf_go = os.path.join(conf_dir, "xray.go")
    if os.path.exists(xray_conf_go):
        with open(xray_conf_go, "r", encoding="utf-8") as f:
            content = f.read()
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
