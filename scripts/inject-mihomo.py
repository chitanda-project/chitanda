#!/usr/bin/env python3
import os
import sys
import shutil


def patch_udp_sender_capacity(mihomo_dir):
    """Buffer UDP packets while an outbound association is being established."""
    tunnel_go = os.path.join(mihomo_dir, "tunnel", "tunnel.go")
    with open(tunnel_go, "r", encoding="utf-8") as f:
        content = f.read()

    original = "\tsenderCapacity = 128 // chan capacity of PacketSender"
    patched = "\tsenderCapacity = 4096 // chan capacity of PacketSender"
    if content.count(patched) == 1 and original not in content:
        return
    if content.count(original) != 1 or patched in content:
        raise RuntimeError(f"unexpected Mihomo UDP sender capacity in {tunnel_go}")

    with open(tunnel_go, "w", encoding="utf-8") as f:
        f.write(content.replace(original, patched, 1))
    print(f"  [+] Patched {tunnel_go} UDP sender capacity for cold H3 associations")


def patch_tun_icmp_route(mihomo_dir):
    prepare_go = os.path.join(mihomo_dir, "listener", "sing_tun", "prepare.go")
    with open(prepare_go, "r", encoding="utf-8") as f:
        content = f.read()
    original = '\t\tlog.Infoln("[ICMP] %s %s --> %s using DIRECT", network, source, destination)'
    patched = (
        '\t\tif action, handled, err := h.prepareChitandaICMP(source.Addr, destination.Addr, routeContext, timeout); handled {\n'
        '\t\t\treturn action, err\n'
        '\t\t}\n' + original
    )
    if content.count(patched) == 1:
        return
    if content.count(original) != 1:
        raise RuntimeError(f"unexpected Mihomo ICMP route in {prepare_go}")
    with open(prepare_go, "w", encoding="utf-8") as f:
        f.write(content.replace(original, patched, 1))


def inject_mihomo(mihomo_dir, chitanda_dir):
    print(f"[*] Injecting Chitanda adapter into Mihomo: {mihomo_dir}")
    patch_udp_sender_capacity(mihomo_dir)
    adapter_dir = os.path.join(mihomo_dir, "adapter", "outbound")
    constant_dir = os.path.join(mihomo_dir, "constant")
    
    os.makedirs(adapter_dir, exist_ok=True)
    
    # 1. Copy chitanda.go into adapter/outbound/
    src_adapter = os.path.join(chitanda_dir, "integration", "mihomo", "chitanda.go")
    dst_adapter = os.path.join(adapter_dir, "chitanda.go")
    shutil.copy2(src_adapter, dst_adapter)
    print(f"  [+] Copied {src_adapter} -> {dst_adapter}")
    for fname in sorted(os.listdir(os.path.dirname(src_adapter))):
        if fname.endswith("_test.go"):
            shutil.copy2(os.path.join(os.path.dirname(src_adapter), fname), os.path.join(adapter_dir, fname))
    for src, dst in (
        (os.path.join(chitanda_dir, "integration", "mihomo_tunnel", "chitanda_icmp.go"),
         os.path.join(mihomo_dir, "tunnel", "chitanda_icmp.go")),
        (os.path.join(chitanda_dir, "integration", "mihomo_sing_tun", "chitanda_icmp.go"),
         os.path.join(mihomo_dir, "listener", "sing_tun", "chitanda_icmp.go")),
        (os.path.join(chitanda_dir, "integration", "mihomo_sing_tun", "chitanda_icmp_test.go"),
         os.path.join(mihomo_dir, "listener", "sing_tun", "chitanda_icmp_test.go")),
    ):
        shutil.copy2(src, dst)
    patch_tun_icmp_route(mihomo_dir)
    src_tests = os.path.join(chitanda_dir, "integration", "mihomo_config")
    if os.path.isdir(src_tests):
        for fname in sorted(os.listdir(src_tests)):
            if fname.endswith("_test.go"):
                shutil.copy2(os.path.join(src_tests, fname), os.path.join(mihomo_dir, "config", fname))
    
    # 2. Patch constant/adapters.go
    adapters_go = os.path.join(constant_dir, "adapters.go")
    if os.path.exists(adapters_go):
        with open(adapters_go, "r", encoding="utf-8") as f:
            content = f.read()
        if 'Chitanda' not in content:
            content = content.replace(
                '\tShadowsocks',
                '\tChitanda\n\tShadowsocks',
                1
            )
            content = content.replace(
                'case Shadowsocks:',
                'case Chitanda:\n\t\treturn "Chitanda"\n\tcase Shadowsocks:',
                1
            )
            with open(adapters_go, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  [+] Patched {adapters_go} with Chitanda enum and Stringer")
            
    # 3. Patch adapter/parser.go
    parser_go = os.path.join(mihomo_dir, "adapter", "parser.go")
    if os.path.exists(parser_go):
        with open(parser_go, "r", encoding="utf-8") as f:
            content = f.read()
        if '"chitanda"' not in content:
            target_hook = 'case "ss":'
            new_hook = '''case "chitanda":
		chitandaOption := &outbound.ChitandaOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, chitandaOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewChitanda(*chitandaOption)
	case "ss":'''
            content = content.replace(target_hook, new_hook, 1)
            with open(parser_go, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  [+] Patched {parser_go} with Chitanda decoder")
            
    # 4. Patch go.mod
    go_mod = os.path.join(mihomo_dir, "go.mod")
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
            
    print("[*] Injection into Mihomo completed successfully!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python inject-mihomo.py <path_to_mihomo_repo> [path_to_chitanda_repo]")
        sys.exit(1)
    mihomo_path = sys.argv[1]
    chitanda_path = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    inject_mihomo(mihomo_path, chitanda_path)
