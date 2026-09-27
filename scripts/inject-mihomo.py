#!/usr/bin/env python3
import os
import sys
import shutil

def inject_mihomo(mihomo_dir, chitanda_dir):
    print(f"[*] Injecting Chitanda adapter into Mihomo: {mihomo_dir}")
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
    src_tests = os.path.join(chitanda_dir, "integration", "mihomo_config")
    if os.path.isdir(src_tests):
        os.makedirs(os.path.join(mihomo_dir, "config"), exist_ok=True)
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

    # 5. Patch tunnel/tunnel.go with Match
    tunnel_go = os.path.join(mihomo_dir, "tunnel", "tunnel.go")
    if os.path.exists(tunnel_go):
        with open(tunnel_go, "r", encoding="utf-8") as f:
            content = f.read()
        if 'func Match(' not in content:
            target = 'func resolveMetadata(metadata *C.Metadata) (proxy C.Proxy, rule C.Rule, err error) {'
            addition = '\nfunc Match(metadata *C.Metadata) (C.Proxy, C.Rule, error) {\n\treturn resolveMetadata(metadata)\n}\n'
            if target in content:
                content = content.replace(target, addition + '\n' + target, 1)
                with open(tunnel_go, "w", encoding="utf-8") as f:
                    f.write(content)
                print(f"  [+] Patched {tunnel_go} with tunnel.Match")

    # 6. Patch adapter/outbound/base.go with UnwrapAdapter
    base_go = os.path.join(adapter_dir, "base.go")
    if os.path.exists(base_go):
        with open(base_go, "r", encoding="utf-8") as f:
            content = f.read()
        if 'UnwrapAdapter()' not in content:
            target = 'func NewAutoCloseProxyAdapter(adapter ProxyAdapter) ProxyAdapter {'
            addition = 'func (p *autoCloseProxyAdapter) UnwrapAdapter() C.ProxyAdapter {\n\treturn p.ProxyAdapter\n}\n\n'
            if target in content:
                content = content.replace(target, addition + target, 1)
                with open(base_go, "w", encoding="utf-8") as f:
                    f.write(content)
                print(f"  [+] Patched {base_go} with UnwrapAdapter")

    # 7. Patch adapter/outbound/singmux.go with UnwrapAdapter
    singmux_go = os.path.join(adapter_dir, "singmux.go")
    if os.path.exists(singmux_go):
        with open(singmux_go, "r", encoding="utf-8") as f:
            content = f.read()
        if 'UnwrapAdapter()' not in content:
            target = 'func NewSingMux(option SingMuxOption, proxy ProxyAdapter) (ProxyAdapter, error) {'
            addition = 'func (s *SingMux) UnwrapAdapter() C.ProxyAdapter {\n\treturn s.ProxyAdapter\n}\n\n'
            if target in content:
                content = content.replace(target, addition + target, 1)
                with open(singmux_go, "w", encoding="utf-8") as f:
                    f.write(content)
                print(f"  [+] Patched {singmux_go} with UnwrapAdapter")

    # 8. Patch listener/sing_tun/prepare.go for ICMP proxy routing
    prepare_go = os.path.join(mihomo_dir, "listener", "sing_tun", "prepare.go")
    if os.path.exists(prepare_go):
        with open(prepare_go, "r", encoding="utf-8") as f:
            content = f.read()
        if 'ICMPDestinationProvider' not in content:
            # Add imports if missing
            if 'github.com/metacubex/mihomo/tunnel' not in content:
                content = content.replace(
                    '"github.com/metacubex/mihomo/log"',
                    'C "github.com/metacubex/mihomo/constant"\n\t"github.com/metacubex/mihomo/log"\n\t"github.com/metacubex/mihomo/tunnel"',
                    1
                )
            
            # Add ICMPDestinationProvider interface
            interface_code = '''type ICMPDestinationProvider interface {
	CreateICMPDestination(sourceAddr, destinationAddr netip.Addr, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error)
}

func (h *ListenerHandler) PrepareConnection'''
            content = content.replace('func (h *ListenerHandler) PrepareConnection', interface_code, 1)

            # Replace direct ping in PrepareConnection with tunnel.Match + dispatch
            old_direct = '''		log.Infoln("[ICMP] %s %s --> %s using DIRECT", network, source, destination)
		directRouteDestination, err := ping.ConnectDestination(context.TODO(), log.SingLogger, dialer.ICMPControl(destination.Addr), destination.Addr, routeContext, timeout)
		if err != nil {
			log.Warnln("[ICMP] failed to connect to %s", destination)
			return nil, err
		}
		log.Debugln("[ICMP] success connect to %s", destination)
		return directRouteDestination, nil'''

            new_routing = '''		metadata := &C.Metadata{
			NetWork: C.UDP,
			Type:    C.TUN,
			SrcIP:   source.Addr,
			DstIP:   destination.Addr,
			SrcPort: source.Port,
			DstPort: 0,
		}
		if destination.IsFqdn() {
			metadata.Host = destination.Fqdn
		}

		proxy, rule, err := tunnel.Match(metadata)

		if err != nil || proxy == nil || proxy.Name() == "DIRECT" {
			log.Infoln("[ICMP] %s %s --> %s using DIRECT", network, source, destination)
			directRouteDestination, err := ping.ConnectDestination(context.TODO(), log.SingLogger, dialer.ICMPControl(destination.Addr), destination.Addr, routeContext, timeout)
			if err != nil {
				log.Warnln("[ICMP] failed to connect to %s", destination)
				return nil, err
			}
			log.Debugln("[ICMP] success connect to %s", destination)
			return directRouteDestination, nil
		}

		if proxy.Name() == "REJECT" || proxy.Name() == "REJECT-DROP" {
			return nil, nil
		}

		leaf := proxy
		for {
			unwrapped := leaf.Unwrap(metadata, false)
			if unwrapped == nil || unwrapped == leaf {
				break
			}
			leaf = unwrapped
		}

		ruleName := ""
		if rule != nil {
			ruleName = rule.RuleType().String()
		}
		log.Infoln("[ICMP] %s %s --> %s match %s using %s[%s]", network, source, destination, ruleName, proxy.Name(), leaf.Name())

		var provider ICMPDestinationProvider
		curr := any(leaf)
		for curr != nil {
			if p, ok := curr.(ICMPDestinationProvider); ok {
				provider = p
				break
			}
			if p, ok := curr.(interface{ Adapter() C.ProxyAdapter }); ok {
				curr = p.Adapter()
			} else if p, ok := curr.(interface{ UnwrapAdapter() C.ProxyAdapter }); ok {
				curr = p.UnwrapAdapter()
			} else {
				break
			}
		}

		if provider != nil {
			dest, err := provider.CreateICMPDestination(source.Addr, destination.Addr, routeContext, timeout)
			if err == nil {
				return dest, nil
			}
			log.Warnln("[ICMP] proxy %s failed to create ICMP destination: %s", leaf.Name(), err)
		}

		log.Infoln("[ICMP] %s %s --> %s proxy does not support ICMP, fallback to DIRECT", network, source, destination)
		return ping.ConnectDestination(context.TODO(), log.SingLogger, dialer.ICMPControl(destination.Addr), destination.Addr, routeContext, timeout)'''

            if old_direct in content:
                content = content.replace(old_direct, new_routing, 1)
                with open(prepare_go, "w", encoding="utf-8") as f:
                    f.write(content)
                print(f"  [+] Patched {prepare_go} for ICMP proxy routing")
            else:
                print(f"  [-] Warning: could not find old_direct pattern in {prepare_go}")

    print("[*] Injection into Mihomo completed successfully!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python inject-mihomo.py <path_to_mihomo_repo> [path_to_chitanda_repo]")
        sys.exit(1)
    mihomo_path = sys.argv[1]
    chitanda_path = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    inject_mihomo(mihomo_path, chitanda_path)
