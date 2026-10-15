package chitanda_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
)

// ProxySettings starts a real forwarding task using the SDK dial context.
// It must survive successful TCP/UDP handoff, and end when the core closes.
func TestChitandaRawProxyChainSurvivesDialHandoff(t *testing.T) {
	tcpEcho, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEcho.Close()
	go func() {
		for {
			conn, err := tcpEcho.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	echoPort := tcpEcho.Addr().(*net.TCPAddr).Port
	udpEcho, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: echoPort})
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		var p [1024]byte
		for {
			n, addr, err := udpEcho.ReadFromUDP(p[:])
			if err != nil {
				return
			}
			_, _ = udpEcho.WriteToUDP(p[:n], addr)
		}
	}()

	for _, mode := range []string{"stream", "h1"} {
		t.Run(mode, func(t *testing.T) {
			psk := bytes.Repeat([]byte{'x'}, 32)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			remotePort := listener.Addr().(*net.TCPAddr).Port
			remoteConfig, err := json.Marshal(map[string]any{
				"log":       map[string]any{"loglevel": "warning"},
				"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": remotePort, "protocol": "chitanda", "settings": map[string]any{"transport": mode, "psk": string(psk), "path": "/chain", "replay_file": t.TempDir() + "/remote.cache"}}},
				"outbounds": []any{map[string]any{"protocol": "freedom"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			_ = listener.Close()
			remoteCore, err := core.StartInstance("json", remoteConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer remoteCore.Close()
			reserve, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			localPort := reserve.Addr().(*net.TCPAddr).Port
			_ = reserve.Close()
			config, err := json.Marshal(map[string]any{
				"log":      map[string]any{"loglevel": "warning"},
				"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": localPort, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1", "port": echoPort, "network": "tcp,udp"}}},
				"outbounds": []any{
					map[string]any{"tag": "chitanda", "protocol": "chitanda", "settings": map[string]any{"server": net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort)), "psk": string(psk), "transport": mode, "path": "/chain"}, "proxySettings": map[string]any{"tag": "chain-direct"}},
					map[string]any{"tag": "chain-direct", "protocol": "freedom"},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			localCore, err := core.StartInstance("json", config)
			if err != nil {
				t.Fatal(err)
			}
			defer localCore.Close()
			for _, network := range []string{"tcp", "udp"} {
				conn, err := net.Dial(network, net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)))
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				for range 3 {
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					if _, err := conn.Write([]byte("chain-echo")); err != nil {
						t.Fatalf("%s write: %v", network, err)
					}
					var got [10]byte
					if _, err := io.ReadFull(conn, got[:]); err != nil || string(got[:]) != "chain-echo" {
						t.Fatalf("%s echo=%q err=%v", network, got, err)
					}
				}
			}
		})
	}
}
