package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/violetaini/chitanda/pkg/auth"
	"github.com/violetaini/chitanda/pkg/client"
)

func main() {
	server := flag.String("server", "", "Server address (required)")
	psk := flag.String("psk", "", "PSK (prefer CHITANDA_PSK environment variable)")
	pskFile := flag.String("psk-file", "", "File containing a hex or base64url PSK (preferred)")
	path := flag.String("path", "", "Private HTTP path (required)")
	sni := flag.String("sni", "", "TLS server name (required for TLS transports)")
	target := flag.String("target", "1.1.1.1", "Ping target")
	transport := flag.String("transport", "h3", "Transport (h3, h2, auto, h1, plain-h1, stream)")
	rounds := flag.Int("rounds", 10, "Number of ping rounds")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification (testing only)")
	flag.Parse()
	if *server == "" || *path == "" || *rounds < 1 {
		fmt.Fprintln(os.Stderr, "-server and -path are required; -rounds must be positive")
		os.Exit(2)
	}
	var pskBytes []byte
	if *pskFile != "" {
		var err error
		pskBytes, err = auth.LoadPSK(*pskFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load PSK: %v\n", err)
			os.Exit(2)
		}
	} else {
		if *psk == "" {
			*psk = os.Getenv("CHITANDA_PSK")
		}
		if *psk == "" {
			fmt.Fprintln(os.Stderr, "set -psk-file, CHITANDA_PSK, or -psk")
			os.Exit(2)
		}
		pskBytes = []byte(*psk)
	}

	c, err := client.New(client.Config{
		Server:             *server,
		ServerName:         *sni,
		PSK:                pskBytes,
		Path:               *path,
		TCPTransport:       *transport,
		InsecureSkipVerify: *insecure,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Client init failed: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()

	fmt.Printf("PING %s via Chitanda %s Proxy (%s)...\n", *target, *transport, *server)
	var totalRTT time.Duration
	success := 0
	for i := 1; i <= *rounds; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		payload := []byte(fmt.Sprintf("chitanda-ping-%d-%d", os.Getpid(), i))
		data, rtt, err := c.Ping(ctx, *target, uint16(os.Getpid()&0xffff), uint16(i), payload)
		cancel()
		if err != nil {
			fmt.Printf("Round %d: FAILED (%v)\n", i, err)
		} else {
			success++
			totalRTT += rtt
			fmt.Printf("Round %d: %d bytes from %s: icmp_seq=%d rtt=%.2f ms\n",
				i, len(data), *target, i, float64(rtt.Microseconds())/1000.0)
		}
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("\n--- %s Chitanda Proxy Ping Statistics ---\n", *target)
	lossRate := float64(*rounds-success) / float64(*rounds) * 100.0
	fmt.Printf("%d packets transmitted, %d received, %.1f%% packet loss\n", *rounds, success, lossRate)
	if success > 0 {
		avgRTT := float64(totalRTT.Microseconds()) / float64(success) / 1000.0
		fmt.Printf("avg rtt = %.2f ms\n", avgRTT)
	}
	if success != *rounds {
		os.Exit(1)
	}
}
