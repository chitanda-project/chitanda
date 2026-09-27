package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/violetaini/chitanda/pkg/client"
)

func main() {
	server := flag.String("server", "170.9.59.149:39600", "Server address")
	psk := flag.String("psk", "JRs8xycp1XOjCzVjd7-SFFf0HlTxobVid5lZ5yhIXC0", "PSK")
	path := flag.String("path", "/chitanda-test", "Path")
	sni := flag.String("sni", "bench.invalid", "SNI")
	target := flag.String("target", "1.1.1.1", "Ping target")
	rounds := flag.Int("rounds", 10, "Number of ping rounds")
	flag.Parse()

	c, err := client.New(client.Config{
		Server:             *server,
		ServerName:         *sni,
		PSK:                []byte(*psk),
		Path:               *path,
		TCPTransport:       client.TCPTransportH3,
		InsecureSkipVerify: true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Client init failed: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()

	fmt.Printf("PING %s via Chitanda H3 Proxy (%s)...\n", *target, *server)
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
}
