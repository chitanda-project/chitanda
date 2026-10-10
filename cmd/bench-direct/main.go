// cmd/bench-direct is a standalone high-performance benchmark tool that tests
// the MyXray client SDK (pkg/client) directly without any SOCKS5 or proxy layer.
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/violetaini/chitanda/internal/auth"
	"github.com/violetaini/chitanda/pkg/client"
)

func main() {
	mode := flag.String("mode", "tcp", "mode: tcp, udp, all, echo-server, or sink-server")
	listen := flag.String("listen", ":18088", "listen address for server modes")
	server := flag.String("server", "170.9.59.149:11322", "server endpoint")
	serverName := flag.String("server-name", "status.chitanda.org", "TLS server name")
	pskFile := flag.String("psk-file", "", "path to PSK file")
	pskStr := flag.String("psk", "", "PSK string")
	pathFile := flag.String("path-file", "", "path to private path file")
	pathStr := flag.String("path", "", "private path string")
	tcpTransport := flag.String("tcp-transport", "h2", "TCP carrier: h2, auto or h3")
	target := flag.String("target", "170.9.59.149:18088", "remote target on the server")
	duration := flag.Duration("duration", 5*time.Second, "test duration per run")
	rateMbps := flag.Int("udp-rate", 150, "UDP target send rate in Mbps")
	packetSize := flag.Int("packet-size", 1350, "UDP payload size in bytes")
	concurrency := flag.Int("concurrency", 1, "TCP concurrency")
	poolSize := flag.Int("pool-size", 4, "TCP physical carrier connection pool size")
	sessionCacheFile := flag.String("session-cache-file", "", "optional persistent session cache")
	cpuProfile := flag.String("cpu-profile", "", "optional CPU profile output path")
	serverID := flag.String("server-id", "", "optional RawStream server identifier")
	flag.Parse()

	if *cpuProfile != "" {
		profileFile, err := os.Create(*cpuProfile)
		if err != nil {
			log.Fatalf("create CPU profile: %v", err)
		}
		if err := pprof.StartCPUProfile(profileFile); err != nil {
			_ = profileFile.Close()
			log.Fatalf("start CPU profile: %v", err)
		}
		defer func() {
			pprof.StopCPUProfile()
			_ = profileFile.Close()
		}()
	}

	if *mode == "echo-server" {
		runEchoServer(*listen)
		return
	}
	if *mode == "sink-server" {
		runSinkServer(*listen)
		return
	}

	var psk []byte
	if *pskFile != "" {
		var err error
		psk, err = auth.LoadPSK(*pskFile)
		if err != nil {
			log.Fatalf("load PSK: %v", err)
		}
	} else if *pskStr != "" {
		psk = []byte(*pskStr)
	} else if env := os.Getenv("CHITANDA_PSK"); env != "" {
		psk = []byte(env)
	} else {
		log.Fatal("-psk-file, -psk, or CHITANDA_PSK is required")
	}

	p := *pathStr
	if p == "" && *pathFile != "" {
		raw, err := os.ReadFile(*pathFile)
		if err != nil {
			log.Fatalf("read path file: %v", err)
		}
		p = strings.TrimSpace(string(raw))
	}
	if p == "" {
		log.Fatal("private path is required")
	}

	cli, err := client.New(client.Config{
		Server:           *server,
		ServerName:       *serverName,
		PSK:              psk,
		Path:             p,
		TCPTransport:     *tcpTransport,
		ServerID:         *serverID,
		TCPPoolSize:      *poolSize,
		SessionCacheFile: *sessionCacheFile,
	})
	if err != nil {
		log.Fatalf("create client: %v", err)
	}
	defer cli.Close()

	_ = cli.Prewarm(context.Background())

	log.Printf("=== MyXray Direct Native Core Benchmark ===")
	log.Printf("Server: %s (%s)", *server, *serverName)
	log.Printf("Target: %s | TCP Carrier: %s (Pool: %d) | Duration: %s", *target, *tcpTransport, *poolSize, *duration)

	if *mode == "tcp" || *mode == "all" {
		runTCPBenchmark(cli, *target, *duration, *concurrency)
	}
	if *mode == "udp" || *mode == "all" {
		runUDPBenchmark(cli, *target, *duration, *rateMbps, *packetSize)
	}
}

func runEchoServer(listenAddr string) {
	log.Printf("Starting Direct Benchmark Echo Server on %s (TCP & UDP)...", listenAddr)

	// UDP Echo
	uaddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		log.Fatalf("resolve UDP listen address: %v", err)
	}
	uconn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		log.Fatalf("listen UDP: %v", err)
	}
	_ = uconn.SetReadBuffer(8 << 20)
	_ = uconn.SetWriteBuffer(8 << 20)
	defer uconn.Close()

	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, raddr, err := uconn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n > 0 {
				_, _ = uconn.WriteToUDP(buf[:n], raddr)
			}
		}
	}()

	// TCP Echo
	tlistener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen TCP: %v", err)
	}
	defer tlistener.Close()

	for {
		conn, err := tlistener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 1<<20)
			_, _ = io.CopyBuffer(c, c, buf)
		}(conn)
	}
}

func runSinkServer(listenAddr string) {
	log.Printf("Starting Direct Benchmark Sink Server on %s (TCP & UDP)...", listenAddr)

	// UDP Sink
	uaddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		log.Fatalf("resolve UDP listen address: %v", err)
	}
	uconn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		log.Fatalf("listen UDP: %v", err)
	}
	_ = uconn.SetReadBuffer(8 << 20)
	defer uconn.Close()

	go func() {
		buf := make([]byte, 64<<10)
		var udpBytes atomic.Uint64
		var udpPackets atomic.Uint64
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			lastBytes := uint64(0)
			lastPkts := uint64(0)
			for range ticker.C {
				curBytes := udpBytes.Load()
				curPkts := udpPackets.Load()
				diffBytes := curBytes - lastBytes
				diffPkts := curPkts - lastPkts
				lastBytes = curBytes
				lastPkts = curPkts
				if diffBytes > 0 {
					mbps := float64(diffBytes*8) / 2.0 / 1e6
					log.Printf("[Sink UDP] Rate: %.2f Mbps (%d pkts/s) | Total: %d pkts", mbps, diffPkts/2, curPkts)
				}
			}
		}()
		for {
			n, _, err := uconn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n > 0 {
				udpBytes.Add(uint64(n))
				udpPackets.Add(1)
			}
		}
	}()

	// TCP Sink
	tlistener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen TCP: %v", err)
	}
	defer tlistener.Close()

	for {
		conn, err := tlistener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_, _ = io.Copy(io.Discard, c)
		}(conn)
	}
}

func runTCPBenchmark(cli *client.Client, target string, duration time.Duration, concurrency int) {
	log.Printf("\n--- [TCP Direct Core Benchmark] (concurrency=%d) ---", concurrency)

	var totalBytes atomic.Int64
	var totalStreams atomic.Int64
	var failedStreams atomic.Int64

	ctx, cancel := context.WithTimeout(context.Background(), duration+10*time.Second)
	defer cancel()

	start := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			buf := make([]byte, 1<<20)
			_, _ = rand.Read(buf)

			conn, err := cli.DialContext(ctx, "tcp", target)
			if err != nil {
				failedStreams.Add(1)
				log.Printf("worker %d dial failed: %v", workerID, err)
				return
			}
			defer conn.Close()
			totalStreams.Add(1)

			// Concurrently drain any response so echo servers don't stall flow control
			go func() {
				discardBuf := make([]byte, 1<<20)
				_, _ = io.CopyBuffer(io.Discard, conn, discardBuf)
			}()

			timer := time.AfterFunc(duration, func() {
				_ = conn.Close()
			})
			defer timer.Stop()

			for {
				n, writeErr := conn.Write(buf)
				if writeErr != nil {
					log.Printf("worker %d write error: %v", workerID, writeErr)
					break
				}
				totalBytes.Add(int64(n))
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	bytesSent := totalBytes.Load()
	mbps := float64(bytesSent*8) / elapsed.Seconds() / 1e6
	mBps := float64(bytesSent) / elapsed.Seconds() / 1e6

	log.Printf("TCP Result: %.2f MB/s (%.2f Mbps) | Streams: %d (failed: %d) | Time: %.2fs",
		mBps, mbps, totalStreams.Load(), failedStreams.Load(), elapsed.Seconds())
}

func runUDPBenchmark(cli *client.Client, target string, duration time.Duration, targetRateMbps int, packetSize int) {
	log.Printf("\n--- [UDP Direct Native Core Benchmark] (targetRate=%d Mbps, packetSize=%d B) ---", targetRateMbps, packetSize)

	targetUDPAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		log.Printf("resolve target UDP address failed: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration+10*time.Second)
	defer cancel()

	pconn, err := cli.ListenPacket(ctx)
	if err != nil {
		log.Printf("open UDP PacketConn failed: %v", err)
		return
	}
	defer pconn.Close()

	var sentPackets atomic.Uint64
	var sentBytes atomic.Uint64
	var rcvdPackets atomic.Uint64
	var rcvdBytes atomic.Uint64

	start := time.Now()
	deadline := start.Add(duration)

	// Receiver loop
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		buf := make([]byte, 64<<10)
		for {
			n, _, err := pconn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > 0 {
				rcvdPackets.Add(1)
				rcvdBytes.Add(uint64(n))
			}
		}
	}()

	// Paced sender with millisecond burst bucket:
	// Every 1ms tick, calculate accumulated token budget and send burst of packets
	tickInterval := time.Millisecond
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	bytesPerSec := float64(targetRateMbps) * 1e6 / 8.0
	bytesPerTick := bytesPerSec * tickInterval.Seconds()

	payload := make([]byte, packetSize)
	_, _ = rand.Read(payload[12:]) // random payload, first 12 bytes for seq + timestamp

	seq := uint64(0)
	var tokenBudget float64

	for time.Now().Before(deadline) {
		<-ticker.C
		tokenBudget += bytesPerTick
		for tokenBudget >= float64(packetSize) {
			tokenBudget -= float64(packetSize)
			seq++
			binary.BigEndian.PutUint64(payload[0:8], seq)
			binary.BigEndian.PutUint32(payload[8:12], uint32(time.Since(start).Milliseconds()))

			_, err := pconn.WriteTo(payload, targetUDPAddr)
			if err != nil {
				continue
			}
			sentPackets.Add(1)
			sentBytes.Add(uint64(len(payload)))
		}
	}

	time.Sleep(500 * time.Millisecond)
	_ = pconn.Close()
	<-recvDone

	elapsed := time.Since(start) - 500*time.Millisecond
	totalSent := sentPackets.Load()
	totalRcvd := rcvdPackets.Load()
	sentBps := float64(sentBytes.Load()*8) / elapsed.Seconds() / 1e6
	rcvdBps := float64(rcvdBytes.Load()*8) / elapsed.Seconds() / 1e6

	lossPercent := float64(0)
	if totalSent > 0 {
		if totalRcvd <= totalSent {
			lossPercent = float64(totalSent-totalRcvd) / float64(totalSent) * 100.0
		}
	}

	log.Printf("UDP Result: Sent %.2f Mbps (%d pkts) | Recv %.2f Mbps (%d pkts) | Loss: %.2f%% | Time: %.2fs",
		sentBps, totalSent, rcvdBps, totalRcvd, lossPercent, elapsed.Seconds())
}
