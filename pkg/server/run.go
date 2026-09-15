package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

func healthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// Run starts the proxy server with the given configuration.
// It blocks until a termination signal is received.
func Run(config *Config, listenAddr, adminListenAddr, quicListenAddr string) error {
	path, psk, replays, err := config.Init()
	if err != nil {
		return err
	}
	defer replays.Close()

	fallback, err := NewFallback(config.FallbackURL, config.FallbackServerName)
	if err != nil {
		return err
	}

	app := NewServer(path, psk, replays, fallback, config.UDPTargetBuffer)
	if config.AllowPrivateTargets {
		app.SetDialTargetForTest(func(ctx context.Context, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 10 * time.Second}
			return dialer.DialContext(ctx, "tcp", address)
		})
	}

	public := &http.Server{
		Addr:              listenAddr,
		Handler:           app,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       3 * time.Minute,
		TLSConfig:         newTLSConfig(config.StrictSNI),
	}
	if err := http2.ConfigureServer(public, &http2.Server{
		MaxUploadBufferPerConnection: 15 * 1024 * 1024,
		MaxUploadBufferPerStream:     15 * 1024 * 1024,
		MaxReadFrameSize:             1 << 20,
		IdleTimeout:                  3 * time.Minute,
	}); err != nil {
		return err
	}

	admin := &http.Server{Addr: adminListenAddr, Handler: healthHandler(), ReadHeaderTimeout: 2 * time.Second}

	var h3Server *http3ServerWrapper
	if quicListenAddr != "" {
		if config.TicketKeyFile == "" {
			return errors.New("ticket-key-file is required when quic-listen is enabled")
		}
		hs, err := newHTTP3Server(quicListenAddr, app, config.TicketKeyFile, config.CertFile, config.KeyFile, config.QuicInitialPacketSize, config.StrictSNI)
		if err != nil {
			return err
		}
		h3Server = &http3ServerWrapper{Server: hs}
	}

	go func() {
		if err := admin.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("admin server: %v", err)
		}
	}()
	if h3Server != nil {
		go func() {
			log.Printf("public HTTP/3 listener started on %s", quicListenAddr)
			udpAddr, err := net.ResolveUDPAddr("udp", quicListenAddr)
			if err != nil {
				log.Fatalf("resolve HTTP/3 addr: %v", err)
			}
			udpConn, err := net.ListenUDP("udp", udpAddr)
			if err != nil {
				log.Fatalf("listen HTTP/3: %v", err)
			}
			_ = udpConn.SetReadBuffer(8 << 20)
			_ = udpConn.SetWriteBuffer(8 << 20)
			if err := h3Server.Serve(udpConn); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTP/3 server: %v", err)
			}
		}()
	}
	serverLifecycleCtx, serverLifecycleCancel := context.WithCancel(context.Background())
	defer serverLifecycleCancel()

	var plainUDPServer *PlainUDPServer
	// Plain-UDP listener: enabled if quicListenAddr is empty or distinct from listenAddr
	if quicListenAddr == "" || quicListenAddr != listenAddr {
		plainUDPAddr, err := net.ResolveUDPAddr("udp", listenAddr)
		if err != nil {
			return fmt.Errorf("resolve plain-UDP addr %q: %w", listenAddr, err)
		}
		plainUDPLn, err := net.ListenUDP("udp", plainUDPAddr)
		if err != nil {
			log.Printf("warning: plain-UDP listen on %s failed: %v", listenAddr, err)
		} else {
			_ = plainUDPLn.SetReadBuffer(8 << 20)
			_ = plainUDPLn.SetWriteBuffer(8 << 20)
			pServer, err := NewPlainUDPServer(plainUDPLn, psk)
			if err != nil {
				_ = plainUDPLn.Close()
				return fmt.Errorf("init plain-UDP server: %w", err)
			}
			plainUDPServer = pServer
			if config.AllowPrivateTargets {
				plainUDPServer.SetResolveUDP(func(ctx context.Context, address string) (*net.UDPAddr, error) {
					return net.ResolveUDPAddr("udp", address)
				})
			}
			go func() {
				log.Printf("public plain-UDP datagram listener started on %s", listenAddr)
				_ = plainUDPServer.Serve(serverLifecycleCtx)
			}()
		}
	}

	var streamServer *StreamServer
	if config.RawStreamListen != "" {
		rawstreamLns, err := ListenTCPMulti(config.RawStreamListen)
		if err != nil {
			return fmt.Errorf("listen rawstream %q: %w", config.RawStreamListen, err)
		}
		streamServer = NewStreamServer(psk, config.ServerID, replays, func(ctx context.Context, network, address string) (net.Conn, error) {
			return app.dialTarget(ctx, address)
		})

		// Optionally attach Native UDP on the same rawstream port if not already bound
		if quicListenAddr != config.RawStreamListen && listenAddr != config.RawStreamListen {
			if uAddr, err := net.ResolveUDPAddr("udp", config.RawStreamListen); err == nil {
				if uConn, err := net.ListenUDP("udp", uAddr); err == nil {
					_ = uConn.SetReadBuffer(8 << 20)
					_ = uConn.SetWriteBuffer(8 << 20)
					_ = streamServer.AttachUDP(uConn)
					if config.AllowPrivateTargets && streamServer.UDPServer() != nil {
						streamServer.UDPServer().SetResolveUDP(func(ctx context.Context, address string) (*net.UDPAddr, error) {
							return net.ResolveUDPAddr("udp", address)
						})
					}
				}
			}
		}

		go func() {
			log.Printf("public RawStream TCP listener started on %s (%d listeners)", config.RawStreamListen, len(rawstreamLns))
			if err := streamServer.Serve(rawstreamLns...); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Fatalf("rawstream server: %v", err)
			}
		}()
	}

	publicLns, err := ListenTCPMulti(listenAddr)
	if err != nil {
		return fmt.Errorf("listen public %q: %w", listenAddr, err)
	}
	for _, ln := range publicLns {
		go func(l net.Listener) {
			if config.CertFile == "" || config.KeyFile == "" {
				log.Printf("public Plain HTTP/1.1 listener started on %s", listenAddr)
				if err := public.Serve(l); err != nil && err != http.ErrServerClosed {
					log.Fatalf("public plain server: %v", err)
				}
			} else {
				log.Printf("public TLS listener started on %s", listenAddr)
				if err := public.ServeTLS(l, config.CertFile, config.KeyFile); err != nil && err != http.ErrServerClosed {
					log.Fatalf("public server: %v", err)
				}
			}
		}(ln)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverLifecycleCancel()
	_ = public.Shutdown(ctx)
	_ = admin.Shutdown(ctx)
	if h3Server != nil {
		_ = h3Server.Close()
	}
	if plainUDPServer != nil {
		_ = plainUDPServer.Close()
	}
	if streamServer != nil {
		_ = streamServer.Close()
	}
	return nil
}

type http3ServerWrapper struct {
	*http3.Server // from github.com/quic-go/quic-go/http3
}
