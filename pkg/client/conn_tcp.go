package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/violetaini/chitanda/internal/frame"
	"golang.org/x/net/http2"
)

type h2TransportClient struct {
	server        string
	serverName    string
	rootURL       string
	requestURL    string
	path          string
	psk           []byte
	client        *http.Client
	transport     *http.Transport
	activeStreams atomic.Int64
}

func newH2TransportClient(server, serverName, rootURL, requestURL, path string, psk []byte, insecureSkipVerify bool, dialRaw func(ctx context.Context, network, addr string) (net.Conn, error)) (*h2TransportClient, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		InsecureSkipVerify: insecureSkipVerify,
		NextProtos:         []string{"h2"},
	}
	dialTLS := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var rawConn net.Conn
		var err error
		if dialRaw != nil {
			rawConn, err = dialRaw(ctx, network, server)
		} else {
			dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}
			rawConn, err = dialer.DialContext(ctx, network, server)
		}
		if err != nil {
			return nil, err
		}
		if tc, ok := rawConn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(15 * time.Second)
		} else if kac, ok := rawConn.(interface {
			SetKeepAlive(bool) error
			SetKeepAlivePeriod(time.Duration) error
		}); ok {
			_ = kac.SetKeepAlive(true)
			_ = kac.SetKeepAlivePeriod(15 * time.Second)
		}
		tlsConn := tls.Client(rawConn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, err
		}

		return tlsConn, nil
	}

	transport := &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     3 * time.Minute,
		TLSClientConfig:     tlsCfg,
		DialTLSContext:      dialTLS,
	}

	h2Transport, err := http2.ConfigureTransports(transport)
	if err != nil {
		return nil, err
	}
	h2Transport.ReadIdleTimeout = 45 * time.Second
	h2Transport.PingTimeout = 15 * time.Second
	h2Transport.MaxReadFrameSize = 1 << 20
	h2Transport.TLSClientConfig = tlsCfg
	h2Transport.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		return dialTLS(ctx, network, addr)
	}

	// Enable RFC 7540 dynamic padding to defeat website fingerprinting (WFP) traffic analysis
	if f := reflect.ValueOf(h2Transport).Elem().FieldByName("MaxDataPadding"); f.IsValid() && f.CanSet() {
		f.SetInt(64)
	}

	return &h2TransportClient{
		server:     server,
		serverName: serverName,
		rootURL:    rootURL,
		requestURL: requestURL,
		path:       path,
		psk:        psk,
		client:     &http.Client{Transport: transport},
		transport:  transport,
	}, nil
}

func (c *h2TransportClient) prewarm(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, c.rootURL, nil)
	if err != nil {
		return err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	return response.Body.Close()
}

func (c *h2TransportClient) dialH2TCP(ctx context.Context, target string) (net.Conn, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := c.dialH2TCPOnce(ctx, target)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if attempt == 0 {
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
		}
	}
	return nil, lastErr
}

func (c *h2TransportClient) dialH2TCPOnce(ctx context.Context, target string) (net.Conn, error) {
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stopCancel := context.AfterFunc(ctx, func() {
		cancel()
	})
	defer stopCancel()

	pipeReader, pipeWriter := io.Pipe()

	request, err := http.NewRequestWithContext(streamCtx, http.MethodPost, c.requestURL, pipeReader)
	if err != nil {
		cancel()
		_ = pipeReader.Close()
		_ = pipeWriter.Close()
		return nil, fmt.Errorf("create h2 request: %w", err)
	}

	if err := signRequest(request, c.psk, c.path, target, ModeTCPv2); err != nil {
		cancel()
		_ = pipeReader.Close()
		_ = pipeWriter.Close()
		return nil, err
	}
	request.Header.Set("X-Session-Framing", "1")

	response, err := c.client.Do(request)
	if err != nil {
		cancel()
		_ = pipeReader.Close()
		_ = pipeWriter.Close()
		return nil, fmt.Errorf("h2 do request: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		cancel()
		_ = response.Body.Close()
		_ = pipeWriter.Close()
		return nil, fmt.Errorf("unexpected status %d from %s", response.StatusCode, c.requestURL)
	}

	if response.Header.Get(HeaderSessionOK) != "1" {
		cancel()
		_ = response.Body.Close()
		_ = pipeWriter.Close()
		return nil, errors.New("missing session confirmation header")
	}

	c.activeStreams.Add(1)
	var body io.ReadCloser = response.Body
	if response.Header.Get("X-Session-Framing") == "1" {
		body = &framedResponseBody{Reader: frame.NewStreamReader(body), Closer: body}
	}
	return newRawH2Conn(target, body, pipeWriter, cancel, c), nil
}

type framedResponseBody struct {
	io.Reader
	io.Closer
}

func (c *h2TransportClient) close() {
	c.transport.CloseIdleConnections()
}

// rawH2Conn wraps HTTP/2 full duplex stream directly into net.Conn without custom framing.
type rawH2Conn struct {
	target        string
	body          io.ReadCloser
	pipeWriter    *io.PipeWriter
	cancel        context.CancelFunc
	h2Client      *h2TransportClient
	closed        atomic.Bool
	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
	readTimer     *time.Timer
	writeTimer    *time.Timer
}

func newRawH2Conn(target string, body io.ReadCloser, pipeWriter *io.PipeWriter, cancel context.CancelFunc, h2Client *h2TransportClient) *rawH2Conn {
	return &rawH2Conn{
		target:     target,
		body:       body,
		pipeWriter: pipeWriter,
		cancel:     cancel,
		h2Client:   h2Client,
	}
}

func (c *rawH2Conn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, io.EOF
	}
	c.mu.Lock()
	if !c.readDeadline.IsZero() && time.Now().After(c.readDeadline) {
		c.mu.Unlock()
		return 0, context.DeadlineExceeded
	}
	c.mu.Unlock()
	return c.body.Read(b)
}

func (c *rawH2Conn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.closed.Load() {
		return 0, errors.New("use of closed connection")
	}
	c.mu.Lock()
	if !c.writeDeadline.IsZero() && time.Now().After(c.writeDeadline) {
		c.mu.Unlock()
		return 0, context.DeadlineExceeded
	}
	c.mu.Unlock()
	return c.pipeWriter.Write(b)
}

func (c *rawH2Conn) CloseWrite() error {
	return c.pipeWriter.Close()
}

func (c *rawH2Conn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	c.mu.Lock()
	if c.readTimer != nil {
		c.readTimer.Stop()
	}
	if c.writeTimer != nil {
		c.writeTimer.Stop()
	}
	c.mu.Unlock()

	if c.h2Client != nil {
		c.h2Client.activeStreams.Add(-1)
	}
	if c.cancel != nil {
		c.cancel()
	}
	_ = c.pipeWriter.CloseWithError(errors.New("use of closed network connection"))
	return c.body.Close()
}

func (c *rawH2Conn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (c *rawH2Conn) RemoteAddr() net.Addr {
	host, portStr, err := net.SplitHostPort(c.target)
	if err == nil {
		var port int
		_, _ = fmt.Sscanf(portStr, "%d", &port)
		return &net.TCPAddr{IP: net.ParseIP(host), Port: port}
	}
	return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
}

func (c *rawH2Conn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *rawH2Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
	if !t.IsZero() {
		dur := time.Until(t)
		if dur <= 0 {
			_ = c.body.Close()
			return nil
		}
		c.readTimer = time.AfterFunc(dur, func() {
			_ = c.body.Close()
		})
	}
	return nil
}

func (c *rawH2Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	if c.writeTimer != nil {
		c.writeTimer.Stop()
		c.writeTimer = nil
	}
	if !t.IsZero() {
		dur := time.Until(t)
		if dur <= 0 {
			_ = c.pipeWriter.CloseWithError(context.DeadlineExceeded)
			return nil
		}
		c.writeTimer = time.AfterFunc(dur, func() {
			_ = c.pipeWriter.CloseWithError(context.DeadlineExceeded)
		})
	}
	return nil
}
