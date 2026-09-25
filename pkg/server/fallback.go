package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

// NewFallback creates a fallback handler based on the target configuration.
func NewFallback(target, serverName string) (http.Handler, error) {
	target = strings.TrimSpace(target)
	if target == "" || target == "embed" || target == "default" || target == "builtin" {
		return newERPFallbackHandler(serverName), nil
	}

	// Check if local directory exists
	if stat, err := os.Stat(target); err == nil && stat.IsDir() {
		return http.FileServer(http.Dir(target)), nil
	}

	// Check Unix Domain Socket (e.g. unix:/run/nginx.sock)
	if strings.HasPrefix(target, "unix:") {
		socketPath := strings.TrimPrefix(target, "unix:")
		proxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = "http"
				req.URL.Host = "localhost"
				if serverName != "" {
					req.Host = serverName
				}
			},
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var dialer net.Dialer
					return dialer.DialContext(ctx, "unix", socketPath)
				},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
			ModifyResponse: sanitizeFallbackResponse,
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
				http.NotFound(w, nil)
			},
		}
		return proxy, nil
	}

	// Local host/port or remote URL
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid fallback target: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = &http.Transport{
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	proxy.ModifyResponse = sanitizeFallbackResponse
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.NotFound(w, nil)
	}
	return proxy, nil
}

func sanitizeFallbackResponse(response *http.Response) error {
	response.Header.Del(headerSessionOK)
	response.Header.Del(headerFraming)
	response.Header.Del("X-Session-Early")
	return nil
}

func (s *Server) serveFallback(w http.ResponseWriter, r *http.Request) {
	privateAttempt := false
	for _, name := range []string{headerTarget, headerTimestamp, headerNonce, headerSignature, headerMode} {
		if _, present := r.Header[http.CanonicalHeaderKey(name)]; present {
			privateAttempt = true
		}
		r.Header.Del(name)
	}
	if privateAttempt {
		if r.ProtoMajor == 1 {
			w.Header().Set("Connection", "close")
			defer func() {
				_ = http.NewResponseController(w).SetReadDeadline(time.Unix(1, 0))
			}()
		}
		r.Body = http.NoBody
		r.GetBody = nil
		r.ContentLength = 0
		r.TransferEncoding = nil
		r.Trailer = nil
		r.Header.Del("Content-Length")
		r.Header.Del("Transfer-Encoding")
		r.Header.Del("Expect")
	}
	if s.fallback != nil {
		s.fallback.ServeHTTP(w, r)
	} else {
		http.NotFound(w, r)
	}
}

type erpFallbackHandler struct {
	serverName string
	tmpl       *template.Template
}

func newERPFallbackHandler(serverName string) http.Handler {
	tmpl := template.Must(template.New("erp").Parse(erpHtmlTemplate))
	return &erpFallbackHandler{
		serverName: serverName,
		tmpl:       tmpl,
	}
}

type erpPageData struct {
	ServerName    string
	ClusterID     string
	TraceID       string
	RequestSyncID string
	Timestamp     string
}

func (h *erpFallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	randomBytes := make([]byte, 8)
	_, _ = rand.Read(randomBytes)
	traceID := "vg-trace-" + hex.EncodeToString(randomBytes)

	syncBytes := make([]byte, 4)
	_, _ = rand.Read(syncBytes)
	syncID := strings.ToUpper(hex.EncodeToString(syncBytes))

	clusterNum := (int(randomBytes[0]) % 8) + 1
	clusterID := fmt.Sprintf("vg-cluster-prod-0%d", clusterNum)

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") || strings.HasPrefix(r.URL.Path, "/api") || strings.HasPrefix(r.URL.Path, "/v1") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":         200,
			"status":       "UP",
			"organization": "Vanguard Global Industrial Group, Ltd.",
			"service":      "Enterprise Operations & SCM Microservices Gateway (VG-ERP-Core)",
			"vendor":       "SoftLink Information Systems Corp.",
			"version":      "4.22.0-RELEASE",
			"cluster":      clusterID,
			"trace_id":     traceID,
			"timestamp":    time.Now().Unix(),
			"path":         r.URL.Path,
		})
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	data := erpPageData{
		ServerName:    h.serverName,
		ClusterID:     clusterID,
		TraceID:       traceID,
		RequestSyncID: syncID,
		Timestamp:     time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
	}
	_ = h.tmpl.Execute(w, data)
}

const erpHtmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vanguard Global - Enterprise Resource & SCM Operations Gateway</title>
    <style>
        :root {
            --bg-dark: #0f172a;
            --card-dark: #1e293b;
            --border-dark: #334155;
            --text-light: #f8fafc;
            --text-dim: #94a3b8;
            --emerald-green: #10b981;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-dark);
            color: var(--text-light);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            padding: 28px 16px;
        }
        .container { max-width: 760px; margin: 0 auto; width: 100%; }
        .card {
            background: var(--card-dark);
            border: 1px solid var(--border-dark);
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4);
            overflow: hidden;
        }
        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--border-dark);
            padding-bottom: 16px;
            margin-bottom: 18px;
            gap: 12px;
        }
        .brand { display: flex; align-items: center; gap: 12px; min-width: 0; }
        .logo-icon {
            width: 38px;
            height: 38px;
            background: linear-gradient(135deg, #1e3a8a, #2563eb);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            color: #fff;
            font-size: 15px;
            letter-spacing: 0.5px;
            flex-shrink: 0;
            box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3);
        }
        .title { font-size: 16px; font-weight: 600; color: #ffffff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .subtitle { font-size: 12px; color: var(--text-dim); margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .badge {
            background: rgba(16, 185, 129, 0.12);
            color: var(--emerald-green);
            border: 1px solid rgba(16, 185, 129, 0.25);
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 11px;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            white-space: nowrap;
            flex-shrink: 0;
        }
        .badge-dot { width: 6px; height: 6px; background: var(--emerald-green); border-radius: 50%; display: inline-block; flex-shrink: 0; }
        .grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 12px;
            margin-bottom: 18px;
        }
        @media (max-width: 540px) {
            .grid { grid-template-columns: 1fr; }
        }
        .stat-box {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--border-dark);
            border-radius: 8px;
            padding: 12px 14px;
            min-width: 0;
        }
        .stat-label { font-size: 10px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
        .stat-val { font-size: 13px; font-weight: 600; color: #38bdf8; margin-top: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .section-title { font-size: 11px; font-weight: 600; color: var(--text-dim); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
        .subsystems-list {
            background: rgba(15, 23, 42, 0.4);
            border: 1px solid var(--border-dark);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 16px;
        }
        .subsystem-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 10px 14px;
            border-bottom: 1px solid rgba(51, 65, 85, 0.6);
            gap: 8px;
        }
        .subsystem-row:last-child {
            border-bottom: none;
        }
        .subsystem-name {
            font-size: 12px;
            font-weight: 500;
            color: #e2e8f0;
            display: flex;
            align-items: center;
            gap: 8px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            min-width: 0;
        }
        .status-badge {
            font-size: 11px;
            font-weight: 600;
            color: var(--emerald-green);
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.2);
            padding: 2px 8px;
            border-radius: 4px;
            white-space: nowrap;
            flex-shrink: 0;
        }
        .notice {
            background: rgba(37, 99, 235, 0.08);
            border-left: 3px solid #2563eb;
            padding: 12px 14px;
            border-radius: 0 6px 6px 0;
            font-size: 11px;
            color: #cbd5e1;
            line-height: 1.6;
        }
        .footer {
            text-align: center;
            font-size: 11px;
            color: var(--text-dim);
            margin-top: 20px;
            line-height: 1.8;
        }
        .footer a { color: var(--text-dim); text-decoration: none; }
        .footer-vendor { color: #64748b; font-size: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header">
                <div class="brand">
                    <div class="logo-icon">VG</div>
                    <div>
                        <div class="title">Vanguard Global Industrial &bull; Operations Hub</div>
                        <div class="subtitle">Enterprise Resource Planning & SCM Gateway v4.2</div>
                    </div>
                </div>
                <div class="badge">
                    <span class="badge-dot"></span>
                    <span>Operational</span>
                </div>
            </div>

            <div class="grid">
                <div class="stat-box">
                    <div class="stat-label">Service Status</div>
                    <div class="stat-val">RUNNING (STANDBY)</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Access Protocol</div>
                    <div class="stat-val">mTLS 1.3 / OAuth 2.0</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Production Cluster Node</div>
                    <div class="stat-val">{{.ClusterID}}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Audit Trace ID</div>
                    <div class="stat-val">{{.TraceID}}</div>
                </div>
            </div>

            <div class="section-title">Core Subsystem Operational Status</div>
            <div class="subsystems-list">
                <div class="subsystem-row">
                    <div class="subsystem-name">
                        <span class="badge-dot"></span>
                        <span>SCM Supply Chain Management Engine</span>
                    </div>
                    <span class="status-badge">Operational</span>
                </div>
                <div class="subsystem-row">
                    <div class="subsystem-name">
                        <span class="badge-dot"></span>
                        <span>CRM Client Relations & Billing Portal</span>
                    </div>
                    <span class="status-badge">Operational</span>
                </div>
                <div class="subsystem-row">
                    <div class="subsystem-name">
                        <span class="badge-dot"></span>
                        <span>FIN General Ledger & Settlement Hub</span>
                    </div>
                    <span class="status-badge">Operational</span>
                </div>
                <div class="subsystem-row">
                    <div class="subsystem-name">
                        <span class="badge-dot"></span>
                        <span>WMS Smart Warehousing & Logistics</span>
                    </div>
                    <span class="status-badge">Operational</span>
                </div>
            </div>

            <div class="notice">
                <strong>Corporate Security Policy</strong>: This access gateway serves as an internal API endpoint for Vanguard Global production services. Access is restricted to authorized corporate networks and authenticated microservices with valid TLS client credentials or access tokens.
            </div>
        </div>

        <div class="footer">
            <div>&copy; 2024-2026 Vanguard Global Industrial Group, Ltd. All rights reserved.</div>
            <div class="footer-vendor">Infrastructure & Systems Management powered by <strong>SoftLink Information Systems Corp.</strong> &bull; Node Sync ID: {{.RequestSyncID}}</div>
        </div>
    </div>
</body>
</html>
`

type flushWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func newFlushWriter(w http.ResponseWriter) flushWriter {
	flusher, _ := w.(http.Flusher)
	return flushWriter{w: w, flusher: flusher}
}

func (w flushWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if w.flusher != nil {
		w.flusher.Flush()
	}
	return n, err
}
