#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

git diff --check
git apply --reverse --check --whitespace=error-all scripts/vendor-performance.patch
git apply --reverse --check --whitespace=error-all scripts/vendor-deadline.patch
cmp scripts/vendor-tests/datagram_queue_test.go.txt vendor/github.com/quic-go/quic-go/datagram_queue_test.go
cmp scripts/vendor-tests/send_conn_batch_linux_test.go.txt vendor/github.com/quic-go/quic-go/send_conn_batch_linux_test.go
cmp scripts/vendor-tests/http3_state_tracking_stream_test.go.txt vendor/github.com/quic-go/quic-go/http3/state_tracking_stream_lazy_test.go

unformatted=$(gofmt -l cmd internal pkg scripts/patch-vendor.go \
  vendor/github.com/quic-go/quic-go/connection.go \
  vendor/github.com/quic-go/quic-go/datagram_queue.go \
  vendor/github.com/quic-go/quic-go/datagram_queue_test.go \
  vendor/github.com/quic-go/quic-go/http3/conn.go \
  vendor/github.com/quic-go/quic-go/http3/state_tracking_stream.go \
  vendor/github.com/quic-go/quic-go/http3/state_tracking_stream_lazy_test.go \
  vendor/github.com/quic-go/quic-go/http3/stream.go \
  vendor/github.com/quic-go/quic-go/send_conn.go \
  vendor/github.com/quic-go/quic-go/send_conn_batch_linux_test.go \
  vendor/github.com/quic-go/quic-go/send_queue.go \
  vendor/github.com/quic-go/quic-go/sys_conn_oob.go)
if [ -n "$unformatted" ]; then
  printf '%s\n' "$unformatted"
  exit 1
fi

go test -mod=vendor ./...
go test -mod=vendor github.com/quic-go/quic-go github.com/quic-go/quic-go/http3
go vet -mod=vendor ./...
go test -race -mod=vendor ./cmd/... ./pkg/... ./internal/... github.com/quic-go/quic-go github.com/quic-go/quic-go/http3

build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -mod=vendor -o "$build_dir/myxray-server" ./cmd/myxray-server
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -mod=vendor -o "$build_dir/myxray-client" ./cmd/myxray-client
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -mod=vendor -o "$build_dir/myxray-v2-client" ./cmd/myxray-v2-client
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -mod=vendor -o "$build_dir/bench-direct" ./cmd/bench-direct
