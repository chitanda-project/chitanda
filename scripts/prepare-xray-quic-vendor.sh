#!/bin/sh
# Run in the injected Xray module. Go builds must then use -mod=vendor.
set -eu

core_dir=${1:?usage: prepare-xray-quic-vendor.sh /path/to/chitanda}
core_dir=$(cd "$core_dir" && pwd)
test -f go.mod
test -f "$core_dir/scripts/vendor-performance.patch"
test -f "$core_dir/scripts/patch-vendor.go"

go mod tidy
quic_version=$(go list -m -f '{{.Version}}{{if .Replace}} replaced{{end}}' github.com/quic-go/quic-go)
net_version=$(go list -m -f '{{.Version}}{{if .Replace}} replaced{{end}}' golang.org/x/net)
test "$quic_version" = 'v0.61.0' || {
    echo "unsupported quic-go resolution: $quic_version" >&2
    exit 1
}
test "$net_version" = 'v0.56.0' || {
    echo "unsupported x/net resolution: $net_version" >&2
    exit 1
}

go mod vendor
queue=vendor/github.com/quic-go/quic-go/datagram_queue.go
flow=vendor/golang.org/x/net/http2/transport.go
test "$(grep -c 'maxDatagramSendQueueLen = 32' "$queue")" -eq 1
test "$(grep -c 'maxDatagramRcvQueueLen  = 128' "$queue")" -eq 1
test "$(grep -c 'transportDefaultStreamFlow = 4 << 20' "$flow")" -eq 1
sed -i 's/maxDatagramSendQueueLen = 32/maxDatagramSendQueueLen = 8192/' "$queue"
sed -i 's/maxDatagramRcvQueueLen  = 128/maxDatagramRcvQueueLen  = 2048/' "$queue"
sed -i 's/transportDefaultStreamFlow = 4 << 20/transportDefaultStreamFlow = 64 << 20/' "$flow"

go run "$core_dir/scripts/patch-vendor.go" --quic-only
git apply --check --include='vendor/github.com/quic-go/quic-go/*' "$core_dir/scripts/vendor-performance.patch"
git apply --include='vendor/github.com/quic-go/quic-go/*' "$core_dir/scripts/vendor-performance.patch"

# The historical Xray workflow patched the global module cache. If that cache
# is already patched, go mod vendor copies the complete H2 change. Otherwise
# apply it to this build's vendor tree; never mutate the shared module cache.
if grep -q 'MaxDataPadding int' vendor/golang.org/x/net/http2/transport_common.go; then
    test "$(grep -c 'MaxDataPadding int' vendor/golang.org/x/net/http2/transport_common.go)" -eq 1
    test "$(grep -c 'WriteDataPadded(cs.ID, sentEnd, data, pad)' "$flow")" -eq 1
else
    go run "$core_dir/scripts/patch-vendor.go" --xnet-only
    git apply --check --include='vendor/golang.org/x/net/*' "$core_dir/scripts/vendor-performance.patch"
    git apply --include='vendor/golang.org/x/net/*' "$core_dir/scripts/vendor-performance.patch"
fi

# Verify the high-BDP performance parameters required for 200M+ zero-loss UDP
sender=vendor/github.com/quic-go/quic-go/internal/congestion/cubic_sender.go
test "$(grep -c 'minCongestionWindowPackets = 1536' "$sender")" -eq 1
test "$(grep -c 'initialCongestionWindow    = 4096' "$sender")" -eq 1
test "$(grep -c 'maxDatagramSendQueueLen = 8192' "$queue")" -eq 1
test "$(grep -c 'MaxDataPadding int' vendor/golang.org/x/net/http2/transport_common.go)" -eq 1

cp "$core_dir/scripts/vendor-tests/datagram_queue_test.go.txt" vendor/github.com/quic-go/quic-go/datagram_queue_test.go
cp "$core_dir/scripts/vendor-tests/send_conn_batch_linux_test.go.txt" vendor/github.com/quic-go/quic-go/send_conn_batch_linux_test.go
cp "$core_dir/scripts/vendor-tests/http3_state_tracking_stream_test.go.txt" vendor/github.com/quic-go/quic-go/http3/state_tracking_stream_lazy_test.go
go test -mod=vendor github.com/quic-go/quic-go github.com/quic-go/quic-go/http3 golang.org/x/net/http2
echo 'Xray root vendor uses verified Chitanda QUIC and H2 patches'
