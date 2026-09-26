#!/bin/sh
set -eu

go mod tidy
go mod vendor
sed -i 's/transportDefaultStreamFlow = 4 << 20/transportDefaultStreamFlow = 64 << 20/' \
  vendor/golang.org/x/net/http2/transport.go
grep -q 'transportDefaultStreamFlow = 64 << 20' vendor/golang.org/x/net/http2/transport.go
sed -i 's/maxDatagramRcvQueueLen  = 128/maxDatagramRcvQueueLen  = 2048/' \
  vendor/github.com/quic-go/quic-go/datagram_queue.go
grep -q 'maxDatagramRcvQueueLen  = 2048' vendor/github.com/quic-go/quic-go/datagram_queue.go
sed -i 's/maxDatagramSendQueueLen = 32/maxDatagramSendQueueLen = 512/' \
  vendor/github.com/quic-go/quic-go/datagram_queue.go
grep -q 'maxDatagramSendQueueLen = 512' vendor/github.com/quic-go/quic-go/datagram_queue.go
go run ./scripts/patch-vendor.go
git apply --check ./scripts/vendor-performance.patch
git apply ./scripts/vendor-performance.patch
git apply --check ./scripts/vendor-deadline.patch
git apply ./scripts/vendor-deadline.patch
cp ./scripts/vendor-tests/datagram_queue_test.go.txt \
  ./vendor/github.com/quic-go/quic-go/datagram_queue_test.go
cp ./scripts/vendor-tests/send_conn_batch_linux_test.go.txt \
  ./vendor/github.com/quic-go/quic-go/send_conn_batch_linux_test.go
cp ./scripts/vendor-tests/http3_state_tracking_stream_test.go.txt \
  ./vendor/github.com/quic-go/quic-go/http3/state_tracking_stream_lazy_test.go
gofmt -w cmd internal scripts/patch-vendor.go \
  ./vendor/github.com/quic-go/quic-go/datagram_queue_test.go \
  ./vendor/github.com/quic-go/quic-go/send_conn_batch_linux_test.go \
  ./vendor/github.com/quic-go/quic-go/http3/state_tracking_stream_lazy_test.go
go test -mod=vendor github.com/quic-go/quic-go github.com/quic-go/quic-go/http3
