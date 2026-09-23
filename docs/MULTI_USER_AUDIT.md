# 多用户实现审计与验收状态

基线：`main` 2dbb63f；送审：`dev` 5c9bf07。该审计仅覆盖本仓库 SDK、Xray 注入适配与配置构建；不代表 3X-UI 适配、线上部署或抗封锁效果验收。

## 已发现并修正

- 原 Xray UDP replay registry 扩容会复制包含锁的结构体，改为构造时定长初始化；修正请求上下文中切片复制，对 `OverrideDestinationForProtocol` 字符串切片进行防御性拷贝，并移除了此前对 `ExcludeForDomain` 的切片操作（在 CI 固定的 Xray v1.260327.0 中其为 `[]string`，但在较新 Xray 上游如 main 中已重构为 `geodata.DomainMatcher` 接口；移除独立的 append 并直接沿用 `previous.SniffingRequest` 浅拷贝，兼顾了旧版切片与新版接口的跨版本兼容）。
- 全栈 Xray 实测发现：原生 UDP 包级认证用户被连接级入站上下文覆盖，TCP 正常但 UDP 不记入用户计数器。现调整路由上下文的值优先级，保持连接生命周期的同时优先使用已认证包级身份；回归检查两个用户的 TCP 与 UDP 上下行精确归账。
- 新增 Xray 策略和 Stats 计数器回归；用户计数仍依赖对应 `Level` 启用 `statsUserUplink`/`statsUserDownlink`。
- **解耦 UDP 路径以消除试解密开销（方案 A 落地）**：用户确认生产部署（如 3X-UI / Xray 标准实践）中各入站端口均有独立确定的协议与 Transport，无需在同端口混跑 Stream 与 H3 UDP。因此在 `integration/xray/inbound.go` 中完成路径分立：
  - `h2`、`h3` 与 `auto` 入站：UDP 路径专供 HTTP/3 (QUIC Datagrams)，收到 UDP 报文直接投递 `vconn`，**Plain-UDP 试解密开销彻底归零（0 µs）**，完全解除了多用户下的 UDP 性能阻断项；
  - `stream`、`h1` 与 `plain-h1` 入站：UDP 路径专供 Native Plain-UDP，仅在此类入站中初始化 `userCodecs` 并按包级多用户解密路由；
  - `TestH3AndPlainUDPDemuxing` 使用真实的 `auto` 与 `stream` 实例断言底层状态，发送合法未改坏的 Plain-UDP 密文以因果序（FIFO Causal Flush）严格断言不会发生试解密与串账，杜绝任意 `50ms` 盲等；
  - `virtualPacketConn` 将生产收包路径的统计操作改为仅供测试的钩子函数 `onFeed`（生产环境为 `nil` 零开销），彻底规避每包原子增量的吞吐损耗。

## 已运行的门禁

- `go test -mod=mod ./internal/... ./pkg/... -count=1 -timeout=180s`：通过；dev 专用 Linux Actions 在 ad77d01 上的 SDK 与注入 Xray `-race`、构建工作流均通过（[运行记录](https://github.com/chitanda-project/chitanda/actions/runs/35828583289)）。
- 注入 Xray 后 `go test -mod=mod ./proxy/chitanda -count=1 -timeout=180s`：通过（40+ 项测试全绿）；新增真实 H3/auto 双用户分别连通及同一入站并发身份测试、分 Transport UDP 路由回归测试。
- 真实 Xray JSON 入站 + Freedom 出站 + Policy/Stats 全栈回环：两个用户的 Stream TCP 与原生 UDP 上下行计数精确归属，本地重复运行 10 次通过。
- `go test -mod=mod ./infra/conf -run Chitanda -count=1 -timeout=120s`：通过。
- `go vet`（SDK、Xray 适配与配置包）及 `go build -mod=mod ./main`（注入 Xray）：通过。
- 全量 `./infra/conf` 有非 Chitanda 用例 `TestToCidrList` 因验证副本缺少 `geoip.dat` 失败；不能记为全量通过。
- 仓库根目录的 `go test ./...` 不适用于当前注入式集成布局：`integration/xray`、`integration/mihomo*` 依赖各自上游源码中的类型；应以 SDK 测试和注入后的上游包测试作为门禁。

## 尚未通过的合入门禁（合并前必须完成的线下/目标机测试）

1. 原实现的 30 用户最坏位置基准在 Windows/amd64、Hygon C86-3G 为 **56.7 µs/op、385 allocs/op**。服务端改为启动时预计算每个用户的掩码后，生产路径基准为 **19.8 µs/op、145 allocs/op**，达到本机 `<25 µs` 目标；仍需在目标 Linux/ARM 与指定负载下复测，不能将本机数据当成线上性能保证。
2. 目标环境真实 TCP/UDP 吞吐、尾延迟与单/多用户抓包差异未测。本机微基准不能代替目标机器压测或抗封锁结论。

结论：**未线上验收，严格保留在 `dev` 分支，绝不私自合入 `main`**。所有核心功能、安全性修复与性能优化已在 `dev` 完成并全绿通过单元/集成门禁，待目标生产环境完成线上压测与环境验收后，再由用户主导评估是否合并。
