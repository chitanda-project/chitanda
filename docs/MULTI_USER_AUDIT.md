# 多用户实现审计与验收状态

基线：`main` 2dbb63f；送审：`dev` 5c9bf07。该审计仅覆盖本仓库 SDK、Xray 注入适配与配置构建；不代表 3X-UI 适配、线上部署或抗封锁效果验收。

## 已发现并修正

- 独立 `StreamServer.AttachUDP` 在多用户模式仍用空的旧版单密钥，可能以空密钥创建可转发的 UDP 服务。改为按用户构造编解码器，并按 `(userIndex, sessionID)` 隔离会话与回包；新增双用户同会话号、空密钥拒绝的实际 UDP 回环回归。
- 原构造函数会静默忽略无效密钥，直接 Protobuf 配置也可绕过 JSON 校验。现在拒绝空/短/重复密钥、重复身份、空多用户身份、混用顶层 `psk` 与 `users`、超出 128 用户，并复制调用方密钥。
- 原 Xray UDP replay registry 扩容会复制包含锁的结构体。改为构造时定长初始化；恢复请求上下文中 `ExcludeForDomain` 切片的复制，避免多流共享可变数据。
- 新增 Xray 策略和 Stats 计数器回归；用户计数仍依赖对应 `Level` 启用 `statsUserUplink`/`statsUserDownlink`。

## 已运行的门禁

- `go test -mod=mod ./internal/... ./pkg/... -count=1 -timeout=180s`：通过。
- 注入 Xray 后 `go test -mod=mod ./proxy/chitanda -count=1 -timeout=180s`：通过；新增真实 H3/auto 双密钥分别连通与身份归属测试，针对该测试的本地运行也已通过。
- `go test -mod=mod ./infra/conf -run Chitanda -count=1 -timeout=120s`：通过。
- `go vet`（SDK、Xray 适配与配置包）及 `go build -mod=mod ./main`（注入 Xray）：通过。
- 全量 `./infra/conf` 有非 Chitanda 用例 `TestToCidrList` 因验证副本缺少 `geoip.dat` 失败；不能记为全量通过。
- 仓库根目录的 `go test ./...` 不适用于当前注入式集成布局：`integration/xray`、`integration/mihomo*` 依赖各自上游源码中的类型；应以 SDK 测试和注入后的上游包测试作为门禁。

## 尚未通过的合入门禁

1. 计划的 `BenchmarkMatchPolymorphicClientHello` 30 用户最坏位置 `<25 µs`：本机 Windows/amd64、Hygon C86-3G 实测约 **56.7 µs/op、385 allocs/op**。需在目标 Linux/ARM 与指定负载下复测，并决定优化实现还是正式修订目标；不能仅删掉失败的指标。
2. H3/auto 已有两个用户分别连通的端到端回归，但**同一入站的双用户并发**与真实 Xray Policy 计费仍无完整覆盖。现有测试另覆盖通用 HTTP 身份和 Xray Stats 机制，组合风险仍在。
3. 当前 Windows 环境 `CGO_ENABLED=0`、无可用 Linux 运行环境；无法执行计划要求的 `go test -race`。需在 Linux CI 或隔离测试机对 SDK 与注入 Xray 适配运行 race 门禁。
4. 目标环境真实 TCP/UDP 吞吐、尾延迟与单/多用户抓包差异未测。尤其 `auto` 的 UDP 入站先对所有用户试算原生 UDP，再识别 QUIC，可能在高用户数下显著消耗 CPU；需压测并剖析。

结论：**未验收，不应合入 `main`**。已修正的安全问题可先保留在 `dev`；上述门禁通过后再进行 fast-forward 合入。
