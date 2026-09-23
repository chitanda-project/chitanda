# 多用户实现审计与验收状态

基线：`main` 2dbb63f；送审：`dev` 5c9bf07。该审计仅覆盖本仓库 SDK、Xray 注入适配与配置构建；不代表 3X-UI 适配、线上部署或抗封锁效果验收。

## 已发现并修正

- 独立 `StreamServer.AttachUDP` 在多用户模式仍用空的旧版单密钥，可能以空密钥创建可转发的 UDP 服务。改为按用户构造编解码器，并按 `(userIndex, sessionID)` 隔离会话与回包；新增双用户同会话号、空密钥拒绝的实际 UDP 回环回归。
- 原构造函数会静默忽略无效密钥，直接 Protobuf 配置也可绕过 JSON 校验。现在拒绝空/短/重复密钥、重复身份、空多用户身份、混用顶层 `psk` 与 `users`、超出 128 用户，并复制调用方密钥。
- 原 Xray UDP replay registry 扩容会复制包含锁的结构体。改为构造时定长初始化；恢复请求上下文中 `ExcludeForDomain` 切片的复制，避免多流共享可变数据。
- 全栈 Xray 实测发现：原生 UDP 包级认证用户被连接级入站上下文覆盖，TCP 正常但 UDP 不记入用户计数器。现调整路由上下文的值优先级，保持连接生命周期的同时优先使用已认证包级身份；回归检查两个用户的 TCP 与 UDP 上下行精确归账。
- 新增 Xray 策略和 Stats 计数器回归；用户计数仍依赖对应 `Level` 启用 `statsUserUplink`/`statsUserDownlink`。

## 已运行的门禁

- `go test -mod=mod ./internal/... ./pkg/... -count=1 -timeout=180s`：通过；dev 专用 Linux Actions 在 ad77d01 上的 SDK 与注入 Xray `-race`、构建工作流均通过（[运行记录](https://github.com/chitanda-project/chitanda/actions/runs/35828583289)）。
- 注入 Xray 后 `go test -mod=mod ./proxy/chitanda -count=1 -timeout=180s`：通过；新增真实 H3/auto 双用户分别连通及同一入站并发身份测试，针对并发测试本地重复运行 10 次通过。
- 真实 Xray JSON 入站 + Freedom 出站 + Policy/Stats 全栈回环：两个用户的 Stream TCP 与原生 UDP 上下行计数精确归属，本地重复运行 10 次通过。
- `go test -mod=mod ./infra/conf -run Chitanda -count=1 -timeout=120s`：通过。
- `go vet`（SDK、Xray 适配与配置包）及 `go build -mod=mod ./main`（注入 Xray）：通过。
- 全量 `./infra/conf` 有非 Chitanda 用例 `TestToCidrList` 因验证副本缺少 `geoip.dat` 失败；不能记为全量通过。
- 仓库根目录的 `go test ./...` 不适用于当前注入式集成布局：`integration/xray`、`integration/mihomo*` 依赖各自上游源码中的类型；应以 SDK 测试和注入后的上游包测试作为门禁。

## 尚未通过的合入门禁

1. 原实现的 30 用户最坏位置基准在 Windows/amd64、Hygon C86-3G 为 **56.7 µs/op、385 allocs/op**。服务端改为启动时预计算每个用户的掩码后，生产路径基准为 **19.8 µs/op、145 allocs/op**，达到本机 `<25 µs` 目标；仍需在目标 Linux/ARM 与指定负载下复测，不能将本机数据当成线上性能保证。
2. `auto` 同端口的 H3/Plain-UDP 混合识别仍是明确性能阻断项：非 Plain-UDP 的 1200B 报文按 1/30/128 用户试解密，在本机 Windows/Hygon 分别约 **1.5/45/215 µs/包**（`BenchmarkDecodePacketMultiMiss`）。现有 `TestH3AndPlainUDPDemuxing` 明确覆盖同端口混合行为；绕过试解密会改变这一兼容性。需决定是保留混合并做有状态、可靠的 QUIC 分类，还是将 H2/H3/auto 限定为 H3 UDP 并明确迁移规则。未经选择不能用“直接跳过 Plain-UDP”冒充无损优化。
3. 目标环境真实 TCP/UDP 吞吐、尾延迟与单/多用户抓包差异未测。本机微基准不能代替目标机器压测或抗封锁结论。

结论：**未验收，不应合入 `main`**。功能与安全修复先保留在 `dev`；先确定同端口 H3/Plain-UDP 混合兼容与速度的取舍，再完成相应实现和目标环境性能门禁。
