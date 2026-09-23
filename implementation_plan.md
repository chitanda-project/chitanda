# Chitanda 协议多用户服务端开发计划 (v2 修订版)

> 状态（审计中）：以下 Proposed Changes 保留原始施工计划，并非已验收事实。当前代码已覆盖多用户身份与原生 UDP；H3/auto 同一入站双用户并发身份与真实 Xray 中 Stream TCP/原生 UDP 按用户计费均已在本地回归。30 用户最坏位置握手匹配经启动时预计算优化，在 Windows/Hygon 上由约 56.7 µs 降为 19.8 µs（原目标 <25 µs）；3ed74e3 的 Linux race/构建通过，最新修复仍待重跑，目标机器性能未测。详见 `docs/MULTI_USER_AUDIT.md`。

本文档记录 Chitanda 服务端多用户识别与 Xray 按用户计费的实施设计。此次改动不更改客户端线格式；旧客户端在其 PSK 仍被服务端配置保留时可继续使用。抗审查性与性能需通过独立抓包和基准测试评估，不能由线格式不变直接推断。

本版本已完整吸纳代码审查意见，重点解决了 **H1 实现路径修正、H2/H3 连接复用请求级上下文隔离、Xray 原生 UDP 多用户隔离、Go 跨包循环依赖规避、Xray Policy 计费策略前置约束与科学验收基准**。

---

## User Review Required

> [!IMPORTANT]
> 1. **单/多用户双模自适应与配置优先级规范**：
>    - 若配置提供非空 `users` 数组，则 `users` 作为唯一用户凭证源；同时传入旧版顶层 `psk` 会报错，避免凭证优先级歧义。迁移时需把旧 PSK 加入 `users`。
>    - 若仅提供顶层 `psk` 且无 `users`，自动启用 **Fast Path** 单用户快速路径。
>    - 严禁配置中出现**重复 Email**（避免 Xray 统计计数器覆盖）与**重复 PSK**（避免试算歧义），校验将在 Protobuf 运行时与 JSON 构建层双重拦截。
> 2. **H2 / H3 连接复用防串账（Per-Request Context Decoupling）**：
>    - 禁止直接修改物理连接上的共享 `session.Inbound.User`。必须在每次 HTTP 请求完成认证后返回独立的用户身份，并在调用 Xray `dispatcher.Dispatch` 前绑定至为该逻辑流复制的独立 `requestContext`，彻底杜绝并发多路复用时的计费串账。
> 3. **Xray 原生 UDP 路径的独立多用户隔离**：
>    - Xray Inbound 的 UDP 传输不经由独立 `PlainUDPServer`，而是走内置的 `handleUDP` 与 `udpRoutes`。多用户改造必须深入改造 Xray 原生 UDP 编解码、路由键隔离（加用户维度）与回包独立加密。
> 4. **Xray 用户流量计费的 Policy 前置约束**：
>    - 根据 Xray 核心调度机制（`app/dispatcher/default.go`），流量计费严格依赖对应用户 `Level` 开启了 `Stats.UserUplink` 与 `Stats.UserDownlink`。实施中将确保默认级别（Level 0）配置契合 3X-UI 面板策略。

---

## Open Questions

上线前仍需验证真实 Linux/Xray 环境下的双用户计费、UDP 丢包与吞吐；Windows 本地自动化测试不能代替这些实测。

---

## Proposed Changes

### 1. 底层解密与协议原语层 (Low-Level Primitives: 避免 Go 导入循环)

> [!NOTE]
> `pkg/server` 已经引用了 `internal/rawstream`、`internal/h1session` 和 `internal/plainudp`。为避免 Go 循环依赖（Import Cycle），底层包**严禁引用 `pkg/server` 的 `UserKey`**。
> 底层试算函数统一接收原始密钥切片 `keys [][]byte` 并返回命中的用户下标 `matchedIndex int`，由上层映射到用户实体。

#### [MODIFY] [`internal/rawstream/frame.go`](file:///d:/myprojetct/my_xray/internal/rawstream/frame.go)
- 新增密钥集合试算函数：
  ```go
  func MatchPolymorphicClientHello(headerBuf []byte, keys [][]byte) (matchedIndex int, padLen int, nonce [16]byte, ts time.Time, err error)
  ```
- 传入 TCP 首次以 `io.ReadFull` 读取的 49 字节固定头部切片。
- 在纯内存中遍历 `keys` 依次计算 HKDF 与 HMAC Tag；匹配成功后解出 `padLen` 并返回命中的 `matchedIndex`；全量失败返回未授权错误。

#### [MODIFY] [`internal/h1session/handshake.go`](file:///d:/myprojetct/my_xray/internal/h1session)
- 新增 H1 密钥试算函数：
  ```go
  func MatchClientHello(keys [][]byte, clientHello []byte, now time.Time) (matchedIndex int, clientNonce [16]byte, ts time.Time, err error)
  ```
- 支持从 HTTP Body 中读取的 48 字节 `clientHello` 切片中，纯内存遍历验证多用户 PSK。

#### [MODIFY] [`internal/plainudp/plainudp.go`](file:///d:/myprojetct/my_xray/internal/plainudp/plainudp.go)
- 新增数据报试算解码函数：
  ```go
  func DecodePacketMulti(codecs []*Codec, data []byte, now time.Time) (matchedIndex int, sessionID uint64, targetAddr string, rawData []byte, padLen int, seq uint64, err error)
  ```
- 纯内存中依次尝试各用户的 `aead.Open()`，解密校验成功即返回对应 `matchedIndex`。

---

### 2. 核心服务端 (Core Server)

#### [MODIFY] [`pkg/server/server.go`](file:///d:/myprojetct/my_xray/pkg/server/server.go)
- 定义用户实体：`type UserKey struct { Email string; PSK []byte; Level uint32 }`。
- `Server` 结构体维护 `users []UserKey` 与预提取的 `pskList [][]byte`。
- 构造函数支持多用户初始化，并在单用户时保留 `psk` 快速路径。
- **H2 / H3 / Auto 模式改造**：
  - 改造 `authorize()` 方法：
    ```go
    func (s *Server) authorizeRequest(r *http.Request, targetAddress, timestamp, nonce, signature string) (*UserKey, error)
    ```
  - 单用户走 Fast Path；多用户在内存中循环执行 `auth.Verify(user.PSK, ...)`，命中即返回该用户的 `*UserKey`。
  - 将命中的 `*UserKey` 注入至当前请求的专属 Context（`context.WithValue(r.Context(), userCtxKey, user)`），供上层分发。
- **H1 (plain-h1) 模式改造**：
  - 修正原计划错误，不走 `authorize()` 也无需 `Hijack`。
  - 在 `servePlainH1(w, r)` 中：
    1. 使用 `io.ReadFull(r.Body, clientHello[:])` 读入 48 字节；
    2. 调用 `h1session.MatchClientHello(s.pskList, clientHello[:], now)` 试算；
    3. 匹配成功后，提取该用户的 `user.PSK` 派生 0-RTT/1-RTT 密钥与 ServerHello；
    4. 将该请求的上下文与 `user` 关联并开始数据中继。

#### [MODIFY] [`pkg/server/stream_server.go`](file:///d:/myprojetct/my_xray/pkg/server/stream_server.go)
- `StreamServer` 维护 `users []UserKey` 及 `pskList [][]byte`。
- 改造 `HandleConnContext(ctx, conn)`：
  1. 使用 `io.ReadFull(conn, headerBuf[:49])` 精确读取 49 字节；
  2. 单用户走原有快速路径，多用户调用 `rawstream.MatchPolymorphicClientHello(headerBuf[:49], s.pskList)`；
  3. 匹配成功得到 `matchedIndex` 与 `padLen`：
     - 若 `padLen > 0`，使用 `io.ReadFull(conn, padBuf[:padLen])` 吞掉填充字节；
     - 派生会话密钥，将命中的 `users[matchedIndex]` 注入会话上下文，建立流转发；
  4. 匹配失败：不写应用层响应并关闭连接；TCP 最终表现为 FIN 还是 RST 取决于套接字状态与系统实现。

---

### 3. Xray 适配层与原生 UDP 计费隔离 (Xray Inbound & Accounting)

#### [MODIFY] [`integration/xray/config.proto`](file:///d:/myprojetct/my_xray/integration/xray/config.proto) & [`integration/xray/config.pb.go`](file:///d:/myprojetct/my_xray/integration/xray/config.pb.go)
- Protobuf 定义扩充：
  ```protobuf
  message User {
    string email = 1;
    string psk = 2;
    uint32 level = 3;
  }
  message InboundConfig {
    string psk = 1;              // 兼容单用户
    repeated User users = 10;    // 多用户列表
    ...
  }
  ```

#### [MODIFY] [`integration/xray_conf/chitanda.go`](file:///d:/myprojetct/my_xray/integration/xray_conf/chitanda.go)
- 增加 `ChitandaUserConfig` 解析与校验：
  - 检查 `email != ""`、`len(psk) >= 32`；
  - 检查 `users` 内不得有重复 `email` 或重复 `psk`；
  - 若 `users` 与顶层 `psk` 同时存在，直接报错。

#### [MODIFY] [`integration/xray/inbound.go`](file:///d:/myprojetct/my_xray/integration/xray/inbound.go)
- `NewInboundHandler` 增加 Protobuf 运行时的二次全量校验（防止绕过 JSON 直接加载 PB 配置）。
- **TCP (Stream / H2 / H3 / H1) 请求级上下文绑定**：
  - 在 `dialTargetFn` 执行时，从传入的请求级 `ctx` 中提取由 `server.Server` 或 `StreamServer` 认证出的 `UserKey`；
  - 为该请求调用 `requestContext(ctx)` 派生全新的独立上下文，并在分发前绑定：
    ```go
    reqInbound := session.InboundFromContext(reqCtx)
    reqInbound.User = &protocol.MemoryUser{
        Email: matchedUser.Email,
        Level: uint32(matchedUser.Level),
    }
    ```
  - 调用 `dispatcher.Dispatch(reqCtx, dest)`，确保并发 H2/H3 连接下的各条逻辑流**完全独立计费，绝不串账**。
- **Xray 原生 UDP 多用户隔离 (`handleUDP`)**：
  - 初始化各用户的 `userCodecs []*server.PlainUDPCodec` 与对应的用户映射切片；
  - 当收到数据报时，调用多用户解密，成功后识别出 `matchedUser`；
  - `udpReplays` 防重放校验按用户隔离（避免跨用户重放窗口冲突）；
  - 将 `packetCtx` 绑定该 `matchedUser`，确保 Xray 原生 Dispatcher 对 UDP 上下行流量正确计费。

#### [MODIFY] [`integration/xray/udp_routes.go`](file:///d:/myprojetct/my_xray/integration/xray/udp_routes.go)
- 改造路由表键名：
  ```go
  type udpRouteKey struct {
      userIndex int    // 按用户隔离
      session   uint64
      target    string
  }
  ```
- 路由条目中保存该用户专属的 `codec`，确保回包（Server to Client）必须使用该用户独有的 `s2cKey` 进行加密。

---

### 4. 自动化测试与科学验收体系 (Verification & Test Suite)

#### [NEW] [`pkg/server/multi_user_test.go`](file:///d:/myprojetct/my_xray/pkg/server/multi_user_test.go)
- **H2/H3/Auto 并发多用户测试**：多客户端使用不同 PSK 并发向同一 Server 发起请求，断言 Context 中提取的用户身份与所用密钥一致，单用户配置走 Fast Path。
- **H1 模式多用户测试**：验证客户端发送真实 `clientHello`，服务端准确识别对应用户并完成 0-RTT/1-RTT 密钥协商。
- **未授权探测测试**：非法 PSK 均被无歧义回退至 Fallback 伪装站。

#### [NEW] [`internal/rawstream/multi_user_test.go`](file:///d:/myprojetct/my_xray/internal/rawstream/multi_user_test.go)
- 针对 30 个并发配置密钥的 ClientHello 试算准确率断言。
- **可观测基准测试**：
  - 编写 `BenchmarkMatchPolymorphicClientHello`：验证在 30 个用户下单次匹配耗时的基准目标为 $< 25 \mu s$。
  - 若评估握手随机性，需用足够大的跨样本字节集合与明确的统计方法；单个 49 字节样本的经验熵不可能达到 7.95 bit/byte。

#### [NEW] [`internal/plainudp/multi_user_test.go`](file:///d:/myprojetct/my_xray/internal/plainudp/multi_user_test.go)
- 验证多用户数据报试算解密，非授权数据报静默丢弃断言。

#### [NEW] [`integration/xray/multi_user_test.go`](file:///d:/myprojetct/my_xray/integration/xray/multi_user_test.go)
- 覆盖 Xray 原生 UDP 路由隔离与 TCP 多用户并发流量计数测试。

---

## Verification Plan

### Automated Tests
1. **SDK 与底层算法单元测试**：
   ```powershell
   go test -mod=mod -v -race ./internal/... ./pkg/...
   ```
2. **基准测试与熵值验证**：
   ```powershell
   go test -mod=mod -benchmem -run=^$ -bench=BenchmarkMultiUser ./internal/rawstream/... ./pkg/server/...
   ```
3. **符合规范的 Xray 适配集成测试**（按照 `.github/workflows/build-xray.yml` 官方流程）：
   ```powershell
   # 注入至 upstream_src 进行真实 Xray 核心集成回归
   python scripts/inject-xray.py upstream_src .
   cd upstream_src
   go test -race ./proxy/chitanda -count=1 -timeout 180s
   go test -race ./infra/conf -run Chitanda -count=1 -timeout 120s
   ```

### Manual Verification
- 使用带有 2 个用户（`alice@chitanda.org`、`bob@chitanda.org`）的 Xray Inbound 配置启动服务（策略开启 Level 0 上下行统计）。
- 分别用两端客户端进行测速，通过 Xray 状态接口拉取：
  - `user>>>alice@chitanda.org>>>traffic>>>uplink`
  - `user>>>bob@chitanda.org>>>traffic>>>uplink`
- 验证双端并发无干扰、无串账、计数精确匹配传输量。
