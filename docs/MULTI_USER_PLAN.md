# Chitanda (MyXray) 多用户无特征平滑演进开发方案

本文档定义了 Chitanda 协议在维持**现有零特征、防审查、高熵离散握手**的前提下，引入服务端多用户识别与 Xray / 3X-UI 流量统计集成的完整技术方案与开发实施路线。

---

## 1. 核心目标与原则

1. **绝对防审查（Zero Fingerprint Regressions）**：
   - 坚决不在握手包明文中引入静态 `UUID`、明文账号或易被关联的时空重复令牌。
   - 无论是 `stream` 模式还是 HTTP 模式，每个连接在外部 DPI/GFW 视界中依然保持 **100% 单次真随机离散、高熵白噪声（香农熵 > 7.99）**。
2. **零客户端负担与全向后兼容（Zero Client Disruption）**：
   - 现有已发版的客户端（Chitanda Verge、Chitanda CMFA、Chitanda OpenClash）**不需要修改一行代码，老版本全线无感兼容**。
   - 单用户场景完全沿用经典快速通道（Fast Path），纳秒级开销保持与当前完全一致。
3. **原生无缝融入 Xray & 3X-UI 生态**：
   - 在 Xray 内部打通用户上下文绑定，使 3X-UI 具备多用户凭证管理、单独流量计费、到期限制与可视化能力。

---

## 2. Xray 中 Email 的核心定位与规范

> [!IMPORTANT]
> **关于 Xray 必须要有 Email 的解答：**
> **是的，Xray 的流量统计与多用户系统强依赖 `Email` 作为唯一用户主键。**

- **Xray 内部机制**：
  Xray 的统计引擎（`features/stats`）为每个用户创建的上行和下行流量计数器格式严格为：
  - `user>>>${email}>>>traffic>>>uplink`
  - `user>>>${email}>>>traffic>>>downlink`
- **为什么必须提供？**
  如果配置中的 `Email` 为空（`""`），Xray 将**跳过流量计数器的注册**，导致该用户无论产生多少网络传输，在 3X-UI 或统计 API 中都无法被计量。
- **命名规范**：
  `Email` 在 Xray 里本质上是一个**用户唯一标识符字符串**，不强制要求是真实的互联网邮箱格式（例如 `alice`、`user_001` 或 `bob@chitanda.org` 均可），3X-UI 面板默认使用邮箱命名法进行展示。

---

## 3. 技术方案设计：服务端内存轻量试算匹配 (Trial Verification)

### 3.1 握手与网络 I/O 零重读机制

以最苛刻的非 TLS 传输 `stream`（RawStream）为例，握手流程设计如下：

```text
客户端 (任意已发布版本)                   服务端 (Xray Inbound / chitanda-server)
      │                                                │
      ├─────── 49~113 字节纯随机 ClientHello ────────►│
      │                                                ├─► 1. 从 TCP 仅读取 1 次：49 字节到内存 Buffer
      │                                                │
      │                                                ├─► 2. 单用户配置检测：
      │                                                │      若仅配单 PSK ──► 走原有 Fast Path 验签
      │                                                │
      │                                                ├─► 3. 多用户配置检测 (方案一)：
      │                                                │      在纯内存中遍历 Users 列表逐个快速 HMAC：
      │                                                │      for _, user := range Users {
      │                                                │          if Verify(user.PSK, memoryBuffer) {
      │                                                │              matchedUser = user
      │                                                │              break
      │                                                │          }
      │                                                │      }
      │                                                │
      │                                                ├─► [命中某用户]：
      │                                                │   - 绑定 session.Inbound.User = MemoryUser(user.Email)
      │                                                │   - 挂载 Xray 上下文，启动流量统计
      │                                                │   - 若 padLen > 0，读取剩余填充，握手完成并建流
      │                                                │
      │                                                └─► [均未命中 (GFW扫描/未授权试探)]：
      │                                                    - 直接 0 字节 RST 关闭连接 (无主动探测暴露)
```

### 3.2 HTTP 传输族 (`h2` / `h3` / `auto` / `h1`) 的多用户零 I/O 试算机制

在 HTTP 传输族下，Chitanda 的多用户实现比 `stream` **更为轻量且具备天然的零 I/O 开销优势**，因为 HTTP 协议栈在应用层早已将完整的 HTTP 请求头解析至内存结构体（`http.Request`）中。

#### 3.2.1 握手与认证时序图

```text
客户端 (Chitanda Verge / CMFA)               服务端 (HTTP/2 / HTTP/3 / HTTP/1.1)
      │                                                │
      ├─────── TLS 1.3 / QUIC 握手建连 (仅对外暴露 SNI) ──────►│ (DPI 仅看到常规网站 TLS 握手)
      │                                                │
      ├─────── HTTP POST /<path> ─────────────────────►│
      │        Headers:                                │
      │          X-Session-Target: 目标地址             ├─► 1. 协议栈解析 Header 至内存 (零额外网络 I/O)
      │          X-Session-Time:   时间戳               │
      │          X-Session-Nonce:  16B 随机串           ├─► 2. 单用户检测：
      │          X-Session-Auth:   HMAC-SHA256 签名     │      若仅配单 PSK ──► 走原有 Fast Path 验签
      │                                                │
      │                                                ├─► 3. 多用户检测：
      │                                                │      在内存中遍历 Users 列表逐个快速 HMAC：
      │                                                │      for _, user := range s.users {
      │                                                │          if auth.Verify(user.PSK, ..., signature) {
      │                                                │              matchedUser = user
      │                                                │              break
      │                                                │          }
      │                                                │      }
      │                                                │
      │                                                ├─► [命中某用户]：
      │                                                │   - 防重放检验：s.replays.Accept(nonce)
      │                                                │   - 绑定 session.Inbound.User = MemoryUser(user.Email)
      │                                                │   - 挂载 Xray 上下文，启动双向流量统计与数据转发
      │                                                │
      │                                                └─► [均未命中 (扫描器/爬虫/普通访客)]：
      │                                                    - 静默回退至 443 伪装站点 (s.serveFallback)
      │                                                    - 返回正常网站 HTML 页面 (Zero Active-Probe Oracle)
```

#### 3.2.2 四种 HTTP 模式的具体运作特性

1. **`h2` (HTTP/2 over TLS 1.3)**：
   - 全程在 TLS 1.3 内运行，HTTP 标头与载荷全部受 HPACK 压缩并加密，外部 DPI 完全不可见。
   - 服务端直接在 `ServeHTTP` 中完成多用户内存验签（耗时 $< 15 \mu s$）。
   - 验证失败时静默反代 Fallback 伪装站，防探测防封锁。

2. **`h3` (HTTP/3 over QUIC)**：
   - 报文封装在 UDP/QUIC 报文中，由 `quic-go/http3` 接收入口。
   - 握手通过 QPACK 压缩传递 Headers，服务端内存解出请求后，进入相同的 `s.authorize()` 多用户试算。
   - 失败同样触发 Fallback，成功则绑定 `Email` 进行双向流控计费。

3. **`auto` (H2 / H3 自动协商)**：
   - 客户端依据网络环境自动选择 H2 或 H3（例如先 H2 握手并利用 `Alt-Svc` 协商升迁 H3，或双路测速）。
   - 服务端底层同时开启 H2（TCP）和 H3（UDP），**共享同一套 `users` 内存用户池**。
   - 无论客户端最终走 H2 还是切换至 H3，用户身份与流量均精确归属至统一的 `Email` 统计槽，无缝跨传输漫游。

4. **`h1` (plain-h1 / HTTP/1.1)**：
   - 用于免 TLS 裸流或低性能边缘转发环境。
   - 握手不走 HTTP 认证标头，而是以 FullDuplex 模式在 `r.Body` 中以 `io.ReadFull` 读取 48 字节加密 `ClientHello`，调用 `h1session.MatchClientHello` 在内存中试算匹配各用户 PSK。
   - 匹配成功后，提取该用户的 PSK 派生 0-RTT/1-RTT 会话密钥并回发 `ServerHello`，绑定该用户的 `Email` 身份并开始流式转发。

---

### 3.3 Native Plain-UDP (Xray Inbound 原生 UDP 多用户隔离)

在 Xray Inbound 环境下，UDP 传输由 `inbound.go:handleUDP` 与 `udpRoutes`（`udp_routes.go`）接管，并非独立的 `PlainUDPServer`：

- **数据报线格式**：`[24B Random Nonce] + [XChaCha20-Poly1305 Ciphertext (含 Poly1305 Tag)]`。
- **多用户内存试算与隔离流程**：
  1. 收到 UDP 数据报后，提取前 24 字节 Nonce。
  2. 纯内存中循环调用各用户的 `userCodec.DecodeClientPacket(data, now)` 进行解密试算。
  3. 解密验签成功即定位出 `matchedUser`。
  4. **路由键与重放隔离**：
     - 将路由键扩展为 `udpRouteKey{ userIndex, session, target }`，杜绝不同用户的随机 Session ID 发生冲突碰撞。
     - 防重放窗口（`udpReplays`）按用户隔离，避免恶意/重放报文跨用户污染防重放状态。
     - 路由条目内锁定该用户专属的编解码器，回包（Server to Client）严格使用该用户的 `s2cKey` 加密。
  5. 派生绑有该用户 `protocol.MemoryUser` 的 `packetCtx` 分发至 Xray Dispatcher 进行独立流量统计。
  6. 若遍历全量用户均解密失败（GFW 随机嗅探或未授权试探）：**直接静默丢弃（Silent Drop）**，绝不返回 ICMP Port Unreachable，确保端口不可见性。

---

### 3.4 5 种流控传输模式的处理一致性全景对比

| 传输模式 | 底层载体 | 服务端匹配机制 | 匹配成功行为 | 匹配失败行为 (抗探测) |
| :--- | :--- | :--- | :--- | :--- |
| **`stream`** *(RawStream)* | 裸 TCP | `io.ReadFull` 读 49B 头部，内存比对 `expectedFullTag` | 读剩余 padLen，派生密钥并建流计费 | 0 字节 RST 关闭连接 |
| **`h2`** *(HTTP/2)* | TLS 1.3 | 纯内存对 `X-Session-Auth` 与各用户 PSK 计算 HMAC | 派生独立请求上下文，绑定 `Email` 计费 | 静默 Fallback 到伪装网站 |
| **`h3`** *(HTTP/3)* | QUIC/UDP | 纯内存对 `X-Session-Auth` 与各用户 PSK 计算 HMAC | 派生独立请求上下文，绑定 `Email` 计费 | 静默 Fallback 到伪装网站 |
| **`auto`** | H2/H3 双栈 | 依实际到达协议栈共享 `users` 内存用户池进行匹配 | 派生独立请求上下文，统一流量计费 | 对应分支自动 Fallback |
| **`h1`** *(plain-h1)* | 裸 HTTP/1.1 | `io.ReadFull` 读 48B Body，`h1session` 试算匹配 | 派生 0-RTT/1-RTT 密钥，绑定计费 | Fallback 或返回 404/400 假页面 |
| **`Plain-UDP`** | 裸 UDP | 纯内存循环各用户 XChaCha20-Poly1305 解密试算 | 建立按用户隔离的路由，绑定计费 | 静默丢弃 (Silent Drop) |



---

## 4. 性能与安全性边界论证

### 4.1 CPU 试算耗时与可扩展性（Falsifiable Benchmark Target）

在现代服务器 CPU（支持 Intel SHA-NI 或 ARMv8 Cryptography 硬件扩展）上，单次 SHA-256 / HMAC 计算 32~64 字节耗时约为 **0.3 ~ 0.5 微秒**。

- **10 个用户**：全量遍历耗时约为 $3 \sim 5 \mu s$（0.003 ~ 0.005 毫秒）。
- **30 个用户**：全量遍历耗时约为 $10 \sim 15 \mu s$（0.01 毫秒）。
- **50 个用户**：全量遍历耗时约为 $15 \sim 25 \mu s$（0.025 毫秒）。

与公网典型 RTT（50 ~ 150 毫秒）相比，**几十微秒的计算延迟在物理上完全无法被用户和网络监测所察觉**。

### 4.2 抗时序攻击设计（Timing Attack Defense）
为了防止未授权攻击者通过高精度网络时延推测服务端用户库大小：
- 当连接未命中任何用户时，系统执行固定常数级循环（或微秒级随机抖动填充），确保所有非法试探请求的握手响应耗时完全平坦。

### 4.3 抗 GFW 审查威胁模型与零指纹保证（GFW Threat Model & Zero Fingerprint Guarantee）

多用户架构的引入**100% 不会破坏原有协议的抗 GFW 与防封锁能力**，具体从三个维度进行形式化验证：

1. **线缆特征零变化（Zero Wire-Format Delta）**：
   - 客户端行为与握手报文 0 改动。客户端继续使用自身的 PSK 构造动态高熵报文。
   - 握手载荷中**坚决不引入任何明文 UUID、用户 ID 或固定特征前缀**。外部 DPI 抓包看到的每个连接，在物理层面上依然与单用户版本 100% 完全相同（香农熵 > 7.99 或合规 TLS 1.3 密文）。
2. **主动探测抗性零削弱（Active Probing Resistance）**：
   - GFW 扫描器或未授权试探者发起的握手包，在遍历所有用户 PSK 后均无法匹配。
   - **`h2` / `h3` / `auto`**：统一静默回退至真实 443 伪装站点，返回合规 HTTP 页面，无任何主动探测判定依据（Zero Oracle）。
   - **`stream`**：立即触发 0 字节 RST 关闭连接，绝不回发任何应用层数据。
   - **`Plain-UDP`**：立即静默丢弃（Silent Drop），绝不返回 ICMP 端口不可达报文。
3. **流控模式分层防审查边界（Operational Boundaries）**：
   - **`h2` / `h3` / `auto`**：主力防封锁模式，强依托正规 TLS 1.3 / QUIC 隧道，公网抗审查能力最强。
   - **`stream` / `Plain-UDP`**：保持白噪声无特征设计，专为 IPLC / IEPL 专线及高品质中转优化（多用户方案未增加任何审查风险，但裸流在公网仍具固有熵阻断边界）。
   - **`h1` (plain-h1)**：因缺乏外层 TLS 保护，明文 Header 不具备公网抗审查能力，架构上严格限定其仅用于本地反向代理与受控内网中转。

### 4.4 网络运维与宿主机防火墙兼容性（UFW / iptables Zero-Impact Guarantee）

多用户架构对服务器宿主机的网络环境与防火墙管理**完全透明、零影响**：

1. **单端口多路复用（Single-Port Multiplexing）**：
   - 所有已配置用户（无论 1 人还是 100 人）**严格共享同一个 Inbound 入站端口**（如 443 或自定义端口）。
   - 服务端仅在应用层内存中根据各自的密钥分流用户与统计流量，绝不使用“一用户一端口”的落后做法。
2. **防火墙规则零改动（Zero Firewall Mutation）**：
   - Linux 宿主机上的 **UFW**、`firewalld`、`iptables` 或 `nftables` 规则保持与单用户完全一致。
   - 运维人员与面板**无需在防火墙上放行任何额外端口**，不增加任何公网攻击暴露面。

---

## 5. 配置协议定义与兼容升级规范

### 5.1 Protobuf 扩展 (`integration/xray/config.proto`)

```protobuf
syntax = "proto3";

package xray.proxy.chitanda;
option go_package = "github.com/xtls/xray-core/proxy/chitanda";

message User {
  string email = 1;
  string psk = 2;
  int32 level = 3;
}

message InboundConfig {
  string psk = 1;              // 经典单用户兼容字段
  repeated User users = 10;    // 多用户支持字段
  string path = 2;
  string fallback = 3;
  string strict_sni = 4;
  string transport = 5;
  string server_id = 6;
  string replay_file = 7;
  string cert_file = 8;
  string key_file = 9;
}
```

### 5.2 Xray JSON 配置示例 (`config.json`)

#### 单用户兼容形态（原汁原味）：
```json
{
  "inbounds": [
    {
      "port": 11322,
      "protocol": "chitanda",
      "settings": {
        "psk": "0123456789abcdef0123456789abcdef",
        "transport": "stream"
      }
    }
  ]
}
```

#### 多用户统计形态（激活方案一）：
```json
{
  "inbounds": [
    {
      "port": 11322,
      "protocol": "chitanda",
      "settings": {
        "transport": "stream",
        "users": [
          { "email": "alice@chitanda.org", "psk": "0123456789abcdef0123456789abcdef" },
          { "email": "bob@chitanda.org",   "psk": "fedcba9876543210fedcba9876543210" }
        ]
      }
    }
  ]
}
```

---

## 6. 开发实施清单 (Implementation Checklist)

- [ ] **Phase 1: 底层协议库多用户试算改造 (涵盖全套 5 种流控)**
  - **HTTP 传输族 (`h2` / `h3` / `auto` / `h1`)**：
    - 在 [`pkg/server/server.go`](file:///d:/myprojetct/my_xray/pkg/server/server.go) 中将配置扩展为 `Users []UserKey`（含 `Email` 与 `PSK`），改造 `authorize()` 方法，实现纯内存快速 HMAC 试算匹配，并在单用户时无缝走 Fast Path。
  - **`stream` 传输模式 (RawStream)**：
    - 在 [`internal/rawstream`](file:///d:/myprojetct/my_xray/internal/rawstream) 中新增 `MatchPolymorphicClientHello(header, users)` 函数，单次网络读取 49 字节后纯内存逐个比对。
    - 在 [`pkg/server/stream_server.go`](file:///d:/myprojetct/my_xray/pkg/server/stream_server.go) 中接管多用户会话生命周期与用户绑定。
  - **`Plain-UDP` (Stream 伴生 UDP 传输)**：
    - 在 [`internal/plainudp/plainudp.go`](file:///d:/myprojetct/my_xray/internal/plainudp/plainudp.go) 与 [`pkg/server/plain_udp.go`](file:///d:/myprojetct/my_xray/pkg/server/plain_udp.go) 中改造 Worker 数据报解码，支持多用户 AEAD 解密试算匹配与静默丢弃。
- [ ] **Phase 2: Xray 集成层与全模式流量计费绑定**
  - 更新 [`integration/xray/config.proto`](file:///d:/myprojetct/my_xray/integration/xray/config.proto) 与 [`integration/xray_conf/chitanda.go`](file:///d:/myprojetct/my_xray/integration/xray_conf/chitanda.go)，支持解析 `users` 数组并校验各用户 Email 非空及 PSK 长度（>=32 字节）。
  - 在 [`integration/xray/inbound.go`](file:///d:/myprojetct/my_xray/integration/xray/inbound.go) 中，统一将 `users` 下发给 HTTP 服务端、RawStream 服务端和 PlainUDP 服务端，并在所有 5 种传输模式握手成功后，统一挂载 `session.Inbound.User = &protocol.MemoryUser{Email: matchedUser.Email}`，打通 Xray 统计管理器。
- [ ] **Phase 3: 自动化回归测试与性能基准**
  - 编写多用户并发回归测试：针对 `h2`, `h3`, `stream`, `auto`, `h1` 分别验证不同用户并发请求时各自的流量独立计费。
  - 编写未授权嗅探与防探测回归：验证 `stream` 下非法请求返回 0 字节 RST，HTTP 族非法请求静默触发 Fallback 网页。
- [ ] **Phase 4: 3X-UI 面板适配**
  - 更新 3X-UI 的 Inbound 模板，支持在 `chitanda` 协议下动态添加、删除用户，绑定 `email` 与一键生成 `psk`。

