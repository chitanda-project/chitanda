# Chitanda 多用户实施与验收说明

本文档描述 Chitanda 服务端多用户识别及 Xray 按用户统计的实现与待验证边界。此次变更不改变客户端线格式；这不等于不可识别，也不能保证抗封锁效果。

---

## 1. 核心目标与原则

1. **保持既有线格式**：
   - 坚决不在握手包明文中引入静态 `UUID`、明文账号或易被关联的时空重复令牌。
   - 多用户标识不以明文字段写入握手；公网可观察的 TLS/QUIC、握手时序和流量模式仍可能被识别。49 字节握手样本的经验香农熵最大仅为 log2(49)，不能宣称大于 7.99 bit/byte。
2. **零客户端负担与全向后兼容（Zero Client Disruption）**：
   - 客户端线格式不变；旧客户端仅在其原 PSK 被保留于新服务端配置时兼容。切换为 `users` 时不能同时配置顶层 `psk`。
   - 单用户仍走原有验证路径；耗时与吞吐需基准测试，不能预设为零成本。
3. **原生无缝融入 Xray & 3X-UI 生态**：
   - 在 Xray 内部绑定用户上下文和计费；3X-UI 的用户管理、到期限制与可视化属于下游适配，未由本仓库实现。

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
  如果配置中的 `Email` 为空（`""`），无法按此身份注册用户流量计数器；还必须为该用户 `Level` 启用 `statsUserUplink` 和 `statsUserDownlink` 策略。
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
      │                                                ├─► 1. 用 io.ReadFull 收集 49 字节固定头（底层可多次读取）
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
      │                                                    - 不写应用层响应并关闭连接（FIN/RST 不作保证）
```

### 3.2 HTTP 传输族 (`h2` / `h3` / `auto` / `h1`) 的多用户零 I/O 试算机制

H2/H3 的认证头由 HTTP 栈解析后在内存中试算；这不代表 HTTP/TLS 本身没有 I/O 或多用户试算没有 CPU 开销。H1 使用独立 Body 握手，不使用这些认证头。

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
      │                                                └─► [均未命中]：
      │                                                    - 按配置进入 Fallback；未配置时返回默认错误响应
      │                                                    - 回退行为不能保证消除主动探测信号
```

#### 3.2.2 四种 HTTP 模式的具体运作特性

1. **`h2` (HTTP/2 over TLS 1.3)**：
   - 在 TLS 中传送 HTTP/2；密文隐藏请求头内容，但握手、SNI、流量形态仍可观察。
   - 服务端在 `ServeHTTP` 中按配置用户数试算，耗时需按 1/30/128 用户基准实测。
   - 验证失败按配置进入 Fallback；未配置时不能声称有真实伪装站。

2. **`h3` (HTTP/3 over QUIC)**：
   - 报文封装在 UDP/QUIC 报文中，由 `quic-go/http3` 接收入口。
   - 握手通过 QPACK 压缩传递 Headers，服务端内存解出请求后，进入相同的 `s.authorize()` 多用户试算。
   - 失败进入配置的 Fallback；成功后绑定 `Email`，且只有相应 Xray 统计策略开启时才产生用户计数器。

3. **`auto` (H2 / H3 自动协商)**：
   - 客户端依据网络环境自动选择 H2 或 H3（例如先 H2 握手并利用 `Alt-Svc` 协商升迁 H3，或双路测速）。
   - 服务端底层同时开启 H2（TCP）和 H3（UDP），**共享同一套 `users` 内存用户池**。
   - 两条传输路径共享用户配置；跨路径统计归属依赖请求级身份绑定和 Xray 统计策略，仍需真实并发验收。

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
  6. 若遍历全量用户均解密失败，应用层丢弃数据报；宿主机/防火墙的 ICMP 行为及端口可见性不由此保证。

---

### 3.4 5 种流控传输模式的处理一致性全景对比

| 传输模式 | 底层载体 | 服务端匹配机制 | 匹配成功行为 | 匹配失败行为 (抗探测) |
| :--- | :--- | :--- | :--- | :--- |
| **`stream`** *(RawStream)* | 裸 TCP | `io.ReadFull` 收集 49B 头部，内存比对认证标签 | 读剩余 padLen，派生密钥并建流计费 | 不写应用层响应并关闭 |
| **`h2`** *(HTTP/2)* | TLS | 对 `X-Session-Auth` 与各用户 PSK 计算 HMAC | 独立请求上下文，按策略绑定 `Email` 计费 | 配置 Fallback 时转至后端 |
| **`h3`** *(HTTP/3)* | QUIC/UDP | 对 `X-Session-Auth` 与各用户 PSK 计算 HMAC | 独立请求上下文，按策略绑定 `Email` 计费 | 配置 Fallback 时转至后端 |
| **`auto`** | H2/H3 双栈 | 依实际到达协议栈共享 `users` 内存用户池进行匹配 | 派生独立请求上下文，统一流量计费 | 对应分支自动 Fallback |
| **`h1`** *(plain-h1)* | 裸 HTTP/1.1 | `io.ReadFull` 读 48B Body，`h1session` 试算匹配 | 派生 0-RTT/1-RTT 密钥，绑定计费 | Fallback 或返回 404/400 假页面 |
| **`Plain-UDP`** | 裸 UDP | 纯内存循环各用户 XChaCha20-Poly1305 解密试算 | 建立按用户隔离的路由，绑定计费 | 静默丢弃 (Silent Drop) |



---

## 4. 性能与安全性边界论证

### 4.1 CPU 试算耗时与可扩展性（Falsifiable Benchmark Target）

认证与解密试算的 CPU 开销随用户数增长；尤其是 `auto` 的 UDP 入口会在判断 H3 报文前尝试原生 UDP 解密。应在目标机器上分别测量 1/30/128 用户、有效密钥位于首位/末位、无效报文及 H3 流量的每包 CPU、吞吐与尾延迟。本文不预设微秒级数值或不可观测性。

### 4.2 抗时序攻击设计（Timing Attack Defense）
当前实现对无效认证尝试逐用户试算，并未实现恒定总耗时或抖动填充；认证成功的早停位置也会影响耗时。需单独做可观测性评估，不应声称具备抗时序侧信道保证。

### 4.3 抗审查威胁模型与可验证边界

多用户不增加明文用户标识，但不能据此推出抗封锁能力不变：CPU 耗时、连接关闭方式、Fallback 配置与流量形态仍可能提供区分信号。验收应包含单/多用户同配置抓包对比和主动探测实验。

1. **线缆特征零变化（Zero Wire-Format Delta）**：
   - 客户端行为与握手报文 0 改动。客户端继续使用自身的 PSK 构造动态高熵报文。
   - 握手没有新增明文 UUID 或用户 ID；客户端线格式维持原样。端到端抓包是否可区分仍需实测。
2. **主动探测抗性零削弱（Active Probing Resistance）**：
   - GFW 扫描器或未授权试探者发起的握手包，在遍历所有用户 PSK 后均无法匹配。
   - **`h2` / `h3` / `auto`**：仅在配置有效 Fallback 时转发至后端；未配置时返回默认响应，不能声称零探测信号。
   - **`stream`**：认证失败不发送应用层数据并关闭连接；FIN/RST 取决于系统状态。
   - **`Plain-UDP`**：应用层丢弃非法数据报；内核与网络设备仍可能产生 ICMP 或其他可见信号。
3. **流控模式分层防审查边界（Operational Boundaries）**：
   - **`h2` / `h3` / `auto`**：主力防封锁模式，强依托正规 TLS 1.3 / QUIC 隧道，公网抗审查能力最强。
   - **`stream` / `Plain-UDP`**：继续使用现有裸流线格式；公网仍有可观察的流量形态与阻断风险，多用户试算也可能影响时序。
   - **`h1` (plain-h1)**：因缺乏外层 TLS 保护，明文 Header 不具备公网抗审查能力，架构上严格限定其仅用于本地反向代理与受控内网中转。

### 4.4 网络运维与宿主机防火墙兼容性（UFW / iptables Zero-Impact Guarantee）

多用户架构本身不新增“一用户一端口”；实际部署仍需核对选定传输的 TCP/UDP 监听端口与防火墙规则。

1. **单端口多路复用（Single-Port Multiplexing）**：
   - 所有已配置用户（无论 1 人还是 100 人）**严格共享同一个 Inbound 入站端口**（如 443 或自定义端口）。
   - 服务端仅在应用层内存中根据各自的密钥分流用户与统计流量，绝不使用“一用户一端口”的落后做法。
2. **防火墙规则零改动（Zero Firewall Mutation）**：
   - Linux 宿主机上的 **UFW**、`firewalld`、`iptables` 或 `nftables` 规则保持与单用户完全一致。
   - 若从纯 TCP 切换到 H3/原生 UDP，仍需开放相应 UDP 端口；不能由“多用户共享端口”推断防火墙零变更。

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
  uint32 level = 3;
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

#### 多用户统计形态：
```json
{
  "policy": { "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } } },
  "stats": {},
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

- [x] **Phase 1: 底层协议库多用户试算改造 (涵盖全套 5 种流控)**
  - **HTTP 传输族 (`h2` / `h3` / `auto` / `h1`)**：
    - 在 `pkg/server/server.go` 中扩展用户配置并在 `authorize()` 中试算密钥；单用户走原有路径。
  - **`stream` 传输模式 (RawStream)**：
    - 在 `internal/rawstream` 中使用 `ReadAndMatchPolymorphicClientHello`：由 `io.ReadFull` 收集 49 字节后在内存中逐个比对。
    - 在 `pkg/server/stream_server.go` 中处理多用户会话与用户绑定。
  - **`Plain-UDP` (Stream 伴生 UDP 传输)**：
    - 在 `internal/plainudp/plainudp.go` 与 `pkg/server/plain_udp.go` 中加入多密钥试算、按用户隔离会话与回包。
- [x] **Phase 2: Xray 集成层的用户身份绑定**
  - 在 `integration/xray/config.proto` 与 `integration/xray_conf/chitanda.go` 中解析并校验用户数组。
  - 在 `integration/xray/inbound.go` 中为请求或 UDP 包绑定独立用户上下文；真正产生计数器还需 Xray Policy 与 Stats 配置。
- [ ] **Phase 3: 自动化回归测试与性能基准**
  - 现有回归覆盖 HTTP 请求级身份、H1、Stream、原生 UDP、H3/auto 同一入站双用户并发身份，以及真实 Xray 中 Stream TCP/原生 UDP 的按用户计费；目标机器性能与线上效果仍待验证。
  - 编写未授权探测回归：验证 `stream` 下非法请求无应用层响应；HTTP 族验证已配置与未配置 Fallback 的实际响应。
- [ ] **Phase 4: 3X-UI 面板适配（不在本仓库）**
  - 更新 3X-UI 的 Inbound 模板，支持在 `chitanda` 协议下动态添加、删除用户，绑定 `email` 与一键生成 `psk`。
