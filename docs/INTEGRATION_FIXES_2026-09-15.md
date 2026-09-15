# Xray / Mihomo 接入修复（2026-09-15）

基于 `167c9f9`。本次只修改代码、测试和打包门禁，不部署或重启生产节点。

## 修复范围

1. 重新用 protoc 生成 Xray 配置：`cert_file`、`key_file` 纳入 protobuf 描述符，序列化往返不再丢失。
2. 移除 Xray 隐式自签证书和 PSK 派生 ticket 密钥。证书须明确提供；ticket 由 Go TLS 使用服务端独立随机密钥并自动轮换。
3. H2 保留嵌入内核的拨号上下文；Xray TCP、原生 UDP、H3 UDP 外层均使用 Xray dialer，服务器域名使用 Xray DNS，无系统拨号兜底。
4. H3 UDP 目标通过 Xray dispatcher；H1/H3 保留入站 tag 等路由元数据，避免在并发请求中修改共享入站对象。
5. UDP 每个数据报独占一个 Buffer，不拆成 8KiB 多包、不引用接收复用缓冲；保留逐包目的地址和响应地址。Xray UDP listener 大接收缓冲仅对 Chitanda 入站启用，其余协议保持上游默认。
6. Xray 取消与错误会关闭对应连接、唤醒阻塞读写并回收工作协程；TCP 干净 EOF 保留另一方向，按双向空闲超时回收。
7. H3 UDP 接收只创建一个子 context；deadline 更新唤醒所有正在等待的读操作。虚拟 UDP socket 支持动态读 deadline。
8. 跨 UDP association 的重放注册表限制为 10,000 个会话；容量耗尽拒绝新会话，不驱逐仍有效的窗口。最后一次接受新包后至少保留 65 秒，覆盖协议正负 30 秒的时间窗，之后定期回收。
9. RawStream/H1 EOF 使用下一序列号的 AEAD 空明文记录；伪造零长度、截断、篡改均不能伪装成正常 EOF。终止错误保持粘性，部分帧超时后保留解析状态。
10. H2/H3 协商 HALF_CLOSE；RawStream/H1 使用认证 EOF。移除固定 250ms drain 截断，保留正常双向空闲限制，并等待转发协程退出。
11. Mihomo 暴露 `ProxyInfo.DialerProxy`，使代理链的自引用和不存在节点检查生效。
12. 原生 UDP 建立失败返回真正的 nil 接口；域名响应地址不再伪造成 `0.0.0.0`。

## 兼容性与边界

- **先安排维护窗口，再一起升级 RawStream/H1 两端。** 旧版本的未认证 EOF 不被新版本接受，不能把正常流量能传输等同于混合版本完全兼容。
- H2/H3 通过 `X-Session-Framing: 1` 协商帧模式；完整的双向半关闭保证要求两端更新，旧服务器的 raw 回退不作此保证。
- Xray `transport: h3/h2/auto`（含默认模式）的 H3 listener 需要有效文件证书。可使用 settings 下的 `cert_file`/`key_file`，或父级 TLS 配置中的 `certificateFile`/`keyFile`。只有内联 PEM 或动态签发证书时，请另行提供文件对；缺失或损坏时启动失败，不再自动生成证书。TCP TLS 仍由 Xray 的 streamSettings 配置负责。
- Xray ticket 不再跨重启稳定；旧 ticket 应回退完整握手。独立服务端显式配置的 ticket-key-file 不受此更改影响，也不应与客户端 PSK 共用。
- UDP 报文最终上限仍受载体、路径 MTU、其他内核出口和代理链限制。H3 不新增 IP 分片或数据报分片能力；9KB 接入层测试不代表 H3 可以发送 9KB QUIC Datagram，也不承诺任意上游出口都支持 64KB UDP。
- 重放保护不会使首次 0-RTT 自动获得前向保密；本次不改变协议既有密钥交换模型，不作“无漏洞/不可识别”的保证。

## 验收方式

- SDK：`go test -mod=mod -race ./internal/... ./pkg/... -count=1 -timeout=180s`
- 注入 Xray：`go test -mod=mod -race ./proxy/chitanda -count=1 -timeout=180s`
- Xray 配置：`go test -mod=mod -race ./infra/conf -run Chitanda -count=1 -timeout=120s`
- 注入 Mihomo：`go test -mod=mod -race ./config -run Chitanda -count=1 -timeout=120s`
- 使用对应上游 Xray v26.3.27、Mihomo v1.19.31 做编译验收，生产网络与吞吐不在本次验收范围。

新增回归覆盖：认证 EOF/截断、四种实际载体空闲 6 秒后双向通信及收到 EOF 后暂停 600ms 继续上传、H2/H3 请求取消、H3 并发 deadline、证书序列化与 ticket 隔离、UDP 9KB 数据报边界/所有权/监听器、重放容量/有效期、Xray UDP 拨号拒绝、真实 H3 UDP dispatcher 转发及入站 tag、Mihomo 错误代理链。

main 推送会触发 `Upstream Sync & Automated Release`。按本次交付要求，不等待或监控 Actions 打包完成。

## CI 后续修复：原生 UDP 解析器数据竞争

`c602e78` 的 Linux CI 在 `TestStreamServer_NativeUDP_Echo` 检出真实数据竞争：
`AttachUDP` 已启动工作线程，随后设置解析器，与 `processTask` 读取解析器之间缺少同步。
独立服务端启用 `AllowPrivateTargets` 时也存在相同调用顺序，因此并非单纯的测试误报。

- 新增线程安全的 `SetResolveUDP`，保留 `SetResolveUDPForTest` 兼容入口；传入 nil 恢复默认安全解析器。
- 仅在新目标解析前持读锁取得函数快照，调用 DNS/用户回调前释放锁；已有目标的数据报转发不加此锁。
- 替换只影响后续解析，不撤销已经建立的目标连接或正在执行的解析，不应当作即时访问策略撤销接口。
- 新增并发回归在旧代码上复现相同 race；修复后与原生 UDP 回显、自更新解析器回归一起重复 50 次通过。
- Windows 本地 SDK 全量 race、Xray 接入与配置 race 通过；本地通过不等于 Linux CI 已通过，重新推送后不等待打包完成。
