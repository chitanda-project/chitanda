# 2026-10-15 H3 UDP 关闭生命周期补修

## 失败证据与验收更正

main `9636efc` 的 [Xray 发布运行](https://github.com/chitanda-project/chitanda/actions/runs/38674430957) 在 SDK 回归门禁失败，未进入产物构建。失败用例为 `TestRegressionOctober15ClientCloseWakesH3UDPRead`；改用原版 quic-go 模块依赖后，本机重复 10 次全部复现。

第二轮验收中的默认/legacy 是 H2 构建路径之别，不是原版/patched QUIC 依赖之别。当时两套 Linux SDK race 都使用 SDK-only patched vendor，不能据此声称原版模块依赖已通过。此次失败暴露的是验收覆盖遗漏，不通过删测试、延长原用例的 300ms 限时或直接重跑失败发布来掩盖。

## 修复与边界

- H3 UDP 关联上下文从独立 Background 改为继承实际物理 QUIC 连接的生命周期，并追加 manager 生命周期取消钩子。客户端关闭、manager 回收或物理连接断开都能通知待决 Datagram 接收，不再依赖 patched HTTP Datagram 队列的额外唤醒行为。
- 显式关联 Close 停止 manager 钩子并取消自身，不取消共享物理连接或其他关联。已关闭父级不会创建仍存活的关联上下文；握手后发现父级关闭时撤销当前 stream。
- 写入入口拒绝生命周期已结束的关联，待决的可取消批量/单包队列写也随上下文退出，避免 deadline 更新引起终止后的再次入队。
- 不继承建连调用方的取消：成功返回后，取消 dial-only context 不应杀死既有流。关联继续由 PacketConn/manager/物理连接控制。
- 不新增每包取消钩子或后台协程，不改变协议格式、密钥、拥塞控制、通道数或配置。H2/auto 的 UDP 同样复用该 H3 关联实现；本补修主要随客户端 SDK/Xray/Mihomo 更新，不能把它描述为服务端线格式升级。此前服务端末批 UDP 修复仍需服务端更新。

## 回归与验收

- 保留原先失败用例原样，新增物理连接/manager/单关联终止、4 路并发读、单包与批量待决写、关闭后拒绝新写、独立关联、已关闭父级、并发 Close/deadline，以及真实 HTTP/3 建连交接、物理连接关闭后重新建连。
- 本机原版模块依赖：默认与 http2legacy 的 SDK internal/pkg 全套测试和 vet 通过；H3 生命周期用例连续 100 轮通过。
- 本机 patched SDK vendor：全套测试和 vet 通过；H3 生命周期用例连续 100 轮通过。
- 本机注入 Xray：Chitanda/UDP Hub 全套、配置回归及相关 vet 通过；恢复到真实 Xray vendor 的 SDK 测试连续 30 轮通过。
- 本机 Mihomo：config/outbound/sing_tun/SOCKS/tunnel 的 Chitanda 回归与 vet 通过。
- Xray 与带 with_gvisor,http2legacy 的 Mihomo：Linux amd64/arm64 交叉编译通过（不是 ARM 运行或公网测速）。
- 24 项 Python 脚本测试通过；修改工作流的 YAML 与 shell 语法通过。

合并前 [Linux CI 验收](https://github.com/chitanda-project/chitanda/actions/runs/38677165545) 已全绿，受验代码为 `87cd635f91f6b679c768e24219bd9a3815b56144`：

| Runner / 依赖 | 已通过结果 |
| --- | --- |
| Go 1.26.9 / 原版模块 | 默认、http2legacy 两套 internal/pkg 全量 race；生命周期 30 轮 race |
| Go 1.27.2 / 原版模块 | 默认、http2legacy 两套 internal/pkg 全量 race；生命周期 30 轮 race |
| 注入 Xray / patched vendor | Chitanda 与配置接入 race；SDK 生命周期 30 轮 race；Xray Linux 构建 |

最终合并随附 README、发布说明与本验收记录，不再改动已经受验的生产代码和测试逻辑。正式多平台发布仍由后续 main 推送触发，不将审计构建冒充已发布产物。

`go mod vendor` 默认剥离依赖包的测试，因此仅运行 `go test github.com/violetaini/chitanda/pkg/client` 可能出现 `[no test files]` 而成功退出。已在审计/发布工作流中显式复制 SDK 客户端测试到生成的 vendor，再执行 patched race；该复制不改变生产源码或二进制的运行逻辑。原版模块全套 race 门禁继续保留。

本轮 Linux 验收仅使用 GitHub 托管 runner，没有再上传源码到生产机、部署、重启代理或改路由器/IEPL/Realm。未做公网吞吐压测，不宣称本补修提高 TCP/UDP 速率或解决所有断线原因。
