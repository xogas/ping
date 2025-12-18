# Ping library design specification

> Positioning: 面向实现的设计规格，聚焦模块职责、接口契约与运行时行为。
> Goal: Linux-only；非 Linux 目标在编译期失败。
> Module: github.com/xogas/ping
> License: MIT
> Go: 1.26+
> Dependencies: golang.org/x/net (icmp / ipv4 / ipv6 / bpf)

---

## Part 1 -- 项目文件结构及职责划分

```txt
github.com/xogas/ping
|-- go.mod
|-- go.sum
|-- license
|-- readme.md
|-- design.md
|-- Makefile
|
|-- logger.go              # Logger 接口及 NoopLogger 实现
|-- options.go             # Functional Options 模式: options 结构体 + Option 函数族
|-- pinger.go              # Pinger 核心结构体, 公开 API (New / Run / Stop / Statistics)
|-- resolve.go             # DNS 解析: 将 host 解析为 net.IPAddr, 区分 IPv4/IPv6
|-- packetconn.go          # PacketConn 抽象接口与连接实现: 使用 icmp.ListenPacket, 支持过滤器与套接字选项
|-- send.go                # 构造并发送 ICMP Echo Request 报文
|-- recv.go                # 接收并解析 ICMP Echo Reply / 错误报文
|-- run.go                 # 主循环: 定时发送, 并发接收, 超时与取消控制
|-- statistics.go          # Statistics 结构体: 汇总 RTT / 丢包率 / 标准差等统计数据
|-- errors.go              # 统一错误定义
|
|-- cmd/
|   |-- ping/
|       |-- ping.go        # CLI 入口: 解析命令行参数, 调用库 API
```

---

## Part 2 -- 整体设计理念

### 2.1 架构原则

1. **职责清晰**
   按解析、连接、发送、接收、统计拆分文件，便于阅读与测试。

2. **接口隔离**
   通过 `packetConn` 抽象连接能力，`send.go` / `recv.go` 只依赖接口。

3. **配置稳定**
   使用 Functional Options（`With*`）扩展参数，不破坏 `New()` 调用方式。

4. **生命周期可控**
   `Run(ctx)` 受 `context.Context` 驱动；`Stop()` 幂等；状态机防止并发/重复运行。

5. **默认轻量**
   默认 `NoopLogger` 无额外日志成本；调用方可按需接入任意日志库。

### 2.2 核心技术选型

| 关注点 | 选型 | 理由 |
| :--- | :--- | :--- |
| ICMP 协议 | `golang.org/x/net/icmp` | Go 官方扩展库, 提供 ICMP 报文的序列化/反序列化 |
| IPv4/IPv6 | `golang.org/x/net/ipv4`, `golang.org/x/net/ipv6` | 设置 TTL, 读取 ControlMessage (HopLimit / TTL) |
| BPF 过滤 | `golang.org/x/net/bpf` | 在内核层过滤非目标报文, 大幅降低用户态开销 (仅 Linux) |
| 套接字类型 | `udp` (非特权) / `ip` (特权) | 非特权模式使用 IPPROTO_ICMP datagram socket, 无需 root |
| 并发模型 | goroutine + channel | 发送/接收分离 + 回调事件队列, channel 传递 `EchoReply/timeout/event`, 主循环 select 聚合 |
| 时间精度 | `time.Now()` (monotonic) | Go 1.9+ 内置单调时钟, 无需 `syscall.ClockGettime` |

### 2.3 特权模式 vs 非特权模式

```txt
+---------------------+--------------------------------+--------------------------------+
| Feature             | Privileged (raw socket)        | Unprivileged (dgram)           |
+---------------------+--------------------------------+--------------------------------+
| Network             | "ip4:icmp" / "ip6:ipv6-icmp"   | "udp4" / "udp6"                |
| Requires root       | Yes                            | No (kernel support required)   |
| ICMP ID management  | User-defined                   | Kernel-assigned                |
| BPF filter          | Filter by ICMP ID              | Isolated by UDP port           |
| IP Header visible   | Yes                            | No                             |
+---------------------+--------------------------------+--------------------------------+
```

### 2.4 报文过滤策略 (ICMP_FILTER / ICMPV6_FILTER + BPF)

特权模式下采用两级过滤：

1. **内核粗筛**：`ICMP_FILTER` / `ICMPV6_FILTER` 仅放行 Echo Reply。
2. **BPF 精筛**：按 Identifier 过滤到当前实例。

非特权模式使用 UDP datagram socket，由端口天然隔离，不附加 BPF/ICMP_FILTER。

> *(BPF 偏移与对比细节见附录 D)*

### 2.5 平台约束

仅支持 Linux，所有实现文件标记 `//go:build linux`，非 Linux 目标编译期直接失败，不提供回退。

### 2.6 套接字选项

除 BPF 外, 当前实现还提供以下与 ping 密切相关的套接字级能力:

- **SO_MARK**: 为报文打上 fwmark, 供策略路由 / iptables / nftables 匹配.
- **IP_MTU_DISCOVER (DF 位)**: 禁止 IP 分片, 用于 PMTU 探测.
- **SO_BROADCAST**: 允许向广播地址发送 ICMP Echo Request.
- **ICMP_FILTER / ICMPV6_FILTER**: 内核级 ICMP 类型过滤, 仅放行 Echo Reply.

**设计策略:**

- `packetConn` 接口为每个选项提供 `Set*` 方法.
- `packetconn.go` 通过 `syscall.RawConn.Control` 安全获取 fd 并调用底层 `setsockopt`.

### 2.7 ICMP ID 与 Seq 生命周期策略

本库将 `Identifier` 与 `Sequence` 视为运行时关键契约:

- `Identifier` 使用进程内原子递增 + 随机种子生成, 最终截断为 16-bit,
  避免仅依赖 `pid` 带来的多实例冲突风险.
- `Sequence` 为 `uint16` 循环计数, 结合 pending 表的活动窗口管理,
  在回绕时仅允许复用已结束生命周期的 Seq 槽位.
- **Seq 回绕边界**: 当 pending 表中 65536 个槽位全部活跃（即 interval 极短 + timeout 极长的极端场景）,
  发送端跳过本轮发送并通过 `Logger.Warnf` 记录告警, 不阻塞主循环.
  此行为**不计入** `Attempts` 或 `TxError`（因为报文未构造、未尝试发送）,
  仅记录日志; 如需监控此场景, 调用方可通过日志告警感知.

非特权模式使用 UDP datagram socket (`"udp4"` / `"udp6"`), 内核会覆盖用户设置的 ICMP Identifier,
将其替换为内核分配的 UDP 源端口号.

因此 `validateReply` 在非特权模式下 **跳过 Identifier 校验**, 仅校验 Type/Code 和来源地址;
内核通过 UDP 端口天然隔离, 只有匹配当前 socket 端口的 Echo Reply 才会被投递.

### 2.8 超时与乱序处理策略

采用发送/接收分离模型，并以 `per-seq Timer` 控制超时：

- **超时**：每个 Seq 独立计时，互不影响。
- **乱序**：超时后到达的回复记为 `LateDrop`，不参与 RTT 与成功统计。
- **错误分级**：可恢复错误继续运行；不可恢复错误终止 `Run`。
- **发送失败**：记录 `Attempts`/`TxError`，不重试；连续失败达到 `maxConsecutiveSendErrors`（常量，默认 3）次返回 `ErrSendFailed`。
  `onSendError` 回调仅在实际尝试发送但失败时触发（已构造 `EchoRequest`）；
  Seq 回绕跳过发送时不触发任何回调（未构造报文）。

### 2.9 运行时契约

- `Run(ctx)` 同时只允许一个活跃执行；并发/重复调用返回 `ErrInvalidState`。
- `Stop()` 幂等（`sync.Once` 保护），可重复调用。
  `Stop()` 主动触发退出时, `Run` 正常完成清理后返回 `nil` (视为用户主动终止, 不是错误).
- `Statistics()` 返回运行中的实时快照副本，供监控/展示使用；`Run()` 返回的是最终统计结果。
  两者数据结构相同，但 `Run()` 返回前额外调用 `compute()` 计算 AvgRTT/StdDevRTT/Loss。
  `Statistics` 的 `on*` 方法仅由 run 主循环 goroutine 调用（单写者），不需要自身加锁；
  `Pinger.Statistics()` 读取快照时持有 `Pinger.mu.RLock`，run 主循环在调用 `on*` 前持有 `Pinger.mu.Lock`，
  由 `Pinger.mu` 统一协调读写互斥。
- `Run(ctx)` 在错误退出时仍然返回已收集的部分统计数据（`*Statistics` 非 nil），
  调用方可据此判断故障前的探测情况。仅当构造阶段失败（如连接建立失败）时 `*Statistics` 为 nil。
- 单次探测异常通过 `onRecvError` 回调上报；仅不可恢复错误会使 `Run` 返回非 `nil`。
- 回调异步派发到有界队列；队列满时**丢弃最新事件**（保留历史），
  并通过 `Logger.Warnf` 记录告警，告警频率受内部 rate limiter 限制（每秒最多 1 条），避免日志风暴。
- `ctx` 取消时 `Run(ctx)` 返回 `ctx.Err()`，并在返回前完成连接关闭与统计收敛。
- `recvLoop` 退出协议：主循环通过关闭 `done` channel 发出退出信号，
  随后调用 `conn.SetReadDeadline(past)` 中断阻塞读取。
  `recvLoop` 在每次读取错误后检查 `done` channel 状态，
  若已关闭则正常退出（不视为错误），主循环等待 goroutine 回收后继续清理。
  `recvLoop` 不依赖 `context.Context`，退出完全由 `done` channel 驱动。

### 2.10 数据流

```txt
Pinger.Run(ctx)
  -> state check (New -> Running)
  -> resolve(ctx, host)            // DNS 解析在 Run 时执行, 受 ctx 控制
  -> newPacketConn(ipv4, id, opts)
  -> run loop
       - ticker 驱动发送（send.go）
       - recv goroutine 持续接收（recv.go）
       - per-seq timer 处理超时
       - select 聚合 reply / timeout / ctx.Done
  -> statistics.compute()
  -> state transition (Stopping -> Stopped)
  -> return Statistics
```

---

## Part 3 -- 详细组件设计

### 3.1 `logger.go`

#### Interface: Logger

```go
type Logger interface {
    Debugf(msg string, v ...any)
    Infof(msg string, v ...any)
    Warnf(msg string, v ...any)
    Errorf(msg string, v ...any)
}
```

- 4 个级别覆盖调试到错误, 签名与 `fmt.Printf` 风格一致.
- 调用方可用 `slog.Logger` 简单适配.

#### Struct: NoopLogger

```go
type NoopLogger struct{}
```

- 所有方法为空实现, 作为 `Logger` 的零值默认.

### 3.2 `options.go`

#### Struct: options

```go
type options struct {
    count             int                         // 发送次数, 0 表示无限
    size              int                         // ICMP payload 字节数
    interval          time.Duration               // 发送间隔
    timeout           time.Duration               // 单次等待超时
    ttl               int                         // IP TTL
    privileged        bool                        // 是否使用 raw socket
    callbackQueueSize int                         // 回调事件队列容量, 0 使用默认值
    mark              int                         // SO_MARK: 套接字标记, 0 表示不设置
    dontFragment      bool                        // DF 位: 禁止分片
    broadcast         bool                        // SO_BROADCAST: 允许发送到广播地址
    onSend            func(*EchoRequest)          // 每次发送成功后回调, nil 表示不回调
    onSendError       func(*EchoRequest, error)   // 发送失败时回调, nil 表示不回调
    onRecv            func(*EchoReply)            // 每次成功收到 EchoReply 后回调, nil 表示不回调
    onRecvError       func(*EchoReply, error)     // 接收异常 (超时) 时回调, nil 表示不回调
    logger            Logger                      // 日志实例
}
```

#### Type: Option

```go
type Option func(*options)
```

```go
// defaultOptions 返回合理的默认配置.
func defaultOptions() options

// WithCount 设置发送 Echo Request 的次数, 0 表示无限.
func WithCount(n int) Option

// WithSize 设置 ICMP payload 大小 (字节).
func WithSize(size int) Option

// WithInterval 设置每次发送 Echo Request 之间的间隔.
func WithInterval(d time.Duration) Option

// WithTimeout 设置等待单次 Echo Reply 的超时时间.
func WithTimeout(d time.Duration) Option

// WithTTL 设置 IP 报文的 Time-To-Live (1-255).
func WithTTL(ttl int) Option

// WithPrivileged 启用或禁用 raw socket (特权) 模式.
func WithPrivileged(v bool) Option

// WithLogger 注入自定义的 Logger 实现.
func WithLogger(l Logger) Option

// WithCallbackQueueSize 设置回调事件队列容量, 默认 64.
// 当队列已满时, 新事件按丢弃策略处理并记录告警日志.
func WithCallbackQueueSize(n int) Option

// WithMark 设置 SO_MARK 套接字标记, 用于策略路由 / netfilter 匹配.
// 需要 CAP_NET_ADMIN 权限.
func WithMark(mark int) Option

// WithDontFragment 设置 IP 报文的 DF (Don't Fragment) 位.
// 用于 Path MTU Discovery.
func WithDontFragment(v bool) Option

// WithBroadcast 允许向广播地址发送 ICMP Echo Request.
func WithBroadcast(v bool) Option

// WithOnSend 注册发送成功回调（异步派发，不阻塞主循环）。
func WithOnSend(fn func(*EchoRequest)) Option

// WithOnSendError 注册发送失败回调（异步派发，不阻塞主循环）。
func WithOnSendError(fn func(*EchoRequest, error)) Option

// WithOnRecv 注册接收成功回调（仅正常回复触发，异步派发）。
func WithOnRecv(fn func(*EchoReply)) Option

// WithOnRecvError 注册接收异常回调（目前仅超时场景触发, 异步派发）。
func WithOnRecvError(fn func(*EchoReply, error)) Option
```

### 3.3 `errors.go`

#### Sentinel Errors

```go
var (
    ErrTimeout             error // 等待回复超时
    ErrInvalidAddr         error // 地址无法解析
    ErrSendFailed          error // 连续发送失败达到阈值
    ErrRecvFailed          error // 不可恢复接收失败
    ErrInvalidState        error // 非法状态转换 (如并发/重复 Run)
)
```

- 使用 `errors.New` 定义, 调用方可用 `errors.Is` 判断.

### 3.4 `resolve.go`

```go
// resolve 将主机名或 IP 字符串解析为 net.IPAddr.
// 自动识别 IPv4/IPv6, 通过 net.Resolver 支持 context 取消.
func resolve(ctx context.Context, host string) (*net.IPAddr, error)

// isIPv4 判断 addr 是否为 IPv4 地址.
// 用于后续选择正确的 ICMP 协议版本.
func isIPv4(addr net.IP) bool
```

### 3.5 `packetconn.go`

#### Interface: packetConn

```go
type packetConn interface {
    // WriteTo 发送 ICMP 报文到目标地址.
    WriteTo(b []byte, dst net.Addr) (int, error)

    // ReadFrom 从连接读取 ICMP 报文, 返回字节数、来源地址和 TTL/HopLimit.
    // TTL 通过 ControlMessage 获取; 如果平台不支持则返回 0.
    ReadFrom(b []byte) (n int, ttl int, addr net.Addr, err error)

    // SetReadDeadline 设置读超时.
    SetReadDeadline(t time.Time) error

    // SetTTL 设置 IP 报文的 TTL / Hop Limit.
    SetTTL(ttl int) error

    // SetMark 设置 SO_MARK 套接字标记.
    SetMark(mark int) error

    // SetDoNotFragment 设置 DF 位, 禁止 IP 分片.
    SetDoNotFragment(v bool) error

    // SetBroadcast 设置 SO_BROADCAST, 允许发送到广播地址.
    SetBroadcast(v bool) error

    // SetICMPFilter 设置 ICMP_FILTER (IPv4) 或 ICMPV6_FILTER (IPv6),
    // 在内核层按 ICMP Type 过滤.
    SetICMPFilter() error

    // EnableTTLControlMessage 启用 ControlMessage 以读取 TTL/HopLimit.
    // IPv4: SetControlMessage(ipv4.FlagTTL, true)
    // IPv6: SetControlMessage(ipv6.FlagHopLimit, true)
    EnableTTLControlMessage() error

    // Close 关闭底层连接.
    Close() error
}
```

- 该接口是平台差异的唯一隔离点.
- `send.go` 和 `recv.go` 仅依赖此接口, 不感知底层实现.

```go
// listenNetwork 根据 IP 版本和特权模式返回 icmp.ListenPacket 所需的
// network 字符串, 如 "udp4" / "ip4:icmp" / "udp6" / "ip6:ipv6-icmp".
func listenNetwork(ipv4 bool, privileged bool) string

// listenAddr 返回监听地址.
// IPv4 -> "0.0.0.0", IPv6 -> "::".
func listenAddr(ipv4 bool) string
```

### 3.6 `packetconn.go` (实现细节)

> Build tag: `//go:build linux`

#### Struct: packetConnImpl

```go
type packetConnImpl struct {
    conn    *icmp.PacketConn // 底层 ICMP 连接
    rawConn syscall.RawConn  // 通过 SyscallConn() 获取, 用于安全访问 fd
    ipv4    bool             // 是否为 IPv4
}
```

```go
// newPacketConn 创建 ICMP 连接, 通过 SyscallConn() 获取 RawConn,
// 设置 TTL, 启用 TTL/HopLimit ControlMessage,
// 附加 ICMP_FILTER/ICMPV6_FILTER 和 BPF 过滤器 (仅特权模式),
// 并根据 opts 配置 SO_MARK / DF / SO_BROADCAST.
// id 为 ICMP Identifier, 特权模式下用于 BPF 过滤; 非特权模式下忽略.
func newPacketConn(ipv4 bool, id int, opts *options) (packetConn, error)

// attachBPF 通过 rawConn.Control 获取 fd, 构造 BPF 指令序列
// 并通过 SO_ATTACH_FILTER 附加到套接字.
// 过滤条件: ICMP Type == Echo Reply && Identifier == id.
// IPv4 和 IPv6 使用不同的 BPF 指令 (Type 值不同, 见下方指令说明).
// 仅在特权模式下调用; 非特权模式由 UDP 端口隔离, 无需 BPF.
func attachBPF(rc syscall.RawConn, id int, ipv4 bool) error

// WriteTo / SetReadDeadline / Close 直接委托给底层 conn, 无额外逻辑.
func (c *packetConnImpl) WriteTo(b []byte, dst net.Addr) (int, error)
func (c *packetConnImpl) SetReadDeadline(t time.Time) error
func (c *packetConnImpl) Close() error

// ReadFrom 通过 ipv4.PacketConn.ReadFrom 或 ipv6.PacketConn.ReadFrom 读取报文,
// 同时从 ControlMessage 中提取 TTL (IPv4) 或 HopLimit (IPv6).
func (c *packetConnImpl) ReadFrom(b []byte) (n int, ttl int, addr net.Addr, err error)

// SetTTL 根据 IP 版本通过 ipv4.PacketConn 设置 TTL
// 或通过 ipv6.PacketConn 设置 HopLimit.
func (c *packetConnImpl) SetTTL(ttl int) error

// SetMark 通过 rawConn.Control 获取 fd, 调用
// setsockopt(SOL_SOCKET, SO_MARK) 设置套接字标记.
// 用于策略路由和 netfilter 规则匹配. 需要 CAP_NET_ADMIN.
func (c *packetConnImpl) SetMark(mark int) error

// SetDoNotFragment 通过 rawConn.Control 获取 fd, 调用
// setsockopt(IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO) (IPv4)
// 或 setsockopt(IPPROTO_IPV6, IPV6_DONTFRAG, 1) (IPv6),
// 禁止 IP 层分片, 用于 Path MTU Discovery.
func (c *packetConnImpl) SetDoNotFragment(v bool) error

// SetBroadcast 通过 rawConn.Control 获取 fd, 调用
// setsockopt(SOL_SOCKET, SO_BROADCAST) 允许向广播地址发送 ICMP Echo Request.
func (c *packetConnImpl) SetBroadcast(v bool) error

// SetICMPFilter 通过 rawConn.Control 获取 fd, 设置内核级 ICMP 类型过滤.
// IPv4: setsockopt(SOL_RAW, ICMP_FILTER), 放行 Echo Reply (Type 0).
// IPv6: setsockopt(IPPROTO_ICMPV6, ICMPV6_FILTER), 放行 Echo Reply (Type 129).
func (c *packetConnImpl) SetICMPFilter() error

// EnableTTLControlMessage 启用 ControlMessage 以读取 TTL/HopLimit.
// IPv4: ipv4.PacketConn.SetControlMessage(ipv4.FlagTTL, true)
// IPv6: ipv6.PacketConn.SetControlMessage(ipv6.FlagHopLimit, true)
func (c *packetConnImpl) EnableTTLControlMessage() error
```

### 3.7 `send.go`

#### Struct: EchoRequest (导出)

```go
type EchoRequest struct {
    ID   int       // ICMP 标识符
    Seq  uint16    // ICMP 序列号 (16-bit, 回绕)
    Size int       // payload 字节数
    Sent time.Time // 发送时间戳 (发送成功时记录; 发送失败时为尝试发送的时间)
}
```

```go
// sendEchoRequest 构造并发送 Echo Request。
// 流程: 记录 req.Sent = time.Now(), 调用 buildPayload 生成 payload
// (发送时间戳编码到前 8 字节), 根据 ipv4 选择 ICMP 消息类型
// (ipv4.ICMPTypeEcho / ipv6.ICMPTypeEchoRequest), 序列化 ICMP 报文后发送.
func sendEchoRequest(conn packetConn, dst net.Addr, req *EchoRequest, ipv4 bool) error

// buildPayload 生成指定大小的 payload.
// 前 8 字节编码 sentAt 时间戳 (UnixNano), 其余字节填充固定模式.
// sentAt 由 sendEchoRequest 在调用前记录并传入, 确保 req.Sent 与 payload 时间戳一致.
func buildPayload(size int, sentAt time.Time) []byte
```

### 3.8 `recv.go`

#### Struct: EchoReply (导出, 供回调/统计使用)

```go
type EchoReply struct {
    Seq  uint16        // 序列号 (16-bit, 回绕)
    RTT  time.Duration // 往返时延 (仅正常回复有效; 超时时为 0)
    TTL  int           // 回复报文的 TTL / HopLimit, 0 表示当前平台或路径未提供
    Size int           // 回复 payload 字节数 (超时时为 0)
    Addr net.Addr      // 回复来源地址 (超时时为 nil)
}
```

**超时场景下的 EchoReply 字段约定:**

当 `onRecvError` 因超时触发时, `error` 为 `ErrTimeout`, `EchoReply` 中仅 `Seq` 字段有效,
其余字段为零值 (`RTT=0`, `TTL=0`, `Size=0`, `Addr=nil`).
调用方应通过 `errors.Is(err, ErrTimeout)` 区分超时与其他接收错误.

```go
// recvEchoReply 从 conn.ReadFrom 读取数据与控制信息 (包括 TTL/HopLimit),
// 使用 icmp.ParseMessage 解析, 通过 validateReply 校验 Type/Code/ID/来源地址,
// 从 payload 前 8 字节提取发送时间戳以计算 RTT, 填充 EchoReply 并返回.
func recvEchoReply(conn packetConn, id int, dst *net.IPAddr, ipv4 bool, privileged bool, buf []byte) (*EchoReply, error)

// validateReply 校验 ICMP 报文是否合法且属于当前探测目标.
// privileged == true: 校验 Type + Code + ID + 来源地址 (特权模式, 用户态兜底校验).
// privileged == false: 校验 Type + Code + 来源地址, 跳过 ID 校验
//   (非特权模式下内核覆盖了 ID, 但 UDP 端口已提供隔离).
// 返回解析后的 Seq 供调用方使用; Seq 的有效性 (是否在 pending 表中) 由 run 主循环判定.
func validateReply(msg *icmp.Message, id int, dst *net.IPAddr, from net.Addr, privileged bool) (seq uint16, err error)
```

### 3.9 `run.go`

```go
// maxConsecutiveSendErrors 是连续发送失败的阈值.
// 超过此值后 Run 返回 ErrSendFailed.
const maxConsecutiveSendErrors = 3
```

#### pending 表: seq → timer 映射

```go
// pendingEntry 记录一个已发送但尚未收到回复的 Echo Request.
type pendingEntry struct {
    timer *time.Timer // per-seq 超时定时器
}
```

run 主循环内部维护 `pending map[uint16]*pendingEntry`:

- **发送成功**: 写入 `pending[seq]`, 启动 per-seq `time.AfterFunc` timer.
  timer 回调通过非阻塞发送将 seq 投递到 `timeoutCh` (见下方定义);
  若 `done` 已关闭 (退出中), 回调静默返回, 避免阻塞泄漏.
- **收到回复**: 从 `pending` 删除对应 seq, 停止 timer, 使用 `reply.RTT` 更新统计.
- **超时触发**: 主循环从 `timeoutCh` 读取 seq, 从 `pending` 删除并触发 `onRecvError(ErrTimeout)`.
- **迟到回复**: 若 seq 不在 `pending` 中, 说明已超时, 计为 `LateDrop`.
- **Seq 回绕**: 分配新 seq 时检查 `pending[seq]` 是否存在, 若存在说明该 seq 仍在活动窗口内, 跳过本轮发送.

pending 表仅在 run 主循环 goroutine 中读写, 不需要额外锁保护.

#### timeoutCh: 超时事件通道

```go
timeoutCh chan uint16 // 缓冲大小 = max(opts.count, 64), count==0 时使用 64
```

`time.AfterFunc` 回调将超时的 seq 投递到 `timeoutCh`, 主循环在 select 中读取.
缓冲大小选择: 正常场景下同时活跃的 pending seq 数量 = `timeout / interval` (通常个位数),
64 的默认缓冲远超实际需求; `count` 模式下以 count 为上界避免极端配置下的丢失.
AfterFunc 回调使用两段式检查: 先检查 `done` 状态, 再非阻塞发送到 `timeoutCh`:

```go
time.AfterFunc(timeout, func() {
    // 第一段: 检查是否正在退出, 避免在清理阶段继续投递超时事件.
    select {
    case <-done:
        return
    default:
    }
    // 第二段: 非阻塞投递; 缓冲满时静默丢弃并记录告警日志.
    select {
    case timeoutCh <- seq:
    default:
        // 缓冲满, 理论上不应到达
    }
})
```

注意: 不能使用三路 select (`<-done` / `timeoutCh <-` / `default`) 合并两段检查,
因为含 `default` 的 select 是非阻塞的, 此时 `<-done` 分支在 done 未关闭时不 ready,
与 default 竞争时行为不等价于"优先检查 done", 需两段分离保证语义清晰.

#### 回调异步派发

```go
// callbackEvent 封装一个待派发的回调事件.
type callbackEvent struct {
    fn func() // 闭包, 捕获具体回调函数及参数
}
```

run 主循环创建有界 channel `callbackCh chan callbackEvent` (容量 = `opts.callbackQueueSize`, 默认 64),
并启动独立的 **dispatcher goroutine** 消费事件:

- **入队**: 主循环在 send/recv/timeout 事件后, 将回调包装为 `callbackEvent` 尝试写入 `callbackCh`.
  使用 `select + default` 非阻塞写入, 队列满时丢弃当前事件 (保留历史), 并通过 `Logger.Warnf` 记录告警.
  告警频率受 rate limiter 限制 (每秒最多 1 条), 避免日志风暴.
- **消费**: dispatcher goroutine 从 `callbackCh` 读取并执行 `event.fn()`.
  回调内的 panic 由 `recover` 捕获并记录日志, 不影响后续派发.
- **退出**: run 主循环退出时关闭 `callbackCh`, dispatcher goroutine 消费完剩余事件后返回,
  主循环等待 dispatcher 回收后继续清理.

```go
// recvResult 封装 recvLoop 向主循环传递的结果.
type recvResult struct {
    reply *EchoReply
    err   error // nil: 正常回复; 不可恢复错误: 连接关闭等
}
```

```go
// run 负责发送/接收主循环：
// - ticker 定时发送并创建 per-seq timer。
//   当 opts.count > 0 时, 发送达到 count 次后停止 ticker, 不再发送;
//   主循环继续运行直到所有 pending seq 超时/收到回复, 或 ctx 取消.
// - recvLoop 持续接收，通过 recvCh (缓冲 = 1) 向主循环传递结果;
//   缓冲为 1 确保 recvLoop 解析完一个回复后不会长时间阻塞,
//   同时避免过大缓冲积压过期数据.
//   recvLoop 向 recvCh 发送时使用 select + done 保护 (见下方退出协议),
//   避免主循环停止消费后 recvLoop 阻塞在 channel send 导致死锁.
// - 主循环在 select 中聚合 recvCh / timeoutCh / ticker / ctx.Done.
// - 正常回复取消 timer 并更新统计；超时触发 onRecvError(ErrTimeout)。
// - 迟到包计为 LateDrop；可恢复错误继续，不可恢复错误返回。
//
// 退出清理顺序 (无论正常完成、ctx 取消还是不可恢复错误):
//   1. close(done) + conn.SetReadDeadline(past) → 中断 recvLoop 阻塞读取,
//      同时 done 用于解除 recvLoop 可能阻塞在 recvCh 发送的情况.
//   2. 等待 recvLoop goroutine 退出 (recvLoop 发送端通过 select + done 保证不死锁).
//   3. 遍历 pending 表, Stop 所有未触发的 timer, 清空 pending.
//   4. close(callbackCh) → dispatcher 消费完剩余事件后退出.
//   5. 等待 dispatcher goroutine 退出.
//   6. conn.Close().
//   7. stats.compute().
func (p *Pinger) run(ctx context.Context) error

// recvLoop 持续读取并解析回复，将结果发送到 recvCh。
// 可恢复解析错误仅记录日志后继续；不可恢复错误或 done channel 关闭时退出。
// 退出协议:
//   - 主循环关闭 done channel 后调用 conn.SetReadDeadline(past) 中断阻塞读取.
//   - recvLoop 在每次读取错误后检查 done channel, 若已关闭则正常返回.
//   - recvLoop 向 recvCh 发送结果时必须使用 select + done 保护,
//     即 `select { case recvCh <- result: case <-done: return }`,
//     防止主循环停止消费 recvCh 后 recvLoop 阻塞在 channel send 导致死锁.
func (p *Pinger) recvLoop(recvCh chan<- recvResult)
```

### 3.10 `statistics.go`

#### Struct: Statistics (导出)

```go
type Statistics struct {
    Addr       string        // 目标地址
    Attempts   int           // 总尝试发送次数 (含失败)
    Sent       int           // 发送成功次数
    TxError    int           // 发送失败次数
    Received   int           // 在超时窗口内收到的有效回复数
    Timeout    int           // 超时次数 (按 per-seq timer 判定)
    LateDrop   int           // 超时后到达并被丢弃的回复数
    Loss       float64       // 网络丢包率: 1 - Received/Sent (Sent==0 时为 0)
    MinRTT     time.Duration // 最小 RTT
    MaxRTT     time.Duration // 最大 RTT
    AvgRTT     time.Duration // 平均 RTT
    StdDevRTT  time.Duration // RTT 标准差
}
```

**Loss 语义说明:**
`Loss` 衡量的是**网络丢包率**, 计算基于发送成功的报文 (`Sent`), 不包含本地发送失败 (`TxError`).
这与标准 `ping` 命令行为一致: 发送失败是本地问题, 不计入网络丢包.
如需端到端失败率, 调用方可自行计算 `1 - Received/Attempts`.

```go
// newStatistics 为给定目标地址创建并初始化 Statistics 结构体.
func newStatistics(addr string) *Statistics

// 以下方法由 run 主循环在对应事件发生时调用, 逐次更新内部计数器.
// onReply 额外更新 MinRTT/MaxRTT 并累加均值/方差中间值.
func (s *Statistics) onSendAttempt()
func (s *Statistics) onSendSuccess()
func (s *Statistics) onSendError()
func (s *Statistics) onReply(rtt time.Duration)
func (s *Statistics) onTimeout()
func (s *Statistics) onLateDrop()

// compute 根据累加值计算 AvgRTT / StdDevRTT / Loss.
// 在 Run 返回前调用一次.
func (s *Statistics) compute()
```

### 3.11 `pinger.go`

#### Struct: Pinger (导出, 库的核心入口)

```go
type Pinger struct {
    host     string         // 原始主机名或 IP
    addr     *net.IPAddr    // 解析后的 IP 地址 (Run 时填充)
    id       int            // ICMP Identifier (16-bit, 原子递增 + 随机种子)
    state    pingerState    // 生命周期状态: New/Running/Stopping/Stopped
    opts     options        // 配置参数
    stats    *Statistics    // 运行时统计
    conn     packetConn     // 底层连接 (平台相关)
    done     chan struct{}  // 关闭信号
    mu       sync.RWMutex   // 保护 state/stats/conn 等运行时状态
    stopOnce sync.Once      // 保证 Stop 幂等
}
```

#### Type: pingerState

```go
type pingerState int

const (
    stateNew      pingerState = iota  // 初始状态, 可调用 Run
    stateRunning                      // Run 执行中, 拒绝并发 Run
    stateStopping                     // Stop 已调用, 正在清理
    stateStopped                      // 已终止, 不可重用
)
```

状态转换:

```txt
New --Run()--> Running --Stop()/ctx.Done/完成--> Stopping --清理完毕--> Stopped
```

非法转换（如 Running 状态调用 Run、Stopped 状态调用 Run）返回 `ErrInvalidState`。

```go
// New 构造 Pinger: 应用 options,
// 生成 16-bit ICMP ID (原子递增 + 随机种子), 初始化状态为 New, 返回就绪实例.
// 注意: DNS 解析延迟到 Run() 执行时, New() 不产生网络 I/O.
func New(host string, opts ...Option) (*Pinger, error)

// Run 是公开入口: 解析 host 为 IP 地址, 创建 packetConn, 通过 p.run(ctx) 执行主循环,
// 按状态机执行 New->Running->Stopping->Stopped 转换;
// 若在 Running/Stopping/Stopped 状态被调用, 返回 ErrInvalidState.
// 退出后关闭连接, 计算并返回 Statistics 快照.
// 即使因错误退出, 仍返回已收集的部分统计 (*Statistics 非 nil);
// 仅当构造阶段失败 (DNS 解析/连接建立) 时 *Statistics 为 nil.
func (p *Pinger) Run(ctx context.Context) (*Statistics, error)

// Stop 主动停止 Pinger: 幂等地关闭 done channel, 触发主循环退出.
func (p *Pinger) Stop()

// Statistics 返回当前统计的实时快照副本. 在 Run 执行期间调用是安全的.
// 注意: 此快照未调用 compute(), AvgRTT/StdDevRTT/Loss 可能尚未计算.
// 最终完整统计请使用 Run() 的返回值.
func (p *Pinger) Statistics() *Statistics
```

### 3.12 `cmd/ping/ping.go`

```go
// main 是 CLI 入口:
//  1. 解析命令行参数 (-c, -s, -i, -t, -W, --privileged).
//  2. 根据解析结果构造 []ping.Option.
//  3. 调用 ping.New + pinger.Run.
//  4. 监听 SIGINT/SIGTERM 信号, 收到后调用 pinger.Stop().
//  5. 打印统计结果, 格式对齐标准 ping 命令输出.
func main()

// printReply 格式化并打印单条回复行.
// 例如 "64 bytes from 1.2.3.4: icmp_seq=1 ttl=64 time=1.23 ms"
func printReply(r *ping.EchoReply)

// printStatistics 格式化并打印统计摘要.
// 例如 "--- 1.2.3.4 ping statistics ---"
func printStatistics(s *ping.Statistics)
```

---

## 附录 -- 关键设计决策（简版）

### A. SyscallConn vs 反射取 fd

- 选择 `SyscallConn + RawConn.Control` 操作 fd。
- 原因：官方 API、类型安全、版本稳定，避免反射脆弱性。

### B. 为什么导出 `EchoRequest` / `EchoReply`

- 两者出现在公开回调签名中，调用方必须可见。
- 命名与 ICMP 术语一致，语义直观。

### C. payload 时间戳策略

- payload 前 8 字节写发送时间戳，用于 RTT 计算与抓包对齐。
- 与常见 `ping` 行为一致，可降低额外状态管理复杂度。

### D. BPF 指令要点

- 先校验 Echo Reply Type，再校验 Identifier，匹配则放行。
- IPv4/IPv6 主要差异是 Reply Type 常量（0 vs 129）。

### E. 为什么不用 SetReadDeadline 做超时

- `SetReadDeadline` 是连接级，和并发多探测模型冲突。
- 采用 per-seq timer，超时与读取解耦，互不覆盖。
