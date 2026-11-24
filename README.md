# FlowTunnel

[![Windows CI and Release](https://github.com/LXY1226/flowtunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/LXY1226/flowtunnel/actions/workflows/ci.yml)

Windows IPv4 透明 L4 隧道原型。客户端通过固定地址 `10.200.0.1` 访问服务端本机的 TCP 和 UDP 端口。
每条 TCP 连接使用独立的原生 TCP 字节流，每个 UDP 五元组使用独立 Fake TCP 会话；两者共用一个服务端 TCP 端口。

## 构建

需要 Windows x64、Visual Studio 2026 C++ 工具链、CMake、PowerShell 和 Python 3（仅本地测试需要 Python）。

```powershell
.\scripts\build.ps1
```

构建脚本下载固定版本的 [WinDivert 2.2.2](https://github.com/basil00/WinDivert/releases/tag/v2.2.2)，
验证驱动 Authenticode 签名，以 MSVC/CMake 构建 C++20 程序并执行 CTest，然后生成 `bin\flowtunnel.exe`、`WinDivert.dll` 和 `WinDivert64.sys`。
TCP 异步 I/O 使用 Asio 1.36.0，配置解析使用 toml++ 3.4.0，加密使用 Windows CNG。依赖版本固定，源码归档校验 SHA-256。
依赖包和构建输出位于忽略目录，不修改上层 WireGuard 源码。

## CI 与自动发布

每次分支推送、针对 `main` 的 PR 和手动触发都会在 GitHub 托管的 Windows x64 / VS 2026 环境中构建，运行原生 CTest 和 WinDivert 双端测试，然后上传 ZIP 与 SHA-256 校验文件。测试失败会阻止打包和发布，测试日志保留 14 天。

发布新版本时推送版本标签：

```powershell
git tag -a v0.1.0 -m "FlowTunnel v0.1.0"
git push origin v0.1.0
```

标签需采用 `vX.Y.Z` 或 `vX.Y.Z-rc.1` 等格式。标签对应的构建和测试全部通过后，工作流自动创建 GitHub Release，上传 `flowtunnel-<版本>-windows-x64.zip` 和 `.zip.sha256`。`v0.x.y` 及带预发布后缀的标签标记为预发布；正式版本标签从 `v1.0.0` 开始。

发布包包含可执行文件、WinDivert DLL/驱动、客户端启动器、两端示例配置及第三方许可证。下载后按包内 `README.txt` 填写地址和生成的共享密钥。构建使用默认 `GITHUB_TOKEN`，发布 job 单独申请 `contents: write`，不需要额外配置 PAT。

也可在本地构建通过后打包：

```powershell
.\scripts\package-release.ps1 -Version v0.1.0
```

## 配置与运行

```powershell
.\bin\flowtunnel.exe genkey
```

将生成的同一个 Base64 密钥放入双方配置，不要使用示例占位符。

服务端 `server.toml`：

```toml
mode = "server"
listen = "0.0.0.0:18080"
key = "<32 字节随机密钥的 Base64>"
```

客户端 `client.toml`：

```toml
mode = "client"
endpoint = "myserver.example.com:18080"
key = "<与服务端相同的密钥>"
```

先检查配置，再在管理员 PowerShell 中分别启动服务端和客户端：

```powershell
.\bin\flowtunnel.exe check .\server.toml
.\bin\flowtunnel.exe run .\server.toml
```

```powershell
.\bin\flowtunnel.exe check .\client.toml
.\bin\flowtunnel.exe run .\client.toml
```

客户端应用直接访问 `10.200.0.1:目标端口`。服务端将该连接转发到 `127.0.0.1:目标端口`，因此目标服务必须监听回环地址或所有 IPv4 地址。
部署时需要让服务端公网 TCP 端口可达，并允许相应防火墙流量；程序不修改防火墙规则、路由或网卡配置。
不要同时运行多个客户端实例；现有路由必须能发送发往 `10.200.0.1` 的 IPv4 流量。
Ctrl+C 或进程自己的停止事件关闭进程及其 WinDivert 句柄。

## 本地双端测试

在管理员 PowerShell 中执行：

```powershell
.\scripts\test-local.ps1 -Exe "$PWD\bin\flowtunnel.exe" -Results "$PWD\test-results\local"
```

测试同时启动双方，通过 `10.200.0.1` 访问本地随机端口上的真实 TCP/UDP 回显服务，检查 TCP 并发、完整字节流、半关闭、多个目标端口、拒绝连接、认证边界，以及 0～60000 字节 UDP 数据报和独立 UDP 会话。
TCP 与 Fake TCP 共用 `127.0.0.1:18080`，测试结果、双方日志、进程清理结果写入指定目录，测试密钥配置在结束时清理。
非管理员运行明确失败，不会将普通 socket 测试报告为 WinDivert 双端通过。

需要重复运行管理员测试时，可一次注册本工作区的固定测试任务：

```powershell
.\scripts\enable-test-authorization.ps1
.\scripts\test-authorized.ps1
```

注册需要一次 UAC。任务以当前用户的最高权限运行，固定调用本工作区的 `test-local.ps1`，不保存密码，没有自动触发器，执行上限五分钟。
任务在本机保留，测试结果写入 `test-results\local-cpp`；不再需要时执行 `scripts\revoke-test-authorization.ps1` 撤销。

## 数据路径与协议约束

- TCP 透明接入采用 WinDivert 官方 `streamdump` 示例中的入站反射方式，映射保留原始目标端口，并对本地源端口做会话级转换以避免不同目标连接冲突。
- Fake TCP SYN 使用实验 TCP option 标识，由 WinDivert 在 Windows TCP 协议栈之前识别。该标识仅用于分流；访问目标服务需要通过 PSK 认证。该 option 在 NAT/防火墙中的保留情况需要真实跨机验证。
- 两种传输均发送固定 HTTP 首包，Host 为 `speedtest.fkcucc.com`；之后使用独立方向的 AES-128-GCM 密钥。HTTP 首包后的内容不是完整 HTTP 会话，实际 ISP QoS 放行效果需要链路测试。
- HMAC-SHA256 认证握手，HKDF-SHA256 派生会话密钥；计数器和 nonce 按方向独立，UDP 使用 1024 个记录的滑动重放窗口。TCP 在服务端随机挑战后验证客户端的加密确认，才连接目标；UDP 在完整数据报通过新会话认证后才打开目标 socket。PSK 握手没有前向保密。
- UDP 数据无外层可靠重传。握手可重试，数据报分片独立认证；缺片、重叠、超时及超出限额的数据报不交付应用。
- Fake TCP 对通过认证的数据和控制记录发送 ACK，保持 NAT/状态防火墙的 TCP 窗口推进；乱序数据不会使 ACK 回退。通过认证的重复记录只补发当前 ACK，不重复交付应用。
- 本地 IPv4 分片先重组，再提取 UDP 载荷；隧道分片重组限制为每会话 64 个未完成数据报、1 MiB，3 秒超时。
- UDP 初始分片载荷 1100 字节，每 15 秒发送认证过的 1400/1500 字节路径探测；仅确认后提高载荷，下一轮恢复保守基线。探测超时不会触发数据重传。低于保守基线的路径、ICMP 错误反馈及更完整的 DPLPMTUD 黑洞恢复仍需扩展和跨机测试。
- 正常分片包含 13 字节数据报元数据、24 字节认证加密记录和 40 字节 IPv4/TCP 包头，共 77 字节开销。握手另有 TCP option，未复用旧方案中的 64 字节预算。
- 每端最多 256 个 Fake TCP 会话；TCP 服务端最多 256 个并发连接。队列和重组空间有上限，UDP 过载时可丢包。活跃 UDP 会话保留原有目标 socket 和端口；双向应用数据空闲两分钟，或两分钟未收到认证过的对端记录时回收。隧道保活和路径探测不刷新应用空闲时间。

## 当前边界

仅支持客户端主动访问服务端本机 IPv4 TCP/UDP。ICMP、IPv6、广播、服务端主动连接客户端、保留原始来源 IP、GUI、Windows 服务安装，以及生产性能优化不在本原型中。
加密算法使用 Windows CNG 实现；自定义握手、记录格式和 Fake TCP 状态机尚未经过第三方安全审查。
本地双端通过只能证明当前机器上的数据路径，不能替代两台机器、真实 NAT/防火墙、动态公网 IP 变化及 ISP 链路验证。

## TCP 31828 远端测试服务

```powershell
.\scripts\server-control.ps1 -Action Start
.\scripts\server-control.ps1 -Action Probe
.\scripts\server-control.ps1 -Action Lifetime
.\scripts\server-control.ps1 -Action Stop
```

该固定操作复用已注册的管理员测试入口，启动独立的最高权限任务运行服务端和测试服务。服务端监听 `0.0.0.0:31828`，Windows 防火墙规则只允许此程序的 TCP 31828 入站。
HTTP 18082、UDP 回显 18083、TCP 回显 18084 绑定回环地址，通过虚拟 IP 访问。Stop 关闭服务端和测试进程，并清理其防火墙规则。
Lifetime 使用独立的最高权限任务运行固定的 UDP 寿命回归，执行上限二十分钟，没有自动触发器。测试通过当前 31828 服务端访问自身的随机回环目标，持续六百六十秒检查双向、仅发送和仅接收会话的目标来源端口；随后检查应用空闲回收及恢复。结果和进度写入 `test-results\udp-lifetime`。撤销测试授权时也会删除该任务。
客户端压缩包位于 `bin\flowtunnel-client-31828.zip`，包含相应密钥配置，按包内 README 操作。公网 TCP 31828 需要由路由器/ISP 映射到本机；本机探测不能替代公网两端验证。
客户端启动器按实际进程识别客户端。没有对应进程的防火墙规则自动清理；已有客户端时显示 PID 和路径，由用户确认是否停止再启动。每次启动的规则独立命名，退出时只清理自己的规则。

TCP 错误日志包含源地址、目标端口、连接阶段和存活毫秒数。双向转发错误按完成顺序标出 `primary` 和 `secondary`，分别保留 `plain_to_tunnel` / `tunnel_to_plain` 方向、失败的读写阶段，以及原始错误类别和数值。`primary` 是首先完成的失败；另一方向的错误可能来自随后的取消，也可能是独立故障。

客户端保持运行时，可以单独检查并发 UDP：

```powershell
python .\remote_probe.py --udp-only --sessions 4 --rounds 20 --results "$PWD\udp-result.json"
```

该命令通过四个独立会话交换 240 个数据报，记录每个会话的源端口和每报发送、接收、匹配结果及耗时。单个会话在首个错误后停止，其他会话的结果仍全部收集；探针不重试数据，也不将丢包报告为通过。socket 的十秒超时约束单次 I/O，持续传输不受额外的 Future 总时限影响。
