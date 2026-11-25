# residential-wg-tunnel

公网 Linux VPS 接收 TCP/UDP，经原生 WireGuard 把指定端口的流量交给 AT&T 家宽容器里的现有代理。容器主动建立隧道，代理认证、计费和互联网出站由原服务处理。

## 适用环境

- 只需要公网 VPS 和家宽容器的 root 权限。两端需有 Linux、正在运行的 systemd、Python 3.9+、iproute2、wireguard-tools 和 nftables。
- 家宽容器必须有创建原生 WireGuard 接口的权限。先运行 `check`，该命令会创建一个临时接口验证权限并删除它。若返回 `Operation not permitted` 或内核不支持 WireGuard，需服务商开放相应能力。
- 公网地址应已配置在 VPS 上。IPv4 一对一 NAT 场景中，`public.ipv4` 填 VPS 实际绑定的本地地址，客户连接外部映射地址。IPv6 入口需要 VPS 具有可从外部到达的 IPv6。
- 放行 VPS 上的 WireGuard UDP 端口和指定的业务端口。云防火墙或已有默认拒绝规则需要在对应的策略中授权这些端口。脚本新增独立 nftables 表，保留现有规则。也请核对家宽容器的防火墙允许隧道对端访问对应代理端口。

转发使用绑定 WireGuard 接口的 TCP/UDP 套接字，适用于全局 IPv6 转发关闭的 VPS。脚本保留默认路由、全局转发开关和现有代理配置。它只为两个隧道对端添加 IPv4 `/32` 和 IPv6 `/128` 路由。原生直连和已有 WARP 分流继续由家宽容器的现有出站策略决定。

## 安装

在两台机器上克隆私有仓库。请先让用于克隆的 GitHub 账号获得读取权限。

```bash
git clone git@github.com:maywind23/residential-wg-tunnel.git
cd residential-wg-tunnel
```

下列步骤假设使用默认实例。若同一台机器有多个部署，每条命令在子命令前加同一个 `--instance 名称`，同时选择独立的接口名和隧道地址。

### 1. 两端分别生成密钥

Debian 或 Ubuntu 可用 `install-deps` 安装缺少的工具。其他发行版使用自己的包管理器。

```bash
sudo ./residential-wg-tunnel.sh install-deps
sudo ./residential-wg-tunnel.sh keygen
```

`keygen` 只打印公钥，重复执行会保留原密钥。私钥由 root 保存在本机的 `/etc/residential-wg-tunnel/<实例>/private.key`。只交换公钥。

### 2. 生成并填写 JSON

在 VPS 上生成前置配置模板。

```bash
./residential-wg-tunnel.sh example vps > vps.json
```

在家宽容器上生成对端配置模板。

```bash
./residential-wg-tunnel.sh example home > home.json
```

填写两端的 `peer.public_key`。VPS 的 `public` 填实际 IPv4/IPv6 监听地址，`wireguard_port` 填可用的 UDP 端口。家宽端 `peer.endpoint.host` 填 VPS 可达的公网 IP，端口填同一个 `wireguard_port`。默认保活为 25 秒。示例 IP 仅用于文档，隧道地址也要检查是否和现有网段重叠。

VPS 的每条 `ports` 配置包括：

- `listen` 是公网端口，`target` 是家宽端的隧道端口，省略时与 `listen` 相同。
- `protocols` 按原应用实际监听填 `["tcp"]`、`["udp"]` 或 `["tcp","udp"]`。
- `target_family` 默认跟随公网入口。家宽代理只监听 IPv4 时可填 `"ipv4"`，保留 IPv6 公网入口。家宽应用访问目的地的地址族仍由原代理决定。
- 转发后的连接源是隧道地址，后端看不到真实客户端 IP。已确认后端没有来源限制时填 `"source_policy":"none"`。存在来源规则时，在 VPS 用 `"source_policy":"acl"` 和 `allow`、`deny` CIDR 列表等效执行，拒绝列表优先。若原应用依赖真实源 IP 计数或限制会话，先保留该端口的原访问方式。
- UDP 用 `udp_security: "authenticated"` 声明确认应用能认证自身的 UDP 流量，例如经过核实的 Shadowsocks 加密入站。使用 `"allowlist"` 时必须填写 `allow`。依赖 SOCKS5 UDP ASSOCIATE 返回地址或控制会话身份的端口，需要先处理该协议的协商规则。

家宽端的 `ports` 列出每个隧道监听端口和协议。应用已经监听通配或隧道地址时，家宽端直接把流量交给该监听。若服务只监听回环，可以使用一个空闲的隧道端口做回环映射，原服务继续绑定原地址。以下示例中，原 Snell 监听在回环端口 55485。

```json
{
  "listen": 35485,
  "protocols": ["tcp", "udp"],
  "loopback": {
    "ipv4": {"host": "127.0.0.1", "port": 55485},
    "ipv6": {"host": "127.0.0.1", "port": 55485}
  }
}
```

此时对应的 VPS 映射写 `"listen":55485,"target":35485`。VPS 如果知道家宽 NAT 的固定出口，可用 `wireguard_sources` CIDR 列表限制 WireGuard 握手的来源。该字段只影响专用 WireGuard UDP 端口。

### 3. 检查、启动并验证

在两端使用各自的配置文件。建议先启动 VPS，再启动家宽端。

```bash
sudo ./residential-wg-tunnel.sh check vps.json
sudo ./residential-wg-tunnel.sh install vps.json
sudo ./residential-wg-tunnel.sh status
```

家宽端把 `vps.json` 换成 `home.json`。若首次验收，先把 VPS 的 `listen` 设为空闲临时端口。用真实客户端从外部测试公共 IPv4 和 IPv6、原代理认证、TCP/UDP 以及目标网站看到的 IP。若节点有面板计数，核对原入站的计数。仅在临时入口测试停掉家宽端隧道后的断流和恢复。VPS 上的 TCP 监听可能仍接受握手，判据是代理请求不再完成。

验收后把 VPS 的 `listen` 改为正式端口，用 `update` 应用。该操作只重启指定实例，会短暂停止这个实例的连接。如果新配置启动失败，安装器会恢复旧配置并尝试重新启动它。VPS 会保留最近一次 WireGuard 对端地址，以便同一对端在 VPS 服务重启后重新握手。

## 日常操作和卸载

```bash
sudo ./residential-wg-tunnel.sh status
sudo ./residential-wg-tunnel.sh stop
sudo ./residential-wg-tunnel.sh start
sudo ./residential-wg-tunnel.sh update vps.json
sudo ./residential-wg-tunnel.sh uninstall
```

两端均可卸载。默认保留该实例的私钥以便重装，确定要移除密钥时使用 `uninstall --purge-key`。卸载只清理该实例的 unit、配置、接口和专属 nftables 表。此前手动添加的云防火墙策略和系统包由管理员管理。

可用下面的命令查看服务日志。

```bash
sudo journalctl -u residential-wg-tunnel-default.service -n 50
```

## 隔离回归测试

`sudo bash tests/integration.sh` 在支持网络命名空间和 systemd 的 Linux 上创建临时测试网络。测试覆盖真实 WireGuard、TCP/UDP 双栈、大包、ACL、回环后端、断流恢复、更新回滚和卸载。脚本使用独立的测试 unit 和端口，退出后清理测试网络。
