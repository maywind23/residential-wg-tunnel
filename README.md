# residential-wg-tunnel

[简体中文](README.zh-CN.md) · This English README is the authoritative documentation.

A public Linux VPS accepts TCP and UDP connections on selected ports and relays them over native WireGuard to existing proxy services in an AT&T residential container. The container initiates the tunnel. The existing proxy handles authentication, traffic accounting, and internet egress.

## Requirements

- Root access to the public VPS and the residential container is sufficient. Both need Linux, a running systemd, Python 3.9 or newer, iproute2, wireguard-tools, and nftables.
- The residential container must be able to create a native WireGuard interface. The `check` command creates and removes a temporary interface to verify this capability. If it reports `Operation not permitted` or missing WireGuard support, ask the container provider to enable it.
- The VPS must have the configured listener addresses assigned locally. With one-to-one IPv4 NAT, set `public.ipv4` to the address assigned on the VPS and have clients connect to the external mapped address. An IPv6 listener requires an IPv6 address reachable from the internet.
- Allow the WireGuard UDP port and the selected service ports through the VPS cloud and host firewalls. Allow the tunnel peer to reach the proxy ports through any existing firewall in the residential container. The installer adds a dedicated nftables table and leaves existing rules in place.

The relay binds its backend TCP and UDP sockets to the dedicated WireGuard interface. It works with global IPv6 forwarding disabled and leaves default routes, forwarding switches, and proxy configuration in place. It adds only IPv4 `/32` and IPv6 `/128` routes to the tunnel peer. Direct residential egress and any existing WARP routing still follow the container's routing policy.

## Installation

Clone the repository on both machines.

```bash
git clone https://github.com/maywind23/residential-wg-tunnel.git
cd residential-wg-tunnel
```

The commands below use the `default` instance. For multiple installations on the same machine, pass `--instance NAME` before the subcommand and give each instance its own interface name and tunnel addresses.

### 1. Generate a key on each machine

On Debian or Ubuntu, `install-deps` installs missing dependencies. On other distributions, use the system package manager.

```bash
sudo ./residential-wg-tunnel.sh install-deps
sudo ./residential-wg-tunnel.sh keygen
```

`keygen` prints only the public key and reuses the existing key on subsequent runs. The private key is stored locally at `/etc/residential-wg-tunnel/<instance>/private.key` with access restricted to root. Exchange only the public keys.

### 2. Generate and edit the configurations

On the VPS, generate the public relay configuration.

```bash
./residential-wg-tunnel.sh example vps > vps.json
```

In the residential container, generate the peer configuration.

```bash
./residential-wg-tunnel.sh example home > home.json
```

Fill in `peer.public_key` on each side with the other machine's public key. On the VPS, set `public` to the IPv4 and/or IPv6 listener addresses and `wireguard_port` to a free UDP port. On the home side, set `peer.endpoint.host` to a reachable public IP of the VPS and use the same UDP port for `peer.endpoint.port`. The default keepalive interval is 25 seconds. Replace the example public IPs and check that the private tunnel addresses do not overlap with your existing networks.

For each entry in the VPS `ports` array, configure the following fields.

- `listen` is the public port. `target` is the home peer's tunnel port and defaults to `listen`.
- `protocols` matches what the application actually listens on. Use `["tcp"]`, `["udp"]`, or `["tcp", "udp"]`.
- `target_family` defaults to the public listener's address family. Set it to `"ipv4"` to reach an IPv4-only backend from an IPv6 listener. The backend still chooses the address family for its own outbound connections.
- The proxy sees the relay's tunnel address as the connection source. Use `"source_policy": "none"` only after confirming that the backend has no source restrictions. To enforce existing source restrictions at the VPS, use `"source_policy": "acl"` with `allow` and `deny` CIDR lists. Deny rules take precedence. If the application requires the original client IP for accounting or session limits, keep that port on its existing ingress path.
- For UDP, set `"udp_security": "authenticated"` only after verifying that the application authenticates its UDP traffic, such as a correctly configured Shadowsocks inbound. With `"udp_security": "allowlist"`, supply an `allow` list. Protocols that advertise a separate UDP endpoint or bind UDP to a control session, such as SOCKS5 UDP ASSOCIATE, require protocol-aware handling beyond port forwarding.

In the home `ports` array, list each tunnel port and its protocols. If the service already listens on a wildcard or tunnel address, the relay can reach it directly. For a service bound to loopback, use a free tunnel port as a handoff. This example exposes a service listening on `127.0.0.1:30443` through tunnel port `31443`.

```json
{
  "listen": 31443,
  "protocols": ["tcp", "udp"],
  "loopback": {
    "ipv4": {"host": "127.0.0.1", "port": 30443},
    "ipv6": {"host": "127.0.0.1", "port": 30443}
  }
}
```

Set `"listen": 30443, "target": 31443` in the corresponding VPS entry. If the residential NAT has a known, fixed egress address, `wireguard_sources` can restrict incoming handshakes to a list of CIDRs. This setting applies only to the dedicated WireGuard UDP port.

### 3. Check, install, and verify

Run these commands on the VPS first, then repeat them in the residential container with `home.json` in place of `vps.json`. The optional `validate` command checks the configuration without applying it. The root-only `check` command also checks local capabilities and available listeners.

```bash
./residential-wg-tunnel.sh validate vps.json
sudo ./residential-wg-tunnel.sh check vps.json
sudo ./residential-wg-tunnel.sh install vps.json
sudo ./residential-wg-tunnel.sh status
```

For the initial test, use an unused public `listen` port. From an external client, test public IPv4 and IPv6, proxy authentication, each configured transport, and the egress IP seen by the destination. If the proxy panel tracks usage, check that the original inbound records the traffic. On the temporary port, stop the tunnel on the home side and confirm that proxy requests fail, then start it and verify recovery. A VPS listener can still accept a TCP handshake while the home side is down.

After testing, set `listen` to the intended public port and run `update`. It briefly interrupts connections for that instance. If the new configuration fails to start, the installer restores the previous configuration and attempts to restart it. The VPS remembers the last authenticated WireGuard peer endpoint so it can reestablish the session with the same peer after a restart.

## Management and uninstall

```bash
sudo ./residential-wg-tunnel.sh status
sudo ./residential-wg-tunnel.sh stop
sudo ./residential-wg-tunnel.sh start
sudo ./residential-wg-tunnel.sh update vps.json
sudo ./residential-wg-tunnel.sh uninstall
```

Use the local configuration file for `update`. Uninstall on each machine to remove that instance's systemd unit, configuration, interface, and dedicated nftables table. The key is retained for reinstallation by default. Use `uninstall --purge-key` to remove it. Cloud firewall changes and packages installed separately are managed outside the installer.

View logs for the default instance with the following command.

```bash
sudo journalctl -u residential-wg-tunnel-default.service -n 50
```

## Integration tests

Run `sudo bash tests/integration.sh` on Linux with network namespace support and systemd. The suite creates an isolated test network and verifies native WireGuard, dual-stack TCP and UDP, large payloads, source ACLs, loopback handoff, recovery after a tunnel outage, update rollback, and uninstall. It uses temporary services, networks, and keys and cleans them up on exit.
