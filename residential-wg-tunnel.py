#!/usr/bin/env python3
"""Manage one native WireGuard link and a narrowly scoped TCP/UDP relay."""

import argparse
import asyncio
import base64
import binascii
import contextlib
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


STATE = Path("/etc/residential-wg-tunnel")
UNITS = Path("/etc/systemd/system")
SCRIPT = Path(__file__).resolve()
FAMILIES = {"ipv4": 4, "ipv6": 6}
UDP_IDLE = 90
UDP_SESSIONS = 512
TCP_SESSIONS = 512


class ConfigError(ValueError):
    pass


def cmd(*args, content=None, capture=False, check=True):
    return subprocess.run(args, input=content, text=True, capture_output=capture, check=check)


def valid_name(value):
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,23}", value):
        raise ConfigError("Use 1–24 lowercase letters, digits, hyphens or underscores for the instance.")
    return value


def section(data, required, optional=()):
    if not isinstance(data, dict):
        raise ConfigError("Expected a JSON object.")
    missing = set(required) - data.keys()
    unknown = data.keys() - set(required) - set(optional)
    if missing or unknown:
        raise ConfigError(f"Missing fields: {', '.join(sorted(missing)) or 'none'}; "
                          f"unknown fields: {', '.join(sorted(unknown)) or 'none'}.")
    return data


def integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ConfigError(f"{name} must be an integer from {low} to {high}.")
    return value


def port(value):
    return integer(value, "port", 1, 65535)


def address(value):
    if not isinstance(value, str) or "%" in value:
        raise ConfigError("Use a literal IP address without a zone suffix.")
    ip = ipaddress.ip_address(value)
    if (ip.is_multicast or ip.is_unspecified or ip.is_link_local
            or ip == ipaddress.IPv4Address("255.255.255.255")
            or (ip.version == 6 and ip.ipv4_mapped)):
        raise ConfigError(f"Unsupported endpoint address {ip}.")
    return ip


def family_addresses(value, *, both):
    section(value, FAMILIES if both else (), () if both else FAMILIES)
    if not value:
        raise ConfigError("Configure at least one IP address.")
    result = {name: address(ip) for name, ip in value.items()}
    if any(ip.version != FAMILIES[name] or ip.is_loopback for name, ip in result.items()):
        raise ConfigError("Address family mismatch or loopback address in a tunnel/VPS address.")
    return result


def cidrs(values):
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise ConfigError("CIDR lists must be JSON arrays of strings.")
    return tuple(ipaddress.ip_network(item, strict=True) for item in values)


def public_key(value):
    if not isinstance(value, str):
        raise ConfigError("peer.public_key must be a WireGuard public key.")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ConfigError("Invalid WireGuard public key.") from exc
    if len(raw) != 32 or not any(raw) or base64.b64encode(raw).decode() != value:
        raise ConfigError("Invalid WireGuard public key.")
    return value


class Configuration:
    def __init__(self, data):
        self.raw = section(data, ("role", "interface", "tunnel", "peer", "ports"),
                           ("public", "wireguard_port", "wireguard_sources", "mtu"))
        self.role = data["role"]
        if self.role not in ("vps", "home"):
            raise ConfigError("role must be vps or home.")
        self.interface = data["interface"]
        if (not isinstance(self.interface, str) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,14}", self.interface)
                or self.interface == "lo"):
            raise ConfigError("Use a dedicated Linux interface name of up to 15 characters.")
        self.mtu = integer(data.get("mtu", 1380), "mtu", 1280, 9000)
        self.local = family_addresses(data["tunnel"], both=True)
        peer = section(data["peer"], ("public_key", "ipv4", "ipv6"),
                       ("endpoint", "keepalive") if self.role == "home" else ())
        self.peer = family_addresses({key: peer[key] for key in FAMILIES}, both=True)
        self.key = public_key(peer["public_key"])
        if any(self.local[key] == self.peer[key] for key in FAMILIES):
            raise ConfigError("Each side needs its own tunnel addresses.")
        self.sources = cidrs(data.get("wireguard_sources", []))
        if self.role == "vps":
            self.public = family_addresses(data.get("public"), both=False)
            self.wg_port = port(data.get("wireguard_port"))
            if set(self.public.values()) & (set(self.local.values()) | set(self.peer.values())):
                raise ConfigError("Public listener addresses must differ from both tunnel peers.")
        else:
            if any(key in data for key in ("public", "wireguard_port", "wireguard_sources")):
                raise ConfigError("public, wireguard_port and wireguard_sources apply only to the VPS.")
            endpoint = section(peer.get("endpoint"), ("host", "port"))
            self.endpoint = (address(endpoint["host"]), port(endpoint["port"]))
            if self.endpoint[0].is_loopback or self.endpoint[0] in (*self.local.values(), *self.peer.values()):
                raise ConfigError("WireGuard endpoint must be the VPS uplink, outside the tunnel.")
            self.keepalive = integer(peer.get("keepalive", 25), "keepalive", 1, 65535)

        if not isinstance(data["ports"], list) or not data["ports"]:
            raise ConfigError("Configure at least one port.")
        self.ports = [self.parse_port(entry) for entry in data["ports"]]
        bindings = [(entry["listen"], proto) for entry in self.ports for proto in entry["protocols"]]
        if len(bindings) != len(set(bindings)):
            raise ConfigError("Each listen port/protocol pair must be unique.")
        if self.role == "vps" and (self.wg_port, "udp") in bindings:
            raise ConfigError("The WireGuard port conflicts with a UDP relay port.")

    def parse_port(self, entry):
        section(entry, ("listen", "protocols"),
                ("target", "target_family", "source_policy", "allow", "deny", "udp_security")
                if self.role == "vps" else ("loopback",))
        result = dict(entry)
        port(entry["listen"])
        protocols = entry["protocols"]
        if (not isinstance(protocols, list) or not protocols
                or any(p not in ("tcp", "udp") for p in protocols) or len(protocols) != len(set(protocols))):
            raise ConfigError("protocols must contain tcp, udp or both with no duplicates.")
        if self.role == "home":
            if "loopback" in entry:
                loopback = section(entry["loopback"], ("ipv4", "ipv6"))
                for name, spec in loopback.items():
                    endpoint = section(spec, ("host", "port"))
                    ip = address(endpoint["host"])
                    if not ip.is_loopback:
                        raise ConfigError("home loopback handoff can only target a loopback address.")
                    port(endpoint["port"])
            return result

        result["target"] = port(entry.get("target", entry["listen"]))
        target_family = entry.get("target_family", "same")
        if target_family not in ("same", *FAMILIES):
            raise ConfigError("target_family must be same, ipv4 or ipv6.")
        result["target_family"] = target_family
        result["allow"] = cidrs(entry.get("allow", []))
        result["deny"] = cidrs(entry.get("deny", []))
        policy = entry.get("source_policy")
        if policy == "acl" and not (result["allow"] or result["deny"]):
            raise ConfigError("source_policy=acl requires source CIDRs in allow or deny.")
        if policy == "none" and (result["allow"] or result["deny"]):
            raise ConfigError("Use source_policy=acl when specifying an ACL.")
        if policy not in ("none", "acl"):
            raise ConfigError("Set source_policy to none after checking the backend, or migrate its ACLs and use acl.")
        if "udp" in protocols:
            security = entry.get("udp_security")
            if security == "allowlist" and not result["allow"]:
                raise ConfigError("udp_security=allowlist requires explicit allowed client networks.")
            if security not in ("authenticated", "allowlist"):
                raise ConfigError("Specify authenticated UDP or an explicit UDP client allowlist.")
        return result


def read_config(path):
    return Configuration(json.loads(Path(path).read_text(encoding="utf-8")))


class Paths:
    def __init__(self, instance):
        self.name = valid_name(instance)
        self.dir = STATE / instance
        self.private = self.dir / "private.key"
        self.learned = self.dir / "learned-peer.json"
        self.config = self.dir / "config.json"
        self.runner = self.dir / "runner.py"
        self.unit_name = f"residential-wg-tunnel-{instance}.service"
        self.unit = UNITS / self.unit_name
        self.owner = f"residential-wg-tunnel:{instance}"
        # The hash-free hex encoding is also unique for names containing hyphens or underscores.
        self.table = "rwg_" + instance.encode().hex()

    def make_dir(self):
        STATE.mkdir(mode=0o700, exist_ok=True)
        require_private_dir(STATE)
        self.dir.mkdir(mode=0o700, exist_ok=True)
        require_private_dir(self.dir)


def require_private_dir(path):
    if path.is_symlink() or not path.is_dir() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
        raise ConfigError(f"Require a private, root-owned directory at {path}.")


def atomic(path, text, mode=0o600):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        tmp = Path(stream.name)
        try:
            stream.write(text)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)


def root_and_linux():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ConfigError("This command requires root access on Linux.")


def dependencies(*tools):
    missing = [tool for tool in tools if not shutil.which(tool)]
    if missing:
        raise ConfigError(f"Missing commands: {', '.join(missing)}. Install dependencies first.")


def probe_kernel():
    interface = "rwgp" + secrets.token_hex(4)
    probe = cmd("ip", "link", "add", "dev", interface, "type", "wireguard", capture=True, check=False)
    if probe.returncode:
        raise ConfigError("Native WireGuard interface creation failed in this namespace: "
                          + probe.stderr.strip())
    cmd("ip", "link", "del", "dev", interface)


def public_from_private(path):
    if not path.is_file() or path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
        raise ConfigError("Generate a private key with keygen before installation.")
    return cmd("wg", "pubkey", content=path.read_text(), capture=True).stdout.strip()


def keygen(paths):
    root_and_linux()
    dependencies("wg")
    paths.make_dir()
    if not paths.private.exists():
        private = cmd("wg", "genkey", capture=True).stdout
        with open(paths.private, "x", encoding="utf-8", opener=secure_open) as stream:
            stream.write(private)
    print(public_from_private(paths.private))


def secure_open(path, flags):
    return os.open(path, flags, 0o600)


def link_owner(name):
    result = cmd("ip", "-j", "-d", "link", "show", "dev", name, capture=True, check=False)
    if result.returncode:
        return None
    return json.loads(result.stdout)[0].get("ifalias", "")


def table_owner(table):
    result = cmd("nft", "-j", "list", "table", "inet", table, capture=True, check=False)
    if result.returncode:
        return None
    return next((item["table"].get("comment", "") for item in json.loads(result.stdout)["nftables"]
                 if "table" in item), "")


def prefix(ip):
    return f"{ip}/{ip.max_prefixlen}"


def learned_endpoint(config, paths):
    if not paths.learned.is_file():
        return None
    try:
        peer = json.loads(paths.learned.read_text())
        if peer["key"] != config.key:
            return None
        host = address(peer["host"])
        if host.is_loopback or host in (*config.local.values(), *config.peer.values()):
            return None
        if config.sources and not any(host in allowed for allowed in config.sources):
            return None
        return host, port(peer["port"])
    except (KeyError, TypeError, ValueError, OSError):
        return None


def remember_endpoint(config, paths):
    if config.role != "vps":
        return
    result = cmd("wg", "show", config.interface, "endpoints", capture=True, check=False)
    if result.returncode:
        return
    for line in result.stdout.splitlines():
        key, _, endpoint = line.partition("\t")
        if key == config.key and endpoint != "(none)":
            host, _, number = endpoint.rpartition(":")
            with contextlib.suppress(ValueError, OSError):
                atomic(paths.learned, json.dumps({"key": key, "host": str(address(host.strip("[]"))),
                                                  "port": port(int(number))}) + "\n")
            return


def wg_conf(config, paths):
    private = paths.private.read_text()
    lines = ["[Interface]", f"PrivateKey = {private.strip()}"]
    if config.role == "vps":
        lines.append(f"ListenPort = {config.wg_port}")
    lines += ["", "[Peer]", f"PublicKey = {config.key}",
              "AllowedIPs = " + ", ".join(map(prefix, config.peer.values()))]
    peer_endpoint = config.endpoint if config.role == "home" else learned_endpoint(config, paths)
    if peer_endpoint:
        host, number = peer_endpoint
        addr = f"[{host}]" if host.version == 6 else str(host)
        interval = config.keepalive if config.role == "home" else 25
        lines += [f"Endpoint = {addr}:{number}", f"PersistentKeepalive = {interval}"]
    return "\n".join(lines) + "\n"


def nft_rules(config, paths):
    """The new chains limit this interface/port and leave other chains in force."""
    iif = f'iifname "{config.interface}"'
    input_rules = [f"{iif} ct state established,related counter accept"]
    if config.role == "home":
        for family, keyword in (("ipv4", "ip"), ("ipv6", "ip6")):
            for protocol in ("tcp", "udp"):
                ports = [str(p["listen"]) for p in config.ports if protocol in p["protocols"]]
                if ports:
                    input_rules.append(f"{iif} {keyword} saddr {config.peer[family]} "
                                       f"{keyword} daddr {config.local[family]} "
                                       f"{protocol} dport {{ {', '.join(ports)} }} counter accept")
    elif config.sources:
        for family, keyword in ((4, "ip"), (6, "ip6")):
            matches = [str(net) for net in config.sources if net.version == family]
            expression = f" {keyword} saddr != {{ {', '.join(matches)} }}" if matches else ""
            input_rules.append(f"meta nfproto ipv{family}{expression} udp dport {config.wg_port} counter drop")
    input_rules.append(f"{iif} counter drop")
    rules = "\n".join(f"    {line}" for line in input_rules)
    return f'''table inet {paths.table} {{
  comment "{paths.owner}"
  chain input {{
    type filter hook input priority filter - 10; policy accept;
{rules}
  }}
  chain forward {{
    type filter hook forward priority filter - 10; policy accept;
    {iif} counter drop
    oifname "{config.interface}" counter drop
  }}
}}
'''


def clean_network(config, paths):
    if link_owner(config.interface) == paths.owner:
        remember_endpoint(config, paths)
        cmd("ip", "link", "del", "dev", config.interface)
    if table_owner(paths.table) == paths.owner:
        cmd("nft", "delete", "table", "inet", paths.table)


def start_network(config, paths):
    if link_owner(config.interface) is not None or table_owner(paths.table) is not None:
        raise ConfigError("Interface or nftables table already exists. Choose an unused interface/instance.")
    cmd("ip", "link", "add", "dev", config.interface, "type", "wireguard")
    try:
        cmd("ip", "link", "set", "dev", config.interface, "alias", paths.owner)
    except subprocess.CalledProcessError:
        cmd("ip", "link", "del", "dev", config.interface)
        raise
    cmd("nft", "-f", "-", content=nft_rules(config, paths))
    cmd("wg", "setconf", config.interface, "/dev/stdin",
        content=wg_conf(config, paths))
    cmd("ip", "link", "set", "dev", config.interface, "mtu", str(config.mtu), "up")
    for family, version in FAMILIES.items():
        local = config.local[family]
        flags = ("nodad",) if version == 6 else ()
        cmd("ip", f"-{version}", "address", "add", prefix(local), "dev", config.interface, *flags)
        cmd("ip", f"-{version}", "route", "add", prefix(config.peer[family]),
            "dev", config.interface, "src", str(local))


def socket_for(ip, kind):
    handle = socket.socket(socket.AF_INET if ip.version == 4 else socket.AF_INET6, kind)
    handle.setblocking(False)
    if ip.version == 6:
        handle.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    return handle


class RelayPort:
    def __init__(self, config, family, entry):
        self.listen = config.public[family] if config.role == "vps" else config.local[family]
        self.port = entry["listen"]
        self.protocols = entry["protocols"]
        self.allow = entry.get("allow", ())
        self.deny = entry.get("deny", ())
        self.interface = None
        self.source = None
        if config.role == "vps":
            target_family = family if entry["target_family"] == "same" else entry["target_family"]
            self.interface = config.interface
            self.source = config.local[target_family]
            self.target = config.peer[target_family]
            self.target_port = entry["target"]
        else:
            backend = entry["loopback"][family]
            self.target = address(backend["host"])
            self.target_port = backend["port"]
        self.sessions = set()

    def permits(self, client):
        ip = ipaddress.ip_address(client[0].split("%")[0])
        return not any(ip in net for net in self.deny) and (not self.allow or any(ip in net for net in self.allow))

    def upstream(self, kind):
        upstream = socket_for(self.target, kind)
        try:
            if self.interface:
                upstream.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.interface.encode() + b"\0")
                upstream.bind((str(self.source), 0))
            return upstream
        except OSError:
            upstream.close()
            raise

    async def stream(self, reader, writer):
        client = writer.get_extra_info("peername")
        task = asyncio.current_task()
        if not self.permits(client) or len(self.sessions) >= TCP_SESSIONS:
            writer.close()
            return
        self.sessions.add(task)
        other = None
        upstream = None
        try:
            upstream = self.upstream(socket.SOCK_STREAM)
            await asyncio.wait_for(asyncio.get_running_loop().sock_connect(
                upstream, (str(self.target), self.target_port)), timeout=8)
            downstream, other = await asyncio.open_connection(sock=upstream)
            upstream = None
            await bridge(reader, other, downstream, writer)
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            if upstream:
                upstream.close()
            for connection in (writer, other):
                if connection:
                    connection.close()
            self.sessions.discard(task)


async def bridge(source, target, remote, local):
    async def copy(reader, writer):
        while chunk := await reader.read(65536):
            writer.write(chunk)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()

    tasks = [asyncio.create_task(copy(src, dst)) for src, dst in ((source, target), (remote, local))]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class UDPRelay(asyncio.DatagramProtocol):
    def __init__(self, spec, listener):
        self.spec = spec
        self.listener = listener
        self.loop = asyncio.get_running_loop()
        self.peers = {}
        self.expiry = None

    def connection_made(self, _):
        self.expiry = self.loop.call_later(10, self.expire)

    def datagram_received(self, data, client):
        if not self.spec.permits(client):
            return
        if client not in self.peers:
            if len(self.peers) >= UDP_SESSIONS:
                return
            upstream = None
            try:
                upstream = self.spec.upstream(socket.SOCK_DGRAM)
                upstream.connect((str(self.spec.target), self.spec.target_port))
                self.loop.add_reader(upstream, self.reply, client)
            except OSError:
                if upstream:
                    upstream.close()
                return
            self.peers[client] = (upstream, time.monotonic())
        upstream, _ = self.peers[client]
        try:
            upstream.send(data)
            self.peers[client] = (upstream, time.monotonic())
        except BlockingIOError:
            pass
        except OSError:
            self.remove(client)

    def reply(self, client):
        entry = self.peers.get(client)
        if not entry:
            return
        upstream, _ = entry
        try:
            self.listener.sendto(upstream.recv(65535), client)
            self.peers[client] = (upstream, time.monotonic())
        except BlockingIOError:
            pass
        except OSError:
            self.remove(client)

    def remove(self, client):
        upstream, _ = self.peers.pop(client)
        self.loop.remove_reader(upstream)
        upstream.close()

    def expire(self):
        threshold = time.monotonic() - UDP_IDLE
        for client, (_, seen) in list(self.peers.items()):
            if seen < threshold:
                self.remove(client)
        self.expiry = self.loop.call_later(10, self.expire)

    def connection_lost(self, _):
        if self.expiry:
            self.expiry.cancel()
        for client in list(self.peers):
            self.remove(client)


def listeners(config):
    if config.role == "vps":
        return [RelayPort(config, family, entry) for family in config.public for entry in config.ports]
    return [RelayPort(config, family, entry) for family in config.local for entry in config.ports if "loopback" in entry]


def bind(spec, kind):
    handle = socket_for(spec.listen, kind)
    try:
        if kind == socket.SOCK_STREAM:
            handle.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        handle.bind((str(spec.listen), spec.port))
        return handle
    except OSError as exc:
        handle.close()
        raise ConfigError(f"Cannot bind {spec.listen}:{spec.port}: {exc.strerror}.") from exc


def notify():
    address = os.environ.get("NOTIFY_SOCKET")
    if address:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"READY=1", "\0" + address[1:] if address.startswith("@") else address)


async def operate(config, paths):
    loop = asyncio.get_running_loop()
    stopped = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stopped.set)
    tcp, udp = [], []
    entries = listeners(config)
    try:
        start_network(config, paths)
        for entry in entries:
            if "tcp" in entry.protocols:
                handle = bind(entry, socket.SOCK_STREAM)
                try:
                    tcp.append(await asyncio.start_server(entry.stream, sock=handle))
                except BaseException:
                    handle.close()
                    raise
            if "udp" in entry.protocols:
                handle = bind(entry, socket.SOCK_DGRAM)
                try:
                    transport, _ = await loop.create_datagram_endpoint(lambda: UDPRelay(entry, handle), sock=handle)
                except BaseException:
                    handle.close()
                    raise
                udp.append(transport)
        notify()
        print(f"{config.role} ready on {config.interface} ({len(tcp)} TCP, {len(udp)} UDP listeners)", flush=True)
        await stopped.wait()
    finally:
        for server in tcp:
            server.close()
        for transport in udp:
            transport.close()
        sessions = [task for entry in entries for task in entry.sessions]
        for task in sessions:
            task.cancel()
        await asyncio.gather(*(server.wait_closed() for server in tcp), *sessions, return_exceptions=True)
        clean_network(config, paths)


def systemd():
    dependencies("systemctl")
    if not Path("/run/systemd/system").is_dir():
        raise ConfigError("Persistent install requires a running systemd inside this machine/container.")


def unit_text(paths):
    return f"""[Unit]
Description=Residential WireGuard tunnel ({paths.name})
Wants=network-online.target
After=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/env python3 {paths.runner} --instance {paths.name} serve
ExecStopPost=/usr/bin/env python3 {paths.runner} --instance {paths.name} cleanup
Restart=on-failure
RestartSec=5
TimeoutStartSec=25

[Install]
WantedBy=multi-user.target
"""


def unit_owned(paths):
    if not paths.unit.exists() or paths.unit.is_symlink():
        return False
    return paths.unit.read_text() == unit_text(paths)


def inspect(config, paths, *, check_bind):
    root_and_linux()
    dependencies("ip", "wg", "nft")
    probe_kernel()
    if config.role == "home":
        route = cmd("ip", f"-{config.endpoint[0].version}", "route", "get", str(config.endpoint[0]),
                    capture=True, check=False)
        if route.returncode or f"dev {config.interface}" in route.stdout:
            raise ConfigError("The VPS endpoint needs a reachable uplink route outside the new tunnel.")
    owner = link_owner(config.interface)
    if owner not in (None, paths.owner):
        raise ConfigError(f"Interface {config.interface} is already in use.")
    if table_owner(paths.table) not in (None, paths.owner):
        raise ConfigError(f"Firewall table {paths.table} is already in use.")
    for ip in (*config.local.values(), *config.peer.values()):
        assigned = cmd("ip", "-j", f"-{ip.version}", "address", "show", capture=True)
        for link in json.loads(assigned.stdout):
            if link["ifname"] != config.interface and any(item.get("local") == str(ip) for item in link.get("addr_info", [])):
                raise ConfigError(f"Tunnel address {ip} is already assigned on {link['ifname']}.")
        existing = cmd("ip", "-j", f"-{ip.version}", "route", "show", "table", "main", capture=True)
        for route in json.loads(existing.stdout):
            network = route.get("dst", "default")
            if network != "default" and route.get("dev") != config.interface and ip in ipaddress.ip_network(network):
                raise ConfigError(f"Tunnel address {ip} overlaps existing route {network}.")
    if check_bind and owner is None and config.role == "vps":
        for spec in listeners(config):
            for proto in spec.protocols:
                bind(spec, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM).close()
        # Linux WireGuard owns one IPv4 socket and, where enabled, an IPv6 socket.
        for address_text in ("0.0.0.0", "::"):
            af = socket.AF_INET if ":" not in address_text else socket.AF_INET6
            with socket.socket(af, socket.SOCK_DGRAM) as hold:
                if af == socket.AF_INET6:
                    hold.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                try:
                    hold.bind((address_text, config.wg_port))
                except OSError as exc:
                    raise ConfigError(f"WireGuard UDP port {config.wg_port} is unavailable: {exc.strerror}.") from exc


def payload(config):
    return json.dumps(config.raw, sort_keys=True, indent=2) + "\n"


def start_unit(paths):
    cmd("systemctl", "reset-failed", paths.unit_name, capture=True, check=False)
    cmd("systemctl", "enable", "--now", paths.unit_name)
    cmd("systemctl", "is-active", "--quiet", paths.unit_name)


def remove_unit(paths):
    if unit_owned(paths):
        cmd("systemctl", "disable", "--now", paths.unit_name)
        paths.unit.unlink()
        cmd("systemctl", "daemon-reload")


def install(paths, config):
    root_and_linux()
    systemd()
    inspect(config, paths, check_bind=True)
    public_from_private(paths.private)
    if paths.unit.exists() and not unit_owned(paths):
        raise ConfigError(f"Refusing to overwrite existing unit {paths.unit}.")
    if paths.config.exists():
        if paths.config.read_text() != payload(config):
            raise ConfigError("A different configuration is installed. Use update.")
        if not unit_owned(paths) or not paths.runner.is_file():
            raise ConfigError("Incomplete installation. Use uninstall before reinstalling.")
        start_unit(paths)
        return
    if paths.runner.exists() or paths.unit.exists():
        raise ConfigError("Installer artifacts exist without a matching configuration.")
    try:
        atomic(paths.config, payload(config))
        atomic(paths.runner, SCRIPT.read_text(), 0o700)
        atomic(paths.unit, unit_text(paths), 0o644)
        cmd("systemctl", "daemon-reload")
        start_unit(paths)
    except BaseException:
        remove_unit(paths)
        clean_network(config, paths)
        paths.config.unlink(missing_ok=True)
        paths.runner.unlink(missing_ok=True)
        raise


def update(paths, config):
    root_and_linux()
    systemd()
    if not unit_owned(paths) or not paths.runner.is_file():
        raise ConfigError("No installed instance to update.")
    old_text = paths.config.read_text()
    old_runner = paths.runner.read_text()
    inspect(config, paths, check_bind=False)
    cmd("systemctl", "stop", paths.unit_name)
    try:
        inspect(config, paths, check_bind=True)
        atomic(paths.config, payload(config))
        atomic(paths.runner, SCRIPT.read_text(), 0o700)
        start_unit(paths)
    except BaseException:
        cmd("systemctl", "stop", paths.unit_name)
        atomic(paths.config, old_text)
        atomic(paths.runner, old_runner, 0o700)
        start_unit(paths)
        print("Previous configuration restored.", file=sys.stderr)
        raise


def uninstall(paths, purge_key):
    root_and_linux()
    systemd()
    if paths.unit.exists() and not unit_owned(paths):
        raise ConfigError(f"Refusing to remove unrelated unit {paths.unit}.")
    remove_unit(paths)
    if paths.config.exists():
        clean_network(read_config(paths.config), paths)
        paths.config.unlink()
        paths.runner.unlink(missing_ok=True)
    paths.learned.unlink(missing_ok=True)
    if purge_key:
        paths.private.unlink(missing_ok=True)
    if paths.dir.exists() and not any(paths.dir.iterdir()):
        paths.dir.rmdir()
    print("Removed the instance." + ("" if purge_key else " Any private key was retained for reinstall."))


def status(paths):
    root_and_linux()
    config = read_config(paths.config)
    cmd("systemctl", "show", paths.unit_name, "-p", "ActiveState", "-p", "SubState", check=False)
    if link_owner(config.interface) == paths.owner:
        for item in ("public-key", "listen-port", "endpoints", "latest-handshakes", "transfer"):
            result = cmd("wg", "show", config.interface, item, capture=True)
            print(f"{item} {result.stdout.strip()}")
    else:
        print(f"Tunnel interface {config.interface} is down.")
    if config.role == "vps":
        for listener in listeners(config):
            print(f"{listener.listen} port {listener.port} {','.join(listener.protocols)} "
                  f"-> {listener.target} port {listener.target_port}")


def example(role):
    data = {
        "role": role, "interface": "rwg0",
        "tunnel": {"ipv4": "10.203.40.1", "ipv6": "fd42:57a1:8a63::1"},
        "peer": {"public_key": "REPLACE_WITH_THE_OTHER_MACHINE_PUBLIC_KEY",
                 "ipv4": "10.203.40.2", "ipv6": "fd42:57a1:8a63::2"},
    }
    if role == "vps":
        data.update(public={"ipv4": "198.51.100.10", "ipv6": "2001:db8::10"},
                    wireguard_port=51820, ports=[
                        {"listen": 25003, "target": 25003, "protocols": ["tcp", "udp"],
                         "source_policy": "none", "udp_security": "authenticated"}
                    ])
    else:
        for key in FAMILIES:
            data["tunnel"][key], data["peer"][key] = data["peer"][key], data["tunnel"][key]
        data["peer"]["endpoint"] = {"host": "198.51.100.10", "port": 51820}
        data["peer"]["keepalive"] = 25
        data["ports"] = [{"listen": 25003, "protocols": ["tcp", "udp"]}]
    print(json.dumps(data, indent=2))


@contextlib.contextmanager
def lock(paths):
    paths.make_dir()
    # Keep a stable lock inode outside the per-instance directory during uninstall.
    lock_file = STATE / ".lock"
    with lock_file.open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance", default="default", help="instance name before the command")
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("example").add_argument("role", choices=("vps", "home"))
    for name in ("validate", "check", "install", "update"):
        actions.add_parser(name).add_argument("config")
    for name in ("keygen", "status", "start", "stop", "serve", "cleanup"):
        actions.add_parser(name)
    actions.add_parser("uninstall").add_argument("--purge-key", action="store_true")
    args = parser.parse_args()
    paths = Paths(args.instance)
    if args.action == "example":
        example(args.role)
    elif args.action == "validate":
        read_config(args.config)
        print("Configuration syntax is valid.")
    elif args.action == "check":
        inspect(read_config(args.config), paths, check_bind=True)
        print("Configuration, local capabilities and available listeners checked.")
    elif args.action == "status":
        status(paths)
    elif args.action in ("serve", "cleanup"):
        root_and_linux()
        config = read_config(paths.config)
        if args.action == "serve":
            asyncio.run(operate(config, paths))
        else:
            clean_network(config, paths)
    else:
        root_and_linux()
        with lock(paths):
            if args.action == "keygen":
                keygen(paths)
            elif args.action == "install":
                install(paths, read_config(args.config))
            elif args.action == "update":
                update(paths, read_config(args.config))
            elif args.action == "uninstall":
                uninstall(paths, args.purge_key)
            else:
                systemd()
                if not unit_owned(paths):
                    raise ConfigError("No installed instance.")
                if args.action == "start":
                    start_unit(paths)
                else:
                    cmd("systemctl", "stop", paths.unit_name)


if __name__ == "__main__":
    if sys.version_info < (3, 9):
        sys.exit("Requires Python 3.9 or later.")
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(f"Error: {error}")
