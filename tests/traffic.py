import socket
import sys
import threading


def address(ip, port):
    return socket.AF_INET6 if ":" in ip else socket.AF_INET, (ip, port)


def echo(stream):
    with stream:
        while data := stream.recv(16384):
            stream.sendall(data)


def tcp_server(sock):
    sock.listen(40)
    while True:
        client, _ = sock.accept()
        threading.Thread(target=echo, args=(client,), daemon=True).start()


def udp_server(sock):
    while True:
        data, client = sock.recvfrom(65535)
        sock.sendto(data, client)


def serve(ip, port):
    family, endpoint = address(ip, port)
    for kind, handler in ((socket.SOCK_STREAM, tcp_server), (socket.SOCK_DGRAM, udp_server)):
        sock = socket.socket(family, kind)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(endpoint)
        threading.Thread(target=handler, args=(sock,), daemon=True).start()
    print(f"Echo ready: {ip} {port}", flush=True)
    threading.Event().wait()


def tcp(ip, port, size):
    with socket.create_connection((ip, port), 1.5) as conn:
        payload = (b"abCD12-" * (size // 7 + 1))[:size]
        conn.sendall(payload)
        conn.shutdown(socket.SHUT_WR)
        received = bytearray()
        while data := conn.recv(65536):
            received.extend(data)
        if received != payload:
            raise AssertionError(f"TCP echo mismatch for {ip}:{port}")


def udp(ip, port, size):
    family, endpoint = address(ip, port)
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1.25)
        sock.connect(endpoint)
        for marker in (b"x", b"y"):
            payload = marker * size
            sock.send(payload)
            if sock.recv(8192) != payload:
                raise AssertionError(f"UDP echo mismatch for {ip}:{port}")


mode, ip, raw = sys.argv[1:]
port = int(raw)
if mode == "serve":
    serve(ip, port)
elif mode == "pass":
    tcp(ip, port, 64)
    tcp(ip, port, 131072)
    udp(ip, port, 0)
    udp(ip, port, 32)
    udp(ip, port, 1200)
    print(f"TCP/UDP, small/large payloads passed: {ip} {port}")
elif mode == "blocked":
    for operation in (tcp, udp):
        try:
            operation(ip, port, 32)
        except (OSError, AssertionError):
            pass
        else:
            raise SystemExit(f"Unexpected {operation.__name__} relay response: {ip} {port}")
    print(f"TCP/UDP payload denied: {ip} {port}")
else:
    raise SystemExit(f"Unknown mode {mode}")
