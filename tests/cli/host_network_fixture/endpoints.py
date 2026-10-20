"""Independent loopback services for host-network CLI acceptance tests."""

import ipaddress
import socketserver
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


class HTTPHandler(BaseHTTPRequestHandler):
    """Return a per-test token so successful traffic has a clear endpoint."""

    def do_GET(self):
        with self.server.calls_lock:
            self.server.calls["tcp"] += 1
        if self.path == "/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for _ in range(1200):
                body = (self.server.token + "\n").encode()
                with self.server.calls_lock:
                    self.server.calls["stream_pushes"] += 1
                try:
                    self.wfile.write(f"{len(body):X}\r\n".encode() + body + b"\r\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    # Keep counting independent server-side push attempts
                    # after revocation so a stopped guest reader cannot be
                    # confused with a stopped endpoint.
                    pass
                time.sleep(0.1)
            return
        body = self.server.token.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class UDPHandler(socketserver.BaseRequestHandler):
    """Echo the fixture token after receiving one real datagram."""

    def handle(self):
        with self.server.calls_lock:
            self.server.calls["udp"] += 1
        self.request[1].sendto(self.server.token.encode() + b":udp\n", self.client_address)


@pytest.fixture
def host_network_endpoints(project):
    """Start TCP and UDP servers on host loopback until the project VM exits."""
    token = "hostnet-endpoint-" + uuid.uuid4().hex
    http = ThreadingHTTPServer(("127.0.0.1", 0), HTTPHandler)
    private_ip = None
    private_http = None
    try:
        links = subprocess.run(
            ["ip", "-o", "link", "show"], check=True,
            capture_output=True, text=True,
        ).stdout
        active_interfaces = set()
        for line in links.splitlines():
            fields = line.split()
            interface = fields[1].rstrip(":")
            flags = fields[2].strip("<>").split(",")
            if "LOWER_UP" in flags:
                active_interfaces.add(interface)
        interface_output = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"], check=True,
            capture_output=True, text=True,
        ).stdout
        guest_routes = (
            ipaddress.ip_network("10.0.2.0/24"),
            ipaddress.ip_network("10.0.3.0/24"),
        )
        for line in interface_output.splitlines():
            fields = line.split()
            interface = fields[1]
            candidate = fields[3].split("/", 1)[0]
            address = ipaddress.ip_address(candidate)
            # These are already assigned to the guest uplink and host alias;
            # binding there would make a private-host probe hit the wrong side.
            if (interface in active_interfaces
                    and address.is_private and not address.is_loopback
                    and not any(address in guest_route for guest_route in guest_routes)):
                private_ip = candidate
                private_http = ThreadingHTTPServer((private_ip, 0), HTTPHandler)
                break
    except OSError:
        # The loopback host endpoint remains useful on machines without a
        # routed IPv4 interface; full-network tests can still cover host data.
        private_ip = None
    http.daemon_threads = True
    http.block_on_close = False
    udp = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UDPHandler)
    calls = {"tcp": 0, "udp": 0, "stream_pushes": 0}
    calls_lock = threading.Lock()
    http.token = token
    if private_http is not None:
        private_http.token = token
    udp.token = token
    http.calls = calls
    udp.calls = calls
    http.calls_lock = calls_lock
    if private_http is not None:
        private_http.calls = calls
        private_http.calls_lock = calls_lock
    udp.calls_lock = calls_lock
    http_thread = threading.Thread(target=http.serve_forever, daemon=True)
    private_http_thread = (
        threading.Thread(target=private_http.serve_forever, daemon=True)
        if private_http is not None else None
    )
    udp_thread = threading.Thread(target=udp.serve_forever, daemon=True)
    http_thread.start()
    if private_http_thread is not None:
        private_http_thread.start()
    udp_thread.start()

    def request_counts():
        with calls_lock:
            return dict(calls)

    try:
        yield {
            "token": token,
            "tcp_port": http.server_address[1],
            "private_ip": private_ip,
            "private_tcp_port": private_http.server_address[1] if private_http is not None else None,
            "udp_port": udp.server_address[1],
            "request_counts": request_counts,
        }
    finally:
        http.shutdown()
        udp.shutdown()
        http.server_close()
        if private_http is not None:
            private_http.shutdown()
            private_http.server_close()
        udp.server_close()
        http_thread.join(timeout=2)
        if private_http_thread is not None:
            private_http_thread.join(timeout=2)
        udp_thread.join(timeout=2)
