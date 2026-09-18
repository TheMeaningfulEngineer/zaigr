"""Serve controlled endpoints inside a disposable user and network namespace."""

import http.server
import json
import shlex
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path


def checked(command):
    """Expose infrastructure commands to the parent's live transcript."""
    print(":: endpoint infrastructure: " + shlex.join(command), flush=True)
    subprocess.run(command, check=True)


class HTTPHandler(http.server.BaseHTTPRequestHandler):
    """Return a sentinel or a continuous stream with fresh host-controlled nonces."""

    def do_GET(self):
        """Serve traffic whose delivery can be observed after permission removal."""
        if self.path.startswith("/mark/"):
            self.server.marker = self.path.removeprefix("/mark/")
        self.send_response(200)
        self.end_headers()
        if self.path == "/sentinel":
            self.wfile.write(self.server.token.encode())
            return
        try:
            for sequence in range(1000 if self.path == "/stream" else 1):
                suffix = f":{self.server.marker}" if self.server.marker else ""
                self.wfile.write(f"{self.server.token}:{sequence}{suffix}\n".encode())
                self.wfile.flush()
                if self.path == "/stream":
                    time.sleep(0.2)
        except (BrokenPipeError, ConnectionResetError):
            pass


class UDPHandler(socketserver.BaseRequestHandler):
    """Echo real datagrams with a destination-specific sentinel and request nonce."""

    def handle(self):
        """Reply on the same service socket to the actual request source."""
        packet, connection = self.request
        connection.sendto(self.server.token.encode() + b":" + packet, self.client_address)


def terminate(signum, frame):
    """Unwind the service owner so every child and socket is closed."""
    raise KeyboardInterrupt


def wait_for_ssh(address, process):
    """Wait for the real SSH banner before exposing a ready endpoint."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"SSH endpoint exited: {process.returncode}")
        try:
            with socket.create_connection((address, 2222), timeout=0.2) as connection:
                if connection.recv(128).startswith(b"SSH-2.0-"):
                    print(f":: endpoint ready: SSH {address}:2222", flush=True)
                    return
        except OSError:
            pass
        time.sleep(0.05)
    raise RuntimeError(f"SSH endpoint did not become ready: {address}")


def serve(directory):
    """Provision only namespace-local interfaces, then supervise all services."""
    config = json.loads((directory / "services.json").read_text(encoding="utf-8"))
    checked(["chown", "0:0", str(directory / "sshd-empty")])
    checked(["mount", "--bind", str(directory / "sshd-empty"), "/run/sshd"])
    # Host root is deliberately unmapped; SSH rejects its included config files.
    checked(["chown", "0:0", str(directory / "ssh-client.conf")])
    checked(["mount", "--bind", str(directory / "ssh-client.conf"), "/etc/ssh/ssh_config"])
    checked(["ip", "link", "set", "lo", "up"])
    for endpoint in config["endpoints"]:
        checked(["ip", "address", "add", endpoint["ip"] + "/32", "dev", "lo"])
    command = ["/usr/sbin/sshd", "-D", "-e", "-f", str(directory / "sshd.conf")]
    print(":: endpoint infrastructure: " + shlex.join(command), flush=True)
    sshd = subprocess.Popen(command)
    servers = []
    threads = []
    started = []
    signal.signal(signal.SIGTERM, terminate)
    try:
        for endpoint in config["endpoints"]:
            for port in (18080, 18081, 18082):
                server_type, handler = (
                    (socketserver.ThreadingUDPServer, UDPHandler) if port == 18082
                    else (http.server.ThreadingHTTPServer, HTTPHandler)
                )
                service = server_type((endpoint["ip"], port), handler)
                service.token = endpoint["token"]
                service.marker = ""
                servers.append(service)
        host = config["host"]
        service = http.server.ThreadingHTTPServer(("127.0.0.1", host["port"]), HTTPHandler)
        service.token = host["token"]
        service.marker = ""
        servers.append(service)
        for service in servers:
            thread = threading.Thread(target=service.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
            started.append(service)
        for endpoint in config["endpoints"]:
            wait_for_ssh(endpoint["ip"], sshd)
        # /proc is the host view; getpid() is 1 in the owned PID namespace.
        status = Path("/proc/self/status").read_text(encoding="utf-8")
        host_pid = next(line.split()[1] for line in status.splitlines() if line.startswith("NSpid:"))
        print(f"IP_NETWORK_READY {host_pid}", flush=True)
        sshd.wait()
        raise RuntimeError(f"SSH endpoint exited unexpectedly: {sshd.returncode}")
    except KeyboardInterrupt:
        pass
    finally:
        sshd.terminate()
        sshd.wait(timeout=10)
        for service in servers:
            if service in started:
                service.shutdown()
            service.server_close()
        for thread in threads:
            thread.join(timeout=5)
            assert not thread.is_alive(), "Endpoint server did not stop"


if __name__ == "__main__":
    serve(Path(sys.argv[1]))
