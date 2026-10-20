"""Controlled real UDP/TCP DNS resolver for host-network CLI acceptance."""

import socket
import socketserver
import struct
import threading
from pathlib import Path

import pytest

from ...conftest import err_msg, run


def encode_name(name):
    return b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.rstrip(".").split(".")) + b"\0"


def parse_question(packet):
    if len(packet) < 12:
        raise ValueError("short DNS header")
    offset = 12
    labels = []
    while True:
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or length > 63 or offset + length > len(packet):
            raise ValueError("unsupported DNS question encoding")
        labels.append(packet[offset:offset + length].decode("ascii").lower())
        offset += length
    if offset + 4 > len(packet):
        raise ValueError("short DNS question")
    return ".".join(labels), struct.unpack("!HH", packet[offset:offset + 4]), packet[12:offset + 4]


def answer_record(owner, kind, ttl, payload):
    return owner + struct.pack("!HHIH", kind, 1, ttl, len(payload)) + payload


class Resolver:
    def __init__(self):
        self.lock = threading.Lock()
        self.queries = {}
        self.answers = {}
        self.dropped = set()
        self.delayed_seen = threading.Event()
        self.release_delayed = threading.Event()

    def count(self, name):
        with self.lock:
            return self.queries.get(name.lower().rstrip("."), 0)

    def set_answer(self, name, address, ttl):
        with self.lock:
            self.answers[name.lower().rstrip(".")] = (address, ttl)

    def drop_replies(self, name, drop=True):
        normalized = name.lower().rstrip(".")
        with self.lock:
            if drop:
                self.dropped.add(normalized)
            else:
                self.dropped.discard(normalized)

    def respond(self, packet):
        query_name, question, question_wire = parse_question(packet)
        qtype, qclass = question
        with self.lock:
            self.queries[query_name] = self.queries.get(query_name, 0) + 1
            drop_reply = query_name in self.dropped
            answer_override = self.answers.get(query_name)

        if drop_reply:
            return b""

        if query_name == "delayed.test":
            self.delayed_seen.set()
            if not self.release_delayed.wait(20):
                return b""

        identifier = packet[:2]
        flags = struct.pack("!H", 0x8180)
        if query_name == "missing.test":
            return identifier + struct.pack("!H", 0x8183) + struct.pack("!HHHH", 1, 0, 0, 0) + question_wire
        if qclass != 1 or qtype != 1:
            return identifier + flags + struct.pack("!HHHH", 1, 0, 0, 0) + question_wire

        if query_name == "unsafe.test":
            answer = answer_record(b"\xc0\x0c", 1, 30, socket.inet_aton("127.0.0.1"))
            count = 1
        elif query_name == "private.test":
            answer = answer_record(b"\xc0\x0c", 1, 30, socket.inet_aton("192.168.1.12"))
            count = 1
        elif query_name == "zero-ttl.test":
            answer = answer_record(b"\xc0\x0c", 1, 0, socket.inet_aton("93.184.216.34"))
            count = 1
        elif query_name == "malformed.test":
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + b"\x5d\xb8\xd8"
            count = 1
        elif query_name == "alias.test":
            cname = answer_record(b"\xc0\x0c", 5, 30, encode_name("linked-target.test"))
            target = answer_record(encode_name("linked-target.test"), 1, 30,
                                   socket.inet_aton("93.184.216.34"))
            answer = cname + target
            count = 2
        else:
            address, ttl = answer_override or ("93.184.216.34", 30)
            answer = answer_record(b"\xc0\x0c", 1, ttl, socket.inet_aton(address))
            count = 1
        return identifier + flags + struct.pack("!HHHH", 1, count, 0, 0) + question_wire + answer


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        payload = self.server.resolver.respond(self.request[0])
        if payload:
            self.request[1].sendto(payload, self.client_address)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        length = struct.unpack("!H", self.request.recv(2))[0]
        packet = bytearray()
        while len(packet) < length:
            chunk = self.request.recv(length - len(packet))
            if not chunk:
                return
            packet.extend(chunk)
        payload = self.server.resolver.respond(bytes(packet))
        if payload:
            self.request.sendall(struct.pack("!H", len(payload)) + payload)


@pytest.fixture
def host_network_dns(project):
    """Install an isolated trusted resolver for this project home and restore it."""
    resolver = Resolver()
    udp = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UDPHandler)
    tcp = socketserver.ThreadingTCPServer(("127.0.0.1", udp.server_address[1]), TCPHandler)
    udp.resolver = resolver
    tcp.resolver = resolver
    udp.daemon_threads = True
    tcp.daemon_threads = True
    threads = [
        threading.Thread(target=udp.serve_forever, daemon=True),
        threading.Thread(target=tcp.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()

    config_path = project.home / ".zaigr" / "host-network-resolvers"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    previous = config_path.read_bytes() if config_path.exists() else None
    config_path.write_text(f"127.0.0.1:{udp.server_address[1]}\n", encoding="ascii")
    config_path.chmod(0o600)
    try:
        yield {
            "resolver": resolver,
            "config_path": config_path,
            "port": udp.server_address[1],
        }
    finally:
        udp.shutdown()
        tcp.shutdown()
        udp.server_close()
        tcp.server_close()
        for thread in threads:
            thread.join(timeout=2)
        if previous is None:
            config_path.unlink(missing_ok=True)
        else:
            config_path.write_bytes(previous)
            config_path.chmod(0o600)


@pytest.fixture
def dns_probe_binary(project):
    """Build a small guest DNS client that can exercise UDP and TCP directly."""
    output = project.cwd / "dns_probe"
    stdout, stderr, code = run([
        "gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
        "-o", output, Path(__file__).with_name("dns_probe.c"),
    ])
    assert code == 0, err_msg(stdout, stderr)
    return output
