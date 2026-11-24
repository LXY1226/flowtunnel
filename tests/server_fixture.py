"""Loopback services used to verify a remote FlowTunnel client."""

from __future__ import annotations

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import signal
import socket
import socketserver
import threading
import time


HTTP_PORT = 18082
UDP_PORT = 18083
TCP_PORT = 18084
BOOT_NONCE = secrets.token_hex(16)
STARTED = time.monotonic()


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/", "/health"):
            self.send_error(404)
            return
        payload = json.dumps(
            {
                "server": True,
                "service": "FlowTunnel remote fixture",
                "nonce": BOOT_NONCE,
                "time": datetime.now(timezone.utc).isoformat(),
                "uptime_seconds": round(time.monotonic() - STARTED, 3),
                "tcp_port": TCP_PORT,
                "udp_port": UDP_PORT,
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass


class TCPEchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(30)
        try:
            while True:
                payload = self.request.recv(65536)
                if not payload:
                    self.request.shutdown(socket.SHUT_WR)
                    return
                self.request.sendall(payload)
        except OSError:
            return


class UDPEchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        payload, connection = self.request
        connection.sendto(payload, self.client_address)


class TCPEchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


class UDPEchoServer(socketserver.ThreadingUDPServer):
    daemon_threads = True
    max_packet_size = 65535


def main() -> int:
    stopped = threading.Event()

    def stop(_signal, _frame):
        stopped.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, stop)
    servers = []
    started_servers = []
    workers = []
    try:
        for server_class, port, handler in (
            (ThreadingHTTPServer, HTTP_PORT, HealthHandler),
            (TCPEchoServer, TCP_PORT, TCPEchoHandler),
            (UDPEchoServer, UDP_PORT, UDPEchoHandler),
        ):
            server = server_class(("127.0.0.1", port), handler)
            servers.append(server)
            worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
            worker.start()
            workers.append(worker)
            started_servers.append(server)
        print(
            f"fixture ready http=127.0.0.1:{HTTP_PORT} tcp=127.0.0.1:{TCP_PORT} "
            f"udp=127.0.0.1:{UDP_PORT} nonce={BOOT_NONCE}",
            flush=True,
        )
        stopped.wait()
        return 0
    finally:
        for server in started_servers:
            server.shutdown()
        for server in servers:
            server.server_close()
        for worker in workers:
            worker.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
