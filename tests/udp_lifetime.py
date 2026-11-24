"""Run real active and application-idle UDP lifetime checks through WinDivert."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import secrets
import select
import signal
import socket
import socketserver
import struct
import subprocess
import threading
import time

from local_e2e import stop_process, wait_ready


ACTIVE_SECONDS = 660
IDLE_SECONDS = 135
MAX_SECONDS = 900
REPLY_TIMEOUT = 10
VIRTUAL_IP = "10.200.0.1"
HEADER = struct.Struct("!4s16sBQ")
MODES = {"echo": 1, "send_only": 2, "receive_only": 3}
CONNECTED = re.compile(r"UDP connected peer=(\S+) target=(\d+) target_local_port=(\d+)")
EXPIRED = re.compile(r"UDP expired peer=(\S+) target=(\d+) age_ms=(\d+) idle_ms=(\d+) reason=(\w+)")


def message(nonce: bytes, mode: str, sequence: int, size: int = 32) -> bytes:
    return HEADER.pack(b"FTLT", nonce, MODES[mode], sequence) + bytes([sequence % 251]) * (size - HEADER.size)


def decode(payload: bytes, nonce: bytes, mode: str) -> int:
    if len(payload) < HEADER.size:
        raise AssertionError("short lifetime datagram")
    magic, received_nonce, kind, sequence = HEADER.unpack_from(payload)
    if magic != b"FTLT" or received_nonce != nonce or kind != MODES[mode]:
        raise AssertionError("incorrect lifetime datagram identity")
    return sequence


def write_json(path: Path, value: dict):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        fixture = self.server.fixture
        try:
            fixture.handle(self.request[0], self.request[1], self.client_address)
        except Exception as exc:
            fixture.errors.put((f"fixture_{fixture.mode}", f"{type(exc).__name__}: {exc}"))


class UDPServer(socketserver.UDPServer):
    max_packet_size = 65535


class Fixture:
    def __init__(self, mode: str, nonce: bytes, errors: queue.Queue):
        self.mode, self.nonce, self.errors = mode, nonce, errors
        self.lock = threading.Lock()
        self.phase = "active"
        self.peer = None
        self.active_peers = set()
        self.recovery_peers = set()
        self.sequences = set()
        self.received = 0
        self.recovery_received = 0
        self.pushed = 0
        self.transmitted = 0
        self.first_received = None
        self.last_received = None
        self.first_push = None
        self.last_push = None
        self.peer_ready = threading.Event()
        self.push_stop = threading.Event()
        self.server = UDPServer(("127.0.0.1", 0), Handler)
        self.server.fixture = self
        self.port = self.server.server_address[1]
        self.worker = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        self.worker.start()
        self.pusher = None
        if mode == "receive_only":
            self.pusher = threading.Thread(target=self.push, daemon=True)
            self.pusher.start()

    def handle(self, payload: bytes, connection: socket.socket, peer: tuple):
        sequence = decode(payload, self.nonce, self.mode)
        with self.lock:
            if self.phase == "active":
                self.active_peers.add(peer)
                if len(self.active_peers) != 1:
                    raise AssertionError(f"active target source tuple changed: {sorted(self.active_peers)}")
                if sequence in self.sequences:
                    raise AssertionError(f"duplicate application datagram {sequence}")
                self.sequences.add(sequence)
                self.received += 1
                now = time.monotonic()
                self.first_received = self.first_received or now
                self.last_received = now
            elif self.phase == "recovery":
                self.recovery_peers.add(peer)
                self.recovery_received += 1
            else:
                raise AssertionError("real application UDP data arrived during the idle stage")
            if self.mode == "receive_only":
                if sequence != 0 or self.received != 1:
                    raise AssertionError("receive-only client sent more than its bootstrap datagram")
                self.peer = peer
                self.peer_ready.set()
        if self.mode == "echo":
            if connection.sendto(payload, peer) != len(payload):
                raise AssertionError("short fixture echo send")
            with self.lock:
                self.transmitted += 1

    def push(self):
        try:
            while not self.peer_ready.wait(0.1):
                if self.push_stop.is_set():
                    return
            sequence = 1
            while not self.push_stop.wait(1):
                with self.lock:
                    peer = self.peer
                payload = message(self.nonce, self.mode, sequence)
                if self.server.socket.sendto(payload, peer) != len(payload):
                    raise AssertionError("short receive-only fixture send")
                with self.lock:
                    self.pushed += 1
                    self.transmitted += 1
                    now = time.monotonic()
                    self.first_push = self.first_push or now
                    self.last_push = now
                sequence += 1
        except Exception as exc:
            self.errors.put(("fixture_receive_only_push", f"{type(exc).__name__}: {exc}"))

    def stop_push(self):
        self.push_stop.set()
        if self.pusher is not None:
            self.pusher.join(timeout=2)
            if self.pusher.is_alive():
                raise RuntimeError("receive-only fixture producer did not stop")

    def set_phase(self, phase: str):
        with self.lock:
            self.phase = phase

    def snapshot(self) -> dict:
        with self.lock:
            first = self.first_push if self.mode == "receive_only" else self.first_received
            last = self.last_push if self.mode == "receive_only" else self.last_received
            return {"target_port": self.port, "target_received": self.received, "target_sent": self.transmitted,
                    "observed_peers": [list(peer) for peer in sorted(self.active_peers)],
                    "recovery_peers": [list(peer) for peer in sorted(self.recovery_peers)],
                    "observed_active_span_seconds": None if first is None or last is None else round(last - first, 3),
                    "target_socket_open": self.server.socket.fileno() != -1}

    def close(self):
        self.stop_push()
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        if self.worker.is_alive():
            raise RuntimeError("fixture listener did not stop")


class Application:
    def __init__(self, fixture: Fixture, nonce: bytes, errors: queue.Queue):
        self.fixture, self.nonce, self.errors = fixture, nonce, errors
        self.mode = fixture.mode
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("0.0.0.0", 0))
        self.socket.settimeout(REPLY_TIMEOUT)
        self.source_port = self.socket.getsockname()[1]
        self.lock = threading.Lock()
        self.sent = 0
        self.received = 0
        self.sequence = 0
        self.stop = threading.Event()
        self.worker = threading.Thread(target=self.run, daemon=True)

    def send(self, sequence: int, size: int):
        payload = message(self.nonce, self.mode, sequence, size)
        if self.socket.sendto(payload, (VIRTUAL_IP, self.fixture.port)) != len(payload):
            raise AssertionError("short application UDP send")
        with self.lock:
            self.sent += 1
        return payload

    def receive_echo(self, payload: bytes):
        reply, peer = self.socket.recvfrom(65535)
        if peer != (VIRTUAL_IP, self.fixture.port) or reply != payload:
            raise AssertionError("echo reply changed payload or virtual source tuple")
        with self.lock:
            self.received += 1

    def run(self):
        try:
            if self.mode == "receive_only":
                self.send(0, 32)
                expected = 1
                last = time.monotonic()
                while not self.stop.is_set():
                    remaining = REPLY_TIMEOUT - (time.monotonic() - last)
                    if remaining <= 0:
                        raise TimeoutError("receive-only application received no data for 10 seconds")
                    readable, _, _ = select.select([self.socket], [], [], min(0.2, remaining))
                    if not readable:
                        continue
                    payload, peer = self.socket.recvfrom(65535)
                    if peer != (VIRTUAL_IP, self.fixture.port) or decode(payload, self.nonce, self.mode) != expected:
                        raise AssertionError(f"receive-only data sequence mismatch at {expected}")
                    expected += 1
                    last = time.monotonic()
                    with self.lock:
                        self.received += 1
                return
            while not self.stop.is_set():
                size = (32, 4096, 32000)[self.sequence % 3] if self.mode == "echo" else 32
                payload = self.send(self.sequence, size)
                if self.mode == "echo":
                    self.receive_echo(payload)
                self.sequence += 1
                self.stop.wait(1)
        except Exception as exc:
            self.errors.put((f"application_{self.mode}", f"{type(exc).__name__}: {exc}"))

    def snapshot(self) -> dict:
        with self.lock:
            return {"application_source_port": self.source_port, "application_sent": self.sent,
                    "application_received": self.received, "application_socket_open": self.socket.fileno() != -1}

    def join(self):
        self.stop.set()
        self.worker.join(timeout=REPLY_TIMEOUT + 2)
        if self.worker.is_alive():
            raise RuntimeError(f"{self.mode} application thread did not stop")


class LogTail:
    def __init__(self, path: Path, offset: int = 0):
        self.path, self.offset = path, offset
        self.pending = ""
        self.lines = []

    def refresh(self):
        if self.path.stat().st_size < self.offset:
            raise RuntimeError(f"log was truncated during the lifetime test: {self.path.name}")
        with self.path.open("rb") as stream:
            stream.seek(self.offset)
            data = stream.read()
            self.offset = stream.tell()
        text = self.pending + data.decode("utf-8", errors="replace")
        lines = text.split("\n")
        self.pending = lines.pop()
        self.lines.extend(lines)

    def records(self, expression: re.Pattern, ports: set[int]) -> list[dict]:
        self.refresh()
        records = []
        for line in self.lines:
            match = expression.search(line)
            if match and int(match[2]) in ports:
                if expression is CONNECTED:
                    records.append({"peer": match[1], "target": int(match[2]), "target_local_port": int(match[3])})
                else:
                    records.append({"peer": match[1], "target": int(match[2]), "age_ms": int(match[3]),
                                    "idle_ms": int(match[4]), "reason": match[5]})
        return records


def server_snapshot(server_id: int) -> dict:
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    command = (
        f"$p=Get-Process -Id {server_id} -ErrorAction Stop;"
        f"$ports=@(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object OwningProcess -eq {server_id} | Select-Object -ExpandProperty LocalPort);"
        "@{pid=$p.Id;creation_time=$p.StartTime.ToUniversalTime().ToString('o');ports=$ports}|ConvertTo-Json -Compress"
    )
    completed = subprocess.run([str(powershell), "-NoProfile", "-Command", command],
                               capture_output=True, text=True, check=True, timeout=15,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    return json.loads(completed.stdout.lstrip("\ufeff"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--results", required=True, type=Path)
    args = parser.parse_args()
    if not all(path.is_absolute() for path in (args.exe, args.profile, args.results)):
        parser.error("all paths must be absolute")
    workspace = Path(__file__).resolve().parents[1]
    results = args.results.resolve()
    if not results.is_relative_to((workspace / "test-results").resolve()):
        parser.error("--results must be inside this workspace's test-results directory")
    results.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    nonce = secrets.token_bytes(16)
    errors = queue.Queue()
    fixtures = []
    applications = []
    child = None
    child_log = None
    abort = threading.Event()
    result = {"success": False, "active_seconds_required": ACTIVE_SECONDS, "idle_seconds_required": IDLE_SECONDS,
              "nonce": nonce.hex(), "stage": "preparing", "child_pid": None, "modes": {}, "cleanup": [], "thread_errors": []}
    active_started = None

    def progress(stage: str):
        result["stage"] = stage
        result["active_seconds"] = 0 if active_started is None else round(min(time.monotonic() - active_started, ACTIVE_SECONDS), 3)
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        result["modes"] = {app.mode: {**app.fixture.snapshot(), **app.snapshot()} for app in applications}
        write_json(results / "progress.json", result)

    def check():
        while not errors.empty():
            name, error = errors.get_nowait()
            result["thread_errors"].append({"worker": name, "error": error})
        if result["thread_errors"]:
            raise RuntimeError(str(result["thread_errors"]))
        if abort.is_set() or time.monotonic() - started > MAX_SECONDS:
            raise RuntimeError("lifetime test stopped or exceeded its fixed 15-minute limit")
        if child is not None and child.poll() is not None:
            raise RuntimeError("the owned lifetime client exited unexpectedly")
        if int(json.loads((args.profile / "ready.json").read_text(encoding="utf-8-sig"))["core_pid"]) != server_id:
            raise RuntimeError("production server identity changed; lifetime test is invalid")

    def wait_stage(seconds: int, stage: str):
        deadline = time.monotonic() + seconds
        update = 0.0
        while time.monotonic() < deadline:
            check()
            if time.monotonic() >= update:
                progress(stage)
                update = time.monotonic() + 15
            abort.wait(min(0.2, max(0, deadline - time.monotonic())))
        progress(stage)

    for signal_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, signal_name):
            signal.signal(getattr(signal, signal_name), lambda _signal, _frame: abort.set())
    progress("preparing")
    try:
        config = args.profile / "client-local.toml"
        server_log = args.profile / "server.log"
        if not args.exe.is_file() or not config.is_file() or not server_log.is_file():
            raise FileNotFoundError("executable, client-local.toml, or server.log is missing")
        with args.exe.open("rb") as executable:
            result["executable_sha256"] = hashlib.file_digest(executable, "sha256").hexdigest()
        server_id = int(json.loads((args.profile / "ready.json").read_text(encoding="utf-8-sig"))["core_pid"])
        if server_id <= 0:
            raise ValueError("invalid server core_pid")
        initial_server = server_snapshot(server_id)
        result["server_instance"] = initial_server
        baseline = server_log.stat().st_size
        result["server_log_baseline_offset"] = baseline
        server_tail = LogTail(server_log, baseline)
        child_path = results / "client.log"
        child_log = child_path.open("wb")
        child = subprocess.Popen([str(args.exe), "run", str(config)], cwd=args.exe.parent,
                                 stdout=child_log, stderr=subprocess.STDOUT,
                                 creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW)
        result["child_pid"] = child.pid
        progress("starting_client")
        wait_ready(child, child_path)
        client_tail = LogTail(child_path)
        progress("client_ready")
        for mode in MODES:
            fixture = Fixture(mode, nonce, errors)
            fixtures.append(fixture)
            applications.append(Application(fixture, nonce, errors))
        ports = {fixture.port for fixture in fixtures}
        active_started = time.monotonic()
        for app in applications:
            app.worker.start()
        progress("active")
        wait_stage(ACTIVE_SECONDS, "active")
        for app in applications:
            if app.mode != "receive_only":
                app.stop.set()
        for fixture in fixtures:
            fixture.stop_push()
        for app in applications:
            if app.mode != "receive_only":
                app.join()
        drain_deadline = time.monotonic() + REPLY_TIMEOUT
        while True:
            check()
            complete = all((app.fixture.received == app.sent if app.mode != "receive_only"
                            else app.received == app.fixture.pushed) for app in applications)
            if complete:
                break
            if time.monotonic() >= drain_deadline:
                raise TimeoutError("active datagram counts did not drain without loss")
            time.sleep(0.05)
        for app in applications:
            if app.mode == "receive_only":
                app.join()
        check()
        connections = server_tail.records(CONNECTED, ports)
        expired_active = server_tail.records(EXPIRED, ports) + client_tail.records(EXPIRED, ports)
        if expired_active:
            raise AssertionError("a UDP flow expired while real application traffic was active")
        source_ports = set()
        for app in applications:
            snapshot = app.fixture.snapshot()
            peer = snapshot["observed_peers"]
            observed = [entry for entry in connections if entry["target"] == app.fixture.port]
            if len(peer) != 1 or len(observed) != 1 or observed[0]["target_local_port"] != peer[0][1]:
                raise AssertionError(f"{app.mode}: target source or UDP connected identity changed")
            if snapshot["observed_active_span_seconds"] is None or snapshot["observed_active_span_seconds"] <= 600:
                raise AssertionError(f"{app.mode}: actual application activity did not cross 10 minutes")
            if app.mode == "receive_only" and (app.sent != 1 or app.fixture.received != 1):
                raise AssertionError("receive-only traffic was not strictly one bootstrap plus backend pushes")
            if app.mode == "send_only" and (app.received != 0 or app.fixture.transmitted != 0):
                raise AssertionError("send-only target unexpectedly generated reverse application traffic")
            source_ports.add(peer[0][1])
            app.fixture.set_phase("idle")
        result["active_connections"] = connections
        result["original_target_source_ports"] = sorted(source_ports)
        active_server = server_snapshot(server_id)
        if active_server["creation_time"] != initial_server["creation_time"] or not source_ports.issubset(set(active_server["ports"])):
            raise AssertionError("active source sockets were not bound by the same server instance")
        progress("idle")
        wait_stage(IDLE_SECONDS, "idle")
        expirations = [{**entry, "endpoint": endpoint} for endpoint, tail in (("server", server_tail), ("client", client_tail))
                       for entry in tail.records(EXPIRED, ports)]
        for port in ports:
            matching = [entry for entry in expirations if entry["target"] == port]
            if not matching or any(entry["reason"] != "application_idle" or entry["idle_ms"] < 120000 for entry in matching):
                raise AssertionError(f"target {port}: missing application_idle or unexpected expiry reason")
        idle_server = server_snapshot(server_id)
        if idle_server["creation_time"] != initial_server["creation_time"]:
            raise AssertionError("production server restarted; socket closure is not idle evidence")
        if source_ports.intersection(set(idle_server["ports"])):
            raise AssertionError("expired target source sockets remain bound by the production server")
        result["idle_expirations"] = expirations
        result["expiry_endpoint_by_target"] = {
            str(port): sorted({entry["endpoint"] for entry in expirations if entry["target"] == port})
            for port in ports
        }
        result["first_expiry_endpoint_by_target"] = {
            port: endpoints[0] if len(endpoints) == 1 else "both; order not established"
            for port, endpoints in result["expiry_endpoint_by_target"].items()
        }
        result["idle_server_snapshot"] = idle_server
        check()
        progress("recovery")
        echo = next(app for app in applications if app.mode == "echo")
        echo.fixture.set_phase("recovery")
        payload = echo.send(echo.sequence + 1000, 32)
        echo.receive_echo(payload)
        check()
        recovered = [entry for entry in server_tail.records(CONNECTED, ports) if entry["target"] == echo.fixture.port]
        recovery_peers = echo.fixture.snapshot()["recovery_peers"]
        if len(recovered) != 2 or len(recovery_peers) != 1 or recovered[-1]["target_local_port"] != recovery_peers[0][1]:
            raise AssertionError("echo did not restore a new target socket through the original application socket")
        final_server = server_snapshot(server_id)
        if final_server["creation_time"] != initial_server["creation_time"]:
            raise AssertionError("production server instance changed during recovery")
        result["recovery_connection"] = recovered[-1]
        result["success"] = True
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        for app in applications:
            app.stop.set()
        for fixture in fixtures:
            try:
                fixture.stop_push()
            except Exception as exc:
                result["success"] = False
                result["cleanup"].append({"fixture": fixture.mode, "error": str(exc)})
        for app in applications:
            try:
                if app.worker.ident is not None:
                    app.join()
                app.socket.close()
            except Exception as exc:
                result["success"] = False
                result["cleanup"].append({"application": app.mode, "error": str(exc)})
        if child is not None:
            try:
                cleanup = stop_process(child, "owned_lifetime_client")
                result["cleanup"].append(cleanup)
                if cleanup["method"] != "named_event" or cleanup["exit_code"] != 0:
                    result["success"] = False
            except Exception as exc:
                result["success"] = False
                result["cleanup"].append({"client_pid": child.pid, "error": str(exc)})
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
        if child_log is not None:
            child_log.close()
        for fixture in fixtures:
            try:
                fixture.close()
            except Exception as exc:
                result["success"] = False
                result["cleanup"].append({"fixture": fixture.mode, "error": str(exc)})
        while not errors.empty():
            name, error = errors.get_nowait()
            result["thread_errors"].append({"worker": name, "error": error})
        if result["thread_errors"]:
            result["success"] = False
        progress("complete" if result["success"] else "failed")
        write_json(results / "result.json", result)
        (results / "exit-code.txt").write_text("0\n" if result["success"] else "1\n", encoding="ascii")
        print(json.dumps({"success": result["success"], "result": str(results / "result.json"),
                          "error": result.get("error")}), flush=True)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
