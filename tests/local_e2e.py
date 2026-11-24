"""Exercise both FlowTunnel roles through the real WinDivert data path."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import struct
import subprocess
import threading
import time
import tomllib


VIRTUAL_IP = "10.200.0.1"
ENDPOINT = ("127.0.0.1", 18080)
TIMEOUT = 10
UDP_SIZES = (0, 1, 32, 512, 1100, 4096, 32000, 60000)
REQUEST_PREFIX = (
    b"GET / HTTP/1.1\r\nHost: speedtest.fkcucc.com\r\nContent-Length: 72\r\n"
    b"Connection: keep-alive\r\n\r\n"
)


class EchoService:
    def __init__(self, protocol: str, *, reply_after_eof: bool = False):
        self.protocol = protocol
        self.reply_after_eof = reply_after_eof
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.2)
        if protocol == "tcp":
            self.sock.listen(16)
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.accepted = 0
        self.connections: set[socket.socket] = set()
        self.workers: list[threading.Thread] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stop.is_set():
            try:
                if self.protocol == "udp":
                    data, address = self.sock.recvfrom(65535)
                    self.sock.sendto(data, address)
                    continue
                conn, _ = self.sock.accept()
                conn.settimeout(TIMEOUT)
                with self.lock:
                    self.accepted += 1
                    self.connections.add(conn)
                worker = threading.Thread(target=self._echo_tcp, args=(conn,), daemon=True)
                self.workers.append(worker)
                worker.start()
            except socket.timeout:
                continue
            except OSError:
                if not self.stop.is_set():
                    raise

    def _echo_tcp(self, conn: socket.socket):
        digest = hashlib.sha256()
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                if self.reply_after_eof:
                    digest.update(data)
                else:
                    conn.sendall(data)
            if self.reply_after_eof:
                conn.sendall(digest.digest())
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        finally:
            with self.lock:
                self.connections.discard(conn)
            conn.close()

    def close(self):
        self.stop.set()
        self.sock.close()
        with self.lock:
            active = tuple(self.connections)
        for conn in active:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
        self.thread.join(timeout=2)
        for worker in self.workers:
            worker.join(timeout=2)
        if self.thread.is_alive() or any(worker.is_alive() for worker in self.workers):
            raise RuntimeError("target service worker did not exit")


def receive_to_eof(conn: socket.socket, maximum: int) -> bytes:
    result = bytearray()
    while True:
        data = conn.recv(65536)
        if not data:
            return bytes(result)
        result.extend(data)
        if len(result) > maximum:
            raise AssertionError(f"TCP returned more than {maximum} bytes")


def tcp_exchange(port: int, payload: bytes):
    with socket.create_connection((VIRTUAL_IP, port), TIMEOUT) as conn:
        conn.settimeout(TIMEOUT)
        errors: list[Exception] = []

        def send():
            try:
                conn.sendall(payload)
                conn.shutdown(socket.SHUT_WR)
            except Exception as exc:
                errors.append(exc)

        writer = threading.Thread(target=send, daemon=True)
        writer.start()
        try:
            actual = receive_to_eof(conn, len(payload))
        finally:
            writer.join(timeout=TIMEOUT)
        if writer.is_alive():
            raise AssertionError("TCP sender did not complete")
        if errors:
            raise errors[0]
        assert actual == payload, f"TCP byte stream mismatch: sent {len(payload)}, received {len(actual)}"


class UDPExchangeError(RuntimeError):
    def __init__(self, report: dict):
        self.report = report
        location = "setup"
        if report.get("failed_index") is not None:
            location = f"packet {report['failed_index']} round {report['failed_round']} size {report['failed_size']}"
        super().__init__(f"UDP {location}: {report['error']}; source_port={report['source_port']}, sent={report['sent_datagrams']}, received={report['received_datagrams']}")


def udp_exchange(port: int, sizes: tuple[int, ...], rounds: int = 1) -> dict:
    started = time.monotonic()
    report = {
        "success": False,
        "destination": [VIRTUAL_IP, port],
        "source_port": None,
        "rounds": rounds,
        "sizes": list(sizes),
        "timeout_seconds": TIMEOUT,
        "timeout": False,
        "expected_datagrams": len(sizes) * rounds,
        "sent_datagrams": 0,
        "received_datagrams": 0,
        "matched_datagrams": 0,
        "sent_bytes": 0,
        "received_bytes": 0,
        "packets": [],
    }
    packet = None
    failure = None
    stage = "bind"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
            conn.bind(("0.0.0.0", 0))
            report["source_port"] = conn.getsockname()[1]
            conn.settimeout(TIMEOUT)
            for round_index in range(rounds):
                for size in sizes:
                    packet_started = time.monotonic()
                    packet = {"index": len(report["packets"]) + 1, "round": round_index + 1, "size": size,
                              "sent": False, "received": False, "matched": False, "timeout": False}
                    report["packets"].append(packet)
                    stage = "prepare"
                    expected = secrets.token_bytes(size)
                    stage = "send"
                    operation_started = time.monotonic()
                    sent = conn.sendto(expected, (VIRTUAL_IP, port))
                    packet["send_ms"] = round((time.monotonic() - operation_started) * 1000, 3)
                    packet["sent"] = True
                    packet["sent_bytes"] = sent
                    report["sent_datagrams"] += 1
                    report["sent_bytes"] += sent
                    assert sent == size, f"UDP send returned {sent} bytes for a {size}-byte datagram"
                    stage = "receive"
                    operation_started = time.monotonic()
                    actual, address = conn.recvfrom(65535)
                    packet["receive_ms"] = round((time.monotonic() - operation_started) * 1000, 3)
                    packet["received"] = True
                    packet["received_bytes"] = len(actual)
                    packet["reply_address"] = list(address)
                    report["received_datagrams"] += 1
                    report["received_bytes"] += len(actual)
                    stage = "validate"
                    assert address == (VIRTUAL_IP, port), f"UDP reply address changed: {address!r}"
                    assert actual == expected, f"UDP datagram mismatch at {size} bytes: received {len(actual)}"
                    packet["matched"] = True
                    packet["elapsed_ms"] = round((time.monotonic() - packet_started) * 1000, 3)
                    report["matched_datagrams"] += 1
        report["success"] = True
    except Exception as exc:
        failure = exc
        report["error"] = f"{type(exc).__name__}: {exc}"
        report["failed_stage"] = stage
        report["timeout"] = isinstance(exc, TimeoutError)
        if packet is not None:
            packet["error"] = report["error"]
            packet["failed_stage"] = stage
            packet["timeout"] = report["timeout"]
            packet["elapsed_ms"] = round((time.monotonic() - packet_started) * 1000, 3)
            if stage == "receive":
                packet["receive_ms"] = round((time.monotonic() - operation_started) * 1000, 3)
            report["failed_index"] = packet["index"]
            report["failed_round"] = packet["round"]
            report["failed_size"] = packet["size"]
    report["seconds"] = round(time.monotonic() - started, 3)
    report["unattempted_datagrams"] = report["expected_datagrams"] - len(report["packets"])
    if failure is not None:
        raise UDPExchangeError(report) from failure
    return report


def wait_ready(process: subprocess.Popen, log_path: Path):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        code = process.poll()
        if code is not None:
            raise RuntimeError(f"{log_path.stem} exited before ready, exit code {code}; see {log_path}")
        if "ready" in log_path.read_text(encoding="utf-8", errors="replace").lower():
            return
        time.sleep(0.05)
    raise TimeoutError(f"{log_path.stem} did not report ready; see {log_path}")


def stop_process(process: subprocess.Popen, name: str) -> dict:
    method = "already_exited"
    if process.poll() is None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenEventW.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p)
        kernel32.OpenEventW.restype = ctypes.c_void_p
        kernel32.SetEvent.argtypes = (ctypes.c_void_p,)
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
        event = kernel32.OpenEventW(2, False, f"Local\\FlowTunnel.Stop.{process.pid}")
        if event:
            try:
                if not kernel32.SetEvent(event):
                    raise ctypes.WinError(ctypes.get_last_error())
                process.wait(timeout=5)
                return {"name": name, "pid": process.pid, "method": "named_event", "exit_code": process.returncode, "exited": True}
            finally:
                kernel32.CloseHandle(event)
        try:
            process.send_signal(signal.CTRL_BREAK_EVENT)
            process.wait(timeout=2)
            method = "ctrl_break"
        except (OSError, subprocess.TimeoutExpired):
            process.terminate()
            method = "terminate"
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                method = "kill"
                process.wait(timeout=5)
    return {"name": name, "pid": process.pid, "method": method, "exit_code": process.returncode, "exited": process.poll() is not None}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--results", required=True, type=Path)
    args = parser.parse_args()
    exe = args.exe.resolve()
    results = args.results.resolve()
    results.mkdir(parents=True, exist_ok=True)
    result_path = results / "result.json"
    started = time.monotonic()
    result: dict = {
        "success": False,
        "windivert_exercised": False,
        "endpoint": f"{ENDPOINT[0]}:{ENDPOINT[1]}",
        "virtual_ip": VIRTUAL_IP,
        "udp_sizes": list(UDP_SIZES),
        "cases": [],
        "cleanup": [],
    }
    processes: list[tuple[str, subprocess.Popen]] = []
    logs = []
    configs: list[Path] = []
    services: list[EchoService] = []

    def case(name, action, **details):
        case_started = time.monotonic()
        entry = {"name": name, "passed": False, **details}
        result["cases"].append(entry)
        action()
        entry["passed"] = True
        entry["seconds"] = round(time.monotonic() - case_started, 3)
        print(f"PASS {name}", flush=True)

    try:
        if os.name != "nt" or not ctypes.windll.shell32.IsUserAnAdmin():
            result["blocked"] = "Administrator privileges are required to load and exercise WinDivert."
            raise PermissionError(result["blocked"])
        if not exe.is_file():
            raise FileNotFoundError(f"FlowTunnel executable not found: {exe}")
        key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        for mode, setting in (
            ("server", f'listen = "{ENDPOINT[0]}:{ENDPOINT[1]}"'),
            ("client", f'endpoint = "{ENDPOINT[0]}:{ENDPOINT[1]}"'),
        ):
            config = results / f"test-{mode}.toml"
            config.write_text(f'mode = "{mode}"\n{setting}\nkey = "{key}"\n', encoding="utf-8")
            configs.append(config)
            subprocess.run([str(exe), "check", str(config)], check=True, capture_output=True, timeout=10)
        del key

        def target(protocol: str, *, reply_after_eof: bool = False):
            service = EchoService(protocol, reply_after_eof=reply_after_eof)
            services.append(service)
            return service

        tcp_targets = [target("tcp"), target("tcp")]
        halfclose_target = target("tcp", reply_after_eof=True)
        udp_targets = [target("udp"), target("udp")]
        result["target_ports"] = {"tcp": [s.port for s in tcp_targets], "halfclose": halfclose_target.port, "udp": [s.port for s in udp_targets]}

        for mode in ("server", "client"):
            log_path = results / f"{mode}.log"
            log = log_path.open("wb")
            logs.append(log)
            process = subprocess.Popen(
                [str(exe), "run", str(results / f"test-{mode}.toml")],
                cwd=exe.parent,
                stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW,
            )
            processes.append((mode, process))
            wait_ready(process, log_path)
        print("Both roles reported ready", flush=True)

        def concurrent_tcp():
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                jobs = [pool.submit(tcp_exchange, tcp_targets[i % 2].port, secrets.token_bytes(1024 * 1024)) for i in range(4)]
                for job in jobs:
                    job.result(timeout=TIMEOUT + 5)

        case("tcp_concurrent_large_streams", concurrent_tcp, connections=4, bytes_per_connection=1024 * 1024, destinations=2)

        def halfclose():
            payload = secrets.token_bytes(131071)
            with socket.create_connection((VIRTUAL_IP, halfclose_target.port), TIMEOUT) as conn:
                conn.settimeout(TIMEOUT)
                conn.sendall(payload)
                conn.shutdown(socket.SHUT_WR)
                assert receive_to_eof(conn, 32) == hashlib.sha256(payload).digest(), "TCP half-close did not preserve response direction"

        case("tcp_half_close", halfclose, bytes=131071)

        def refused_target():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
                try:
                    with socket.create_connection((VIRTUAL_IP, port), TIMEOUT) as conn:
                        conn.settimeout(TIMEOUT)
                        assert conn.recv(1) == b"", "unavailable TCP target returned data"
                except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError):
                    pass

        case("tcp_unavailable_target", refused_target)
        case("udp_datagram_sizes", lambda: udp_exchange(udp_targets[0].port, UDP_SIZES), datagrams=len(UDP_SIZES))

        def concurrent_udp():
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                jobs = [pool.submit(udp_exchange, udp_targets[i % 2].port, (4096, 32000), 3) for i in range(4)]
                for job in jobs:
                    job.result(timeout=TIMEOUT + 5)

        case("udp_independent_sessions", concurrent_udp, sessions=4, destinations=2, datagrams=24)

        def mixed_protocols():
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                jobs = [pool.submit(tcp_exchange, target.port, secrets.token_bytes(1024 * 1024)) for target in tcp_targets]
                jobs.extend(pool.submit(udp_exchange, target.port, (32, 4096, 32000), 2) for target in udp_targets)
                for job in jobs:
                    job.result(timeout=TIMEOUT + 5)

        case("tcp_udp_same_public_port", mixed_protocols, tcp_connections=2, udp_sessions=2, udp_datagrams=12)

        def unauthenticated_connection():
            accepted_before = sum(target.accepted for target in tcp_targets)
            hello = struct.pack("!4sBBH", b"FT01", 1, 0, tcp_targets[0].port) + secrets.token_bytes(32) + bytes(32)
            with socket.create_connection(ENDPOINT, TIMEOUT) as conn:
                conn.settimeout(TIMEOUT)
                conn.sendall(REQUEST_PREFIX + hello)
                try:
                    assert conn.recv(1) == b"", "unauthenticated connection received a response"
                except (ConnectionResetError, ConnectionAbortedError):
                    pass
            assert sum(target.accepted for target in tcp_targets) == accepted_before, "target was contacted before authentication"
            assert all(process.poll() is None for _, process in processes), "a tunnel role exited after malformed authentication"
            tcp_exchange(tcp_targets[0].port, b"still alive after rejected authentication")

        case("authentication_before_target_access", unauthenticated_connection)

        def replayed_hello():
            accepted_before = sum(target.accepted for target in tcp_targets)
            secret = base64.b64decode(tomllib.loads(configs[0].read_text(encoding="utf-8"))["key"])
            header = struct.pack("!4sBBH", b"FT01", 1, 0, tcp_targets[0].port) + secrets.token_bytes(32)
            hello = header + hmac.digest(secret, b"flowtunnel/client-hello/v1\0" + header, "sha256")
            del secret
            responses = []
            prefix = b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: keep-alive\r\n\r\n"
            for _ in range(2):
                with socket.create_connection(ENDPOINT, TIMEOUT) as conn:
                    conn.settimeout(TIMEOUT)
                    conn.sendall(REQUEST_PREFIX + hello)
                    response = bytearray()
                    while len(response) < len(prefix) + 64:
                        data = conn.recv(len(prefix) + 64 - len(response))
                        assert data, "server closed before issuing session challenge"
                        response.extend(data)
                    assert response[:len(prefix)] == prefix
                    responses.append(bytes(response[len(prefix):]))
                    time.sleep(0.05)
                    assert sum(target.accepted for target in tcp_targets) == accepted_before, "replayed hello contacted target without session proof"
            assert responses[0] != responses[1], "replayed hello reused server challenge"

        case("replayed_hello_requires_session_proof", replayed_hello)

        def client_launcher_cleanup():
            launcher_test = Path(__file__).with_name("client_launcher_test.ps1").resolve()
            powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
            baseline_client = next(process for name, process in processes if name == "client")
            baseline_server = next(process for name, process in processes if name == "server")
            launcher_log = results / "client-launcher-test.log"
            with launcher_log.open("wb") as output:
                completed = subprocess.run(
                    [str(powershell), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(launcher_test),
                     "-Exe", str(exe), "-ClientConfig", str(results / "test-client.toml"),
                     "-BaselineClientId", str(baseline_client.pid), "-ServerId", str(baseline_server.pid),
                     "-Results", str(results)],
                    stdout=output, stderr=subprocess.STDOUT, timeout=60,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            if completed.returncode != 0:
                raise RuntimeError(f"Client launcher helper test failed with exit code {completed.returncode}; see {launcher_log}")
            launcher_result = json.loads((results / "client-launcher-result.json").read_text(encoding="utf-8-sig"))
            assert launcher_result["success"] is True, "Client launcher helper did not report successful cleanup"
            assert all(process.poll() is None for _, process in processes), "Launcher helper stopped a baseline tunnel process"
            result["client_launcher"] = launcher_result

        case("client_launcher_process_and_rule_cleanup", client_launcher_cleanup)
        assert all(process.poll() is None for _, process in processes), "a tunnel role exited during tests"
        result["success"] = True
        result["windivert_exercised"] = True
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        print(result["error"], flush=True)
    finally:
        for name, process in reversed(processes):
            try:
                result["cleanup"].append(stop_process(process, name))
            except Exception as exc:
                result["success"] = False
                result["cleanup"].append({"name": name, "pid": process.pid, "exited": False, "error": str(exc)})
        if result["success"]:
            graceful = all(item.get("method") == "named_event" and item.get("exit_code") == 0 for item in result["cleanup"])
            result["cases"].append({"name": "graceful_shutdown", "passed": graceful, "processes": len(processes)})
            result["success"] = graceful
        for log in logs:
            log.close()
        for service in services:
            try:
                service.close()
            except Exception as exc:
                result["success"] = False
                result["cleanup"].append({"name": "target_service", "port": service.port, "error": str(exc)})
        for config in configs:
            try:
                config.unlink(missing_ok=True)
            except OSError as exc:
                result["success"] = False
                result["cleanup"].append({"name": "temporary_key_config", "error": str(exc)})
        result["windivert_exercised"] = result["success"] and result["windivert_exercised"]
        result["passed_cases"] = sum(case["passed"] for case in result["cases"])
        result["total_cases"] = len(result["cases"])
        result["seconds"] = round(time.monotonic() - started, 3)
        result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"Result: {result_path}", flush=True)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
