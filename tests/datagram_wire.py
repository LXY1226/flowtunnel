"""Measure fake TCP ACKs and inject scoped UDP transport faults using real WinDivert."""

from __future__ import annotations

import argparse
import base64
from collections import Counter
import ctypes
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import threading
import time

from local_e2e import stop_process


VIRTUAL_IP = "10.200.0.1"
HEADER = struct.Struct("!4s16sI")
MAX_SECONDS = 90
RECORD_OVERHEAD = 37


def require(condition: bool, message: str):
    if not condition:
        raise AssertionError(message)


class Address(ctypes.Structure):
    _fields_ = [("timestamp", ctypes.c_int64), ("flags", ctypes.c_uint32),
                ("reserved", ctypes.c_uint32), ("data", ctypes.c_ubyte * 64)]


def parse_packet(raw: bytes, public_port: int) -> dict | None:
    if len(raw) < 40 or raw[0] >> 4 != 4 or raw[9] != 6:
        return None
    ip_size = (raw[0] & 15) * 4
    total = int.from_bytes(raw[2:4], "big")
    if ip_size < 20 or len(raw) < total or total < ip_size + 20:
        return None
    tcp_size = (raw[ip_size + 12] >> 4) * 4
    if tcp_size < 20 or total < ip_size + tcp_size:
        return None
    source, destination, sequence, ack = struct.unpack_from("!HHII", raw, ip_size)
    if public_port not in (source, destination):
        return None
    payload = raw[ip_size + tcp_size:total]
    kind = "hello" if payload.startswith(b"GET /") else "response" if payload.startswith(b"HTTP/") else "record" if payload else "empty"
    flags = raw[ip_size + 13]
    return {"direction": "s2c" if source == public_port else "c2s",
            "peer_port": destination if source == public_port else source,
            "seq": sequence, "ack": ack, "flags": flags,
            "payload_size": len(payload), "kind": kind,
            "counter": int.from_bytes(payload[:8], "big") if kind == "record" and len(payload) >= 24 else None,
            "pure_ack": not payload and flags == 16}


class DivertAPI:
    def __init__(self, dll: Path):
        require(ctypes.sizeof(Address) == 80, "incorrect WINDIVERT_ADDRESS layout")
        frequency = ctypes.c_int64()
        require(bool(ctypes.windll.kernel32.QueryPerformanceFrequency(ctypes.byref(frequency))),
                "QueryPerformanceFrequency failed")
        self.frequency = frequency.value
        self.library_directory = os.add_dll_directory(str(dll.parent))
        self.dll = ctypes.WinDLL(str(dll), use_last_error=True)
        self.dll.WinDivertOpen.argtypes = (ctypes.c_char_p, ctypes.c_int, ctypes.c_int16, ctypes.c_uint64)
        self.dll.WinDivertOpen.restype = ctypes.c_void_p
        self.dll.WinDivertRecv.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                          ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(Address))
        self.dll.WinDivertRecv.restype = ctypes.c_int
        self.dll.WinDivertSend.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                          ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(Address))
        self.dll.WinDivertSend.restype = ctypes.c_int
        self.dll.WinDivertShutdown.argtypes = (ctypes.c_void_p, ctypes.c_int)
        self.dll.WinDivertShutdown.restype = ctypes.c_int
        self.dll.WinDivertClose.argtypes = (ctypes.c_void_p,)
        self.dll.WinDivertClose.restype = ctypes.c_int

    def open(self, packet_filter: str, priority: int, flags: int):
        handle = self.dll.WinDivertOpen(packet_filter.encode("ascii"), 0, priority, flags)
        if not handle or handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def send(self, handle, raw: bytes, address: Address):
        buffer = ctypes.create_string_buffer(raw)
        count = ctypes.c_uint32()
        if not self.dll.WinDivertSend(handle, buffer, len(raw), ctypes.byref(count), ctypes.byref(address)):
            raise ctypes.WinError(ctypes.get_last_error())
        require(count.value == len(raw), "WinDivertSend returned a partial packet")


class Tap:
    def __init__(self, api: DivertAPI, packet_filter: str, priority: int, public_port: int, *, faults=False):
        self.api, self.public_port, self.faults = api, public_port, faults
        self.handle = api.open(packet_filter, priority, 0 if faults else 1 | 4)
        self.lock = threading.RLock()
        self.records: list[dict] = []
        self.templates: dict[tuple[int, str], tuple[bytes, bytes]] = {}
        self.errors: list[str] = []
        self.stopping = threading.Event()
        self.plan: dict | None = None
        self.held: tuple[bytes, bytes, dict] | None = None
        self.actions: list[dict] = []
        self.thread = threading.Thread(target=self._receive, daemon=True)
        self.thread.start()

    def _receive(self):
        buffer = ctypes.create_string_buffer(65535)
        try:
            while True:
                count, address = ctypes.c_uint32(), Address()
                if not self.api.dll.WinDivertRecv(self.handle, buffer, len(buffer), ctypes.byref(count), ctypes.byref(address)):
                    error = ctypes.get_last_error()
                    if self.stopping.is_set() and error in (6, 232, 995):
                        return
                    raise ctypes.WinError(error)
                raw = buffer.raw[:count.value]
                row = parse_packet(raw, self.public_port)
                if row is None:
                    if self.faults:
                        self.api.send(self.handle, raw, address)
                    continue
                row.update(time=address.timestamp / self.api.frequency, observed_time=time.perf_counter(),
                           outbound=bool(address.flags & (1 << 17)),
                           loopback=bool(address.flags & (1 << 18)), impostor=bool(address.flags & (1 << 19)))
                with self.lock:
                    self.records.append(row)
                    if row["pure_ack"]:
                        self.templates[row["peer_port"], row["direction"]] = (raw, bytes(address))
                    if self.faults:
                        self._forward(raw, address, row)
        except Exception as error:
            with self.lock:
                self.errors.append(f"{type(error).__name__}: {error}")

    def _forward(self, raw: bytes, address: Address, row: dict):
        plan = self.plan
        if plan and plan["kind"] == "response" and row["kind"] == "response":
            self.actions.append({**row, "action": "drop_first_handshake_response"})
            self.plan = None
            return
        if (plan and plan["kind"] == "records" and row["direction"] == "c2s"
                and row["peer_port"] == plan["peer_port"] and row["payload_size"] == plan["payload_size"]):
            plan["seen"] += 1
            if plan["seen"] == 1:
                self.actions.append({**row, "action": "drop_data"})
                return
            if plan["seen"] == 2:
                self.held = (raw, bytes(address), row)
                self.actions.append({**row, "action": "hold_data"})
                return
            if plan["seen"] == 3:
                self.api.send(self.handle, raw, address)
                self.actions.append({**row, "action": "release_third_before_second"})
                held_raw, held_address, held_row = self.held
                self.api.send(self.handle, held_raw, Address.from_buffer_copy(held_address))
                self.actions.append({**held_row, "action": "release_second_after_third"})
                self.held = None
                self.plan = None
                return
        self.api.send(self.handle, raw, address)

    def arm(self, kind: str, **details):
        with self.lock:
            require(self.plan is None and self.held is None, "an earlier fault plan is still active")
            self.plan = {"kind": kind, "seen": 0, **details}

    def rows(self, *, since=0.0, peer_port=None) -> list[dict]:
        with self.lock:
            return [dict(row) for row in self.records
                    if row["time"] >= since and (peer_port is None or row["peer_port"] == peer_port)]

    def inject_ack(self, peer_port: int, direction: str):
        with self.lock:
            require((peer_port, direction) in self.templates, "no captured pure ACK template is available")
            raw, address = self.templates[peer_port, direction]
            injected_address = Address.from_buffer_copy(address)
            injected_address.flags &= ~(1 << 16)
            self.api.send(self.handle, raw, injected_address)

    def close(self) -> dict:
        self.stopping.set()
        shutdown = bool(self.api.dll.WinDivertShutdown(self.handle, 1))
        shutdown_error = None if shutdown else ctypes.get_last_error()
        self.thread.join(timeout=2)
        forced_close = self.thread.is_alive()
        if forced_close:
            self.api.dll.WinDivertClose(self.handle)
            self.thread.join(timeout=2)
        else:
            self.api.dll.WinDivertClose(self.handle)
        with self.lock:
            return {"priority_fault_hook": self.faults, "shutdown": shutdown,
                    "shutdown_error": shutdown_error, "forced_handle_close": forced_close,
                    "thread_exited": not self.thread.is_alive(), "errors": list(self.errors),
                    "unreleased_held_packet": self.held is not None}


class Fixture:
    def __init__(self, echo: bool):
        self.echo = echo
        self.nonce = secrets.token_bytes(16)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.1)
        self.port = self.socket.getsockname()[1]
        self.lock = threading.Lock()
        self.received: list[dict] = []
        self.errors: list[str] = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._receive, daemon=True)
        self.thread.start()

    def message(self, sequence: int, size: int) -> bytes:
        return HEADER.pack(b"FTAW", self.nonce, sequence) + bytes([sequence % 251]) * (size - HEADER.size)

    def decode(self, raw: bytes) -> int:
        require(len(raw) >= HEADER.size, "short fixture datagram")
        magic, nonce, sequence = HEADER.unpack_from(raw)
        require(magic == b"FTAW" and nonce == self.nonce, "unexpected fixture datagram identity")
        require(raw == self.message(sequence, len(raw)), "application datagram corruption")
        return sequence

    def _receive(self):
        try:
            while not self.stop.is_set():
                try:
                    raw, peer = self.socket.recvfrom(65535)
                except socket.timeout:
                    continue
                received = time.perf_counter()
                sequence = self.decode(raw)
                with self.lock:
                    self.received.append({"sequence": sequence, "time": received, "size": len(raw), "peer": list(peer)})
                if self.echo:
                    self.socket.sendto(raw, peer)
        except OSError as error:
            if not self.stop.is_set():
                self.errors.append(f"{type(error).__name__}: {error}")
        except Exception as error:
            self.errors.append(f"{type(error).__name__}: {error}")

    def rows(self) -> list[dict]:
        with self.lock:
            return [dict(row) for row in self.received]

    def close(self) -> dict:
        self.stop.set()
        self.socket.close()
        self.thread.join(timeout=1)
        return {"target_port": self.port, "thread_exited": not self.thread.is_alive(), "errors": list(self.errors)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--results", required=True, type=Path)
    args = parser.parse_args()
    require(args.exe.is_absolute() and args.results.is_absolute(), "--exe and --results must be absolute")
    exe, results = args.exe.resolve(), args.results.resolve()
    results.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    deadline = started + 40
    result = {"success": False, "windivert_exercised": False, "cases": [], "cleanup": [],
              "capture_layout": {"pre_fault_priority": 2000, "fault_priority": 1000,
                                 "post_fault_priority": 500, "runtime_server_priority": 200,
                                 "runtime_client_priority": 100, "runtime_injection_priority": 30000},
              "limits": {"maximum_seconds": MAX_SECONDS, "ack_delay_tolerance_ms": 100}}
    result["timestamp_source"] = "WinDivert QPC capture timestamp / QueryPerformanceFrequency; application perf_counter"
    processes, logs, configs, fixtures, applications, taps = [], [], [], [], [], []
    pre = post = faults = None

    def healthy():
        require(time.perf_counter() < deadline, "wire test exceeded its execution budget")
        for name, process in processes:
            require(process.poll() is None, f"owned {name} exited unexpectedly with {process.returncode}")
        for tap in taps:
            require(not tap.errors, f"WinDivert capture failed: {tap.errors}")
        for fixture in fixtures:
            require(not fixture.errors, f"fixture failed: {fixture.errors}")

    def wait_until(predicate, description: str, timeout=3):
        until = min(deadline, time.perf_counter() + timeout)
        while time.perf_counter() < until:
            healthy()
            value = predicate()
            if value:
                return value
            time.sleep(0.002)
        raise TimeoutError(description)

    def settle(seconds=0.06):
        until = min(deadline, time.perf_counter() + seconds)
        while time.perf_counter() < until:
            healthy()
            time.sleep(min(0.01, max(0, until - time.perf_counter())))

    def make_flow(echo: bool):
        fixture = Fixture(echo)
        fixtures.append(fixture)
        application = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        application.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        application.bind(("0.0.0.0", 0))
        application.settimeout(2)
        applications.append(application)
        return fixture, application

    def send(fixture, application, sequence, size):
        raw = fixture.message(sequence, size)
        require(application.sendto(raw, (VIRTUAL_IP, fixture.port)) == size, "partial UDP application send")

    def receive(fixture, application, sequence, size):
        raw, peer = application.recvfrom(65535)
        require(peer == (VIRTUAL_IP, fixture.port), "virtual UDP peer changed")
        require(fixture.decode(raw) == sequence and len(raw) == size, "unexpected echo datagram")

    def peer_for(since):
        rows = wait_until(lambda: [row for row in pre.rows(since=since) if row["kind"] == "hello"], "no fake TCP hello captured")
        peers = {row["peer_port"] for row in rows}
        require(len(peers) == 1, f"new UDP flow has ambiguous outer peers: {peers}")
        return next(iter(peers))

    def warmup(fixture, application):
        since = time.perf_counter()
        send(fixture, application, 0, 32)
        wait_until(lambda: fixture.rows(), "UDP fixture did not receive bootstrap")
        if fixture.echo:
            receive(fixture, application, 0, 32)
        peer = peer_for(since)
        settle(0.12)
        return peer

    def run_case(name, action):
        entry = {"name": name, "passed": False}
        result["cases"].append(entry)
        case_started = time.perf_counter()
        try:
            action(entry)
            healthy()
            entry["passed"] = True
            print(f"PASS {name}", flush=True)
        except Exception as error:
            entry["error"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            entry["seconds"] = round(time.perf_counter() - case_started, 3)

    try:
        require(os.name == "nt" and ctypes.windll.shell32.IsUserAnAdmin(), "administrator Windows session required")
        require(exe.is_file(), "FlowTunnel executable does not exist")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            public_port = reservation.getsockname()[1]
        result["endpoint"] = f"127.0.0.1:{public_port}"
        api = DivertAPI(exe.with_name("WinDivert.dll"))
        packet_filter = ("ip and tcp and ip.SrcAddr == 127.0.0.1 and ip.DstAddr == 127.0.0.1 and "
                         f"(tcp.SrcPort == {public_port} or tcp.DstPort == {public_port})")
        result["capture_filter"] = packet_filter
        # Below-runtime sniffers miss packets consumed by the fake TCP runtime.
        # These two passive taps bracket only the scoped fault handle above both roles.
        for priority, fault_handle in ((2000, False), (1000, True), (500, False)):
            tap = Tap(api, packet_filter, priority, public_port, faults=fault_handle)
            taps.append(tap)
        pre, faults, post = taps
        low_observer = Tap(api, packet_filter, -1000, public_port)
        taps.append(low_observer)
        result["capture_layout"]["below_runtime_passive_priority"] = -1000
        token = secrets.token_hex(8)
        key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        for mode, field in (("server", "listen"), ("client", "endpoint")):
            config = results / f"wire-{token}-{mode}.toml"
            configs.append(config)
            config.write_text(f'mode = "{mode}"\n{field} = "127.0.0.1:{public_port}"\nkey = "{key}"\n', encoding="utf-8")
            checked = subprocess.run([str(exe), "check", str(config)], capture_output=True, timeout=5)
            require(checked.returncode == 0, f"isolated {mode} configuration rejected")
            log_path = results / f"{mode}.log"
            log = log_path.open("wb")
            logs.append(log)
            process = subprocess.Popen([str(exe), "run", str(config)], cwd=exe.parent, stdout=log,
                                       stderr=subprocess.STDOUT,
                                       creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW)
            processes.append((mode, process))
            wait_until(lambda: "ready" in log_path.read_text(encoding="utf-8", errors="replace"),
                       f"owned {mode} did not report ready", timeout=15)
        del key

        def paced_echo(entry):
            fixture, application = make_flow(True)
            peer = warmup(fixture, application)
            since = time.perf_counter()
            for sequence in range(1, 51):
                send(fixture, application, sequence, 96)
                receive(fixture, application, sequence, 96)
                settle(0.005)
            settle()
            rows = post.rows(since=since, peer_port=peer)
            records = [row for row in rows if row["payload_size"] == 96 + RECORD_OVERHEAD]
            counts = Counter(row["direction"] for row in records)
            pure = sum(row["pure_ack"] for row in rows)
            entry.update(target_port=fixture.port, peer_port=peer, application_datagrams_per_direction=50,
                         data_records=dict(counts), pure_acks=pure, pure_ack_to_data_ratio=round(pure / max(1, len(records)), 4))
            require(counts == {"c2s": 50, "s2c": 50}, f"echo capture missing or duplicating data records: {counts}")
            require(pure < len(records) * 0.35, "paced echo did not suppress pure ACKs through piggyback")

        run_case("paced_bidirectional_piggyback", paced_echo)

        def one_way(entry):
            fixture, application = make_flow(False)
            peer = warmup(fixture, application)
            since = time.perf_counter()
            for sequence in range(1, 65):
                send(fixture, application, sequence, 1100)
                if sequence % 8 == 0:
                    settle(0.001)
            wait_until(lambda: len(fixture.rows()) >= 65, "one-way burst did not reach target")
            settle()
            require([row["sequence"] for row in fixture.rows()] == list(range(65)), "one-way burst corruption, loss or reordering")
            rows = post.rows(since=since, peer_port=peer)
            records = [row for row in rows if row["direction"] == "c2s" and row["payload_size"] == 1100 + RECORD_OVERHEAD]
            pure = [row for row in rows if row["direction"] == "s2c" and row["pure_ack"]]
            entry.update(target_port=fixture.port, peer_port=peer, application_datagrams=64,
                         data_records=len(records), pure_acks=len(pure),
                         pure_ack_to_data_ratio=round(len(pure) / max(1, len(records)), 4),
                         acknowledged_sequence_ends=[row["ack"] for row in pure])
            require(len(records) == 64, "one-way burst capture did not contain exactly one record per datagram")
            require(0 < len(pure) < 32, "one-way burst ACK count was not reduced")

        run_case("one_way_burst_batched_ack", one_way)
        single_flow = {}

        def single_record(entry):
            fixture, application = make_flow(False)
            peer = warmup(fixture, application)
            since = time.perf_counter()
            send(fixture, application, 1, 128)
            wait_until(lambda: len(fixture.rows()) == 2, "single datagram did not reach application")
            data = wait_until(lambda: [row for row in post.rows(since=since, peer_port=peer)
                                      if row["direction"] == "c2s" and row["payload_size"] == 128 + RECORD_OVERHEAD], "single data record was not captured")[0]
            expected_ack = (data["seq"] + data["payload_size"]) & 0xffffffff
            acknowledgments = wait_until(lambda: [row for row in post.rows(since=since, peer_port=peer)
                                                 if row["direction"] == "s2c" and row["pure_ack"] and row["ack"] == expected_ack], "single datagram did not get a pure ACK")
            ack = acknowledgments[0]
            delivered = fixture.rows()[1]["time"]
            delay = (ack["time"] - data["time"]) * 1000
            delivery_delay = (delivered - data["time"]) * 1000
            entry.update(target_port=fixture.port, peer_port=peer, data_sequence=data["seq"],
                         expected_ack=expected_ack, ack_delay_ms=round(delay, 3),
                         application_delivery_ms=round(delivery_delay, 3),
                         application_before_ack_ms=round((ack["time"] - delivered) * 1000, 3))
            require(1 <= delay <= 100, f"single-record delayed ACK outside scheduling tolerance: {delay:.3f} ms")
            require(delivered < ack["time"], "application delivery waited until after the delayed ACK")
            single_flow.update(peer=peer, fixture=fixture)
            settle()

        run_case("single_record_timer_without_application_gate", single_record)

        def ack_only(entry):
            peer = single_flow["peer"]
            before = len(single_flow["fixture"].rows())
            since = time.perf_counter()
            for _ in range(3):
                faults.inject_ack(peer, "s2c")
                settle(0.005)
            settle(0.08)
            rows = post.rows(since=since, peer_port=peer)
            injected = [row for row in rows if row["direction"] == "s2c" and row["pure_ack"]]
            feedback = [row for row in rows if row["direction"] == "c2s" and row["pure_ack"]]
            entry.update(peer_port=peer, injected_pure_acks=3, observed_pure_acks=len(injected),
                         feedback_pure_acks=len(feedback), observation_ms=round((time.perf_counter() - since) * 1000, 3))
            require(len(injected) == 3, "injected pure ACKs were not observed exactly once")
            require(not feedback, "pure incoming ACK elicited an ACK feedback response")
            require(len(single_flow["fixture"].rows()) == before, "pure ACK produced application data")

        run_case("pure_ack_no_feedback_loop", ack_only)

        def loss_reorder(entry):
            fixture, application = make_flow(False)
            peer = warmup(fixture, application)
            faults.arm("records", peer_port=peer, payload_size=192 + RECORD_OVERHEAD)
            since = time.perf_counter()
            for sequence in range(1, 6):
                send(fixture, application, sequence, 192)
                settle(0.002)
            wait_until(lambda: len(fixture.rows()) >= 5, "later datagrams blocked after loss/reorder")
            settle(0.3)
            delivered = [row["sequence"] for row in fixture.rows()]
            pre_records = [row for row in pre.rows(since=since, peer_port=peer)
                           if row["direction"] == "c2s" and row["payload_size"] == 192 + RECORD_OVERHEAD]
            post_records = [row for row in post.rows(since=since, peer_port=peer)
                            if row["direction"] == "c2s" and row["payload_size"] == 192 + RECORD_OVERHEAD]
            actions = [dict(row) for row in faults.actions if row["time"] >= since and row["peer_port"] == peer]
            entry.update(target_port=fixture.port, peer_port=peer, dropped_application_sequence=1,
                         delivered_application_order=delivered, pre_fault_record_sequences=[row["seq"] for row in pre_records],
                         post_fault_record_sequences=[row["seq"] for row in post_records],
                         fault_actions=[{key: row[key] for key in ("action", "seq", "counter")} for row in actions],
                         duplicate_counters={str(key): count for key, count in Counter(row["counter"] for row in pre_records).items() if count > 1})
            require(delivered == [0, 3, 2, 4, 5], f"UDP did not preserve explicit loss/reorder semantics: {delivered}")
            require(len(pre_records) == 5 and len(post_records) == 4, "wire record count changed after scoped fault injection")
            require([row["seq"] for row in post_records] == [pre_records[index]["seq"] for index in (2, 1, 3, 4)], "post-fault tap did not confirm the intended wire order")
            require(not entry["duplicate_counters"], "dropped UDP record was retransmitted")
            require(len(actions) == 4 and faults.plan is None and faults.held is None, "fault plan did not complete")

        run_case("dropped_and_reordered_datagrams_continue", loss_reorder)

        def handshake_retry(entry):
            fixture, application = make_flow(True)
            faults.arm("response")
            since = time.perf_counter()
            send(fixture, application, 1, 80)
            receive(fixture, application, 1, 80)
            peer = peer_for(since)
            settle()
            rows = pre.rows(since=since, peer_port=peer)
            hellos = [row for row in rows if row["kind"] == "hello"]
            responses = [row for row in rows if row["kind"] == "response"]
            data = [row for row in rows if row["payload_size"] == 80 + RECORD_OVERHEAD]
            outgoing = {direction: [row for row in data if row["direction"] == direction] for direction in ("c2s", "s2c")}
            entry.update(target_port=fixture.port, peer_port=peer, client_hello_sequences=[row["seq"] for row in hellos],
                         server_response_sequences=[row["seq"] for row in responses],
                         first_data_sequences={direction: records[0]["seq"] if records else None for direction, records in outgoing.items()},
                         dropped_handshake_responses=sum(row["action"] == "drop_first_handshake_response" and row["time"] >= since for row in faults.actions))
            require(len(hellos) >= 2 and len(responses) >= 2, "dropped response did not exercise handshake retry")
            require(len({row["seq"] for row in hellos}) == 1, "client hello retry advanced its wire sequence")
            require(len({row["seq"] for row in responses}) == 1, "server response retry advanced its wire sequence")
            for direction, handshake in (("c2s", hellos[0]), ("s2c", responses[0])):
                require(len(outgoing[direction]) == 1, "handshake retry duplicated or lost application data")
                expected_sequence = (handshake["seq"] + handshake["payload_size"]) & 0xffffffff
                encrypted_records = [row for row in rows if row["direction"] == direction and row["kind"] == "record"]
                for record in encrypted_records:
                    require(record["seq"] == expected_sequence,
                            f"{direction} record sequence did not follow the handshake and intervening records")
                    expected_sequence = (expected_sequence + record["payload_size"]) & 0xffffffff
            require(entry["dropped_handshake_responses"] == 1, "unexpected handshake fault count")

        run_case("handshake_response_loss_reuses_sequences", handshake_retry)
        result["windivert_exercised"] = True
        result["success"] = True
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        # Stop only process handles created above; the public port and fault filter are exclusive to this fixture.
        for name, process in reversed(processes):
            try:
                item = stop_process(process, name)
                result["cleanup"].append(item)
                if not item["exited"] or item["exit_code"] != 0:
                    result["success"] = False
            except Exception as error:
                result["cleanup"].append({"name": name, "error": f"{type(error).__name__}: {error}"})
                result["success"] = False
                if process.poll() is None:
                    try:
                        process.terminate()
                        try:
                            process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=2)
                        result["cleanup"].append({"name": name, "pid": process.pid,
                                                  "fallback_owned_process_exit": process.returncode})
                    except Exception as cleanup_error:
                        result["cleanup"].append({"name": name, "pid": process.pid,
                                                  "fallback_error": f"{type(cleanup_error).__name__}: {cleanup_error}"})
        for application in applications:
            application.close()
        for fixture in fixtures:
            item = fixture.close()
            result["cleanup"].append(item)
            if not item["thread_exited"] or item["errors"]:
                result["success"] = False
        for tap in taps:
            item = tap.close()
            result["cleanup"].append(item)
            if not item["thread_exited"] or item["errors"] or item["unreleased_held_packet"]:
                result["success"] = False
        for config in configs:
            try:
                config.unlink(missing_ok=True)
                result["cleanup"].append({"config": config.name, "removed": not config.exists()})
            except OSError as error:
                result["cleanup"].append({"config": config.name, "error": str(error)})
                result["success"] = False
        for log in logs:
            log.close()
        capture = {}
        for name, tap in (("pre_fault", pre), ("post_fault", post)):
            if tap:
                rows = tap.rows()
                capture[name] = [{**row, "time": round(row["time"] - started, 6),
                                  "observed_time": round(row["observed_time"] - started, 6)} for row in rows]
        capture["fault_actions"] = [{**row, "time": round(row["time"] - started, 6),
                                    "observed_time": round(row["observed_time"] - started, 6)} for row in faults.actions] if faults else []
        result["capture_counts"] = {name: len(rows) for name, rows in capture.items()}
        if len(taps) > 3:
            result["below_runtime_capture_count"] = len(taps[3].rows())
        result["capture_metadata"] = "wire-metadata.json"
        result["seconds"] = round(time.perf_counter() - started, 3)
        if result["seconds"] > MAX_SECONDS:
            result["success"] = False
            result["runtime_limit_exceeded"] = True
        (results / "wire-metadata.json").write_text(json.dumps(capture, indent=2) + "\n", encoding="utf-8")
        (results / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2), flush=True)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
