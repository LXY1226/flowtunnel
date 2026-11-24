"""Verify the remote services after the local FlowTunnel client is running."""

from __future__ import annotations

import argparse
import concurrent.futures
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import time
from urllib.request import ProxyHandler, build_opener

import local_e2e as transfer


HTTP_PORT = 18082
UDP_PORT = 18083
TCP_PORT = 18084
UDP_SIZES = (0, 32, 512, 1100, 4096, 32000, 60000)
SESSION_SIZES = (32, 4096, 32000)


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def udp_session(session_id: int, sizes: tuple[int, ...], rounds: int) -> dict:
    try:
        report = transfer.udp_exchange(UDP_PORT, sizes, rounds)
    except transfer.UDPExchangeError as exc:
        report = exc.report
    report["session_id"] = session_id
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, help="Absolute path for the result JSON file")
    parser.add_argument("--udp-only", action="store_true", help="Run only the concurrent UDP-session test")
    parser.add_argument("--sessions", type=positive_int, default=4, help="Concurrent UDP sessions (default: 4)")
    parser.add_argument("--rounds", type=positive_int, default=2, help="32/4096/32000-byte exchanges per UDP session (default: 2 rounds)")
    args = parser.parse_args()
    if args.results is not None and not args.results.is_absolute():
        parser.error("--results must be an absolute JSON file path")
    started = time.monotonic()
    result = {
        "success": False,
        "target": transfer.VIRTUAL_IP,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "udp_sizes": list(UDP_SIZES),
        "udp_only": args.udp_only,
        "udp_sessions": args.sessions,
        "udp_rounds": args.rounds,
        "timeout_seconds": transfer.TIMEOUT,
        "cases": [],
    }

    def case(name, action, **details):
        case_started = time.monotonic()
        entry = {"name": name, "passed": False, **details}
        result["cases"].append(entry)
        try:
            action()
            entry["passed"] = True
        except Exception as exc:
            entry["error"] = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            entry["seconds"] = round(time.monotonic() - case_started, 3)

    try:
        def health():
            opener = build_opener(ProxyHandler({}))
            with opener.open(f"http://{transfer.VIRTUAL_IP}:{HTTP_PORT}/health", timeout=transfer.TIMEOUT) as response:
                assert response.status == 200, f"unexpected HTTP status {response.status}"
                body = response.read(65537)
            assert len(body) <= 65536, "HTTP health response exceeded limit"
            decoded = json.loads(body)
            assert decoded.get("server") is True, "remote health response did not identify a server"
            assert decoded.get("service") == "FlowTunnel remote fixture", "unexpected remote health service"
            assert isinstance(decoded.get("nonce"), str) and len(decoded["nonce"]) == 32, "invalid remote boot nonce"
            datetime.fromisoformat(decoded["time"])
            assert decoded.get("tcp_port") == TCP_PORT and decoded.get("udp_port") == UDP_PORT, "remote fixture ports differ"
            result["health"] = decoded

        if not args.udp_only:
            case("http_health_without_proxy", health)

        def concurrent_tcp():
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                jobs = [pool.submit(transfer.tcp_exchange, TCP_PORT, secrets.token_bytes(1024 * 1024)) for _ in range(2)]
                for job in jobs:
                    job.result()

        if not args.udp_only:
            case("tcp_concurrent_binary_and_half_close", concurrent_tcp, connections=2, bytes_per_connection=1024 * 1024)

            def basic_udp():
                report = udp_session(1, UDP_SIZES, 1)
                result["udp_datagram_report"] = report
                if not report["success"]:
                    raise RuntimeError(f"UDP size test failed at packet {report.get('failed_index')}, size {report.get('failed_size')}: {report.get('error')}")

            case("udp_datagram_sizes", basic_udp, datagrams=len(UDP_SIZES))

        def concurrent_udp():
            reports = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.sessions) as pool:
                jobs = {pool.submit(udp_session, session_id, SESSION_SIZES, args.rounds): session_id
                        for session_id in range(1, args.sessions + 1)}
                for job in concurrent.futures.as_completed(jobs):
                    try:
                        reports.append(job.result())
                    except Exception as exc:
                        reports.append({"session_id": jobs[job], "success": False,
                                        "error": f"Unexpected worker error: {type(exc).__name__}: {exc}"})
            reports.sort(key=lambda report: report["session_id"])
            result["udp_session_reports"] = reports
            result["udp_totals"] = {field: sum(report.get(field, 0) for report in reports)
                                    for field in ("expected_datagrams", "sent_datagrams", "received_datagrams", "matched_datagrams")}
            failed = [report for report in reports if not report["success"]]
            if failed:
                descriptions = [f"session {report['session_id']} packet {report.get('failed_index')} round {report.get('failed_round')} size {report.get('failed_size')}: {report.get('error')}"
                                for report in failed]
                raise RuntimeError("; ".join(descriptions))

        case("udp_independent_sessions", concurrent_udp, sessions=args.sessions, rounds=args.rounds,
             sizes=list(SESSION_SIZES), datagrams=args.sessions * args.rounds * len(SESSION_SIZES))
        result["success"] = True
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    result["seconds"] = round(time.monotonic() - started, 3)
    result["passed_cases"] = sum(entry["passed"] for entry in result["cases"])
    result["total_cases"] = len(result["cases"])
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.results is not None:
        try:
            args.results.parent.mkdir(parents=True, exist_ok=True)
            args.results.write_text(encoded, encoding="utf-8")
        except OSError as exc:
            result["success"] = False
            result["error"] = f"Cannot write result file: {type(exc).__name__}: {exc}"
            encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    print(encoded, end="", flush=True)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
