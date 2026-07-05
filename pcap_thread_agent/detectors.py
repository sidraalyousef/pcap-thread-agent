"""Heuristics that flag security-relevant sequences among reconstructed flows."""
import ipaddress
import math
import statistics
from collections import defaultdict
from typing import Dict, List, Tuple

from .models import Flow, Thread

SUSPICIOUS_PORTS = {4444, 1337, 31337, 6667, 12345, 5555}


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _flow_participants(flow: Flow) -> Tuple[str, str]:
    """Returns (initiator_ip, responder_ip), falling back to endpoint_a/b if unknown."""
    if flow.initiator is not None and flow.responder is not None:
        return flow.initiator[0], flow.responder[0]
    return flow.endpoint_a[0], flow.endpoint_b[0]


def detect_port_scans(flows: List[Flow], port_threshold: int = 15, window: float = 60.0) -> List[Thread]:
    """Flags a source IP that probes many distinct (host, port) pairs with no real data exchange."""
    probes_by_initiator: Dict[str, List[Tuple[float, str, int]]] = defaultdict(list)

    for flow in flows:
        if flow.proto != "TCP" or flow.initiator is None:
            continue
        responder_ip, responder_port = flow.responder
        # A "probe" here: initiator sent a SYN, but the flow carried effectively no payload back.
        no_data_exchanged = flow.bytes_b_to_a <= 60 and flow.packets_b_to_a <= 2
        if flow.syn_count >= 1 and no_data_exchanged:
            probes_by_initiator[flow.initiator[0]].append((flow.start_time, responder_ip, responder_port))

    threads = []
    for initiator_ip, probes in probes_by_initiator.items():
        probes.sort(key=lambda p: p[0])
        window_start = 0
        for i in range(len(probes)):
            while probes[i][0] - probes[window_start][0] > window:
                window_start += 1
            windowed = probes[window_start : i + 1]
            distinct_targets = {(ip, port) for _, ip, port in windowed}
            if len(distinct_targets) >= port_threshold:
                threads.append(
                    Thread(
                        id=f"port_scan-{initiator_ip}-{int(probes[window_start][0])}",
                        type="port_scan",
                        severity="high",
                        actor=initiator_ip,
                        targets=sorted({ip for _, ip, _ in windowed}),
                        start_time=probes[window_start][0],
                        end_time=probes[i][0],
                        evidence={
                            "distinct_targets_probed": len(distinct_targets),
                            "window_seconds": window,
                            "sample_targets": sorted(distinct_targets)[:20],
                        },
                    )
                )
                break  # one thread per initiator is enough for v1
    return threads


def detect_beaconing(flows: List[Flow], min_occurrences: int = 5, max_cv: float = 0.15) -> List[Thread]:
    """Flags a pair of hosts with many separate connections at suspiciously regular intervals."""
    by_pair: Dict[Tuple[str, str], List[Flow]] = defaultdict(list)
    for flow in flows:
        initiator_ip, responder_ip = _flow_participants(flow)
        by_pair[(initiator_ip, responder_ip)].append(flow)

    threads = []
    for (initiator_ip, responder_ip), pair_flows in by_pair.items():
        if len(pair_flows) < min_occurrences:
            continue
        pair_flows.sort(key=lambda f: f.start_time)
        intervals = [
            b.start_time - a.start_time for a, b in zip(pair_flows, pair_flows[1:]) if b.start_time > a.start_time
        ]
        if len(intervals) < min_occurrences - 1:
            continue
        mean_interval = statistics.mean(intervals)
        if mean_interval <= 0:
            continue
        stdev = statistics.pstdev(intervals)
        cv = stdev / mean_interval
        if cv <= max_cv:
            threads.append(
                Thread(
                    id=f"beaconing-{initiator_ip}-{responder_ip}",
                    type="beaconing",
                    severity="medium",
                    actor=initiator_ip,
                    targets=[responder_ip],
                    start_time=pair_flows[0].start_time,
                    end_time=pair_flows[-1].start_time,
                    evidence={
                        "connection_count": len(pair_flows),
                        "mean_interval_seconds": round(mean_interval, 2),
                        "coefficient_of_variation": round(cv, 3),
                    },
                    flows=pair_flows,
                )
            )
    return threads


def detect_data_exfil(flows: List[Flow], min_bytes: int = 5_000_000, asymmetry_ratio: float = 5.0) -> List[Thread]:
    """Flags large, asymmetric transfers from an internal host out to an external one."""
    threads = []
    for flow in flows:
        if flow.initiator is None or flow.responder is None:
            continue
        initiator_ip, _ = flow.initiator
        responder_ip, _ = flow.responder
        if not (_is_private(initiator_ip) and not _is_private(responder_ip)):
            continue

        outbound = flow.bytes_a_to_b if flow.initiator == flow.endpoint_a else flow.bytes_b_to_a
        inbound = flow.total_bytes - outbound
        if outbound < min_bytes:
            continue
        ratio = outbound / max(inbound, 1)
        if ratio >= asymmetry_ratio:
            threads.append(
                Thread(
                    id=f"exfil-{initiator_ip}-{responder_ip}-{int(flow.start_time)}",
                    type="data_exfil_volume",
                    severity="high",
                    actor=initiator_ip,
                    targets=[responder_ip],
                    start_time=flow.start_time,
                    end_time=flow.end_time,
                    evidence={
                        "outbound_bytes": outbound,
                        "inbound_bytes": inbound,
                        "asymmetry_ratio": round(ratio, 1),
                        "tls_sni": sorted(flow.tls_sni) or None,
                    },
                    flows=[flow],
                )
            )
    return threads


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def detect_dns_tunneling(flows: List[Flow], min_queries: int = 30, entropy_threshold: float = 3.5) -> List[Thread]:
    """Flags hosts issuing many long/high-entropy DNS queries, a common tunneling signature.

    DNS queries are aggregated per querying host across all of its flows, since each query
    typically rides its own ephemeral-port flow rather than sharing one long-lived flow.
    """
    entries_by_initiator: Dict[str, List[Tuple[float, str, str]]] = defaultdict(list)
    for flow in flows:
        if not flow.dns_queries:
            continue
        initiator_ip = flow.initiator[0] if flow.initiator else flow.endpoint_a[0]
        responder_ip = flow.responder[0] if flow.responder else flow.endpoint_b[0]
        for query in flow.dns_queries:
            entries_by_initiator[initiator_ip].append((flow.start_time, query, responder_ip))

    threads = []
    for initiator_ip, entries in entries_by_initiator.items():
        if len(entries) < min_queries:
            continue
        queries = [q for _, q, _ in entries]
        avg_len = statistics.mean(len(q) for q in queries)
        avg_entropy = statistics.mean(_shannon_entropy(q.split(".")[0]) for q in queries)
        if avg_len > 40 or avg_entropy > entropy_threshold:
            start_time = min(t for t, _, _ in entries)
            end_time = max(t for t, _, _ in entries)
            threads.append(
                Thread(
                    id=f"dns_tunneling-{initiator_ip}-{int(start_time)}",
                    type="dns_tunneling",
                    severity="medium",
                    actor=initiator_ip,
                    targets=sorted({r for _, _, r in entries}),
                    start_time=start_time,
                    end_time=end_time,
                    evidence={
                        "query_count": len(queries),
                        "avg_query_length": round(avg_len, 1),
                        "avg_label_entropy": round(avg_entropy, 2),
                        "sample_queries": queries[:10],
                    },
                )
            )
    return threads


def detect_auth_failures(flows: List[Flow], min_failures: int = 5) -> List[Thread]:
    """Flags repeated 401/403 HTTP responses between the same pair of hosts."""
    threads = []
    for flow in flows:
        failures = [s for s in flow.http_statuses if s in (401, 403)]
        if len(failures) >= min_failures:
            initiator_ip = flow.initiator[0] if flow.initiator else flow.endpoint_a[0]
            responder_ip = flow.responder[0] if flow.responder else flow.endpoint_b[0]
            threads.append(
                Thread(
                    id=f"auth_failures-{initiator_ip}-{responder_ip}-{int(flow.start_time)}",
                    type="repeated_auth_failure",
                    severity="medium",
                    actor=initiator_ip,
                    targets=[responder_ip],
                    start_time=flow.start_time,
                    end_time=flow.end_time,
                    evidence={"failure_count": len(failures)},
                    flows=[flow],
                )
            )
    return threads


def detect_suspicious_ports(flows: List[Flow]) -> List[Thread]:
    """Flags TCP connections to ports commonly associated with backdoors/C2 tooling."""
    threads = []
    for flow in flows:
        if flow.proto != "TCP" or flow.initiator is None or flow.responder is None:
            continue
        _, responder_port = flow.responder
        if responder_port in SUSPICIOUS_PORTS:
            initiator_ip = flow.initiator[0]
            responder_ip = flow.responder[0]
            threads.append(
                Thread(
                    id=f"suspicious_port-{initiator_ip}-{responder_ip}-{responder_port}",
                    type="suspicious_port_usage",
                    severity="low",
                    actor=initiator_ip,
                    targets=[responder_ip],
                    start_time=flow.start_time,
                    end_time=flow.end_time,
                    evidence={"port": responder_port, "bytes_total": flow.total_bytes},
                    flows=[flow],
                )
            )
    return threads


def run_all_detectors(flows: List[Flow]) -> List[Thread]:
    threads: List[Thread] = []
    threads += detect_port_scans(flows)
    threads += detect_beaconing(flows)
    threads += detect_data_exfil(flows)
    threads += detect_dns_tunneling(flows)
    threads += detect_auth_failures(flows)
    threads += detect_suspicious_ports(flows)
    severity_rank = {"high": 0, "medium": 1, "low": 2}
    threads.sort(key=lambda t: (severity_rank.get(t.severity, 3), t.start_time))
    return threads
