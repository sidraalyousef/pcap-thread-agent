"""Streams packet records out of a pcap/pcapng file via tshark."""
import csv
import os
import shutil
import subprocess
from typing import Dict, Iterator, Optional

FIELDS = [
    "frame.time_epoch",
    "frame.number",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ip.proto",
    "frame.len",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.reset",
    "tcp.flags.fin",
    "tcp.analysis.retransmission",
    "udp.srcport",
    "udp.dstport",
    "dns.qry.name",
    "dns.a",
    "http.request.method",
    "http.request.full_uri",
    "http.host",
    "http.response.code",
    "tls.handshake.extensions_server_name",
]

_PROTO_NAMES = {"1": "ICMP", "6": "TCP", "17": "UDP", "58": "ICMPv6"}

_FALLBACK_TSHARK_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]


def find_tshark() -> str:
    env_path = os.environ.get("PCAP_AGENT_TSHARK_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    on_path = shutil.which("tshark")
    if on_path:
        return on_path

    for candidate in _FALLBACK_TSHARK_PATHS:
        if os.path.isfile(candidate):
            return candidate

    raise FileNotFoundError(
        "tshark not found on PATH, in common Wireshark install locations, "
        "or via PCAP_AGENT_TSHARK_PATH."
    )


def _to_int(value: Optional[str]) -> Optional[int]:
    if value in (None, ""):
        return None
    return int(value)


def _to_bool(value: Optional[str]) -> bool:
    return value in ("1", "True", "true")


def parse_row(row: Dict[str, str]) -> Dict:
    src_ip = row.get("ip.src") or row.get("ipv6.src") or ""
    dst_ip = row.get("ip.dst") or row.get("ipv6.dst") or ""
    proto = _PROTO_NAMES.get(row.get("ip.proto") or "", row.get("ip.proto") or "OTHER")
    src_port = _to_int(row.get("tcp.srcport") or row.get("udp.srcport"))
    dst_port = _to_int(row.get("tcp.dstport") or row.get("udp.dstport"))
    return {
        "time": float(row["frame.time_epoch"]) if row.get("frame.time_epoch") else 0.0,
        "frame_no": _to_int(row.get("frame.number")) or 0,
        "proto": proto,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "length": _to_int(row.get("frame.len")) or 0,
        "syn": _to_bool(row.get("tcp.flags.syn")),
        "ack": _to_bool(row.get("tcp.flags.ack")),
        "rst": _to_bool(row.get("tcp.flags.reset")),
        "fin": _to_bool(row.get("tcp.flags.fin")),
        "retransmission": _to_bool(row.get("tcp.analysis.retransmission")),
        "dns_query": row.get("dns.qry.name") or None,
        "dns_answer": row.get("dns.a") or None,
        "http_method": row.get("http.request.method") or None,
        "http_uri": row.get("http.request.full_uri") or None,
        "http_host": row.get("http.host") or None,
        "http_status": _to_int(row.get("http.response.code")),
        "tls_sni": row.get("tls.handshake.extensions_server_name") or None,
    }


def extract_packets(pcap_path: str) -> Iterator[Dict]:
    """Yields one parsed packet record per packet in the capture."""
    if not os.path.isfile(pcap_path):
        raise FileNotFoundError(pcap_path)

    tshark = find_tshark()
    cmd = [tshark, "-r", pcap_path, "-T", "fields"]
    for field in FIELDS:
        cmd += ["-e", field]
    cmd += ["-E", "header=y", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.stdout is not None
    reader = csv.DictReader(proc.stdout)
    for row in reader:
        yield parse_row(row)

    proc.stdout.close()
    stderr = proc.stderr.read() if proc.stderr else ""
    if proc.stderr:
        proc.stderr.close()
    ret = proc.wait()
    if ret != 0:
        raise RuntimeError(f"tshark exited with code {ret}: {stderr.strip()}")
