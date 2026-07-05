"""Groups parsed packet records into 5-tuple conversations."""
from typing import Dict, Iterable, Tuple

from .models import Flow

FlowKey = Tuple[str, Tuple[str, int], Tuple[str, int]]


def _canonical_key(proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Tuple[FlowKey, bool]:
    endpoint_src = (src_ip, src_port)
    endpoint_dst = (dst_ip, dst_port)
    if endpoint_src <= endpoint_dst:
        return (proto, endpoint_src, endpoint_dst), True
    return (proto, endpoint_dst, endpoint_src), False


def build_flows(packets: Iterable[Dict]) -> Dict[FlowKey, Flow]:
    flows: Dict[FlowKey, Flow] = {}

    for pkt in packets:
        src_port = pkt["src_port"] or 0
        dst_port = pkt["dst_port"] or 0
        key, forward = _canonical_key(pkt["proto"], pkt["src_ip"], src_port, pkt["dst_ip"], dst_port)

        flow = flows.get(key)
        if flow is None:
            _, endpoint_a, endpoint_b = key
            flow = Flow(
                proto=pkt["proto"],
                endpoint_a=endpoint_a,
                endpoint_b=endpoint_b,
                start_time=pkt["time"],
                end_time=pkt["time"],
            )
            flows[key] = flow

        if flow.initiator is None:
            flow.initiator = (pkt["src_ip"], src_port)

        flow.start_time = min(flow.start_time, pkt["time"])
        flow.end_time = max(flow.end_time, pkt["time"])

        if forward:
            flow.packets_a_to_b += 1
            flow.bytes_a_to_b += pkt["length"]
        else:
            flow.packets_b_to_a += 1
            flow.bytes_b_to_a += pkt["length"]

        if pkt["syn"]:
            flow.syn_count += 1
        if pkt["rst"]:
            flow.rst_count += 1
        if pkt["retransmission"]:
            flow.retransmissions += 1
        if pkt["dns_query"]:
            flow.dns_queries.append(pkt["dns_query"])
        if pkt["http_method"]:
            flow.http_requests.append(
                {
                    "method": pkt["http_method"],
                    "uri": pkt["http_uri"],
                    "host": pkt["http_host"],
                }
            )
        if pkt["http_status"] is not None:
            flow.http_statuses.append(pkt["http_status"])
        if pkt["tls_sni"]:
            flow.tls_sni.add(pkt["tls_sni"])

    return flows
