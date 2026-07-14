"""Turns a detector's structured evidence into a human-readable threat summary.

Fully local and deterministic -- no external API calls, no network dependency, no API key.
"""
from typing import List

from .models import Thread

_TECHNIQUE_BY_TYPE = {
    "port_scan": "T1046 - Network Service Scanning",
    "beaconing": "T1071 - Application Layer Protocol (possible C2 beaconing)",
    "data_exfil_volume": "T1041 - Exfiltration Over C2 Channel (or a large legitimate transfer)",
    "dns_tunneling": "T1071.004 - Application Layer Protocol: DNS (possible DNS tunneling)",
    "repeated_auth_failure": "T1110 - Brute Force",
    "suspicious_port_usage": "T1571 - Non-Standard Port (possible backdoor/C2 tooling)",
}

_NEXT_STEP_BY_TYPE = {
    "port_scan": "Confirm whether the source host is an authorized scanner; if not, isolate it and check the target for follow-on exploitation attempts.",
    "beaconing": "Inspect the protocol/payload of these connections and check the destination against threat intel before ruling out legitimate scheduled traffic.",
    "data_exfil_volume": "Identify the process behind this transfer and check the destination's reputation; compare against known backup/upload jobs.",
    "dns_tunneling": "Check whether the queried domain is tied to known tunneling tools (e.g. iodine, dnscat2) and review DNS logs for repeat activity.",
    "repeated_auth_failure": "Check for account lockout/rate limiting and confirm whether this looks like credential stuffing or brute forcing.",
    "suspicious_port_usage": "Verify what process on the source host is using this port and whether it matches known backdoor/C2 tooling.",
}


def _duration(thread: Thread) -> float:
    return round(thread.end_time - thread.start_time, 2)


def _summary_line(thread: Thread) -> str:
    e = thread.evidence
    target = thread.targets[0] if thread.targets else "an unknown host"

    if thread.type == "port_scan":
        return (
            f"{thread.actor} probed {e.get('distinct_targets_probed')} distinct host/port combinations "
            f"within a {e.get('window_seconds')}-second window without completing normal data exchange -- "
            "consistent with automated port scanning."
        )
    if thread.type == "beaconing":
        return (
            f"{thread.actor} made {e.get('connection_count')} separate connections to {target} at a "
            f"highly regular ~{e.get('mean_interval_seconds')}-second interval "
            f"(coefficient of variation {e.get('coefficient_of_variation')}), which is atypical of "
            "human-driven traffic."
        )
    if thread.type == "data_exfil_volume":
        outbound = e.get("outbound_bytes", 0)
        inbound = e.get("inbound_bytes", 0)
        return (
            f"{thread.actor} sent {outbound:,} bytes to external host {target} while receiving only "
            f"{inbound:,} bytes back (ratio ~{e.get('asymmetry_ratio')}:1) over {_duration(thread)} seconds -- "
            "a highly asymmetric transfer."
        )
    if thread.type == "dns_tunneling":
        return (
            f"{thread.actor} issued {e.get('query_count')} DNS queries averaging "
            f"{e.get('avg_query_length')} characters with label entropy {e.get('avg_label_entropy')}, "
            "consistent with encoded or randomized subdomains rather than typical hostnames."
        )
    if thread.type == "repeated_auth_failure":
        return (
            f"{thread.actor} triggered {e.get('failure_count')} HTTP 401/403 responses from {target}, "
            "suggesting repeated failed authentication attempts."
        )
    if thread.type == "suspicious_port_usage":
        total_bytes = e.get("bytes_total", 0)
        return (
            f"{thread.actor} connected to {target} on port {e.get('port')}, which is commonly associated "
            f"with backdoor/C2 tooling ({total_bytes:,} bytes exchanged)."
        )
    return f"{thread.actor} triggered the '{thread.type}' detector against {', '.join(thread.targets)}."


def generate_narrative(thread: Thread) -> str:
    summary = _summary_line(thread)
    technique = _TECHNIQUE_BY_TYPE.get(thread.type, "no specific technique mapping available")
    next_step = _NEXT_STEP_BY_TYPE.get(
        thread.type, "Review the raw evidence and corroborate with other logs before acting."
    )
    return (
        f"Summary: {summary}\n"
        f"Likely technique: {technique}\n"
        f"Severity: {thread.severity.upper()} -- based on heuristic thresholds, not confirmed malicious intent.\n"
        f"Recommended next step: {next_step}"
    )


def generate_narratives(threads: List[Thread]) -> None:
    """Populates thread.narrative in place, purely from local templates."""
    for thread in threads:
        thread.narrative = generate_narrative(thread)
