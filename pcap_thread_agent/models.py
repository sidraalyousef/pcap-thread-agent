"""Data structures shared across flow reconstruction, detection, and reporting."""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class Flow:
    """A reconstructed 5-tuple conversation, aggregated across its lifetime."""

    proto: str
    endpoint_a: Tuple[str, int]
    endpoint_b: Tuple[str, int]
    initiator: Optional[Tuple[str, int]] = None
    start_time: float = 0.0
    end_time: float = 0.0
    packets_a_to_b: int = 0
    packets_b_to_a: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0
    syn_count: int = 0
    rst_count: int = 0
    retransmissions: int = 0
    dns_queries: List[str] = field(default_factory=list)
    http_requests: List[Dict] = field(default_factory=list)
    http_statuses: List[int] = field(default_factory=list)
    tls_sni: Set[str] = field(default_factory=set)

    @property
    def duration(self) -> float:
        return max(0.0, self.end_time - self.start_time)

    @property
    def total_bytes(self) -> int:
        return self.bytes_a_to_b + self.bytes_b_to_a

    @property
    def responder(self) -> Optional[Tuple[str, int]]:
        if self.initiator is None:
            return None
        return self.endpoint_b if self.initiator == self.endpoint_a else self.endpoint_a


@dataclass
class Thread:
    """A security-relevant sequence surfaced by a detector, ready for LLM narration."""

    id: str
    type: str
    severity: str  # "low" | "medium" | "high"
    actor: str
    targets: List[str]
    start_time: float
    end_time: float
    evidence: Dict
    flows: List[Flow] = field(default_factory=list)
    narrative: Optional[str] = None
