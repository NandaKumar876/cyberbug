"""Reusable feature extraction over observed flow windows."""

from __future__ import annotations

from collections import Counter
from math import log2, sqrt

from app.flow.schemas import FlowFeatures, FlowRecord


def shannon_entropy(value: str | None) -> float:
    if not value:
        return 0.0
    counts = Counter(value.lower())
    length = len(value)
    return round(-sum((count / length) * log2(count / length) for count in counts.values()), 4)


def _distribution(values: list[str]) -> dict[str, float]:
    counts = Counter(values)
    total = len(values) or 1
    return {name: round(count / total, 4) for name, count in sorted(counts.items())}


def _periodicity(intervals: list[float]) -> float:
    """A consistency score, not a threat verdict.  At least three observations are needed."""
    usable = [value for value in intervals if value > 0]
    if len(usable) < 3:
        return 0.0
    mean = sum(usable) / len(usable)
    standard_deviation = sqrt(sum((value - mean) ** 2 for value in usable) / len(usable))
    return round(max(0.0, min(1.0, 1 - standard_deviation / max(mean, 0.001))), 4)


def extract_features(flow: FlowRecord, recent_flows: list[FlowRecord], *, baseline_deviation: float = 0.0) -> FlowFeatures:
    """Extract only from the flow and the supplied observation window.

    The caller owns window selection, making this deterministic and suitable for
    online processing as well as replay tests.
    """
    window = [*recent_flows, flow]
    to_destination = [item for item in window if item.destination_ip == flow.destination_ip]
    from_source = [item for item in window if item.source_ip == flow.source_ip]
    dns_flows = [item for item in from_source if item.dns_query]
    domains = [item.dns_query for item in dns_flows if item.dns_query]
    flags = [flag for item in window for flag in item.tcp_flags if flag]
    syn_ratio = sum("S" in item.tcp_flags and "A" not in item.tcp_flags for item in from_source) / max(1, len(from_source))
    successful_ratio = sum(not (item.tcp_flags == "S") for item in from_source) / max(1, len(from_source))
    destination_concentration = len(to_destination) / max(1, len(window))
    return FlowFeatures(
        event_id=flow.event_id,
        window_seconds=60,
        packet_rate=flow.packet_rate,
        byte_rate=flow.byte_rate,
        flow_duration=flow.flow_duration,
        source_ip_count=len({item.source_ip for item in to_destination}),
        destination_ip_count=len({item.destination_ip for item in from_source}),
        port_diversity=len({item.destination_port for item in from_source}),
        protocol_distribution=_distribution([item.protocol for item in window]),
        tcp_flag_distribution=_distribution(flags),
        inter_arrival_time=round(sum(item.inter_arrival_time for item in from_source) / max(1, len(from_source)), 5),
        connection_periodicity=_periodicity([item.connection_interval or 0.0 for item in from_source]),
        dns_query_length=flow.dns_query_length,
        dns_entropy=shannon_entropy(flow.dns_query),
        domain_frequency=domains.count(flow.dns_query) if flow.dns_query else 0,
        unique_domain_ratio=round(len(set(domains)) / max(1, len(domains)), 4),
        destination_concentration=round(destination_concentration, 4),
        syn_ratio=round(syn_ratio, 4),
        successful_session_ratio=round(successful_ratio, 4),
        host_behaviour_deviation=round(max(0.0, min(1.0, baseline_deviation)), 4),
    )


def numeric_vector(features: FlowFeatures) -> list[float]:
    """Stable preprocessing order used by both training and inference."""
    return [
        features.packet_rate, features.byte_rate, features.flow_duration,
        float(features.source_ip_count), float(features.destination_ip_count),
        float(features.port_diversity), features.inter_arrival_time,
        features.connection_periodicity, float(features.dns_query_length),
        features.dns_entropy, float(features.domain_frequency), features.unique_domain_ratio,
        features.destination_concentration, features.syn_ratio,
        features.successful_session_ratio, features.host_behaviour_deviation,
    ]
