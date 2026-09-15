"""Adaptive host and peer behaviour baselines for observed network flows."""

from __future__ import annotations

from collections import Counter
from statistics import median

from app.db.models import NetworkBaselineRecord
from app.flow.schemas import BaselineResponse, FlowFeatures, FlowRecord


_LIMIT = 240


def _robust_deviation(value: float, history: list[float]) -> float:
    if len(history) < 3:
        return 0.0
    centre = median(history)
    deviations = [abs(item - centre) for item in history]
    mad = median(deviations)
    if mad == 0:
        return 0.0 if value == centre else 0.875
    return min(1.0, abs(0.6745 * (value - centre) / mad) / 4.0)


def profile_for(record: NetworkBaselineRecord | None) -> dict[str, object]:
    if record is None:
        return {
            "packet_rates": [], "byte_rates": [], "periodicities": [],
            "destinations": {}, "ports": {}, "dns_lengths": [], "dns_entropies": [],
        }
    return {
        "packet_rates": [float(value) for value in record.profile.get("packet_rates", [])],
        "byte_rates": [float(value) for value in record.profile.get("byte_rates", [])],
        "periodicities": [float(value) for value in record.profile.get("periodicities", [])],
        "destinations": dict(record.profile.get("destinations", {})),
        "ports": dict(record.profile.get("ports", {})),
        "dns_lengths": [float(value) for value in record.profile.get("dns_lengths", [])],
        "dns_entropies": [float(value) for value in record.profile.get("dns_entropies", [])],
    }


def deviation(record: NetworkBaselineRecord | None, flow: FlowRecord, features: FlowFeatures) -> float:
    """Normalized deviation: robust statistical signals plus bounded categorical novelty."""
    profile = profile_for(record)
    scores = [
        _robust_deviation(features.packet_rate, profile["packet_rates"]),  # type: ignore[arg-type]
        _robust_deviation(features.byte_rate, profile["byte_rates"]),  # type: ignore[arg-type]
        _robust_deviation(features.connection_periodicity, profile["periodicities"]),  # type: ignore[arg-type]
        _robust_deviation(float(features.dns_query_length), profile["dns_lengths"]),  # type: ignore[arg-type]
        _robust_deviation(features.dns_entropy, profile["dns_entropies"]),  # type: ignore[arg-type]
    ]
    destinations: dict[str, int] = profile["destinations"]  # type: ignore[assignment]
    ports: dict[str, int] = profile["ports"]  # type: ignore[assignment]
    novelty = 0.0
    if destinations and flow.destination_ip not in destinations:
        novelty += 0.25
    if ports and str(flow.destination_port) not in ports:
        novelty += 0.15
    return round(min(1.0, max(scores, default=0.0) * 0.8 + novelty), 4)


def update(record: NetworkBaselineRecord | None, flow: FlowRecord, features: FlowFeatures) -> NetworkBaselineRecord:
    """Learn only trusted normal observations; callers decide trust after detection."""
    profile = profile_for(record)
    for key, value in (
        ("packet_rates", features.packet_rate), ("byte_rates", features.byte_rate),
        ("periodicities", features.connection_periodicity), ("dns_lengths", float(features.dns_query_length)),
        ("dns_entropies", features.dns_entropy),
    ):
        values: list[float] = profile[key]  # type: ignore[assignment]
        values.append(round(value, 6))
        del values[:-_LIMIT]
    destinations: dict[str, int] = profile["destinations"]  # type: ignore[assignment]
    ports: dict[str, int] = profile["ports"]  # type: ignore[assignment]
    destinations[flow.destination_ip] = destinations.get(flow.destination_ip, 0) + 1
    ports[str(flow.destination_port)] = ports.get(str(flow.destination_port), 0) + 1
    if record is None:
        return NetworkBaselineRecord(host_id=flow.host_id, profile=profile, trusted_observations=1)
    record.profile = profile
    record.trusted_observations += 1
    return record


def to_response(record: NetworkBaselineRecord, current_deviation: float = 0.0) -> BaselineResponse:
    profile = profile_for(record)
    destinations: dict[str, int] = profile["destinations"]  # type: ignore[assignment]
    ports: dict[str, int] = profile["ports"]  # type: ignore[assignment]
    return BaselineResponse(
        host_id=record.host_id,
        normal_packet_rate=round(sum(profile["packet_rates"]) / max(1, len(profile["packet_rates"])), 2),  # type: ignore[arg-type]
        normal_byte_rate=round(sum(profile["byte_rates"]) / max(1, len(profile["byte_rates"])), 2),  # type: ignore[arg-type]
        known_destinations=[item for item, _ in Counter(destinations).most_common(5)],
        typical_ports=[int(item) for item, _ in Counter(ports).most_common(5)],
        communication_periodicity=round(sum(profile["periodicities"]) / max(1, len(profile["periodicities"])), 3),  # type: ignore[arg-type]
        deviation=round(current_deviation, 4),
        status="ESTABLISHED" if record.trusted_observations >= 15 else "LEARNING",
        trusted_observations=record.trusted_observations,
        last_updated=record.last_updated,
    )
