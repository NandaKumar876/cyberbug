"""Independent rules, ML, anomaly, and fusion for passive flow observations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from math import log10

from app.flow.features import numeric_vector
from app.flow.ml import ModelBundle
from app.flow.schemas import DetectionResult, DetectorScores, FlowFeatures, FlowRecord, ThreatDNA, TrafficLabel


@dataclass(frozen=True)
class RuleAssessment:
    threat: TrafficLabel
    score: float
    signals: list[str]


def evaluate_rules(features: FlowFeatures) -> RuleAssessment:
    candidates: list[RuleAssessment] = []
    ddos_signals = [
        features.packet_rate >= 1_000,
        features.source_ip_count >= 5,
        features.destination_concentration >= .65,
        features.syn_ratio >= .5,
    ]
    candidates.append(RuleAssessment(TrafficLabel.DDOS, sum(ddos_signals) / 4, ["packet_rate", "source_diversity", "destination_concentration", "syn_ratio"]))
    c2_signals = [
        features.connection_periodicity >= .85,
        features.destination_concentration >= .65,
        features.packet_rate <= 100,
        features.host_behaviour_deviation >= .2,
    ]
    candidates.append(RuleAssessment(TrafficLabel.C2_BEACONING, sum(c2_signals) / 4, ["periodicity", "destination_consistency", "small_transfer", "baseline_deviation"]))
    dns_signals = [
        features.dns_query_length >= 32,
        features.dns_entropy >= 3.5,
        features.unique_domain_ratio >= .7,
        features.host_behaviour_deviation >= .25,
    ]
    candidates.append(RuleAssessment(TrafficLabel.DGA, sum(dns_signals) / 4, ["dns_length", "dns_entropy", "unique_domain_ratio", "baseline_deviation"]))
    scan_signals = [
        features.port_diversity >= 6,
        features.destination_ip_count >= 5,
        features.flow_duration <= .3,
        features.successful_session_ratio <= .3,
    ]
    candidates.append(RuleAssessment(TrafficLabel.SCANNING, sum(scan_signals) / 4, ["port_diversity", "destination_diversity", "short_flows", "low_success_ratio"]))
    winner = max(candidates, key=lambda item: item.score)
    return winner if winner.score >= .5 else RuleAssessment(TrafficLabel.NORMAL, 0.0, [])


_SEVERITY = {
    TrafficLabel.NORMAL: 0.0,
    TrafficLabel.SCANNING: .60,
    TrafficLabel.DGA: .68,
    TrafficLabel.DNS_TUNNELING: .72,
    TrafficLabel.C2_BEACONING: .78,
    TrafficLabel.DDOS: .92,
}


def _severity(risk_score: int) -> str:
    return "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 35 else "LOW"


def _threat_dna(features: FlowFeatures) -> ThreatDNA:
    return ThreatDNA(
        high_traffic=round(min(1.0, log10(max(1.0, features.packet_rate)) / 4.5), 4),
        source_diversity=round(min(1.0, features.source_ip_count / 25), 4),
        periodicity=features.connection_periodicity,
        dns_entropy=round(min(1.0, features.dns_entropy / 5.0), 4),
        port_diversity=round(min(1.0, features.port_diversity / 20), 4),
        baseline_deviation=features.host_behaviour_deviation,
    )


def _evidence(threat: TrafficLabel, features: FlowFeatures, *, baseline_packet_rate: float, baseline_observations: int) -> tuple[list[str], list[str]]:
    support: list[str] = []
    counter: list[str] = []
    if threat is TrafficLabel.DDOS:
        ratio = features.packet_rate / max(1.0, baseline_packet_rate)
        support.extend([
            f"Packet rate is {features.packet_rate:,.0f}/s ({ratio:.1f}x the host baseline).",
            f"{features.source_ip_count} distinct private source IPs converge on one destination in the active window.",
            f"Destination concentration is {features.destination_concentration:.0%}; SYN-only flow ratio is {features.syn_ratio:.0%}.",
        ])
        if baseline_observations < 15:
            counter.append(f"Adaptive baseline is still learning ({baseline_observations} trusted observations).")
        elif features.destination_concentration < .9:
            counter.append("Traffic is not exclusively concentrated on one destination.")
    elif threat is TrafficLabel.C2_BEACONING:
        support.extend([
            f"Connection timing consistency is {features.connection_periodicity:.0%} across observed intervals.",
            f"Traffic remains concentrated on one destination ({features.destination_concentration:.0%}).",
            f"Host behaviour deviation is {features.host_behaviour_deviation:.0%} above its adaptive baseline.",
        ])
        counter.append("Periodicity by itself is insufficient; this is a suspicious association, not a confirmed command channel.")
    elif threat in {TrafficLabel.DGA, TrafficLabel.DNS_TUNNELING}:
        support.extend([
            f"DNS query length is {features.dns_query_length} characters with Shannon entropy {features.dns_entropy:.2f}.",
            f"Unique-domain ratio is {features.unique_domain_ratio:.0%} in the host observation window.",
            f"Host behaviour deviation is {features.host_behaviour_deviation:.0%} above normal DNS behaviour.",
        ])
        counter.append("Long labels alone do not prove tunnelling; query frequency and entropy are evaluated together.")
    elif threat is TrafficLabel.SCANNING:
        support.extend([
            f"Source contacted {features.destination_ip_count} destinations across {features.port_diversity} destination ports.",
            f"Median-like active flow duration is {features.flow_duration:.3f}s with a {features.successful_session_ratio:.0%} successful-session ratio.",
            f"SYN-only flow ratio is {features.syn_ratio:.0%}.",
        ])
        counter.append("A port-management task can resemble reconnaissance; analyst validation is required.")
    return support, counter


def fuse(
    flow: FlowRecord, features: FlowFeatures, *, baseline_packet_rate: float,
    baseline_observations: int, model: ModelBundle,
) -> DetectionResult:
    """Keep detector outputs separate, then combine them into confidence and risk."""
    rules = evaluate_rules(features)
    ml_threat, ml_probability, anomaly_score, inference_ms = model.infer(features)
    if rules.score >= .75:
        threat = rules.threat
    elif ml_threat is not TrafficLabel.NORMAL and ml_probability >= .55 and (rules.score >= .5 or features.host_behaviour_deviation >= .2):
        threat = ml_threat
    else:
        threat = TrafficLabel.NORMAL
    confidence = min(1.0, .48 * ml_probability + .30 * rules.score + .12 * anomaly_score + .10 * features.host_behaviour_deviation)
    if threat is TrafficLabel.NORMAL:
        confidence = max(0.0, min(1.0, 1 - confidence))
    correlation_factor = min(.15, max(0.0, (features.port_diversity - 1) / 100))
    risk = round(100 * _SEVERITY[threat] * (.62 * confidence + .28 * features.host_behaviour_deviation + .10 * anomaly_score + correlation_factor))
    support, counter = _evidence(threat, features, baseline_packet_rate=baseline_packet_rate, baseline_observations=baseline_observations)
    return DetectionResult(
        detection_id=f"DET-{flow.event_id.removeprefix('EVT-')}", event_id=flow.event_id, predicted_threat=threat,
        confidence=round(confidence, 4), risk_score=max(0, min(100, risk)), severity=_severity(risk),
        scores=DetectorScores(rule_score=round(rules.score, 4), ml_probability=round(ml_probability, 4), anomaly_score=round(anomaly_score, 4), baseline_deviation=features.host_behaviour_deviation, model_inference_ms=inference_ms),
        threat_dna=_threat_dna(features), supporting_evidence=support, counter_evidence=counter,
        created_at=datetime.now(UTC),
    )
