"""Deterministic, private-address synthetic flow generator for the live demo.

The generator creates flow metadata only.  It never opens sockets, sends packets,
or contacts the addresses embedded in its records.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from random import Random
from uuid import uuid4

from app.flow.schemas import FlowRecord, ScenarioKind, TrafficLabel


_SEEDS = {
    ScenarioKind.NORMAL: 261451,
    ScenarioKind.DDOS: 261452,
    ScenarioKind.C2: 261453,
    ScenarioKind.DNS: 261454,
    ScenarioKind.SCANNING: 261455,
    ScenarioKind.MIXED: 261456,
    ScenarioKind.FULL_STORY: 261457,
}


class FlowScenarioGenerator:
    """Reproducible event sequence for a single synthetic simulation run."""

    def __init__(self, scenario: ScenarioKind, *, start_at: datetime | None = None) -> None:
        self.scenario = scenario
        self.run_id = f"RUN-{uuid4().hex[:10].upper()}"
        self._rng = Random(_SEEDS[scenario])
        self._start_at = start_at or datetime.now(UTC)
        self._index = 0

    def next_flow(self) -> FlowRecord:
        index = self._index
        self._index += 1
        stage = self._stage_for(index)
        timestamp = self._start_at + timedelta(seconds=index * 5)
        if stage is ScenarioKind.DDOS:
            return self._ddos(index, timestamp)
        if stage is ScenarioKind.C2:
            return self._c2(index, timestamp)
        if stage is ScenarioKind.DNS:
            return self._dns(index, timestamp)
        if stage is ScenarioKind.SCANNING:
            return self._scan(index, timestamp)
        return self._normal(index, timestamp)

    def _stage_for(self, index: int) -> ScenarioKind:
        if self.scenario is ScenarioKind.FULL_STORY:
            return (
                ScenarioKind.NORMAL if index < 15 else
                ScenarioKind.DNS if index < 30 else
                ScenarioKind.C2 if index < 45 else
                ScenarioKind.SCANNING if index < 60 else
                ScenarioKind.DDOS
            )
        if self.scenario is ScenarioKind.MIXED:
            stages = (ScenarioKind.NORMAL, ScenarioKind.DNS, ScenarioKind.C2, ScenarioKind.SCANNING, ScenarioKind.DDOS)
            return stages[(index // 8) % len(stages)]
        return self.scenario

    def _event_id(self, index: int) -> str:
        return f"EVT-{self.run_id.removeprefix('RUN-')}-{index:06d}"

    def _normal(self, index: int, timestamp: datetime) -> FlowRecord:
        host_number = 7 if index % 4 == 0 else (index % 10) + 10
        source = f"10.20.0.{host_number}"
        destinations = (("10.30.0.10", 443), ("10.30.0.20", 443), ("10.30.0.53", 53), ("10.30.0.60", 80))
        destination, port = destinations[index % len(destinations)]
        protocol = "UDP" if port == 53 else "TCP"
        packets = self._rng.randint(18, 70)
        duration = round(self._rng.uniform(0.5, 2.0), 3)
        bytes_per_packet = self._rng.randint(400, 900)
        dns_query = ("www.example.org" if index % 2 else "api.example.org") if port == 53 else None
        return self._flow(
            index=index, timestamp=timestamp, source=source, destination=destination,
            source_port=41000 + (index % 2000), destination_port=port, protocol=protocol,
            packets=packets, byte_count=packets * bytes_per_packet, duration=duration,
            inter_arrival=round(self._rng.uniform(0.03, 0.18), 4), flags="A" if protocol == "TCP" else "",
            dns_query=dns_query, interval=round(self._rng.uniform(24, 36), 2) if source.endswith(".7") else None,
            host_id=f"HOST-{host_number:02d}", label=TrafficLabel.NORMAL,
        )

    def _ddos(self, index: int, timestamp: datetime) -> FlowRecord:
        source = f"10.90.{(index // 200) % 200}.{(index % 200) + 1}"
        packets = self._rng.randint(2_200, 4_200)
        duration = round(self._rng.uniform(0.08, 0.25), 3)
        return self._flow(
            index=index, timestamp=timestamp, source=source, destination="10.30.0.50",
            source_port=10000 + (index % 50000), destination_port=443, protocol="TCP",
            packets=packets, byte_count=packets * self._rng.randint(48, 96), duration=duration,
            inter_arrival=round(self._rng.uniform(0.0002, 0.002), 5), flags="S",
            dns_query=None, interval=None, host_id="HOST-WEB-50", label=TrafficLabel.DDOS,
        )

    def _c2(self, index: int, timestamp: datetime) -> FlowRecord:
        packets = self._rng.randint(7, 12)
        duration = round(self._rng.uniform(0.3, 0.65), 3)
        return self._flow(
            index=index, timestamp=timestamp, source="10.20.0.7", destination="10.30.0.77",
            source_port=50500 + (index % 5), destination_port=443, protocol="TCP",
            packets=packets, byte_count=packets * self._rng.randint(220, 270), duration=duration,
            inter_arrival=round(self._rng.uniform(0.04, 0.07), 4), flags="PA",
            dns_query=None, interval=round(30 + self._rng.uniform(-1.2, 1.2), 2),
            host_id="HOST-07", label=TrafficLabel.C2_BEACONING,
        )

    def _dns(self, index: int, timestamp: datetime) -> FlowRecord:
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        token = "".join(self._rng.choice(alphabet) for _ in range(36))
        query = f"{token}.demo.invalid"
        packets = self._rng.randint(4, 10)
        duration = round(self._rng.uniform(0.05, 0.22), 3)
        return self._flow(
            index=index, timestamp=timestamp, source="10.20.0.7", destination="10.30.0.53",
            source_port=53000 + (index % 500), destination_port=53, protocol="UDP",
            packets=packets, byte_count=packets * self._rng.randint(130, 220), duration=duration,
            inter_arrival=round(self._rng.uniform(0.005, 0.025), 4), flags="", dns_query=query,
            interval=round(self._rng.uniform(1.0, 3.0), 2), host_id="HOST-07", label=TrafficLabel.DGA,
        )

    def _scan(self, index: int, timestamp: datetime) -> FlowRecord:
        ports = (21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 3389, 5432, 8080)
        target_octet = 20 + (index % 20)
        return self._flow(
            index=index, timestamp=timestamp, source="10.20.0.88", destination=f"10.30.0.{target_octet}",
            source_port=42000 + (index % 2000), destination_port=ports[index % len(ports)], protocol="TCP",
            packets=1, byte_count=60, duration=round(self._rng.uniform(0.03, 0.12), 3),
            inter_arrival=round(self._rng.uniform(0.001, 0.009), 4), flags="S", dns_query=None,
            interval=round(self._rng.uniform(0.02, 0.2), 3), host_id="HOST-88", label=TrafficLabel.SCANNING,
        )

    def _flow(
        self, *, index: int, timestamp: datetime, source: str, destination: str,
        source_port: int, destination_port: int, protocol: str, packets: int,
        byte_count: int, duration: float, inter_arrival: float, flags: str,
        dns_query: str | None, interval: float | None, host_id: str, label: TrafficLabel,
    ) -> FlowRecord:
        dns_length = len(dns_query) if dns_query else 0
        return FlowRecord(
            event_id=self._event_id(index), timestamp=timestamp, source_ip=source,
            destination_ip=destination, source_port=source_port, destination_port=destination_port,
            protocol=protocol, packet_count=packets, byte_count=byte_count,
            packet_rate=round(packets / duration, 2), byte_rate=round(byte_count / duration, 2),
            flow_duration=duration, inter_arrival_time=inter_arrival, tcp_flags=flags,
            dns_query=dns_query, dns_query_length=dns_length, dns_entropy=0.0,
            domain_length=dns_length, connection_interval=interval,
            session_id=f"SES-{host_id}-{destination.replace('.', '-')}", host_id=host_id,
            scenario_id=f"{self.run_id}:{self.scenario.value}", traffic_label=label,
        )
