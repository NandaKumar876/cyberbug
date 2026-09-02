"""Windows-only local/WEC collector that sends normalized metadata to CyberBug."""

from __future__ import annotations

import argparse
import json
import os
import platform
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app.collector.forwarded_events import read_forwarded_events
from app.collector.windows_events import read_security_events
from app.config import settings
from app.normalization.event import NormalizedEvent
from app.privacy.pseudonymizer import Pseudonymizer

_MAX_SEEN_EVENTS = 10_000


@dataclass
class CollectorState:
    """Bounded idempotency cache; the backend also enforces event-ID deduplication."""

    path: Path
    seen_event_ids: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "CollectorState":
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return cls(path=path, seen_event_ids=[str(value) for value in payload.get("seen_event_ids", [])][- _MAX_SEEN_EVENTS:])
        except FileNotFoundError:
            return cls(path=path)
        except (OSError, ValueError, TypeError):
            # A corrupt cache must never stop security metadata collection.
            return cls(path=path)

    def contains(self, event_id: str) -> bool:
        return event_id in self.seen_event_ids

    def record(self, event_id: str) -> None:
        self.seen_event_ids.append(event_id)
        del self.seen_event_ids[:-_MAX_SEEN_EVENTS]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"seen_event_ids": self.seen_event_ids}), encoding="utf-8")


class BackendEventClient:
    def __init__(self, endpoint: str, token: str | None = None) -> None:
        self.endpoint = endpoint.rstrip("/") + "/api/v1/events"
        self.token = token

    def heartbeat(self, collector_id: str, source: str, submitted: int, skipped: int) -> bool:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["X-CyberBug-Collector-Token"] = self.token
        body = json.dumps({"collector_id": collector_id, "source": source, "submitted": submitted, "skipped": skipped}).encode("utf-8")
        try:
            with urlopen(Request(self.endpoint.replace("/api/v1/events", "/api/v1/collectors/heartbeat"), data=body, headers=headers, method="POST"), timeout=10) as response:
                return response.status == 200
        except (HTTPError, URLError):
            return False

    def submit(self, event: NormalizedEvent) -> bool:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["X-CyberBug-Collector-Token"] = self.token
        request = Request(self.endpoint, data=event.model_dump_json().encode("utf-8"), headers=headers, method="POST")
        try:
            with urlopen(request, timeout=10) as response:  # noqa: S310 -- endpoint is explicitly configured by the operator
                return response.status in {200, 201, 409}
        except HTTPError as error:
            return error.code == 409  # Existing event: safely idempotent.
        except URLError:
            return False


def collect_once(*, source: str, max_events: int, state: CollectorState, client: BackendEventClient, pseudonymizer: Pseudonymizer) -> tuple[int, int]:
    reader: Iterable[NormalizedEvent]
    if source == "security":
        reader = read_security_events(max_events=max_events, pseudonymizer=pseudonymizer)
    elif source == "forwarded":
        reader = read_forwarded_events(max_events=max_events, pseudonymizer=pseudonymizer)
    else:
        raise ValueError("source must be 'security' or 'forwarded'")
    submitted = skipped = 0
    for event in reader:
        if state.contains(event.event_id):
            skipped += 1
            continue
        if client.submit(event):
            state.record(event.event_id)
            submitted += 1
    state.save()
    return submitted, skipped


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect authorized Windows Event Log metadata for CyberBug.")
    parser.add_argument("--source", choices=("security", "forwarded"), default="security")
    parser.add_argument("--endpoint", default=os.environ.get("CYBERBUG_API_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--interval", type=int, default=30, help="Polling interval in seconds; use 0 for one pass.")
    parser.add_argument("--max-events", type=int, default=100)
    parser.add_argument("--collector-id", default=os.environ.get("CYBERBUG_COLLECTOR_ID", platform.node() or "windows-collector"))
    parser.add_argument("--state-file", type=Path, default=Path(os.environ.get("PROGRAMDATA", ".")) / "CyberBug" / "collector-state.json")
    args = parser.parse_args()
    if platform.system() != "Windows":
        raise SystemExit("The Windows Event Log collector must run on Windows.")
    state = CollectorState.load(args.state_file)
    client = BackendEventClient(args.endpoint, token=os.environ.get("CYBERBUG_COLLECTOR_TOKEN"))
    pseudonymizer = Pseudonymizer(settings.pseudonymization_secret)
    while True:
        submitted, skipped = collect_once(source=args.source, max_events=args.max_events, state=state, client=client, pseudonymizer=pseudonymizer)
        print(f"CyberBug collector: submitted={submitted} skipped={skipped}")
        client.heartbeat(args.collector_id, args.source, submitted, skipped)
        if args.interval <= 0:
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
