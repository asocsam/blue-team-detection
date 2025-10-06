"""Log source ingestion helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, MutableMapping, Optional

ISO_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
]


@dataclass
class Event:
    """Normalised event structure."""

    source: str
    timestamp: datetime
    raw: MutableMapping[str, object]

    def get(self, key: str, default: Optional[object] = None) -> Optional[object]:
        return self.raw.get(key, default)


def _parse_timestamp(value: str) -> datetime:
    for fmt in ISO_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unsupported timestamp format: {value}")


def load_events(path: Path, source: str) -> Iterator[Event]:
    """Load JSONL events from *path* for the given *source*."""

    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            payload: Dict[str, object] = json.loads(line)
            timestamp_str = (
                payload.get("eventTime")
                or payload.get("creationDateTime")
                or payload.get("timestamp")
                or payload.get("@timestamp")
            )
            if not isinstance(timestamp_str, str):
                raise ValueError(f"Missing timestamp in {source} event: {payload}")
            yield Event(source=source, timestamp=_parse_timestamp(timestamp_str), raw=payload)


def load_all_events(sources: Iterable[tuple[str, Path]]) -> List[Event]:
    """Load events from all *sources* and return them sorted by time."""

    events = [event for name, path in sources for event in load_events(path, name)]
    events.sort(key=lambda event: event.timestamp)
    return events
