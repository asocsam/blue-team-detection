"""Alert formatting helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence

from .detections import Detection


@dataclass
class Alert:
    """Serializable alert structure."""

    detection: Detection

    def to_dict(self) -> dict:
        payload = self.detection.to_dict()
        payload["alert_type"] = self.detection.title
        return payload


def alerts_to_json(detections: Sequence[Detection], output: Path) -> None:
    """Write detections to *output* as JSON alerts."""

    payload = [Alert(detection).to_dict() for detection in detections]
    with output.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def format_table(detections: Iterable[Detection]) -> str:
    """Return a human-friendly table string."""

    rows: List[str] = []
    header = f"{'Severity':<8} | {'Technique':<10} | Title"
    rows.append(header)
    rows.append("-" * len(header))
    for detection in detections:
        rows.append(f"{detection.severity:<8} | {detection.technique:<10} | {detection.title}")
    return "\n".join(rows)
