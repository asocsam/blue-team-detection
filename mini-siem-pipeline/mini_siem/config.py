"""Configuration for the mini SIEM pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Dict, Iterable, Mapping


@dataclass(frozen=True)
class Thresholds:
    """Threshold values for detections."""

    dns_query_length: int = 60
    dns_query_volume: int = 25
    rdp_failures: int = 6
    credential_failure_window: timedelta = timedelta(minutes=15)


@dataclass(frozen=True)
class PipelineConfig:
    """Runtime configuration values."""

    data_dir: Path
    thresholds: Thresholds = field(default_factory=Thresholds)
    ip_reputation: Mapping[str, str] = field(
        default_factory=lambda: {
            "203.0.113.5": "Known threat actor infrastructure",
            "198.51.100.10": "Anonymous VPN provider",
            "198.51.100.77": "Credential stuffing botnet node",
        }
    )
    geoip_lookup: Mapping[str, str] = field(
        default_factory=lambda: {
            "198.51.100.10": "RU",
            "198.51.100.77": "CN",
            "203.0.113.5": "BR",
        }
    )

    @property
    def sources(self) -> Dict[str, Path]:
        """Mapping of log source names to file paths."""

        return {
            "cloudtrail": self.data_dir / "cloudtrail.jsonl",
            "guardduty": self.data_dir / "guardduty.jsonl",
            "sysmon": self.data_dir / "sysmon.jsonl",
            "vpcflow": self.data_dir / "vpcflow.jsonl",
        }

    def iter_existing_sources(self) -> Iterable[tuple[str, Path]]:
        for name, path in self.sources.items():
            if path.exists():
                yield name, path
