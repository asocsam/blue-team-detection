"""Detection logic for the mini SIEM pipeline."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, List

from .config import PipelineConfig
from .enrichment import EnrichedEvent


@dataclass
class Detection:
    """Represents a detection finding."""

    title: str
    description: str
    severity: str
    technique: str
    events: List[EnrichedEvent]

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "technique": self.technique,
            "events": [event.event.raw for event in self.events],
        }


def run_detections(config: PipelineConfig, events: Iterable[EnrichedEvent]) -> List[Detection]:
    enriched_events = list(events)
    detections: List[Detection] = []
    detections.extend(_detect_mfa_bypass(config, enriched_events))
    detections.extend(_detect_public_s3(config, enriched_events))
    detections.extend(_detect_dns_tunneling(config, enriched_events))
    detections.extend(_detect_rdp_bruteforce(config, enriched_events))
    return detections


def _detect_mfa_bypass(config: PipelineConfig, events: List[EnrichedEvent]) -> List[Detection]:
    suspicious: List[EnrichedEvent] = []
    for event in events:
        raw = event.event.raw
        if event.source != "cloudtrail":
            continue
        if raw.get("eventName") != "ConsoleLogin":
            continue
        additional = raw.get("additionalEventData", {})
        if isinstance(additional, dict) and additional.get("MFAUsed") == "No":
            suspicious.append(event)
    if not suspicious:
        return []
    description = (
        "Console logins detected without MFA from IPs with questionable reputation. "
        "Verify whether the users expected this access."
    )
    return [
        Detection(
            title="AWS console login without MFA",
            description=description,
            severity="high",
            technique="T1078",
            events=suspicious,
        )
    ]


def _detect_public_s3(config: PipelineConfig, events: List[EnrichedEvent]) -> List[Detection]:
    suspicious: List[EnrichedEvent] = []
    for event in events:
        if event.source != "cloudtrail":
            continue
        raw = event.event.raw
        if raw.get("eventName") != "PutBucketAcl":
            continue
        request_params = raw.get("requestParameters") or {}
        if isinstance(request_params, dict):
            acl = str(request_params.get("AccessControlList", "")).lower()
            if "public" in acl:
                suspicious.append(event)
    if not suspicious:
        return []
    return [
        Detection(
            title="S3 bucket exposed to public",
            description="S3 ACL change granted public access. Confirm business justification and revert if unintended.",
            severity="critical",
            technique="T1530",
            events=suspicious,
        )
    ]


def _detect_dns_tunneling(config: PipelineConfig, events: List[EnrichedEvent]) -> List[Detection]:
    by_asset: defaultdict[str, list[EnrichedEvent]] = defaultdict(list)
    for event in events:
        if event.source not in {"sysmon", "vpcflow"}:
            continue
        raw = event.event.raw
        if str(raw.get("event_id")) not in {"22", "dns"} and raw.get("eventName") != "DnsRequest":
            continue
        by_asset[event.asset].append(event)

    detections: List[Detection] = []
    for asset, asset_events in by_asset.items():
        long_queries = [
            ev
            for ev in asset_events
            if len(str(ev.event.raw.get("QueryName", ""))) >= config.thresholds.dns_query_length
        ]
        if long_queries or len(asset_events) >= config.thresholds.dns_query_volume:
            detections.append(
                Detection(
                    title=f"Possible DNS tunnelling on {asset}",
                    description="High volume of long DNS queries detected. Investigate for exfiltration via DNS.",
                    severity="medium",
                    technique="T1071.004",
                    events=asset_events,
                )
            )
    return detections


def _detect_rdp_bruteforce(config: PipelineConfig, events: List[EnrichedEvent]) -> List[Detection]:
    failures_by_source: defaultdict[str, list[datetime]] = defaultdict(list)
    event_lookup: defaultdict[str, list[EnrichedEvent]] = defaultdict(list)
    window: timedelta = config.thresholds.credential_failure_window

    for event in events:
        raw = event.event.raw
        if event.source not in {"sysmon", "vpcflow"}:
            continue
        event_id = str(raw.get("event_id"))
        if event_id not in {"4625", "rdp-fail"} and raw.get("eventName") != "RdpLogonFailed":
            continue
        source_ip = raw.get("sourceIPAddress") or raw.get("srcaddr")
        if not isinstance(source_ip, str):
            continue
        failures_by_source[source_ip].append(event.event.timestamp)
        event_lookup[source_ip].append(event)

    detections: List[Detection] = []
    for ip, timestamps in failures_by_source.items():
        timestamps.sort()
        counter = _count_within_window(timestamps, window)
        if counter >= config.thresholds.rdp_failures:
            detections.append(
                Detection(
                    title=f"RDP brute-force from {ip}",
                    description="Multiple failed RDP authentications in a short window. Review for credential stuffing attempts.",
                    severity="high",
                    technique="T1110",
                    events=event_lookup[ip],
                )
            )
    return detections


def _count_within_window(timestamps: List[datetime], window: timedelta) -> int:
    left = 0
    best = 0
    for right, current in enumerate(timestamps):
        while timestamps[left] < current - window:
            left += 1
        best = max(best, right - left + 1)
    return best
