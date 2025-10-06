"""Enrichment utilities for the pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .config import PipelineConfig
from .log_sources import Event


@dataclass
class EnrichedEvent:
    """Event plus enrichment metadata."""

    event: Event
    asset: str
    user: str | None
    geo: str | None
    reputation: str | None

    @property
    def source(self) -> str:
        return self.event.source


def enrich_events(config: PipelineConfig, events: Iterable[Event]) -> list[EnrichedEvent]:
    """Attach enrichment context to events."""

    enriched: list[EnrichedEvent] = []
    for event in events:
        raw = event.raw
        ip_address = _extract_ip(raw)
        user = _extract_user(raw)
        asset = _extract_asset(raw)
        enriched.append(
            EnrichedEvent(
                event=event,
                asset=asset,
                user=user,
                geo=config.geoip_lookup.get(ip_address) if ip_address else None,
                reputation=config.ip_reputation.get(ip_address) if ip_address else None,
            )
        )
    return enriched


def _extract_ip(raw: Mapping[str, object]) -> str | None:
    for key in ("sourceIPAddress", "source_ip_address", "srcaddr", "SourceIp"):
        value = raw.get(key)
        if isinstance(value, str):
            return value
    # Sysmon sometimes puts it under nested fields
    event_data = raw.get("event_data")
    if isinstance(event_data, Mapping):
        return event_data.get("SourceIp") if isinstance(event_data.get("SourceIp"), str) else None
    return None


def _extract_user(raw: Mapping[str, object]) -> str | None:
    user_identity = raw.get("userIdentity")
    if isinstance(user_identity, Mapping):
        if isinstance(user_identity.get("userName"), str):
            return user_identity["userName"]
        if isinstance(user_identity.get("arn"), str):
            return user_identity["arn"].split("/")[-1]
    for key in ("user", "User", "Account", "dstuser"):
        value = raw.get(key)
        if isinstance(value, str):
            return value
    event_data = raw.get("event_data")
    if isinstance(event_data, Mapping):
        user = event_data.get("TargetUserName")
        if isinstance(user, str):
            return user
    return None


def _extract_asset(raw: Mapping[str, object]) -> str:
    for key in ("instance", "hostname", "Computer", "dstaddr"):
        value = raw.get(key)
        if isinstance(value, str):
            return value
    event_data = raw.get("event_data")
    if isinstance(event_data, Mapping):
        for key in ("Computer", "WorkstationName", "TargetComputer"):
            value = event_data.get(key)
            if isinstance(value, str):
                return value
    return raw.get("detail-type", "unknown")
