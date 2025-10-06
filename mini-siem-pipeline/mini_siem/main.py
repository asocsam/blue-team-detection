"""Entry point for the mini SIEM pipeline."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable

from .alerts import alerts_to_json, format_table
from .config import PipelineConfig
from .detections import run_detections
from .enrichment import enrich_events
from .log_sources import load_all_events


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the mini SIEM detection pipeline")
    parser.add_argument("--data-dir", default="data", help="Directory containing JSONL telemetry files")
    parser.add_argument("--output", default="alerts.json", help="File path for JSON alert output")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    config = PipelineConfig(data_dir=Path(args.data_dir))
    events = load_all_events(config.iter_existing_sources())
    enriched = enrich_events(config, events)
    detections = run_detections(config, enriched)

    if detections:
        print(format_table(detections))
        alerts_to_json(detections, Path(args.output))
        print(f"\nWrote {len(detections)} alerts to {args.output}")
    else:
        print("No detections generated.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
