"""Validate and canonicalise CICIDS-style network-flow CSV files.

This module uses standard library constructs to check data contracts,
enforce strict typing, reject corrupted/invalid records (e.g. NaN, Infinity,
negative durations), preserve raw labels verbatim, and map canonical attack
families without modifying immutable raw source files.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence


CANONICAL_COLUMNS = (
    "flow_duration_ms",
    "total_forward_packets",
    "total_backward_packets",
    "total_forward_bytes",
    "total_backward_bytes",
    "packets_per_second",
    "destination_port",
    "raw_label",
    "attack_family",
    "is_attack",
)

REQUIRED_CANONICAL_FEATURES = (
    "flow_duration_ms",
    "total_forward_packets",
    "total_backward_packets",
    "total_forward_bytes",
    "total_backward_bytes",
    "packets_per_second",
    "destination_port",
    "raw_label",
)

# Header names are normalised (lowercased, stripped, internal whitespace unified)
# before lookup. Note that raw CICIDS CSVs omit protocol; no artificial protocol is mapped.
CICIDS_COLUMN_MAP = {
    "flow duration": "flow_duration_ms",
    "total fwd packets": "total_forward_packets",
    "total backward packets": "total_backward_packets",
    "total length of fwd packets": "total_forward_bytes",
    "total length of bwd packets": "total_backward_bytes",
    "flow packets/s": "packets_per_second",
    "destination port": "destination_port",
    "label": "raw_label",
}

INTEGER_COLUMNS = {
    "total_forward_packets",
    "total_backward_packets",
    "destination_port",
    "is_attack",
}


@dataclass(frozen=True)
class PipelineReport:
    source: str
    total_rows: int
    accepted_rows: int
    rejected_rows: int
    rejection_reasons: dict[str, int]
    raw_label_distribution: dict[str, int]
    attack_family_distribution: dict[str, int]
    schema_version: str = "0.2.0"


def normalise_header(header: str) -> str:
    """Strip byte order marks, remove extra whitespace, and lowercase."""
    return " ".join(header.replace("\ufeff", "").strip().lower().split())


def canonical_headers(fieldnames: Iterable[str] | None) -> dict[str, str]:
    """Map raw CSV headers to canonical field names, tolerating duplicate raw columns."""
    if not fieldnames:
        raise ValueError("CSV has no header row")

    resolved: dict[str, str] = {}
    for source_header in fieldnames:
        norm = normalise_header(source_header)
        canonical = CICIDS_COLUMN_MAP.get(norm)
        # If mapped and not already captured, retain the first occurrence
        if canonical and canonical not in resolved:
            resolved[canonical] = source_header

    missing = set(REQUIRED_CANONICAL_FEATURES) - set(resolved)
    if missing:
        raise ValueError("missing required columns: " + ", ".join(sorted(missing)))
    return resolved


def map_attack_family(raw_label: str) -> tuple[str, int]:
    """Map a raw label to its canonical attack family and binary attack indicator.
    
    Preserves distinct attack families (DOS and DDOS are strictly separate).
    """
    if not raw_label or not raw_label.strip():
        raise ValueError("empty label")

    # Normalize special characters, dashes, and replacement characters
    clean = " ".join(
        raw_label.replace("\ufffd", " ")
        .replace("\x96", " ")
        .replace("\u2013", " ")
        .replace("–", " ")
        .replace("-", " ")
        .replace("ï¿½", " ")
        .strip()
        .upper()
        .split()
    )

    if clean in {"BENIGN", "NORMAL"}:
        return "BENIGN", 0
    # Web attacks must be checked before generic brute-force to classify 'Web Attack - Brute Force' correctly
    if "WEB ATTACK" in clean or "SQL INJECTION" in clean or "XSS" in clean:
        return "WEB_ATTACK", 1
    if "DDOS" in clean:
        return "DDOS", 1
    if "HEARTBLEED" in clean:
        return "HEARTBLEED", 1
    if "DOS" in clean:
        return "DOS", 1
    if "PORTSCAN" in clean or "PORT SCAN" in clean:
        return "PORT_SCAN", 1
    if "PATATOR" in clean or "BRUTE" in clean:
        return "BRUTE_FORCE", 1
    if "BOT" in clean:
        return "BOTNET", 1
    if "INFILTRATION" in clean:
        return "INFILTRATION", 1
    return "OTHER_ATTACK", 1


def parse_number(column: str, raw_value: str | None) -> int | float:
    """Parse numeric values with explicit checks for non-finite and negative records."""
    if raw_value is None:
        raise ValueError(f"{column}: missing value")
    val_str = raw_value.strip()
    if not val_str:
        raise ValueError(f"{column}: empty value")

    val_lower = val_str.lower()
    if val_lower in {"nan", "null", "none"}:
        raise ValueError(f"{column}: NaN value")
    if "inf" in val_lower:
        raise ValueError(f"{column}: infinite value")

    try:
        numeric = float(val_str)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{column}: not numeric ('{val_str}')") from exc

    if not math.isfinite(numeric):
        raise ValueError(f"{column}: not finite")
    if numeric < 0:
        raise ValueError(f"{column}: negative value ({numeric})")

    if column in INTEGER_COLUMNS:
        if not numeric.is_integer():
            raise ValueError(f"{column}: expected integer, got {numeric}")
        return int(numeric)
    return numeric


def canonicalise_row(row: dict[str, str], headers: dict[str, str]) -> dict[str, int | float | str]:
    """Validate and convert a single raw dictionary row to the canonical schema."""
    raw_label_header = headers["raw_label"]
    raw_label_val = row.get(raw_label_header, "").strip()
    if not raw_label_val:
        raise ValueError("empty label")

    attack_family, is_attack = map_attack_family(raw_label_val)

    converted: dict[str, int | float | str] = {
        "raw_label": raw_label_val,
        "attack_family": attack_family,
        "is_attack": is_attack,
    }

    for canonical, source_header in headers.items():
        if canonical == "raw_label":
            continue
        converted[canonical] = parse_number(canonical, row.get(source_header))

    if converted["destination_port"] > 65535:
        raise ValueError("destination_port: outside valid port range (0-65535)")

    return converted


def open_csv_reader(file_path: Path):
    """Open CSV with UTF-8 BOM tolerance and fallback encoding."""
    return file_path.open("r", encoding="utf-8-sig", errors="replace", newline="")


def process_csv(
    input_path: Path,
    output_path: Path,
    limit: int | None = None,
    chunk_size: int = 10000,
) -> PipelineReport:
    """Validate and canonicalise a CICIDS CSV dataset with streaming / chunked I/O."""
    rejected = Counter()
    raw_labels = Counter()
    family_distribution = Counter()
    total_rows = 0
    accepted_count = 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open_csv_reader(input_path) as source, output_path.open("w", encoding="utf-8", newline="") as destination:
        reader = csv.DictReader(source)
        headers = canonical_headers(reader.fieldnames)
        writer = csv.DictWriter(destination, fieldnames=CANONICAL_COLUMNS)
        writer.writeheader()

        batch: list[dict[str, int | float | str]] = []
        for total_rows, row in enumerate(reader, start=1):
            if limit and total_rows > limit:
                total_rows -= 1
                break
            try:
                canonical = canonicalise_row(row, headers)
            except ValueError as exc:
                rejected[str(exc)] += 1
                continue

            raw_labels[str(canonical["raw_label"])] += 1
            family_distribution[str(canonical["attack_family"])] += 1
            batch.append(canonical)
            accepted_count += 1

            if len(batch) >= chunk_size:
                writer.writerows(batch)
                batch.clear()

        if batch:
            writer.writerows(batch)
            batch.clear()

    return PipelineReport(
        source=str(input_path),
        total_rows=total_rows,
        accepted_rows=accepted_count,
        rejected_rows=sum(rejected.values()),
        rejection_reasons=dict(sorted(rejected.items())),
        raw_label_distribution=dict(sorted(raw_labels.items())),
        attack_family_distribution=dict(sorted(family_distribution.items())),
        schema_version="0.2.0",
    )


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Validate and canonicalise CICIDS network-flow CSV data.")
    parser.add_argument("--input", type=Path, required=True, help="Immutable raw CSV source path")
    parser.add_argument("--output", type=Path, required=True, help="Canonical processed CSV destination path")
    parser.add_argument("--report", type=Path, required=True, help="JSON validation report destination path")
    parser.add_argument("--limit", type=int, default=None, help="Optional maximum rows to process (for testing)")
    parser.add_argument("--chunk-size", type=int, default=10000, help="Batch write chunk size")
    args = parser.parse_args(argv)

    report = process_csv(args.input, args.output, limit=args.limit, chunk_size=args.chunk_size)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(asdict(report), indent=2) + "\n", encoding="utf-8")
    print(json.dumps(asdict(report), indent=2))


if __name__ == "__main__":
    main()
