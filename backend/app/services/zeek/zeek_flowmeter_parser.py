"""Parser for packet-level Zeek FlowMeter log output (flowmeter.log).

Supports both standard Zeek TSV (#fields header) and JSON Lines formats.
Validates all 48 canonical CICFlowMeter features for model compatibility.
"""

from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.flows import FlowFeaturesInput

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ZeekFlowProvenance:
    """Provenance and identity metadata for a Zeek-extracted flow."""

    uid: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    ts: float
    duration: float


@dataclass(frozen=True, slots=True)
class ZeekFlowRecord:
    """A fully validated Zeek flow containing provenance and 48 model features."""

    provenance: ZeekFlowProvenance
    features: FlowFeaturesInput


@dataclass(frozen=True, slots=True)
class ZeekFlowMeterParseResult:
    """Result of parsing a flowmeter.log file."""

    flows: List[ZeekFlowRecord]
    total_lines_read: int
    malformed_count: int
    format_detected: str


class ZeekFlowMeterParser:
    """Parses and validates Zeek flowmeter log data."""

    # Set of 48 required canonical feature names
    CANONICAL_FEATURES = set(FlowFeaturesInput.model_fields.keys())

    @classmethod
    def parse_content(
        cls,
        content: bytes | str,
        max_flows: int = 100_000,
    ) -> ZeekFlowMeterParseResult:
        """Parse raw content from a flowmeter.log file."""
        if isinstance(content, bytes):
            text = content.decode("utf-8", errors="replace")
        else:
            text = content

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            return ZeekFlowMeterParseResult(
                flows=[],
                total_lines_read=0,
                malformed_count=0,
                format_detected="unknown",
            )

        # Detect format from first non-comment line or comment
        format_detected = "tsv"
        first_line = lines[0]
        if first_line.startswith("{") or any(l.startswith("{") for l in lines[:5]):
            format_detected = "json"

        if format_detected == "json":
            return cls._parse_json(lines, max_flows)
        else:
            return cls._parse_tsv(lines, max_flows)

    @classmethod
    def _parse_json(cls, lines: List[str], max_flows: int) -> ZeekFlowMeterParseResult:
        flows: List[ZeekFlowRecord] = []
        malformed = 0
        total_read = 0

        for line in lines:
            if not line or line.startswith("#"):
                continue
            total_read += 1
            if len(flows) >= max_flows:
                break

            try:
                data = json.loads(line)
                record = cls._build_record_from_dict(data)
                if record is not None:
                    flows.append(record)
                else:
                    malformed += 1
            except Exception as e:
                logger.debug("Failed to parse JSON flow line: %s", e)
                malformed += 1

        return ZeekFlowMeterParseResult(
            flows=flows,
            total_lines_read=total_read,
            malformed_count=malformed,
            format_detected="json",
        )

    @classmethod
    def _parse_tsv(cls, lines: List[str], max_flows: int) -> ZeekFlowMeterParseResult:
        flows: List[ZeekFlowRecord] = []
        malformed = 0
        total_read = 0
        fields: Optional[List[str]] = None

        for line in lines:
            if line.startswith("#fields"):
                parts = line.split("\t")
                fields = parts[1:]
                continue
            elif line.startswith("#"):
                continue

            total_read += 1
            if fields is None:
                malformed += 1
                continue

            if len(flows) >= max_flows:
                break

            parts = line.split("\t")
            if len(parts) != len(fields):
                malformed += 1
                continue

            row_dict: Dict[str, Any] = {}
            for k, v in zip(fields, parts):
                clean_val = None if v in ("-", "(empty)", "") else v
                row_dict[k] = clean_val

            record = cls._build_record_from_dict(row_dict)
            if record is not None:
                flows.append(record)
            else:
                malformed += 1

        return ZeekFlowMeterParseResult(
            flows=flows,
            total_lines_read=total_read,
            malformed_count=malformed,
            format_detected="tsv",
        )

    @classmethod
    def _build_record_from_dict(cls, data: Dict[str, Any]) -> Optional[ZeekFlowRecord]:
        """Validate and construct a ZeekFlowRecord from a dictionary."""
        try:
            # Extract provenance
            # Handle dot notation (id.orig_h) and underscore notation (id_orig_h)
            uid = str(data.get("uid") or "")
            if not uid:
                return None

            src_ip = str(data.get("id.orig_h") or data.get("id_orig_h") or "")
            dst_ip = str(data.get("id.resp_h") or data.get("id_resp_h") or "")
            src_port = int(data.get("id.orig_p") or data.get("id_orig_p") or 0)
            dst_port = int(data.get("id.resp_p") or data.get("id_resp_p") or 0)
            proto = str(data.get("proto") or "tcp").lower()
            ts = float(data.get("ts") or 0.0)
            duration = float(data.get("duration") or 0.0)

            if not src_ip or not dst_ip or src_port <= 0 or dst_port <= 0:
                return None

            provenance = ZeekFlowProvenance(
                uid=uid,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                proto=proto,
                ts=ts,
                duration=duration,
            )

            # Build 48 features dict
            feature_dict: Dict[str, float] = {}
            for feat_name in cls.CANONICAL_FEATURES:
                raw_val = data.get(feat_name)
                if raw_val is None:
                    # Check dot/hyphen replacement
                    raw_val = data.get(feat_name.replace("_", "-"))
                if raw_val is None:
                    return None

                val = float(raw_val)
                # Check finiteness
                if math.isnan(val) or math.isinf(val):
                    return None

                feature_dict[feat_name] = val

            features = FlowFeaturesInput(**feature_dict)
            return ZeekFlowRecord(provenance=provenance, features=features)
        except Exception:
            return None
