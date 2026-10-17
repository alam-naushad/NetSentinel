"""Zeek Feature-Schema Completeness Scoring and Safe Routing Service.

Formalizes the boundary between network telemetry visibility and frozen K=48 ML
model inference. Evaluates presence, typing, finiteness, and domain constraints
across the 48 canonical CICFlowMeter features from the Stage 3 contract.

Guarantees:
- Single source of truth: CANONICAL_48_FEATURES is derived dynamically from
  the authoritative FlowFeaturesInput contract (matching data/metadata/selected_features.json).
- Source compatibility and schema completeness are decoupled into a dual-gate decision rule.
- Source compatibility is determined exclusively by trusted backend pipeline context
  (TrustedSourceChannel), never by trusting client-submitted payload fields.
- Zeek native telemetry (ZEEK_CONN) and unverified flowmeter logs (ZEEK_FLOWMETER)
  remain strictly TELEMETRY_ONLY.
- Input dictionary key ordering is treated as arbitrary; canonical vector construction
  is strictly guaranteed.
- Zero silent imputation: missing or invalid features are never fabricated.
- Frozen production models and inference contracts remain immutable.
"""

from __future__ import annotations

import json
import logging
import math
from pathlib import Path
from typing import Any, Mapping

import numpy as np

from app.schemas.flows import FlowFeaturesInput
from app.schemas.zeek import (
    FeatureCompletenessReport,
    FlowRoutingResponse,
    RoutingDecision,
    TrustedSourceChannel,
)

logger = logging.getLogger(__name__)

# ==============================================================================
# 1. Authoritative Canonical K=48 Feature Schema (Single Source of Truth)
# Derived directly from FlowFeaturesInput to prevent manual list drift
# ==============================================================================

CANONICAL_48_FEATURES: tuple[str, ...] = tuple(FlowFeaturesInput.model_fields.keys())
CANONICAL_48_SET: frozenset[str] = frozenset(CANONICAL_48_FEATURES)

# Features that may legitimately take signed / negative values
# - init_win_bytes_fwd / init_win_bytes_bwd: -1.0 when no TCP window was observed
# - fwd_header_length / bwd_header_length: unconstrained due to legacy CICFlowMeter integer overflow anomalies
SIGNED_FEATURES: frozenset[str] = frozenset({
    "init_win_bytes_fwd",
    "init_win_bytes_bwd",
    "fwd_header_length",
    "bwd_header_length",
})

# Standard networking provenance / envelope fields that are not model features
PROVENANCE_KEYS: frozenset[str] = frozenset({
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "id_orig_h",
    "id_orig_p",
    "id_resp_h",
    "id_resp_p",
    "proto",
    "service",
    "ts",
    "duration",
    "flow_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "ip_proto",
    "protocol_name",
    "start_time",
    "end_time",
    "start_time_iso",
    "end_time_iso",
    "duration_ms",
    "total_packets",
    "total_bytes",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "history",
    "orig_pkts",
    "resp_pkts",
    "orig_ip_bytes",
    "resp_ip_bytes",
    "missed_bytes",
    "local_orig",
    "local_resp",
    "tunnel_parents",
})

# Trusted backend sources that have been empirically verified as compatible
# with the frozen CICFlowMeter K=48 model schema.
# Note: ZEEK_CONN is connection-level telemetry and NOT compatible.
# Note: ZEEK_FLOWMETER is NOT included because semantic feature parity with
#       CICFlowMeter ground truth has not yet been established.
VALIDATED_ML_COMPATIBLE_SOURCES: frozenset[TrustedSourceChannel] = frozenset({
    TrustedSourceChannel.PCAP_RECONSTRUCTED,
    TrustedSourceChannel.REST_INFERENCE,
})


# ==============================================================================
# 2. Schema Consistency Verification
# ==============================================================================


def verify_canonical_schema_consistency(
    selected_features_path: Path | str | None = None,
) -> bool:
    """Verify that CANONICAL_48_FEATURES matches data/metadata/selected_features.json bit-for-bit."""
    if selected_features_path is None:
        # Resolve relative to project root (backend/app/services/zeek -> 4 levels up to root)
        project_root = Path(__file__).resolve().parents[4]
        selected_features_path = project_root / "data" / "metadata" / "selected_features.json"
    else:
        selected_features_path = Path(selected_features_path)

    if not selected_features_path.exists():
        raise FileNotFoundError(f"Canonical metadata file not found at {selected_features_path}")

    with open(selected_features_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    selected = tuple(meta.get("selected_features", []))
    if len(selected) != 48:
        raise ValueError(f"Expected 48 features in selected_features.json, found {len(selected)}")

    if CANONICAL_48_FEATURES != selected:
        raise ValueError(
            "Canonical schema mismatch between FlowFeaturesInput and selected_features.json!"
        )

    return True


# ==============================================================================
# 3. Individual Feature Validation
# ==============================================================================


def validate_feature_value(name: str, raw_value: Any) -> tuple[bool, float | None, str | None]:
    """Validate an individual feature value against presence, typing, finiteness, and domain rules.

    Returns:
        (is_valid, float_value, error_reason)
    """
    if raw_value is None:
        return False, None, "value is None"

    # Booleans are subclasses of int in Python, but are not valid flow measurements
    if isinstance(raw_value, bool):
        return False, None, f"boolean type rejected (expected numeric, got {raw_value!r})"

    # Check for empty placeholder strings common in Zeek/CSV logs
    if isinstance(raw_value, str):
        cleaned = raw_value.strip()
        if cleaned in ("", "-", "(empty)", "null", "none", "nan"):
            return False, None, f"empty placeholder value ({raw_value!r})"

    # Attempt IEEE 754 float conversion
    try:
        val = float(raw_value)
    except (ValueError, TypeError):
        return False, None, f"invalid numeric type or format ({raw_value!r})"

    # Finiteness check: reject NaN, +inf, -inf
    if not math.isfinite(val):
        return False, None, f"non-finite value ({val})"

    # Domain constraint: destination_port in [0, 65535]
    if name == "destination_port":
        if not (0.0 <= val <= 65535.0):
            return False, None, f"destination_port out of bounds [0, 65535] ({val})"

    # Domain constraint: non-negative metrics (packet lengths, timings, counts, rates, flags)
    elif name not in SIGNED_FEATURES:
        if val < 0.0:
            return False, None, f"feature '{name}' must be non-negative ({val})"

    return True, val, None


# ==============================================================================
# 4. Feature Completeness Evaluation
# ==============================================================================


def evaluate_feature_completeness(
    flow_data: Mapping[str, Any],
    *,
    allow_hyphen_alias: bool = True,
) -> FeatureCompletenessReport:
    """Evaluate feature-schema completeness against the canonical 48-feature contract.

    Mathematical formulation:
        C(R) = (Sum_{i=1}^{48} v(f_i, R)) / 48

    Where v(f_i, R) = 1 if feature f_i is present, numeric, finite, and within domain;
    0 otherwise.

    Dictionary insertion order is invariant: evaluation strictly iterates
    through CANONICAL_48_FEATURES.
    """
    valid_count = 0
    missing_features: list[str] = []
    invalid_features: dict[str, str] = {}
    matched_keys: set[str] = set()

    for feat in CANONICAL_48_FEATURES:
        raw_val = None
        key_found = False

        if feat in flow_data:
            raw_val = flow_data[feat]
            key_found = True
            matched_keys.add(feat)
        elif allow_hyphen_alias:
            hyphen_key = feat.replace("_", "-")
            if hyphen_key in flow_data:
                raw_val = flow_data[hyphen_key]
                key_found = True
                matched_keys.add(hyphen_key)

        if not key_found:
            missing_features.append(feat)
            continue

        is_valid, _, reason = validate_feature_value(feat, raw_val)
        if is_valid:
            valid_count += 1
        else:
            invalid_features[feat] = reason or "validation failed"

    # Identify extraneous/unexpected keys that are neither canonical features nor provenance
    unexpected_features = [
        k for k in flow_data.keys()
        if k not in matched_keys
        and k not in CANONICAL_48_SET
        and k not in PROVENANCE_KEYS
        and (not allow_hyphen_alias or k.replace("-", "_") not in CANONICAL_48_SET)
    ]

    total_req = len(CANONICAL_48_FEATURES)
    completeness_score = round(valid_count / float(total_req), 6)
    is_schema_complete = (valid_count == total_req) and (len(invalid_features) == 0)

    # Note: is_eligible_for_ml in completeness report evaluates schema completeness alone;
    # final ML eligibility is gated additionally by source compatibility in route_flow().
    if is_schema_complete:
        route = RoutingDecision.ML_INFERENCE
        routing_reason = (
            f"All {total_req} canonical features valid and present "
            f"(completeness: {completeness_score:.2%}). Schema is complete."
        )
    else:
        route = RoutingDecision.TELEMETRY_ONLY
        details: list[str] = []
        if missing_features:
            details.append(f"{len(missing_features)} missing")
        if invalid_features:
            details.append(f"{len(invalid_features)} invalid")
        summary_str = ", ".join(details) if details else "schema mismatch"
        routing_reason = (
            f"Schema completeness {completeness_score:.2%} ({valid_count}/{total_req}) "
            f"is below required 100.00% threshold [{summary_str}]. "
            f"Flow routed to TELEMETRY_ONLY to protect model integrity."
        )

    return FeatureCompletenessReport(
        total_required_features=total_req,
        valid_features_count=valid_count,
        completeness_score=completeness_score,
        is_eligible_for_ml=is_schema_complete,
        route=route,
        routing_reason=routing_reason,
        missing_features=missing_features,
        invalid_features=invalid_features,
        unexpected_features=unexpected_features,
    )


# ==============================================================================
# 5. Dual-Gate Safe Routing Engine
# ==============================================================================


def route_flow(
    flow_data: Mapping[str, Any],
    *,
    source_channel: TrustedSourceChannel,
    provenance: Mapping[str, Any] | None = None,
    allow_hyphen_alias: bool = True,
) -> FlowRoutingResponse:
    """Deterministically route a flow record to ML_INFERENCE or TELEMETRY_ONLY.

    Dual-Gate Decision Invariants:
    1. Gate 1 (Source Compatibility): source_channel must belong to
       VALIDATED_ML_COMPATIBLE_SOURCES. Any client-submitted 'source' key
       inside flow_data is ignored; source_channel must be assigned by trusted backend context.
    2. Gate 2 (Schema Completeness): Completeness score must be 1.0 (100% valid).
    3. If either gate fails:
       - route = TELEMETRY_ONLY.
       - is_eligible_for_ml = False.
       - feature_vector is None (guarantees NO malformed vector reaches ML).
       - telemetry is preserved for SOC visibility.
       - Zero synthetic or guessed feature values are injected.
    """
    completeness = evaluate_feature_completeness(flow_data, allow_hyphen_alias=allow_hyphen_alias)

    # Compile telemetry metadata for preservation
    telemetry_preserved: dict[str, Any] = {}
    if provenance:
        telemetry_preserved.update(dict(provenance))

    # Also capture available basic connection metadata from flow_data
    for k in (
        "uid", "ts", "proto", "service", "duration", "src_ip", "dst_ip",
        "src_port", "dst_port", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "orig_bytes", "resp_bytes", "conn_state", "history"
    ):
        if k in flow_data and k not in telemetry_preserved:
            telemetry_preserved[k] = flow_data[k]

    flow_id = str(
        telemetry_preserved.get("flow_id")
        or telemetry_preserved.get("uid")
        or flow_data.get("uid")
        or ""
    ) or None

    # Gate 1: Source Compatibility
    is_source_compatible = source_channel in VALIDATED_ML_COMPATIBLE_SOURCES

    # Gate 2: Schema Completeness
    is_schema_complete = (completeness.valid_features_count == len(CANONICAL_48_FEATURES)) and (
        len(completeness.invalid_features) == 0
    )

    # Dual-Gate Evaluation
    if is_source_compatible and is_schema_complete:
        # Both gates passed: construct strictly ordered canonical feature vector
        feature_vector: dict[str, float] = {}
        for feat in CANONICAL_48_FEATURES:
            raw = flow_data.get(feat)
            if raw is None and allow_hyphen_alias:
                raw = flow_data.get(feat.replace("_", "-"))
            feature_vector[feat] = float(raw)  # type: ignore

        routing_reason = (
            f"Source '{source_channel.value}' is verified ML-compatible and all 48 canonical "
            f"features are complete and valid. Flow is eligible for ML inference."
        )

        return FlowRoutingResponse(
            flow_id=flow_id,
            source_channel=source_channel,
            route=RoutingDecision.ML_INFERENCE,
            is_eligible_for_ml=True,
            completeness=completeness,
            ml_classification_performed=False,
            routing_reason=routing_reason,
            telemetry_preserved=telemetry_preserved,
            feature_vector=feature_vector,
        )

    # Telemetry-Only Route Determination
    if not is_source_compatible:
        if source_channel == TrustedSourceChannel.ZEEK_CONN:
            routing_reason = (
                "Source 'ZEEK_CONN' is native Zeek connection telemetry without packet-level "
                "flow metrics. Telemetry is preserved for network visibility; ML classification is bypassed."
            )
        elif source_channel == TrustedSourceChannel.ZEEK_FLOWMETER:
            routing_reason = (
                "Source 'ZEEK_FLOWMETER' contains flow fields but semantic feature parity "
                "with frozen CICFlowMeter model schema has not been empirically verified. "
                "Telemetry is preserved for visibility; ML classification is bypassed pending parity calibration."
            )
        else:
            routing_reason = (
                f"Source '{source_channel.value}' is unvalidated or untrusted. "
                "Telemetry is preserved for visibility; ML classification is bypassed."
            )
    else:
        # Source compatible, but schema incomplete
        routing_reason = (
            f"Source '{source_channel.value}' is ML-compatible, but schema completeness "
            f"{completeness.completeness_score:.2%} ({completeness.valid_features_count}/{len(CANONICAL_48_FEATURES)}) "
            f"is below the required 100.00% threshold. Flow routed to TELEMETRY_ONLY to protect model integrity."
        )

    # Update completeness report eligibility to reflect dual-gate decision
    updated_completeness = FeatureCompletenessReport(
        total_required_features=completeness.total_required_features,
        valid_features_count=completeness.valid_features_count,
        completeness_score=completeness.completeness_score,
        is_eligible_for_ml=False,
        route=RoutingDecision.TELEMETRY_ONLY,
        routing_reason=routing_reason,
        missing_features=completeness.missing_features,
        invalid_features=completeness.invalid_features,
        unexpected_features=completeness.unexpected_features,
    )

    return FlowRoutingResponse(
        flow_id=flow_id,
        source_channel=source_channel,
        route=RoutingDecision.TELEMETRY_ONLY,
        is_eligible_for_ml=False,
        completeness=updated_completeness,
        ml_classification_performed=False,
        routing_reason=routing_reason,
        telemetry_preserved=telemetry_preserved,
        feature_vector=None,
    )


# ==============================================================================
# 6. Canonical Vector Extraction & Safe Evaluation Adapter
# ==============================================================================


def extract_canonical_feature_vector(
    flow_data: Mapping[str, Any],
    *,
    source_channel: TrustedSourceChannel,
    allow_hyphen_alias: bool = True,
) -> np.ndarray:
    """Extract a 1D float64 numpy array of 48 features strictly aligned with CANONICAL_48_FEATURES.

    Invariance Guarantee:
    Input dictionary key ordering has zero effect; elements are placed in canonical sequence.

    Raises:
        ValueError: If flow is not eligible for ML (source incompatible or incomplete).
    """
    routing = route_flow(
        flow_data,
        source_channel=source_channel,
        allow_hyphen_alias=allow_hyphen_alias,
    )
    if not routing.is_eligible_for_ml or routing.feature_vector is None:
        raise ValueError(f"Cannot extract ML feature matrix: {routing.routing_reason}")

    # Extract in exact canonical order
    values = [routing.feature_vector[feat] for feat in CANONICAL_48_FEATURES]
    return np.array(values, dtype=np.float64)


def safe_route_and_evaluate(
    flow_data: Mapping[str, Any],
    *,
    source_channel: TrustedSourceChannel,
    provenance: Mapping[str, Any] | None = None,
    inference_runner: Any | None = None,
) -> dict[str, Any]:
    """Safely route a flow and conditionally execute ML inference only when both gates pass.

    When routed to TELEMETRY_ONLY:
    - Guaranteed zero execution of ML inference models.
    - Guaranteed zero fabrication of predicted_family, anomaly scores, or risk scores.
    - Preserves all network observability metadata.
    """
    routing = route_flow(flow_data, source_channel=source_channel, provenance=provenance)

    if routing.route == RoutingDecision.TELEMETRY_ONLY or not routing.is_eligible_for_ml:
        return {
            "flow_id": routing.flow_id,
            "source_channel": routing.source_channel.value,
            "route": RoutingDecision.TELEMETRY_ONLY.value,
            "is_eligible_for_ml": False,
            "ml_classification_performed": False,
            "predicted_family": None,
            "class_confidence": None,
            "raw_decision_score": None,
            "normalized_anomaly_score": None,
            "is_statistical_anomaly": False,
            "risk_score": None,
            "severity": None,
            "triage_status": None,
            "routing_reason": routing.routing_reason,
            "completeness_score": routing.completeness.completeness_score,
            "valid_features_count": routing.completeness.valid_features_count,
            "missing_features": routing.completeness.missing_features,
            "invalid_features": routing.completeness.invalid_features,
            "unexpected_features": routing.completeness.unexpected_features,
            "telemetry_preserved": routing.telemetry_preserved,
            "feature_vector": None,
        }

    # Route is ML_INFERENCE: execute inference runner if provided
    ml_result: dict[str, Any] = {}
    if inference_runner is not None and callable(inference_runner):
        features_input = FlowFeaturesInput(**routing.feature_vector)  # type: ignore
        ml_result = inference_runner(features_input)

    return {
        "flow_id": routing.flow_id,
        "source_channel": routing.source_channel.value,
        "route": RoutingDecision.ML_INFERENCE.value,
        "is_eligible_for_ml": True,
        "ml_classification_performed": bool(ml_result.get("ml_classification_performed", True)),
        "predicted_family": ml_result.get("predicted_family"),
        "class_confidence": ml_result.get("class_confidence"),
        "raw_decision_score": ml_result.get("raw_decision_score"),
        "normalized_anomaly_score": ml_result.get("normalized_anomaly_score"),
        "is_statistical_anomaly": ml_result.get("is_statistical_anomaly", False),
        "risk_score": ml_result.get("risk_score"),
        "severity": ml_result.get("severity"),
        "triage_status": ml_result.get("triage_status"),
        "routing_reason": routing.routing_reason,
        "completeness_score": routing.completeness.completeness_score,
        "valid_features_count": routing.completeness.valid_features_count,
        "missing_features": routing.completeness.missing_features,
        "invalid_features": routing.completeness.invalid_features,
        "unexpected_features": routing.completeness.unexpected_features,
        "telemetry_preserved": routing.telemetry_preserved,
        "feature_vector": routing.feature_vector,
    }
