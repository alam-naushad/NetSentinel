"""Zeek Native Telemetry and Flow Feature Processing Package."""

from app.services.zeek.feature_completeness import (
    CANONICAL_48_FEATURES,
    CANONICAL_48_SET,
    SIGNED_FEATURES,
    VALIDATED_ML_COMPATIBLE_SOURCES,
    evaluate_feature_completeness,
    extract_canonical_feature_vector,
    route_flow,
    safe_route_and_evaluate,
    validate_feature_value,
    verify_canonical_schema_consistency,
)
from app.services.zeek.zeek_connection_record import ZeekConnectionRecord
from app.services.zeek.zeek_flowmeter_parser import ZeekFlowMeterParser, ZeekFlowRecord
from app.services.zeek.zeek_log_parser import ZeekLogParser

__all__ = [
    "CANONICAL_48_FEATURES",
    "CANONICAL_48_SET",
    "SIGNED_FEATURES",
    "VALIDATED_ML_COMPATIBLE_SOURCES",
    "evaluate_feature_completeness",
    "extract_canonical_feature_vector",
    "route_flow",
    "safe_route_and_evaluate",
    "validate_feature_value",
    "verify_canonical_schema_consistency",
    "ZeekConnectionRecord",
    "ZeekFlowMeterParser",
    "ZeekFlowRecord",
    "ZeekLogParser",
]
