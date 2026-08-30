"""Deterministic hybrid decision policy.

Combines supervised classifier outputs (predicted attack family, class confidence)
with statistical anomaly detector outputs (raw decision score, calibrated anomaly flag,
display anomaly score) and contextual metadata.

Note: All decision threshold values in PolicyConfig are initial operational application
policy candidates, not experimentally validated ML properties.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.domain import AttackFamily, DetectionStatus, Severity


@dataclass(frozen=True)
class PolicyConfig:
    """Configurable application-level heuristic triage policy thresholds."""

    known_attack_confidence_threshold: float = 0.80
    unknown_anomaly_score_threshold: float = 0.70
    critical_risk_threshold: int = 85
    high_risk_threshold: int = 65
    medium_risk_threshold: int = 40
    policy_version: str = "production-v1.0"


DEFAULT_POLICY = PolicyConfig()


@dataclass(frozen=True)
class DecisionSignals:
    """Input signals presented to the hybrid decision engine."""

    anomaly_score: float  # Display/normalized anomaly score in [0.0, 1.0] (1.0 = highly anomalous)
    predicted_class: str  # Predicted attack family string (e.g. "BENIGN", "DOS", "DDOS")
    class_confidence: float  # Classification confidence in [0.0, 1.0]
    raw_decision_score: float | None = None  # Exact scikit-learn decision_function output
    is_statistical_anomaly: bool = False  # Flagged by calibrated threshold (score < threshold)
    repeated_source_events: int = 0
    targets_sensitive_service: bool = False


@dataclass(frozen=True)
class Decision:
    """Analyst-facing decision result produced by the hybrid engine."""

    status: DetectionStatus
    severity: Severity
    risk_score: int
    explanation: str
    policy_version: str


def _validate_unit_interval(name: str, value: float) -> None:
    if not (0.0 <= value <= 1.0):
        raise ValueError(f"{name} must be between 0 and 1, got {value}")


def decide(signals: DecisionSignals, policy: PolicyConfig = DEFAULT_POLICY) -> Decision:
    """Turn supervised model, anomaly detector, and context signals into a triage decision.

    Hybrid Logic Rules:
    1. A high-confidence known attack (predicted_class != BENIGN and confidence >= threshold)
       is triaged as KNOWN_ATTACK with priority HIGH/CRITICAL, even if the anomaly score is low.
    2. An event with low classifier confidence (or predicted BENIGN) that exhibits a high
       anomaly score (or is_statistical_anomaly == True) is triaged as UNKNOWN_ANOMALY.
    3. Normal traffic with low anomaly score and no attack signal is triaged as NORMAL.
    """
    _validate_unit_interval("anomaly_score", signals.anomaly_score)
    _validate_unit_interval("class_confidence", signals.class_confidence)
    if signals.repeated_source_events < 0:
        raise ValueError("repeated_source_events cannot be negative")

    normalized_class = signals.predicted_class.strip().upper()
    is_benign_or_normal = normalized_class in (
        AttackFamily.BENIGN.value,
        "NORMAL",
        "BENIGN",
    )

    # Rule 1: High-confidence known attack
    is_known_attack = (
        not is_benign_or_normal
        and signals.class_confidence >= policy.known_attack_confidence_threshold
    )

    # Rule 2: Statistical unknown anomaly (applies if not a confident known attack)
    is_unknown_anomaly = (
        not is_known_attack
        and (
            signals.anomaly_score >= policy.unknown_anomaly_score_threshold
            or signals.is_statistical_anomaly
        )
    )

    # Risk Score calculation
    # Weighted combination of anomaly intensity, attack confidence, and contextual modifiers
    attack_weight = signals.class_confidence if not is_benign_or_normal else 0.0
    risk_score = round(
        signals.anomaly_score * 50
        + attack_weight * 35
        + min(signals.repeated_source_events, 5) * 2
        + (5 if signals.targets_sensitive_service else 0)
    )

    # Apply priority floors
    if is_known_attack:
        risk_score = max(risk_score, policy.high_risk_threshold)
    elif is_unknown_anomaly:
        risk_score = max(risk_score, policy.medium_risk_threshold)
    risk_score = min(max(0, risk_score), 100)

    # Status and explanation determination
    if is_known_attack:
        status = DetectionStatus.KNOWN_ATTACK
        explanation = (
            f"The supervised classifier identified {normalized_class} with "
            f"{signals.class_confidence:.1%} confidence."
        )
    elif is_unknown_anomaly:
        status = DetectionStatus.UNKNOWN_ANOMALY
        if is_benign_or_normal:
            explanation = (
                f"The flow was classified as {normalized_class} by supervised model, but the statistical "
                f"anomaly detector flagged anomalous behavior (anomaly score: {signals.anomaly_score:.2f})."
            )
        else:
            explanation = (
                f"The flow exhibited anomalous behavioral patterns but classifier confidence for "
                f"{normalized_class} ({signals.class_confidence:.1%}) is below the {policy.known_attack_confidence_threshold:.0%} policy gate."
            )
    else:
        status = DetectionStatus.NORMAL
        explanation = (
            "No high-confidence known attack signal or anomalous behavioral deviation was detected."
        )

    # Severity determination
    if risk_score >= policy.critical_risk_threshold:
        severity = Severity.CRITICAL
    elif risk_score >= policy.high_risk_threshold:
        severity = Severity.HIGH
    elif risk_score >= policy.medium_risk_threshold:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW

    return Decision(
        status=status,
        severity=severity,
        risk_score=risk_score,
        explanation=explanation,
        policy_version=policy.policy_version,
    )

