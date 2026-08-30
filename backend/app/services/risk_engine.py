"""Deterministic hybrid decision policy.

Model training is intentionally separate from this policy. A trained pipeline will
provide the anomaly and class-confidence signals in a later phase.
"""

from dataclasses import dataclass

from app.domain import DetectionStatus, Severity


@dataclass(frozen=True)
class DecisionSignals:
    anomaly_score: float
    predicted_class: str
    class_confidence: float
    repeated_source_events: int = 0
    targets_sensitive_service: bool = False


@dataclass(frozen=True)
class Decision:
    status: DetectionStatus
    severity: Severity
    risk_score: int
    explanation: str


def _validate_unit_interval(name: str, value: float) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1")


def decide(signals: DecisionSignals) -> Decision:
    """Turn model/context signals into an analyst-facing result.

    Scores are deliberately simple and documented during the foundation stage.
    Their thresholds are configuration candidates, not validated production values;
    we will calibrate them against validation data in the ML-baseline phase.
    """
    _validate_unit_interval("anomaly_score", signals.anomaly_score)
    _validate_unit_interval("class_confidence", signals.class_confidence)
    if signals.repeated_source_events < 0:
        raise ValueError("repeated_source_events cannot be negative")

    is_known_attack = (
        signals.predicted_class.upper() != "NORMAL"
        and signals.class_confidence >= 0.80
    )
    is_unknown_anomaly = (
        signals.anomaly_score >= 0.70 and signals.class_confidence < 0.80
    )

    risk_score = round(
        signals.anomaly_score * 55
        + signals.class_confidence * 35
        + min(signals.repeated_source_events, 5) * 2
        + (5 if signals.targets_sensitive_service else 0)
    )
    # A confident known attack warrants priority even when the anomaly model sees
    # a familiar pattern as relatively close to normal. Conversely, a strong
    # unknown anomaly merits analyst review rather than a silent LOW event.
    if is_known_attack:
        risk_score = max(risk_score, 65)
    elif is_unknown_anomaly:
        risk_score = max(risk_score, 40)
    risk_score = min(risk_score, 100)

    if is_known_attack:
        status = DetectionStatus.KNOWN_ATTACK
        explanation = (
            f"The classifier identified {signals.predicted_class.upper()} with "
            f"{signals.class_confidence:.0%} confidence."
        )
    elif is_unknown_anomaly:
        status = DetectionStatus.UNKNOWN_ANOMALY
        explanation = (
            "The flow is strongly unusual but does not meet the confidence gate "
            "for a known attack class."
        )
    else:
        status = DetectionStatus.NORMAL
        explanation = "No strong anomaly or high-confidence known attack signal was found."

    if risk_score >= 85:
        severity = Severity.CRITICAL
    elif risk_score >= 65:
        severity = Severity.HIGH
    elif risk_score >= 40:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW

    return Decision(status, severity, risk_score, explanation)
