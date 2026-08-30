"""Unit tests for deterministic hybrid risk decision engine."""

import sys
import unittest
from pathlib import Path

# Ensure backend is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.domain import DetectionStatus, Severity
from app.services.risk_engine import DecisionSignals, PolicyConfig, decide


class RiskEngineTests(unittest.TestCase):
    """Test suite for deterministic hybrid triage policy."""

    def test_known_attack_is_preserved(self) -> None:
        result = decide(
            DecisionSignals(
                anomaly_score=0.75,
                predicted_class="PORT_SCAN",
                class_confidence=0.92,
            )
        )
        self.assertEqual(result.status, DetectionStatus.KNOWN_ATTACK)
        self.assertEqual(result.severity, Severity.HIGH)
        self.assertIn("PORT_SCAN", result.explanation)

    def test_confident_known_attack_is_not_downgraded_by_low_anomaly_score(self) -> None:
        result = decide(
            DecisionSignals(
                anomaly_score=0.10,
                predicted_class="BRUTE_FORCE",
                class_confidence=0.85,
            )
        )
        self.assertEqual(result.status, DetectionStatus.KNOWN_ATTACK)
        self.assertEqual(result.severity, Severity.HIGH)

    def test_benign_flow_with_high_anomaly_score_becomes_unknown_anomaly(self) -> None:
        """Requirement 4: Flow predicted BENIGN with high anomaly score must become UNKNOWN_ANOMALY."""
        result = decide(
            DecisionSignals(
                anomaly_score=0.82,
                predicted_class="BENIGN",
                class_confidence=0.95,
            )
        )
        self.assertEqual(result.status, DetectionStatus.UNKNOWN_ANOMALY)
        self.assertIn("BENIGN", result.explanation)
        self.assertIn("statistical anomaly detector flagged", result.explanation)

    def test_benign_flow_with_statistical_anomaly_flag_becomes_unknown_anomaly(self) -> None:
        """Flow flagged by calibrated threshold becomes UNKNOWN_ANOMALY even if display score is borderline."""
        result = decide(
            DecisionSignals(
                anomaly_score=0.55,
                predicted_class="BENIGN",
                class_confidence=0.90,
                is_statistical_anomaly=True,
            )
        )
        self.assertEqual(result.status, DetectionStatus.UNKNOWN_ANOMALY)

    def test_low_confidence_attack_with_high_anomaly_is_unknown_anomaly(self) -> None:
        result = decide(
            DecisionSignals(
                anomaly_score=0.91,
                predicted_class="PORT_SCAN",
                class_confidence=0.42,
            )
        )
        self.assertEqual(result.status, DetectionStatus.UNKNOWN_ANOMALY)
        self.assertIn("below the 80% policy gate", result.explanation)

    def test_normal_flow_with_low_anomaly_score(self) -> None:
        result = decide(
            DecisionSignals(
                anomaly_score=0.15,
                predicted_class="BENIGN",
                class_confidence=0.99,
                is_statistical_anomaly=False,
            )
        )
        self.assertEqual(result.status, DetectionStatus.NORMAL)
        self.assertEqual(result.severity, Severity.LOW)

    def test_contextual_modifiers_and_critical_severity(self) -> None:
        result = decide(
            DecisionSignals(
                anomaly_score=0.95,
                predicted_class="DOS",
                class_confidence=0.99,
                repeated_source_events=5,
                targets_sensitive_service=True,
            )
        )
        self.assertEqual(result.status, DetectionStatus.KNOWN_ATTACK)
        self.assertEqual(result.severity, Severity.CRITICAL)
        self.assertGreaterEqual(result.risk_score, 85)

    def test_configurable_policy_thresholds(self) -> None:
        custom_policy = PolicyConfig(
            known_attack_confidence_threshold=0.95,
            unknown_anomaly_score_threshold=0.60,
            policy_version="custom-v2.0",
        )
        result = decide(
            DecisionSignals(
                anomaly_score=0.65,
                predicted_class="DOS",
                class_confidence=0.90,  # Below 0.95 gate
            ),
            policy=custom_policy,
        )
        self.assertEqual(result.status, DetectionStatus.UNKNOWN_ANOMALY)
        self.assertEqual(result.policy_version, "custom-v2.0")

    def test_invalid_scores_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            decide(
                DecisionSignals(
                    anomaly_score=1.2,
                    predicted_class="NORMAL",
                    class_confidence=0.2,
                )
            )

        with self.assertRaises(ValueError):
            decide(
                DecisionSignals(
                    anomaly_score=0.5,
                    predicted_class="NORMAL",
                    class_confidence=-0.1,
                )
            )

        with self.assertRaises(ValueError):
            decide(
                DecisionSignals(
                    anomaly_score=0.5,
                    predicted_class="NORMAL",
                    class_confidence=0.5,
                    repeated_source_events=-1,
                )
            )


if __name__ == "__main__":
    unittest.main()

