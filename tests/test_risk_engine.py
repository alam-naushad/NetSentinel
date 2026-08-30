import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.domain import DetectionStatus, Severity
from app.services.risk_engine import DecisionSignals, decide


class RiskEngineTests(unittest.TestCase):
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

    def test_low_confidence_unusual_flow_is_unknown_anomaly(self) -> None:
        result = decide(
            DecisionSignals(
                anomaly_score=0.91,
                predicted_class="PORT_SCAN",
                class_confidence=0.42,
            )
        )

        self.assertEqual(result.status, DetectionStatus.UNKNOWN_ANOMALY)
        self.assertNotIn("PORT_SCAN with", result.explanation)

    def test_invalid_scores_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            decide(
                DecisionSignals(
                    anomaly_score=1.2,
                    predicted_class="NORMAL",
                    class_confidence=0.2,
                )
            )


if __name__ == "__main__":
    unittest.main()
